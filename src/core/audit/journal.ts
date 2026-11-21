// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * The atomic journal contract (AUDITABILITY.md, Atomic journal contract).
 * `AuditJournalProvider` is the upstream interface exactly: one
 * serialization point for expected-head comparison plus exact append,
 * unique epoch sequence and logical-ledger idempotency, same id and same
 * content returning the original entry, same id and different content
 * refused, ordered snapshot-stable range reads, and no update or delete.
 *
 * Helix adds two ports the managed recorder needs around it:
 * `AuditEpochControl` (one recorder authority per epoch, sealing an epoch
 * at a verified terminal head) and `AuditLedgerDirectory` (one ledger per
 * tenant, and which epoch of it is active). Neither has an update or delete
 * path for entries; sealing only ever closes an epoch.
 */

import { canonicalize } from '../crypto/jcs.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './ledger-errors.js';
import type { AuditHead, AuditLedgerRef, SignedAuditEntry } from './ledger.js';
import { auditEventFamily, type DecimalString, type Digest, type PartyRef, type SignerRef } from './types.js';

export type AuditAppendResult =
  | { kind: 'appended'; entry: SignedAuditEntry }
  | { kind: 'duplicate'; entry: SignedAuditEntry }
  | { kind: 'head_conflict'; actualHead: AuditHead | null }
  | { kind: 'idempotency_conflict'; existing: SignedAuditEntry };

export interface AuditRangeQuery extends AuditLedgerRef {
  afterSequence?: string;
  limit?: number;
}

export interface AuditJournalProvider {
  readonly capabilities: {
    durability: 'ephemeral' | 'durable';
    atomicAppend: true;
    orderedRead: true;
  };

  getHead(ledger: AuditLedgerRef): Promise<AuditHead | null>;
  getByIdempotencyKey(ledgerId: string, idempotencyKey: Digest): Promise<SignedAuditEntry | null>;
  compareAndAppend(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead | null;
    entry: SignedAuditEntry;
    idempotencyKey: Digest;
  }): Promise<AuditAppendResult>;
  readRange(query: AuditRangeQuery): AsyncIterable<SignedAuditEntry>;
}

// ── epochs ────────────────────────────────────────────────────────────────────

/** Why an epoch closed and its successor opened (AUDITABILITY.md, Recorder authority and topology). */
export const AUDIT_EPOCH_TRANSITION_REASONS = ['failover', 'key_rotation', 'retention_rollover', 'restore'] as const;
export type AuditEpochTransitionReason = (typeof AUDIT_EPOCH_TRANSITION_REASONS)[number];

export interface AuditEpochRecord extends AuditLedgerRef {
  status: 'active' | 'sealed';
  /** The one authority allowed to append to this epoch: the signer of its genesis. */
  recorder: SignerRef;
  head: AuditHead;
  sealedAt?: number;
  terminalDigest?: Digest;
  sealReason?: AuditEpochTransitionReason;
  successorEpochId?: string;
}

export interface AuditEpochControl {
  /** Every epoch of a ledger that has a genesis, in the order they were opened. */
  listEpochs(ledgerId: string): Promise<AuditEpochRecord[]>;
  /**
   * Closes an epoch at exactly `expectedHead` and records the terminal digest
   * and successor. Idempotent for identical input; refuses (`AUDIT_JOURNAL_FAILURE`)
   * a head that is not the committed one or an epoch already sealed differently.
   * After it, `compareAndAppend` to the epoch fails with `AUDIT_EPOCH_MISMATCH`.
   */
  sealEpoch(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead;
    terminalDigest: Digest;
    reason: AuditEpochTransitionReason;
    successorEpochId: string;
  }): Promise<'sealed' | 'already_sealed'>;
}

// ── ledgers ───────────────────────────────────────────────────────────────────

export interface AuditLedgerRecord {
  ledgerId: string;
  tenantRef: PartyRef;
  /** The epoch new appends go to; null before the first genesis. */
  activeEpochId: string | null;
  createdAt: number;
}

export interface AuditLedgerDirectory {
  getLedger(ledgerId: string): Promise<AuditLedgerRecord | null>;
  /** The ledger of a tenant, by the RFC 8785 text of its reference. */
  findLedgerByTenant(tenantRef: PartyRef): Promise<AuditLedgerRecord | null>;
  /** Creates the ledger or returns the existing one with that id (first writer wins). */
  ensureLedger(input: { ledgerId: string; tenantRef: PartyRef; createdAt: number }): Promise<AuditLedgerRecord>;
  /** Compare-and-set of the active epoch pointer. */
  setActiveEpoch(ledgerId: string, expected: string | null, next: string): Promise<boolean>;
  listLedgers(): Promise<AuditLedgerRecord[]>;
}

// ── reading for listings and verification ─────────────────────────────────────

/** An entry as storage holds it: the indexed columns beside the exact stored text. */
export interface StoredAuditEntry {
  ledgerId: string;
  ledgerEpochId: string;
  sequence: string;
  entryDigest: string;
  eventDigest: string;
  previousEntryDigest: string | null;
  /** The stored JSON text of the signed entry; parse it, never trust the columns over it. */
  entryText: string;
}

export interface ListAuditEntriesFilters {
  ledgerId?: string | undefined;
  eventType?: string | undefined;
  family?: string | undefined;
  correlationId?: string | undefined;
  since?: Date | undefined;
  limit: number;
}

export interface AuditJournalReader {
  /** Raw stored rows of one epoch in sequence order, for the verify command. */
  readStoredRange(ledger: AuditLedgerRef): AsyncIterable<StoredAuditEntry>;
  /** Newest first. */
  listEntries(filters: ListAuditEntriesFilters): Promise<SignedAuditEntry[]>;
  /**
   * The stored entries at these positions, in the order asked; a position
   * with no entry is left out. For an index kept beside the journal (one
   * that pages by its own keys and reads the entries here).
   */
  getEntries(positions: readonly AuditEntryPosition[]): Promise<SignedAuditEntry[]>;
}

/** Where one entry sits: its ledger, epoch and sequence. */
export interface AuditEntryPosition extends AuditLedgerRef {
  sequence: DecimalString;
}

/** The text key of a position, for matching rows to positions. */
export function auditEntryPositionKey(position: AuditEntryPosition): string {
  return `${position.ledgerId}\u0000${position.ledgerEpochId}\u0000${position.sequence}`;
}

/** The entries found, in the order of the positions asked (a missing one left out). */
export function inPositionOrder(positions: readonly AuditEntryPosition[], entries: readonly SignedAuditEntry[]): SignedAuditEntry[] {
  const byKey = new Map(entries.map((entry) => [auditEntryPositionKey(entry.core), entry]));
  return positions.flatMap((position) => byKey.get(auditEntryPositionKey(position)) ?? []);
}

/** Everything the managed recorder needs from storage. */
export type AuditLedgerStore = AuditJournalProvider & AuditEpochControl & AuditLedgerDirectory & AuditJournalReader;

/** The canonical text of a party reference: how ledgers are keyed by tenant. */
export function tenantKey(tenantRef: PartyRef): string {
  return canonicalize(tenantRef);
}

export function headsEqual(left: AuditHead | null, right: AuditHead | null): boolean {
  if (left === null || right === null) return left === right;
  return (
    left.ledgerId === right.ledgerId &&
    left.ledgerEpochId === right.ledgerEpochId &&
    left.sequence === right.sequence &&
    left.entryDigest === right.entryDigest
  );
}

export function sameSignerRef(left: SignerRef, right: SignerRef): boolean {
  return left.did === right.did && left.kid === right.kid && left.alg === right.alg;
}

export function epochSealedError(ledger: AuditLedgerRef): AuditProtocolError {
  return new AuditProtocolError(AUDIT_ERROR_CODES.EPOCH_MISMATCH, 'This audit ledger epoch is sealed; appends go to its successor', {
    ledgerId: ledger.ledgerId,
    ledgerEpochId: ledger.ledgerEpochId,
    reason: 'epoch_sealed',
  });
}

export function epochAuthorityError(ledger: AuditLedgerRef): AuditProtocolError {
  return new AuditProtocolError(
    AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
    'Only the recorder that signed this epoch genesis may append to it',
    { ledgerId: ledger.ledgerId, ledgerEpochId: ledger.ledgerEpochId },
  );
}

/** Whether a stored entry passes the listing filters. */
export function matchesListFilters(entry: SignedAuditEntry, filters: ListAuditEntriesFilters): boolean {
  const event = entry.core.event;
  return (
    (filters.ledgerId === undefined || entry.core.ledgerId === filters.ledgerId) &&
    (filters.eventType === undefined || event.eventType === filters.eventType) &&
    (filters.family === undefined || auditEventFamily(event.eventType) === filters.family) &&
    (filters.correlationId === undefined || event.correlationId === filters.correlationId) &&
    (filters.since === undefined || entry.core.recordedAt >= filters.since.getTime())
  );
}

function ledgerKey(ledger: AuditLedgerRef): string {
  return `${ledger.ledgerId}\0${ledger.ledgerEpochId}`;
}

interface MemoryEpoch {
  record: AuditEpochRecord;
  entries: Array<{ entry: SignedAuditEntry; text: string; idempotencyKey: Digest }>;
}

/**
 * Ephemeral reference journal with the same atomic contract as the durable
 * adapters; for tests, examples and memory-mode development. It advertises
 * `ephemeral`, so it never qualifies a deployment for AAP-2.
 */
export class MemoryAuditJournal implements AuditLedgerStore {
  readonly capabilities = { durability: 'ephemeral' as const, atomicAppend: true as const, orderedRead: true as const };

  private readonly epochs = new Map<string, MemoryEpoch>();
  private readonly epochOrder = new Map<string, string[]>();
  private readonly idempotency = new Map<string, SignedAuditEntry>();
  private readonly ledgers = new Map<string, AuditLedgerRecord>();

  async getHead(ledger: AuditLedgerRef): Promise<AuditHead | null> {
    const epoch = this.epochs.get(ledgerKey(ledger));
    return epoch === undefined ? null : { ...epoch.record.head };
  }

  async getByIdempotencyKey(ledgerId: string, key: Digest): Promise<SignedAuditEntry | null> {
    return this.idempotency.get(`${ledgerId}\0${key}`) ?? null;
  }

  async compareAndAppend(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead | null;
    entry: SignedAuditEntry;
    idempotencyKey: Digest;
  }): Promise<AuditAppendResult> {
    const idKey = `${input.ledger.ledgerId}\0${input.idempotencyKey}`;
    const existing = this.idempotency.get(idKey);
    if (existing !== undefined) {
      return existing.eventDigest === input.entry.eventDigest
        ? { kind: 'duplicate', entry: existing }
        : { kind: 'idempotency_conflict', existing };
    }
    const key = ledgerKey(input.ledger);
    const epoch = this.epochs.get(key);
    const actualHead = epoch === undefined ? null : { ...epoch.record.head };
    if (!headsEqual(input.expectedHead, actualHead)) return { kind: 'head_conflict', actualHead };
    if (epoch?.record.status === 'sealed') throw epochSealedError(input.ledger);
    if (epoch !== undefined && !sameSignerRef(epoch.record.recorder, input.entry.core.recorder)) {
      throw epochAuthorityError(input.ledger);
    }
    const head: AuditHead = { ...input.ledger, sequence: input.entry.core.sequence, entryDigest: input.entry.entryDigest };
    const stored = { entry: structuredClone(input.entry), text: canonicalize(input.entry), idempotencyKey: input.idempotencyKey };
    if (epoch === undefined) {
      this.epochs.set(key, { record: { ...input.ledger, status: 'active', recorder: { ...input.entry.core.recorder }, head }, entries: [stored] });
      this.epochOrder.set(input.ledger.ledgerId, [...(this.epochOrder.get(input.ledger.ledgerId) ?? []), input.ledger.ledgerEpochId]);
    } else {
      epoch.entries.push(stored);
      epoch.record.head = head;
    }
    this.idempotency.set(idKey, stored.entry);
    return { kind: 'appended', entry: input.entry };
  }

  async *readRange(query: AuditRangeQuery): AsyncIterable<SignedAuditEntry> {
    const snapshot = [...(this.epochs.get(ledgerKey(query))?.entries ?? [])];
    const after = query.afterSequence === undefined ? null : BigInt(query.afterSequence);
    let yielded = 0;
    for (const { entry } of snapshot) {
      if (after !== null && BigInt(entry.core.sequence) <= after) continue;
      if (query.limit !== undefined && yielded >= query.limit) return;
      yielded += 1;
      yield entry;
    }
  }

  async listEpochs(ledgerId: string): Promise<AuditEpochRecord[]> {
    return (this.epochOrder.get(ledgerId) ?? []).map((epochId) => {
      const record = this.epochs.get(`${ledgerId}\0${epochId}`)!.record;
      return { ...record, head: { ...record.head }, recorder: { ...record.recorder } };
    });
  }

  async sealEpoch(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead;
    terminalDigest: Digest;
    reason: AuditEpochTransitionReason;
    successorEpochId: string;
  }): Promise<'sealed' | 'already_sealed'> {
    const epoch = this.epochs.get(ledgerKey(input.ledger));
    if (epoch === undefined || !headsEqual(epoch.record.head, input.expectedHead)) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'Cannot seal an audit epoch at a head that is not its committed head', {
        ledgerId: input.ledger.ledgerId,
        ledgerEpochId: input.ledger.ledgerEpochId,
      });
    }
    if (epoch.record.status === 'sealed') {
      if (epoch.record.terminalDigest === input.terminalDigest && epoch.record.successorEpochId === input.successorEpochId) {
        return 'already_sealed';
      }
      throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'This audit epoch was already sealed with another terminal or successor', {
        ledgerId: input.ledger.ledgerId,
        ledgerEpochId: input.ledger.ledgerEpochId,
      });
    }
    Object.assign(epoch.record, {
      status: 'sealed',
      sealedAt: Date.now(),
      terminalDigest: input.terminalDigest,
      sealReason: input.reason,
      successorEpochId: input.successorEpochId,
    });
    const ledger = this.ledgers.get(input.ledger.ledgerId);
    if (ledger !== undefined && ledger.activeEpochId === input.ledger.ledgerEpochId) ledger.activeEpochId = input.successorEpochId;
    return 'sealed';
  }

  async getLedger(ledgerId: string): Promise<AuditLedgerRecord | null> {
    const ledger = this.ledgers.get(ledgerId);
    return ledger === undefined ? null : { ...ledger };
  }

  async findLedgerByTenant(tenantRef: PartyRef): Promise<AuditLedgerRecord | null> {
    const key = tenantKey(tenantRef);
    for (const ledger of this.ledgers.values()) if (tenantKey(ledger.tenantRef) === key) return { ...ledger };
    return null;
  }

  async ensureLedger(input: { ledgerId: string; tenantRef: PartyRef; createdAt: number }): Promise<AuditLedgerRecord> {
    const existing = this.ledgers.get(input.ledgerId);
    if (existing !== undefined) return { ...existing };
    const created: AuditLedgerRecord = { ledgerId: input.ledgerId, tenantRef: input.tenantRef, activeEpochId: null, createdAt: input.createdAt };
    this.ledgers.set(input.ledgerId, created);
    return { ...created };
  }

  async setActiveEpoch(ledgerId: string, expected: string | null, next: string): Promise<boolean> {
    const ledger = this.ledgers.get(ledgerId);
    if (ledger === undefined || ledger.activeEpochId !== expected) return false;
    ledger.activeEpochId = next;
    return true;
  }

  async listLedgers(): Promise<AuditLedgerRecord[]> {
    return [...this.ledgers.values()].map((ledger) => ({ ...ledger }));
  }

  async *readStoredRange(ledger: AuditLedgerRef): AsyncIterable<StoredAuditEntry> {
    for (const { entry, text } of [...(this.epochs.get(ledgerKey(ledger))?.entries ?? [])]) {
      yield {
        ledgerId: entry.core.ledgerId,
        ledgerEpochId: entry.core.ledgerEpochId,
        sequence: entry.core.sequence,
        entryDigest: entry.entryDigest,
        eventDigest: entry.eventDigest,
        previousEntryDigest: entry.core.previousEntryDigest,
        entryText: text,
      };
    }
  }

  async listEntries(filters: ListAuditEntriesFilters): Promise<SignedAuditEntry[]> {
    const all: SignedAuditEntry[] = [];
    for (const epoch of this.epochs.values()) for (const { entry } of epoch.entries) all.push(entry);
    return all
      .filter((entry) => matchesListFilters(entry, filters))
      .sort((a, b) => b.core.recordedAt - a.core.recordedAt)
      .slice(0, filters.limit);
  }

  async getEntries(positions: readonly AuditEntryPosition[]): Promise<SignedAuditEntry[]> {
    const found: SignedAuditEntry[] = [];
    for (const position of positions) {
      const entry = this.epochs.get(ledgerKey(position))?.entries.find((item) => item.entry.core.sequence === position.sequence)?.entry;
      if (entry !== undefined) found.push(entry);
    }
    return found;
  }

  /**
   * Test seam: the stored text of one entry replaced, as an attacker with
   * write access to storage would. Production journals have no such method.
   */
  tamperForTesting(ledger: AuditLedgerRef, sequence: string, text: string): void {
    const stored = this.epochs.get(ledgerKey(ledger))?.entries.find((item) => item.entry.core.sequence === sequence);
    if (stored === undefined) throw new Error('no such entry');
    stored.text = text;
  }
}
