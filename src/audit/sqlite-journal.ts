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
 * `AuditJournalProvider` on SQLite for the self-hosted single-file
 * deployment: one `BEGIN IMMEDIATE` transaction per compare-and-append (the
 * database's single writer is the serialization point), the same unique
 * constraints and append-only triggers as PostgreSQL (`sqlite-schema.ts`).
 */

import {
  AUDIT_ERROR_CODES,
  AuditProtocolError,
  auditEventFamily,
  canonicalize,
  epochAuthorityError,
  epochSealedError,
  headsEqual,
  parseSignedAuditEntry,
  sameSignerRef,
  tenantKey,
  type AuditAppendResult,
  type AuditEpochRecord,
  type AuditEpochTransitionReason,
  type AuditHead,
  type AuditLedgerRecord,
  type AuditEntryPosition,
  type AuditLedgerRef,
  type AuditLedgerStore,
  type AuditRangeQuery,
  type Digest,
  type ListAuditEntriesFilters,
  type PartyRef,
  type SignedAuditEntry,
  type StoredAuditEntry,
} from '../core/index.js';
import type { SqliteStore } from '../storage/sqlite.js';

interface HeadRow {
  ledger_id: string;
  ledger_epoch_id: string;
  sequence: number;
  entry_digest: string;
  recorder_did: string;
  recorder_kid: string;
  recorder_alg: string;
  status: 'active' | 'sealed';
  terminal_digest: string | null;
  seal_reason: string | null;
  successor_epoch_id: string | null;
  sealed_at: number | null;
}

interface LedgerRow {
  ledger_id: string;
  tenant_ref: string;
  active_epoch_id: string | null;
  created_at: number;
}

interface EntryRow {
  ledger_id: string;
  ledger_epoch_id: string;
  sequence: number;
  entry_digest: string;
  event_digest: string;
  previous_entry_digest: string | null;
  entry: string;
}

function headOf(row: Pick<HeadRow, 'ledger_id' | 'ledger_epoch_id' | 'sequence' | 'entry_digest'>): AuditHead {
  return { ledgerId: row.ledger_id, ledgerEpochId: row.ledger_epoch_id, sequence: String(row.sequence), entryDigest: row.entry_digest as Digest };
}

function epochOf(row: HeadRow): AuditEpochRecord {
  return {
    ledgerId: row.ledger_id,
    ledgerEpochId: row.ledger_epoch_id,
    status: row.status,
    recorder: { did: row.recorder_did, kid: row.recorder_kid, alg: row.recorder_alg as 'EdDSA' | 'ES256' },
    head: headOf(row),
    ...(row.sealed_at !== null ? { sealedAt: row.sealed_at } : {}),
    ...(row.terminal_digest !== null ? { terminalDigest: row.terminal_digest as Digest } : {}),
    ...(row.seal_reason !== null ? { sealReason: row.seal_reason as AuditEpochTransitionReason } : {}),
    ...(row.successor_epoch_id !== null ? { successorEpochId: row.successor_epoch_id } : {}),
  };
}

function ledgerOf(row: LedgerRow): AuditLedgerRecord {
  return { ledgerId: row.ledger_id, tenantRef: JSON.parse(row.tenant_ref) as PartyRef, activeEpochId: row.active_epoch_id, createdAt: row.created_at };
}

function parseStored(text: string): SignedAuditEntry {
  try {
    return parseSignedAuditEntry(JSON.parse(text));
  } catch (error) {
    throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'A stored audit entry is not a signed entry', undefined, { cause: error });
  }
}

const PAGE_SIZE = 500;

export class SqliteAuditJournal implements AuditLedgerStore {
  readonly capabilities = { durability: 'durable' as const, atomicAppend: true as const, orderedRead: true as const };

  constructor(private readonly sqlite: SqliteStore) {}

  async getHead(ledger: AuditLedgerRef): Promise<AuditHead | null> {
    return this.head(ledger);
  }

  async getByIdempotencyKey(ledgerId: string, idempotencyKey: Digest): Promise<SignedAuditEntry | null> {
    return this.byIdempotency(ledgerId, idempotencyKey);
  }

  async compareAndAppend(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead | null;
    entry: SignedAuditEntry;
    idempotencyKey: Digest;
  }): Promise<AuditAppendResult> {
    const { ledger, entry, idempotencyKey } = input;
    return this.sqlite.transaction((): AuditAppendResult => {
      const existing = this.byIdempotency(ledger.ledgerId, idempotencyKey);
      if (existing !== null) {
        return existing.eventDigest === entry.eventDigest ? { kind: 'duplicate', entry: existing } : { kind: 'idempotency_conflict', existing };
      }
      const row = this.headRow(ledger);
      const actualHead = row === undefined ? null : headOf(row);
      if (!headsEqual(input.expectedHead, actualHead)) return { kind: 'head_conflict', actualHead };
      if (row?.status === 'sealed') throw epochSealedError(ledger);
      if (row !== undefined && !sameSignerRef(epochOf(row).recorder, entry.core.recorder)) throw epochAuthorityError(ledger);
      const event = entry.core.event;
      this.sqlite.write(
        `INSERT INTO audit_journal_entries (ledger_id, ledger_epoch_id, sequence, idempotency_key, event_id, source_id, event_type, family,
           event_digest, entry_digest, previous_entry_digest, recorded_at, correlation_id, entry)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ledger.ledgerId,
        ledger.ledgerEpochId,
        Number(entry.core.sequence),
        idempotencyKey,
        event.eventId,
        event.source.sourceId,
        event.eventType,
        auditEventFamily(event.eventType),
        entry.eventDigest,
        entry.entryDigest,
        entry.core.previousEntryDigest,
        entry.core.recordedAt,
        event.correlationId ?? null,
        canonicalize(entry),
      );
      if (row === undefined) {
        this.sqlite.write(
          `INSERT INTO audit_ledger_heads (ledger_id, ledger_epoch_id, sequence, entry_digest, recorder_did, recorder_kid, recorder_alg)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          ledger.ledgerId,
          ledger.ledgerEpochId,
          Number(entry.core.sequence),
          entry.entryDigest,
          entry.core.recorder.did,
          entry.core.recorder.kid,
          entry.core.recorder.alg,
        );
      } else {
        this.sqlite.write(
          `UPDATE audit_ledger_heads SET sequence = ?, entry_digest = ? WHERE ledger_id = ? AND ledger_epoch_id = ?`,
          Number(entry.core.sequence),
          entry.entryDigest,
          ledger.ledgerId,
          ledger.ledgerEpochId,
        );
      }
      return { kind: 'appended', entry };
    });
  }

  async *readRange(query: AuditRangeQuery): AsyncIterable<SignedAuditEntry> {
    for (const stored of this.rows(query, query.afterSequence, query.limit)) yield parseStored(stored.entryText);
  }

  async *readStoredRange(ledger: AuditLedgerRef): AsyncIterable<StoredAuditEntry> {
    yield* this.rows(ledger, undefined, undefined);
  }

  async listEpochs(ledgerId: string): Promise<AuditEpochRecord[]> {
    return this.sqlite.select<HeadRow>(`SELECT * FROM audit_ledger_heads WHERE ledger_id = ? ORDER BY position`, ledgerId).map(epochOf);
  }

  async sealEpoch(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead;
    terminalDigest: Digest;
    reason: AuditEpochTransitionReason;
    successorEpochId: string;
  }): Promise<'sealed' | 'already_sealed'> {
    const { ledger } = input;
    return this.sqlite.transaction(() => {
      const row = this.headRow(ledger);
      if (row === undefined || !headsEqual(headOf(row), input.expectedHead)) {
        throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'Cannot seal an audit epoch at a head that is not its committed head', { ...ledger });
      }
      if (row.status === 'sealed') {
        if (row.terminal_digest === input.terminalDigest && row.successor_epoch_id === input.successorEpochId) return 'already_sealed';
        throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'This audit epoch was already sealed with another terminal or successor', { ...ledger });
      }
      this.sqlite.write(
        `UPDATE audit_ledger_heads SET status = 'sealed', terminal_digest = ?, seal_reason = ?, successor_epoch_id = ?, sealed_at = ?
          WHERE ledger_id = ? AND ledger_epoch_id = ?`,
        input.terminalDigest,
        input.reason,
        input.successorEpochId,
        Date.now(),
        ledger.ledgerId,
        ledger.ledgerEpochId,
      );
      this.sqlite.write(
        `UPDATE audit_ledgers SET active_epoch_id = ? WHERE ledger_id = ? AND active_epoch_id = ?`,
        input.successorEpochId,
        ledger.ledgerId,
        ledger.ledgerEpochId,
      );
      return 'sealed';
    });
  }

  async getLedger(ledgerId: string): Promise<AuditLedgerRecord | null> {
    const row = this.sqlite.select<LedgerRow>(`SELECT * FROM audit_ledgers WHERE ledger_id = ?`, ledgerId)[0];
    return row === undefined ? null : ledgerOf(row);
  }

  async findLedgerByTenant(tenantRef: PartyRef): Promise<AuditLedgerRecord | null> {
    const row = this.sqlite.select<LedgerRow>(`SELECT * FROM audit_ledgers WHERE tenant_key = ?`, tenantKey(tenantRef))[0];
    return row === undefined ? null : ledgerOf(row);
  }

  async ensureLedger(input: { ledgerId: string; tenantRef: PartyRef; createdAt: number }): Promise<AuditLedgerRecord> {
    this.sqlite.write(
      `INSERT OR IGNORE INTO audit_ledgers (ledger_id, tenant_key, tenant_ref, created_at) VALUES (?, ?, ?, ?)`,
      input.ledgerId,
      tenantKey(input.tenantRef),
      JSON.stringify(input.tenantRef),
      input.createdAt,
    );
    const ledger = await this.getLedger(input.ledgerId);
    if (ledger === null) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'This tenant already has a ledger under another id', { ledgerId: input.ledgerId });
    }
    return ledger;
  }

  async setActiveEpoch(ledgerId: string, expected: string | null, next: string): Promise<boolean> {
    return this.sqlite.write(`UPDATE audit_ledgers SET active_epoch_id = ? WHERE ledger_id = ? AND active_epoch_id IS ?`, next, ledgerId, expected).changes === 1;
  }

  async listLedgers(): Promise<AuditLedgerRecord[]> {
    return this.sqlite.select<LedgerRow>(`SELECT * FROM audit_ledgers ORDER BY created_at, ledger_id`).map(ledgerOf);
  }

  async listEntries(filters: ListAuditEntriesFilters): Promise<SignedAuditEntry[]> {
    const conditions: string[] = [];
    const values: unknown[] = [];
    const add = (sql: string, value: unknown): void => {
      conditions.push(sql);
      values.push(value);
    };
    if (filters.ledgerId !== undefined) add('ledger_id = ?', filters.ledgerId);
    if (filters.eventType !== undefined) add('event_type = ?', filters.eventType);
    if (filters.family !== undefined) add('family = ?', filters.family);
    if (filters.correlationId !== undefined) add('correlation_id = ?', filters.correlationId);
    if (filters.since !== undefined) add('recorded_at >= ?', filters.since.getTime());
    if (filters.before !== undefined) {
      const { recordedAt, ledgerId, ledgerEpochId, sequence } = filters.before;
      conditions.push('(recorded_at, ledger_id, ledger_epoch_id, sequence) < (?, ?, ?, ?)');
      values.push(recordedAt, ledgerId, ledgerEpochId, Number(sequence));
    }
    const rows = this.sqlite.select<{ entry: string }>(
      `SELECT entry FROM audit_journal_entries ${conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''}
        ORDER BY recorded_at DESC, ledger_id DESC, ledger_epoch_id DESC, sequence DESC LIMIT ?`,
      ...values,
      Math.trunc(filters.limit),
    );
    return rows.map((row) => parseStored(row.entry));
  }

  async getEntries(positions: readonly AuditEntryPosition[]): Promise<SignedAuditEntry[]> {
    const found: SignedAuditEntry[] = [];
    for (const position of positions) {
      const row = this.sqlite.select<{ entry: string }>(
        `SELECT entry FROM audit_journal_entries WHERE ledger_id = ? AND ledger_epoch_id = ? AND sequence = ?`,
        position.ledgerId,
        position.ledgerEpochId,
        Number(position.sequence),
      )[0];
      if (row !== undefined) found.push(parseStored(row.entry));
    }
    return found;
  }

  private headRow(ledger: AuditLedgerRef): HeadRow | undefined {
    return this.sqlite.select<HeadRow>(`SELECT * FROM audit_ledger_heads WHERE ledger_id = ? AND ledger_epoch_id = ?`, ledger.ledgerId, ledger.ledgerEpochId)[0];
  }

  private head(ledger: AuditLedgerRef): AuditHead | null {
    const row = this.headRow(ledger);
    return row === undefined ? null : headOf(row);
  }

  private byIdempotency(ledgerId: string, idempotencyKey: Digest): SignedAuditEntry | null {
    const row = this.sqlite.select<{ entry: string }>(
      `SELECT entry FROM audit_journal_entries WHERE ledger_id = ? AND idempotency_key = ?`,
      ledgerId,
      idempotencyKey,
    )[0];
    return row === undefined ? null : parseStored(row.entry);
  }

  /** One epoch in sequence order, bounded by the head when iteration starts (snapshot-stable). */
  private *rows(ledger: AuditLedgerRef, afterSequence: string | undefined, limit: number | undefined): Iterable<StoredAuditEntry> {
    const head = this.head(ledger);
    if (head === null) return;
    let after = afterSequence === undefined ? -1 : Number(afterSequence);
    let remaining = limit ?? Number.POSITIVE_INFINITY;
    while (remaining > 0) {
      const rows = this.sqlite.select<EntryRow>(
        `SELECT ledger_id, ledger_epoch_id, sequence, entry_digest, event_digest, previous_entry_digest, entry FROM audit_journal_entries
          WHERE ledger_id = ? AND ledger_epoch_id = ? AND sequence > ? AND sequence <= ? ORDER BY sequence LIMIT ?`,
        ledger.ledgerId,
        ledger.ledgerEpochId,
        after,
        Number(head.sequence),
        Math.min(PAGE_SIZE, remaining),
      );
      if (rows.length === 0) return;
      for (const row of rows) {
        yield {
          ledgerId: row.ledger_id,
          ledgerEpochId: row.ledger_epoch_id,
          sequence: String(row.sequence),
          entryDigest: row.entry_digest,
          eventDigest: row.event_digest,
          previousEntryDigest: row.previous_entry_digest,
          entryText: row.entry,
        };
        remaining -= 1;
        after = row.sequence;
      }
    }
  }
}
