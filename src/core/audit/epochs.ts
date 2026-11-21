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
 * Epochs (story A-2 point 5; AUDITABILITY.md, Recorder authority and
 * topology). Failover, recorder key rotation, retention rollover and restore
 * each close the current epoch at its committed head and open a successor
 * whose genesis commits the previous epoch id and its terminal digest. A
 * restore is a transition, never a rewind: no entry is ever signed again at
 * a sequence of an epoch that was receipted.
 *
 * The terminal digest is computed from the chain head for now
 * (`terminalHeadDigest`): story A-3 brings RFC 9162 checkpoints, and the
 * genesis field it fills (`previousTerminalCheckpointDigest`) then carries
 * the signed terminal checkpoint's digest instead.
 */

import { randomBytes } from 'node:crypto';
import { mkdir, open, readFile, rename } from 'node:fs/promises';
import { dirname } from 'node:path';
import { auditDigest } from './digest.js';
import { headsEqual, type AuditEpochControl, type AuditEpochTransitionReason, type AuditJournalProvider } from './journal.js';
import type { AuditHead } from './ledger.js';
import { isAuditError, AUDIT_ERROR_CODES } from './ledger-errors.js';
import type { AuditEpochTransitionGuard } from './recorder.js';
import { AUDIT_DIGEST_DOMAINS, type Digest } from './types.js';

/** Marks the head commitment apart from A-3's checkpoint core, which shares the checkpoint domain. */
export const AUDIT_TERMINAL_HEAD_SCHEMA = 'urn:helix:audit:terminal-head:v1';

/**
 * The terminal digest of an epoch, computed from its chain head: domain
 * `org.kya-os.audit.checkpoint.v1` over `{schema, ledgerId, ledgerEpochId,
 * treeSize, lastSequence, headEntryDigest}`. Anyone holding the epoch's
 * entries recomputes it; A-3 replaces it with a signed checkpoint digest.
 */
export function terminalHeadDigest(head: AuditHead): Digest {
  return auditDigest(AUDIT_DIGEST_DOMAINS.checkpoint, {
    schema: AUDIT_TERMINAL_HEAD_SCHEMA,
    ledgerId: head.ledgerId,
    ledgerEpochId: head.ledgerEpochId,
    treeSize: (BigInt(head.sequence) + 1n).toString(),
    lastSequence: head.sequence,
    headEntryDigest: head.entryDigest,
  });
}

/** `epoch-<index, 4 digits>-<yyyymmdd>-<8 hex>`: ordered by index, unique by the random part. */
export function newAuditEpochId(index: number, now: number = Date.now()): string {
  const date = new Date(now).toISOString().slice(0, 10).replaceAll('-', '');
  return `epoch-${String(index).padStart(4, '0')}-${date}-${randomBytes(4).toString('hex')}`;
}

/**
 * Verify-and-seal over the journal's epoch control: the predecessor's
 * terminal digest must equal the one computed from its committed head, and
 * sealing at exactly that head is atomic with moving the ledger's active
 * epoch to the successor. Identical input on an already sealed predecessor
 * is accepted (idempotent).
 */
export class JournalEpochTransitionGuard implements AuditEpochTransitionGuard {
  constructor(private readonly store: AuditEpochControl & AuditJournalProvider) {}

  async verifyAndSeal(input: {
    ledgerId: string;
    previousEpochId: string;
    nextEpochId: string;
    previousTerminalCheckpointDigest: Digest;
    reason: AuditEpochTransitionReason;
  }): Promise<boolean> {
    const previous = (await this.store.listEpochs(input.ledgerId)).find((epoch) => epoch.ledgerEpochId === input.previousEpochId);
    if (previous === undefined) return false;
    if (previous.status === 'sealed') {
      return previous.terminalDigest === input.previousTerminalCheckpointDigest && previous.successorEpochId === input.nextEpochId;
    }
    if (terminalHeadDigest(previous.head) !== input.previousTerminalCheckpointDigest) return false;
    try {
      await this.store.sealEpoch({
        ledger: { ledgerId: input.ledgerId, ledgerEpochId: input.previousEpochId },
        expectedHead: previous.head,
        terminalDigest: input.previousTerminalCheckpointDigest,
        reason: input.reason,
        successorEpochId: input.nextEpochId,
      });
      return true;
    } catch (error) {
      if (isAuditError(error, AUDIT_ERROR_CODES.JOURNAL_FAILURE)) return false;
      throw error;
    }
  }
}

// ── the restore witness ───────────────────────────────────────────────────────

/**
 * What one recorder instance last committed per ledger, kept outside the
 * journal's database. On start, a journal whose active epoch is behind the
 * witness (or holds another digest at the witnessed sequence) was restored
 * from a backup or failed over to a lagging primary: the recorder opens a
 * successor epoch instead of signing again at receipted sequences.
 */
export interface AuditRecorderWitness {
  read(ledgerId: string): Promise<AuditHead | null>;
  record(head: AuditHead): Promise<void>;
  readonly durability: 'ephemeral' | 'durable';
}

export class MemoryRecorderWitness implements AuditRecorderWitness {
  readonly durability = 'ephemeral' as const;
  private readonly heads = new Map<string, AuditHead>();

  async read(ledgerId: string): Promise<AuditHead | null> {
    const head = this.heads.get(ledgerId);
    return head === undefined ? null : { ...head };
  }

  async record(head: AuditHead): Promise<void> {
    const current = this.heads.get(head.ledgerId);
    if (current === undefined || current.ledgerEpochId !== head.ledgerEpochId || BigInt(head.sequence) > BigInt(current.sequence)) {
      this.heads.set(head.ledgerId, { ...head });
    }
  }
}

/**
 * A JSON file of `{ ledgerId: head }`, replaced atomically (write, fsync,
 * rename) on every commit; writes are coalesced so a burst costs one write
 * per drain. Keep it on a different volume from the database it witnesses.
 */
export class FileRecorderWitness implements AuditRecorderWitness {
  readonly durability = 'durable' as const;
  private heads: Map<string, AuditHead> | undefined;
  private pending: Promise<void> = Promise.resolve();
  private dirty = false;

  constructor(private readonly path: string) {}

  async read(ledgerId: string): Promise<AuditHead | null> {
    const head = (await this.load()).get(ledgerId);
    return head === undefined ? null : { ...head };
  }

  async record(head: AuditHead): Promise<void> {
    const heads = await this.load();
    const current = heads.get(head.ledgerId);
    if (current !== undefined && current.ledgerEpochId === head.ledgerEpochId && BigInt(head.sequence) <= BigInt(current.sequence)) return;
    heads.set(head.ledgerId, { ...head });
    this.dirty = true;
    this.pending = this.pending.then(() => this.flush());
    await this.pending;
  }

  private async load(): Promise<Map<string, AuditHead>> {
    if (this.heads !== undefined) return this.heads;
    try {
      const parsed = JSON.parse(await readFile(this.path, 'utf8')) as Record<string, AuditHead>;
      this.heads = new Map(Object.entries(parsed));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      this.heads = new Map();
    }
    return this.heads;
  }

  private async flush(): Promise<void> {
    if (!this.dirty) return;
    this.dirty = false;
    const text = JSON.stringify(Object.fromEntries(this.heads!), null, 2);
    await mkdir(dirname(this.path), { recursive: true });
    const temporary = `${this.path}.${process.pid}.tmp`;
    const handle = await open(temporary, 'w');
    try {
      await handle.writeFile(text, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, this.path);
  }
}

/**
 * Whether a journal head (and the digest the journal holds at the witnessed
 * sequence) shows a restore: the witnessed epoch is the active one, and the
 * journal is behind the witness or disagrees at the witnessed sequence.
 */
export function witnessShowsRestore(witnessed: AuditHead, journalHead: AuditHead | null, digestAtWitnessed: Digest | null): boolean {
  if (journalHead === null) return true;
  if (BigInt(journalHead.sequence) < BigInt(witnessed.sequence)) return true;
  if (headsEqual(journalHead, witnessed)) return false;
  return digestAtWitnessed !== witnessed.entryDigest;
}
