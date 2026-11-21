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
 * `AuditJournalProvider` on PostgreSQL (story A-2 point 2; AUDITABILITY.md:
 * "use a ledger-head row plus entry/idempotency unique constraints inside
 * one transaction"). One compare-and-append is one transaction: the
 * idempotency key is resolved first, the epoch's head row is locked
 * `FOR UPDATE` and compared with the expected head, then the entry is
 * inserted and the head advanced. Unique constraints on `(ledger, epoch,
 * sequence)` and `(ledger, idempotencyKey)` settle every race the lock does
 * not (two genesis appends, two submissions of one event), and a race
 * resolves to the same answers the contract defines: `duplicate`,
 * `idempotency_conflict` or `head_conflict` with the head that won.
 *
 * There is no update or delete path: this class issues neither on the
 * journal, and the migration's triggers refuse both (and truncation) for
 * every role that does not disable triggers.
 */

import type pg from 'pg';
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
  type AuditLedgerRef,
  type AuditLedgerStore,
  type AuditRangeQuery,
  type Digest,
  type ListAuditEntriesFilters,
  type PartyRef,
  type SignedAuditEntry,
  type StoredAuditEntry,
} from '../core/index.js';

type Queryable = Pick<pg.Pool, 'query'> | pg.PoolClient;

interface HeadRow {
  ledgerId: string;
  ledgerEpochId: string;
  sequence: string;
  entryDigest: string;
  recorderDid: string;
  recorderKid: string;
  recorderAlg: string;
  status: 'active' | 'sealed';
  terminalDigest: string | null;
  sealReason: string | null;
  successorEpochId: string | null;
  sealedAt: Date | null;
}

interface LedgerRow {
  ledgerId: string;
  tenantRef: PartyRef;
  activeEpochId: string | null;
  createdAt: Date;
}

const PAGE_SIZE = 500;

/**
 * A concurrent append won: a unique constraint refused this one (23505), or
 * the insert trigger did (23514) because the winner's genesis committed
 * after this transaction found no head row to lock. With a head row locked
 * neither can happen, so both mean "answer with what the winner committed".
 */
function lostTheRace(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return code === '23505' || code === '23514';
}

function headOf(row: Pick<HeadRow, 'ledgerId' | 'ledgerEpochId' | 'sequence' | 'entryDigest'>): AuditHead {
  return { ledgerId: row.ledgerId, ledgerEpochId: row.ledgerEpochId, sequence: String(row.sequence), entryDigest: row.entryDigest as Digest };
}

function epochOf(row: HeadRow): AuditEpochRecord {
  return {
    ledgerId: row.ledgerId,
    ledgerEpochId: row.ledgerEpochId,
    status: row.status,
    recorder: { did: row.recorderDid, kid: row.recorderKid, alg: row.recorderAlg as 'EdDSA' | 'ES256' },
    head: headOf(row),
    ...(row.sealedAt !== null ? { sealedAt: row.sealedAt.getTime() } : {}),
    ...(row.terminalDigest !== null ? { terminalDigest: row.terminalDigest as Digest } : {}),
    ...(row.sealReason !== null ? { sealReason: row.sealReason as AuditEpochTransitionReason } : {}),
    ...(row.successorEpochId !== null ? { successorEpochId: row.successorEpochId } : {}),
  };
}

function ledgerOf(row: LedgerRow): AuditLedgerRecord {
  return { ledgerId: row.ledgerId, tenantRef: row.tenantRef, activeEpochId: row.activeEpochId, createdAt: row.createdAt.getTime() };
}

/** A stored entry, parsed strictly: a row that is not a signed entry fails closed. */
function parseStored(text: string): SignedAuditEntry {
  try {
    return parseSignedAuditEntry(JSON.parse(text));
  } catch (error) {
    throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'A stored audit entry is not a signed entry', undefined, { cause: error });
  }
}

export class PostgresAuditJournal implements AuditLedgerStore {
  readonly capabilities = { durability: 'durable' as const, atomicAppend: true as const, orderedRead: true as const };

  constructor(private readonly pool: pg.Pool) {}

  async getHead(ledger: AuditLedgerRef): Promise<AuditHead | null> {
    return this.readHead(this.pool, ledger);
  }

  async getByIdempotencyKey(ledgerId: string, idempotencyKey: Digest): Promise<SignedAuditEntry | null> {
    return this.readByIdempotency(this.pool, ledgerId, idempotencyKey);
  }

  async compareAndAppend(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead | null;
    entry: SignedAuditEntry;
    idempotencyKey: Digest;
  }): Promise<AuditAppendResult> {
    const { ledger, entry, idempotencyKey } = input;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      try {
        const existing = await this.readByIdempotency(client, ledger.ledgerId, idempotencyKey);
        if (existing !== null) {
          await client.query('COMMIT');
          return existing.eventDigest === entry.eventDigest ? { kind: 'duplicate', entry: existing } : { kind: 'idempotency_conflict', existing };
        }
        const { rows } = await client.query<HeadRow>(
          `SELECT * FROM "audit_ledger_heads" WHERE "ledgerId" = $1 AND "ledgerEpochId" = $2 FOR UPDATE`,
          [ledger.ledgerId, ledger.ledgerEpochId],
        );
        const row = rows[0];
        const actualHead = row === undefined ? null : headOf(row);
        if (!headsEqual(input.expectedHead, actualHead)) {
          await client.query('COMMIT');
          return { kind: 'head_conflict', actualHead };
        }
        if (row?.status === 'sealed') throw epochSealedError(ledger);
        if (row !== undefined && !sameSignerRef(epochOf(row).recorder, entry.core.recorder)) throw epochAuthorityError(ledger);

        const event = entry.core.event;
        await client.query(
          `INSERT INTO "audit_journal_entries"
             ("ledgerId", "ledgerEpochId", "sequence", "idempotencyKey", "eventId", "sourceId", "eventType", "family",
              "eventDigest", "entryDigest", "previousEntryDigest", "recordedAt", "correlationId", "entry")
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
          [
            ledger.ledgerId,
            ledger.ledgerEpochId,
            entry.core.sequence,
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
          ],
        );
        if (row === undefined) {
          await client.query(
            `INSERT INTO "audit_ledger_heads" ("ledgerId", "ledgerEpochId", "sequence", "entryDigest", "recorderDid", "recorderKid", "recorderAlg")
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [ledger.ledgerId, ledger.ledgerEpochId, entry.core.sequence, entry.entryDigest, entry.core.recorder.did, entry.core.recorder.kid, entry.core.recorder.alg],
          );
        } else {
          await client.query(`UPDATE "audit_ledger_heads" SET "sequence" = $3, "entryDigest" = $4 WHERE "ledgerId" = $1 AND "ledgerEpochId" = $2`, [
            ledger.ledgerId,
            ledger.ledgerEpochId,
            entry.core.sequence,
            entry.entryDigest,
          ]);
        }
        await client.query('COMMIT');
        return { kind: 'appended', entry };
      } catch (error) {
        await client.query('ROLLBACK');
        if (!lostTheRace(error)) throw error;
        // A concurrent append won the race: answer with what it committed.
        const raced = await this.readByIdempotency(this.pool, ledger.ledgerId, idempotencyKey);
        if (raced !== null) {
          return raced.eventDigest === entry.eventDigest ? { kind: 'duplicate', entry: raced } : { kind: 'idempotency_conflict', existing: raced };
        }
        return { kind: 'head_conflict', actualHead: await this.readHead(this.pool, ledger) };
      }
    } finally {
      client.release();
    }
  }

  async *readRange(query: AuditRangeQuery): AsyncIterable<SignedAuditEntry> {
    for await (const stored of this.pages(query, query.afterSequence, query.limit)) yield parseStored(stored.entryText);
  }

  async *readStoredRange(ledger: AuditLedgerRef): AsyncIterable<StoredAuditEntry> {
    yield* this.pages(ledger, undefined, undefined);
  }

  async listEpochs(ledgerId: string): Promise<AuditEpochRecord[]> {
    const { rows } = await this.pool.query<HeadRow>(`SELECT * FROM "audit_ledger_heads" WHERE "ledgerId" = $1 ORDER BY "position"`, [ledgerId]);
    return rows.map(epochOf);
  }

  async sealEpoch(input: {
    ledger: AuditLedgerRef;
    expectedHead: AuditHead;
    terminalDigest: Digest;
    reason: AuditEpochTransitionReason;
    successorEpochId: string;
  }): Promise<'sealed' | 'already_sealed'> {
    const { ledger } = input;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      try {
        const { rows } = await client.query<HeadRow>(
          `SELECT * FROM "audit_ledger_heads" WHERE "ledgerId" = $1 AND "ledgerEpochId" = $2 FOR UPDATE`,
          [ledger.ledgerId, ledger.ledgerEpochId],
        );
        const row = rows[0];
        if (row === undefined || !headsEqual(headOf(row), input.expectedHead)) {
          throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'Cannot seal an audit epoch at a head that is not its committed head', { ...ledger });
        }
        if (row.status === 'sealed') {
          await client.query('COMMIT');
          if (row.terminalDigest === input.terminalDigest && row.successorEpochId === input.successorEpochId) return 'already_sealed';
          throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'This audit epoch was already sealed with another terminal or successor', { ...ledger });
        }
        await client.query(
          `UPDATE "audit_ledger_heads"
              SET "status" = 'sealed', "terminalDigest" = $3, "sealReason" = $4, "successorEpochId" = $5, "sealedAt" = CURRENT_TIMESTAMP
            WHERE "ledgerId" = $1 AND "ledgerEpochId" = $2`,
          [ledger.ledgerId, ledger.ledgerEpochId, input.terminalDigest, input.reason, input.successorEpochId],
        );
        await client.query(`UPDATE "audit_ledgers" SET "activeEpochId" = $3 WHERE "ledgerId" = $1 AND "activeEpochId" = $2`, [
          ledger.ledgerId,
          ledger.ledgerEpochId,
          input.successorEpochId,
        ]);
        await client.query('COMMIT');
        return 'sealed';
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw error;
      }
    } finally {
      client.release();
    }
  }

  async getLedger(ledgerId: string): Promise<AuditLedgerRecord | null> {
    const { rows } = await this.pool.query<LedgerRow>(`SELECT * FROM "audit_ledgers" WHERE "ledgerId" = $1`, [ledgerId]);
    return rows[0] === undefined ? null : ledgerOf(rows[0]);
  }

  async findLedgerByTenant(tenantRef: PartyRef): Promise<AuditLedgerRecord | null> {
    const { rows } = await this.pool.query<LedgerRow>(`SELECT * FROM "audit_ledgers" WHERE "tenantKey" = $1`, [tenantKey(tenantRef)]);
    return rows[0] === undefined ? null : ledgerOf(rows[0]);
  }

  async ensureLedger(input: { ledgerId: string; tenantRef: PartyRef; createdAt: number }): Promise<AuditLedgerRecord> {
    await this.pool.query(
      `INSERT INTO "audit_ledgers" ("ledgerId", "tenantKey", "tenantRef", "createdAt") VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
      [input.ledgerId, tenantKey(input.tenantRef), JSON.stringify(input.tenantRef), new Date(input.createdAt)],
    );
    const ledger = await this.getLedger(input.ledgerId);
    if (ledger === null) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'This tenant already has a ledger under another id', { ledgerId: input.ledgerId });
    }
    return ledger;
  }

  async setActiveEpoch(ledgerId: string, expected: string | null, next: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE "audit_ledgers" SET "activeEpochId" = $3 WHERE "ledgerId" = $1 AND "activeEpochId" IS NOT DISTINCT FROM $2`,
      [ledgerId, expected, next],
    );
    return result.rowCount === 1;
  }

  async listLedgers(): Promise<AuditLedgerRecord[]> {
    const { rows } = await this.pool.query<LedgerRow>(`SELECT * FROM "audit_ledgers" ORDER BY "createdAt", "ledgerId"`);
    return rows.map(ledgerOf);
  }

  async listEntries(filters: ListAuditEntriesFilters): Promise<SignedAuditEntry[]> {
    const conditions: string[] = [];
    const values: unknown[] = [];
    const add = (column: string, value: unknown, op = '='): void => {
      values.push(value);
      conditions.push(`"${column}" ${op} $${values.length}`);
    };
    if (filters.ledgerId !== undefined) add('ledgerId', filters.ledgerId);
    if (filters.eventType !== undefined) add('eventType', filters.eventType);
    if (filters.family !== undefined) add('family', filters.family);
    if (filters.correlationId !== undefined) add('correlationId', filters.correlationId);
    if (filters.since !== undefined) add('recordedAt', filters.since.getTime(), '>=');
    values.push(Math.trunc(filters.limit));
    const { rows } = await this.pool.query<{ entry: string }>(
      `SELECT "entry" FROM "audit_journal_entries" ${conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''}
        ORDER BY "recordedAt" DESC, "id" DESC LIMIT $${values.length}`,
      values,
    );
    return rows.map((row) => parseStored(row.entry));
  }

  private async readHead(db: Queryable, ledger: AuditLedgerRef): Promise<AuditHead | null> {
    const { rows } = await db.query<HeadRow>(
      `SELECT "ledgerId", "ledgerEpochId", "sequence", "entryDigest" FROM "audit_ledger_heads" WHERE "ledgerId" = $1 AND "ledgerEpochId" = $2`,
      [ledger.ledgerId, ledger.ledgerEpochId],
    );
    return rows[0] === undefined ? null : headOf(rows[0]);
  }

  private async readByIdempotency(db: Queryable, ledgerId: string, idempotencyKey: Digest): Promise<SignedAuditEntry | null> {
    const { rows } = await db.query<{ entry: string }>(
      `SELECT "entry" FROM "audit_journal_entries" WHERE "ledgerId" = $1 AND "idempotencyKey" = $2`,
      [ledgerId, idempotencyKey],
    );
    return rows[0] === undefined ? null : parseStored(rows[0].entry);
  }

  /**
   * Pages through one epoch in sequence order, bounded by the head read when
   * iteration starts: entries are immutable, so the range is snapshot-stable.
   */
  private async *pages(ledger: AuditLedgerRef, afterSequence: string | undefined, limit: number | undefined): AsyncIterable<StoredAuditEntry> {
    const head = await this.readHead(this.pool, ledger);
    if (head === null) return;
    let after = afterSequence === undefined ? -1n : BigInt(afterSequence);
    let remaining = limit ?? Number.POSITIVE_INFINITY;
    while (remaining > 0) {
      const { rows } = await this.pool.query<{
        sequence: string;
        entryDigest: string;
        eventDigest: string;
        previousEntryDigest: string | null;
        entry: string;
        ledgerId: string;
        ledgerEpochId: string;
      }>(
        `SELECT "ledgerId", "ledgerEpochId", "sequence", "entryDigest", "eventDigest", "previousEntryDigest", "entry"
           FROM "audit_journal_entries"
          WHERE "ledgerId" = $1 AND "ledgerEpochId" = $2 AND "sequence" > $3 AND "sequence" <= $4
          ORDER BY "sequence" LIMIT $5`,
        [ledger.ledgerId, ledger.ledgerEpochId, after.toString(), head.sequence, Math.min(PAGE_SIZE, remaining)],
      );
      if (rows.length === 0) return;
      for (const row of rows) {
        yield {
          ledgerId: row.ledgerId,
          ledgerEpochId: row.ledgerEpochId,
          sequence: String(row.sequence),
          entryDigest: row.entryDigest,
          eventDigest: row.eventDigest,
          previousEntryDigest: row.previousEntryDigest,
          entryText: row.entry,
        };
        remaining -= 1;
        after = BigInt(row.sequence);
      }
    }
  }
}
