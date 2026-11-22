// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Story A-2 on real PostgreSQL: 100 concurrent submissions give a gap-free
 * sequence with one receipt each (one recorder, and four replicas sharing the
 * journal); a stale head is refused; idempotency both ways; a journal
 * restored behind the recorder fails closed with AUDIT_JOURNAL_FAILURE, and
 * the restarted recorder opens a new epoch whose genesis commits the previous
 * epoch id and terminal digest, with history verifying across the boundary;
 * key rotation, failover and retention rollover; and the migration's
 * triggers refusing every mutation of the journal.
 */

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import {
  AuditProtocolError,
  FileRecorderWitness,
  ManagedAuditRecorder,
  terminalHeadDigest,
  verifyAuditLedger,
  type AuditLedgerStore,
  type AuditSigner,
  type SignedAuditEntry,
} from '../../../src/core/index.js';
import { PostgresAuditEvidenceStore } from '../../../src/audit/postgres-evidence.js';
import { PostgresAuditJournal } from '../../../src/audit/postgres-journal.js';
import { TEST_RECORDER_KEYS, TENANT, contextFor, producerEvent, submission, testRecorderSigner } from '../../utils/auditLedger.js';
import { auditJournalDatabaseUrl, createMigratedSchema } from '../../utils/postgresSchema.js';

const url = auditJournalDatabaseUrl;
const cleanups: Array<() => Promise<void>> = [];

async function freshJournal(): Promise<{ journal: PostgresAuditJournal; pool: pg.Pool; schema: string }> {
  const migrated = await createMigratedSchema(url!);
  cleanups.push(() => migrated.drop());
  return { journal: new PostgresAuditJournal(migrated.pool), pool: migrated.pool, schema: migrated.schema };
}

function managed(journal: AuditLedgerStore, options: { signer?: AuditSigner; witnessPath?: string; evidence?: PostgresAuditEvidenceStore } = {}): ManagedAuditRecorder {
  return new ManagedAuditRecorder({
    store: journal,
    signer: options.signer ?? testRecorderSigner(),
    ...(options.witnessPath !== undefined ? { witness: new FileRecorderWitness(options.witnessPath) } : {}),
    ...(options.evidence !== undefined ? { evidence: options.evidence } : {}),
  });
}

async function verifyAll(journal: PostgresAuditJournal, ledgerId: string, trustedRecorders?: string[]): ReturnType<typeof verifyAuditLedger> {
  const epochs = await journal.listEpochs(ledgerId);
  return verifyAuditLedger({
    ledgerId,
    epochs: epochs.map((epoch) => ({ ledgerEpochId: epoch.ledgerEpochId, read: () => journal.readStoredRange(epoch), storedHead: epoch.head })),
    ...(trustedRecorders !== undefined ? { trustedRecorders } : {}),
  });
}

async function entriesOf(journal: PostgresAuditJournal, ledgerId: string, ledgerEpochId: string): Promise<SignedAuditEntry[]> {
  const entries: SignedAuditEntry[] = [];
  for await (const entry of journal.readRange({ ledgerId, ledgerEpochId })) entries.push(entry);
  return entries;
}

async function rejection(promise: Promise<unknown>): Promise<AuditProtocolError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof AuditProtocolError) return error;
    throw error;
  }
  throw new Error('expected a refusal');
}

describe.skipIf(!url)('AuditRecorderService on PostgreSQL', () => {
  afterAll(async () => {
    for (const cleanup of cleanups.reverse()) await cleanup();
  });

  it('gives 100 concurrent submissions a gap-free sequence with one receipt each', async () => {
    const { journal } = await freshJournal();
    const recorder = managed(journal);
    const events = Array.from({ length: 100 }, (_, i) => producerEvent(`concurrent-${i}`));
    const entries = await Promise.all(events.map((event) => recorder.submit(submission(event), contextFor(event))));

    const sequences = entries.map((entry) => Number(entry.core.sequence)).sort((a, b) => a - b);
    expect(sequences).toEqual(Array.from({ length: 100 }, (_, i) => i + 1));
    expect(new Set(entries.map((entry) => entry.recorderReceipt.jws)).size).toBe(100);
    expect(new Set(entries.map((entry) => entry.core.event.eventId)).size).toBe(100);

    const ledgerId = recorder.ledgerIdOf(TENANT);
    const [epoch] = await journal.listEpochs(ledgerId);
    const stored = await entriesOf(journal, ledgerId, epoch!.ledgerEpochId);
    expect(stored.map((entry) => entry.core.sequence)).toEqual(Array.from({ length: 101 }, (_, i) => String(i)));
    for (let i = 1; i < stored.length; i += 1) expect(stored[i]!.core.previousEntryDigest).toBe(stored[i - 1]!.entryDigest);
    const verified = await verifyAll(journal, ledgerId, [recorder.signer.ref.did]);
    expect(verified).toMatchObject({ ok: true, entriesVerified: 101 });
  });

  it('serializes four replicas sharing the journal through compare-and-append, gap-free', async () => {
    const { journal } = await freshJournal();
    const signer = testRecorderSigner();
    const replicas = Array.from({ length: 4 }, () => managed(journal, { signer }));
    const events = Array.from({ length: 100 }, (_, i) => producerEvent(`replica-${i}`));
    const entries = await Promise.all(events.map((event, i) => replicas[i % 4]!.submit(submission(event), contextFor(event))));
    expect(entries.map((entry) => Number(entry.core.sequence)).sort((a, b) => a - b)).toEqual(Array.from({ length: 100 }, (_, i) => i + 1));
    const ledgerId = replicas[0]!.ledgerIdOf(TENANT);
    expect(await journal.listEpochs(ledgerId)).toHaveLength(1);
    expect((await verifyAll(journal, ledgerId)).ok).toBe(true);
  });

  it('refuses a stale head at the journal, leaving the committed head as it was', async () => {
    const { journal } = await freshJournal();
    const recorder = managed(journal);
    const first = await recorder.submit(submission(producerEvent('stale-1')), contextFor(producerEvent('stale-1')));
    const ledger = { ledgerId: first.core.ledgerId, ledgerEpochId: first.core.ledgerEpochId };
    const head = await journal.getHead(ledger);
    const genesisHead = { ...ledger, sequence: '0', entryDigest: first.core.previousEntryDigest! };
    const result = await journal.compareAndAppend({ ledger, expectedHead: genesisHead, entry: first, idempotencyKey: `sha256:${'9'.repeat(64)}` });
    expect(result).toEqual({ kind: 'head_conflict', actualHead: head });
    expect(await journal.getHead(ledger)).toEqual(head);
  });

  it('returns the original receipt for the same id and content, and refuses the same id with other content', async () => {
    const { journal } = await freshJournal();
    const recorder = managed(journal);
    const event = producerEvent('idempotent');
    const original = await recorder.submit(submission(event), contextFor(event));
    const again = await recorder.submit(submission(event), contextFor(event));
    expect(again).toEqual(original);
    const changed = producerEvent('idempotent', { outcome: 'failed' });
    const refused = await rejection(recorder.submit(submission(changed), contextFor(changed)));
    expect(refused.code).toBe('AUDIT_EVENT_ID_CONFLICT');
    expect(refused.httpStatus).toBe(409);
    const head = await journal.getHead({ ledgerId: original.core.ledgerId, ledgerEpochId: original.core.ledgerEpochId });
    expect(head?.sequence).toBe('1');
  });

  it('fails closed with AUDIT_JOURNAL_FAILURE when the journal is restored behind it, then opens a restore epoch that verifies across the boundary', async () => {
    const { journal, pool, schema } = await freshJournal();
    const witnessPath = join(mkdtempSync(join(tmpdir(), 'a2-witness-')), 'witness.json');
    const recorder = managed(journal, { witnessPath });
    for (let i = 1; i <= 3; i += 1) await recorder.submit(submission(producerEvent(`before-${i}`)), contextFor(producerEvent(`before-${i}`)));
    const ledgerId = recorder.ledgerIdOf(TENANT);
    const [epoch1] = await journal.listEpochs(ledgerId);

    // Take a backup at head 3, then commit two more entries the backup will not have.
    const tables = ['audit_ledgers', 'audit_ledger_heads', 'audit_journal_entries'];
    const backup = `${schema}_backup`;
    await pool.query(`CREATE SCHEMA "${backup}"`);
    for (const table of tables) await pool.query(`CREATE TABLE "${backup}"."${table}" AS TABLE "${schema}"."${table}"`);
    cleanups.push(async () => {
      const client = new pg.Client({ connectionString: url });
      await client.connect();
      await client.query(`DROP SCHEMA IF EXISTS "${backup}" CASCADE`);
      await client.end();
    });
    const lost: SignedAuditEntry[] = [];
    for (let i = 1; i <= 2; i += 1) lost.push(await recorder.submit(submission(producerEvent(`after-${i}`)), contextFor(producerEvent(`after-${i}`))));
    expect(lost.map((entry) => entry.core.sequence)).toEqual(['4', '5']);
    await recorder.settled();

    // Restore the database from the backup (as a superuser would: triggers off while the rows go back).
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL session_replication_role = replica`);
      for (const table of [...tables].reverse()) await client.query(`DELETE FROM "${table}"`);
      for (const table of tables) await client.query(`INSERT INTO "${table}" SELECT * FROM "${backup}"."${table}"`);
      await client.query('COMMIT');
    } finally {
      client.release();
    }
    expect((await journal.getHead(epoch1!))?.sequence).toBe('3');

    // The running recorder committed head 5: the journal now answers head 3, so it refuses to sign.
    const failed = await rejection(recorder.submit(submission(producerEvent('after-restore')), contextFor(producerEvent('after-restore'))));
    expect(failed.code).toBe('AUDIT_JOURNAL_FAILURE');
    expect(failed.httpStatus).toBe(503);
    expect((await journal.getHead(epoch1!))?.sequence).toBe('3');

    // Restarted (same key, same witness): the restore is detected and a new epoch opens.
    const restarted = managed(journal, { witnessPath });
    await restarted.start();
    const epochs = await journal.listEpochs(ledgerId);
    expect(epochs.map((epoch) => epoch.status)).toEqual(['sealed', 'active']);
    expect(epochs[0]).toMatchObject({ ledgerEpochId: epoch1!.ledgerEpochId, sealReason: 'restore', successorEpochId: epochs[1]!.ledgerEpochId });
    expect(epochs[0]!.head.sequence).toBe('3');
    const [genesis] = await entriesOf(journal, ledgerId, epochs[1]!.ledgerEpochId);
    expect(genesis!.core.event.eventType).toBe('ledger.epoch.started');
    expect(genesis!.core.event.reason).toEqual({ code: 'restore' });
    expect(genesis!.core.event.details).toMatchObject({
      family: 'ledger',
      phase: 'epoch_started',
      previousEpochId: epoch1!.ledgerEpochId,
      previousTerminalCheckpointDigest: terminalHeadDigest(epochs[0]!.head),
    });

    // The new epoch restarts its own sequence; never a second entry at a receipted sequence of the old one.
    const next = await restarted.submit(submission(producerEvent('after-restore')), contextFor(producerEvent('after-restore')));
    expect(next.core).toMatchObject({ ledgerEpochId: epochs[1]!.ledgerEpochId, sequence: '1' });
    const verified = await verifyAll(journal, ledgerId, [restarted.signer.ref.did]);
    expect(verified.ok).toBe(true);
    expect(verified.epochs.map((epoch) => [epoch.entries, epoch.previousEpochId, epoch.transitionReason])).toEqual([
      [4, null, null],
      [2, epoch1!.ledgerEpochId, 'restore'],
    ]);
  });

  it('opens a key_rotation epoch when the recorder key changes, and refuses the old key afterwards', async () => {
    const { journal } = await freshJournal();
    const before = managed(journal, { signer: testRecorderSigner(TEST_RECORDER_KEYS.primary) });
    await before.submit(submission(producerEvent('rot-1')), contextFor(producerEvent('rot-1')));
    const after = managed(journal, { signer: testRecorderSigner(TEST_RECORDER_KEYS.rotated) });
    await after.start();
    const ledgerId = after.ledgerIdOf(TENANT);
    const epochs = await journal.listEpochs(ledgerId);
    expect(epochs.map((epoch) => [epoch.status, epoch.sealReason ?? null])).toEqual([
      ['sealed', 'key_rotation'],
      ['active', null],
    ]);
    expect(epochs[1]!.recorder.did).toBe(after.signer.ref.did);
    // The old process still holding the sealed epoch: it reopens, finds another authority, and is refused.
    const refused = await rejection(before.submit(submission(producerEvent('rot-2')), contextFor(producerEvent('rot-2'))));
    expect(refused.code).toBe('AUDIT_UNAUTHORIZED_SUBMISSION');
    await after.submit(submission(producerEvent('rot-3')), contextFor(producerEvent('rot-3')));
    expect((await verifyAll(journal, ledgerId, [before.signer.ref.did, after.signer.ref.did])).ok).toBe(true);
    const pinnedOld = await verifyAll(journal, ledgerId, [before.signer.ref.did]);
    expect(pinnedOld.brokenLink).toMatchObject({ ledgerEpochId: epochs[1]!.ledgerEpochId, sequence: '0', reason: 'recorder_untrusted' });
  });

  it('runs failover and retention rollover transitions, keeping logical-ledger idempotency across them', async () => {
    const { journal } = await freshJournal();
    const recorder = managed(journal);
    const early = producerEvent('early');
    const original = await recorder.submit(submission(early), contextFor(early));
    const ledgerId = recorder.ledgerIdOf(TENANT);

    const failover = await recorder.transition(ledgerId, 'failover');
    expect(failover).toMatchObject({ reason: 'failover', previousEpochId: original.core.ledgerEpochId });
    const rollover = await recorder.transition(ledgerId, 'retention_rollover');
    const epochs = await journal.listEpochs(ledgerId);
    expect(epochs.map((epoch) => epoch.sealReason ?? 'active')).toEqual(['failover', 'retention_rollover', 'active']);

    // A rollover by the same authority closes its epoch with ledger.epoch.transitioned naming the successor.
    const closing = (await entriesOf(journal, ledgerId, failover.nextEpochId)).at(-1)!;
    expect(closing.core.event).toMatchObject({
      eventType: 'ledger.epoch.transitioned',
      details: { family: 'ledger', phase: 'epoch_transitioned', successorEpochIds: [rollover.nextEpochId] },
    });
    expect(rollover.terminalDigest).toBe(terminalHeadDigest({ ledgerId, ledgerEpochId: failover.nextEpochId, sequence: closing.core.sequence, entryDigest: closing.entryDigest }));

    // A redelivery from before both rollovers resolves to its original entry, in its original epoch.
    expect(await recorder.submit(submission(early), contextFor(early))).toEqual(original);
    const pinned = await rejection(recorder.submit(submission(producerEvent('pinned'), { expectedLedgerEpochId: original.core.ledgerEpochId }), contextFor(producerEvent('pinned'))));
    expect(pinned.code).toBe('AUDIT_EPOCH_MISMATCH');
    expect((await verifyAll(journal, ledgerId)).ok).toBe(true);
  });

  it('refuses every mutation of the journal in the database itself', async () => {
    const { journal, pool } = await freshJournal();
    const recorder = managed(journal);
    const entry = await recorder.submit(submission(producerEvent('locked')), contextFor(producerEvent('locked')));
    const where = `"ledgerId" = '${entry.core.ledgerId}'`;
    await expect(pool.query(`UPDATE "audit_journal_entries" SET "entry" = '{}' WHERE ${where}`)).rejects.toThrow(/append-only/);
    await expect(pool.query(`DELETE FROM "audit_journal_entries" WHERE ${where}`)).rejects.toThrow(/append-only/);
    await expect(pool.query(`TRUNCATE "audit_journal_entries"`)).rejects.toThrow(/append-only/);
    await expect(pool.query(`DELETE FROM "audit_ledger_heads" WHERE ${where}`)).rejects.toThrow(/append-only/);
    await expect(pool.query(`UPDATE "audit_ledger_heads" SET "sequence" = 0 WHERE ${where}`)).rejects.toThrow(/advances by one/);
    await expect(pool.query(`UPDATE "audit_ledger_heads" SET "recorderDid" = 'did:key:zOther' WHERE ${where}`)).rejects.toThrow(/never change/);
    await expect(pool.query(`DELETE FROM "audit_ledgers" WHERE ${where}`)).rejects.toThrow(/append-only/);
    await expect(pool.query(`UPDATE "audit_ledgers" SET "tenantKey" = 'x' WHERE ${where}`)).rejects.toThrow(/tenant never changes/);
    // An insert that skips a sequence, or names another predecessor, is refused.
    const insert = (sequence: number, previous: string): Promise<unknown> =>
      pool.query(
        `INSERT INTO "audit_journal_entries" ("ledgerId", "ledgerEpochId", "sequence", "idempotencyKey", "eventId", "sourceId", "eventType", "family",
           "eventDigest", "entryDigest", "previousEntryDigest", "recordedAt", "entry")
         VALUES ($1, $2, $3, $4, 'x', 'x', 'x', 'x', 'x', 'x', $5, 0, '{}')`,
        [entry.core.ledgerId, entry.core.ledgerEpochId, sequence, `k-${sequence}`, previous],
      );
    await expect(insert(5, entry.entryDigest)).rejects.toThrow(/next one after the committed head/);
    await expect(insert(2, `sha256:${'0'.repeat(64)}`)).rejects.toThrow(/next one after the committed head/);
    expect((await verifyAll(journal, entry.core.ledgerId)).ok).toBe(true);
  });

  it('refuses appends to a sealed epoch and keeps the authority of an epoch to its genesis signer', async () => {
    const { journal, pool } = await freshJournal();
    const recorder = managed(journal);
    const entry = await recorder.submit(submission(producerEvent('sealed-1')), contextFor(producerEvent('sealed-1')));
    const ledger = { ledgerId: entry.core.ledgerId, ledgerEpochId: entry.core.ledgerEpochId };
    const foreign = { ...entry, core: { ...entry.core, recorder: { did: 'did:key:zForeign', kid: 'did:key:zForeign#k', alg: 'EdDSA' as const } } };
    const head = (await journal.getHead(ledger))!;
    const authority = await rejection(journal.compareAndAppend({ ledger, expectedHead: head, entry: foreign, idempotencyKey: `sha256:${'8'.repeat(64)}` }));
    expect(authority.code).toBe('AUDIT_UNAUTHORIZED_SUBMISSION');
    await recorder.transition(ledger.ledgerId, 'failover');
    const sealed = await rejection(journal.compareAndAppend({ ledger, expectedHead: head, entry, idempotencyKey: `sha256:${'7'.repeat(64)}` }));
    expect(sealed.code).toBe('AUDIT_EPOCH_MISMATCH');
    await expect(pool.query(`UPDATE "audit_ledger_heads" SET "status" = 'active' WHERE "ledgerEpochId" = $1`, [ledger.ledgerEpochId])).rejects.toThrow(/sealed/);
  });
});
