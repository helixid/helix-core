// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/** The PostgreSQL journal and vault at their edges: races resolved by unique constraints, corrupt rows, seals, lookups. */

import { afterAll, describe, expect, it } from 'vitest';
import {
  AuditProtocolError,
  EvidenceEncryptor,
  ManagedAuditRecorder,
  evidenceAad,
  publicDid,
  type SignedAuditEntry,
} from '../../../src/core/index.js';
import { PostgresAuditEvidenceStore } from '../../../src/audit/postgres-evidence.js';
import { PostgresAuditJournal } from '../../../src/audit/postgres-journal.js';
import { TENANT, contextFor, producerEvent, submission, testRecorderSigner } from '../../utils/auditLedger.js';
import { auditJournalDatabaseUrl, createMigratedSchema } from '../../utils/postgresSchema.js';

const url = auditJournalDatabaseUrl;
const cleanups: Array<() => Promise<void>> = [];

async function fresh() {
  const migrated = await createMigratedSchema(url!);
  cleanups.push(() => migrated.drop());
  return { pool: migrated.pool, journal: new PostgresAuditJournal(migrated.pool), evidence: new PostgresAuditEvidenceStore(migrated.pool) };
}

describe.skipIf(!url)('PostgreSQL adapters at their edges', () => {
  afterAll(async () => {
    for (const cleanup of cleanups.reverse()) await cleanup();
  });

  it('resolves concurrent genesis and same-identity appends through the unique constraints', async () => {
    const { journal } = await fresh();
    const recorder = new ManagedAuditRecorder({ store: journal, signer: testRecorderSigner() });
    const first = await recorder.submit(submission(producerEvent('g')), contextFor(producerEvent('g')));
    const ledger = { ledgerId: first.core.ledgerId, ledgerEpochId: 'epoch-race' };
    const entry = (sequence: string, eventId: string): SignedAuditEntry => {
      const copy = structuredClone(first);
      copy.core = { ...copy.core, ...ledger, sequence, previousEntryDigest: null };
      copy.core.event = { ...copy.core.event, eventId };
      copy.entryDigest = `sha256:${eventId === 'one' ? '1'.repeat(64) : '2'.repeat(64)}`;
      return copy;
    };
    const results = await Promise.all([
      journal.compareAndAppend({ ledger, expectedHead: null, entry: entry('0', 'one'), idempotencyKey: `sha256:${'a'.repeat(64)}` }),
      journal.compareAndAppend({ ledger, expectedHead: null, entry: entry('0', 'two'), idempotencyKey: `sha256:${'b'.repeat(64)}` }),
    ]);
    expect(results.map((result) => result.kind).sort()).toEqual(['appended', 'head_conflict']);
    const conflict = results.find((result) => result.kind === 'head_conflict');
    expect(conflict).toMatchObject({ actualHead: { sequence: '0' } });

    const same = { ledgerId: first.core.ledgerId, ledgerEpochId: 'epoch-same' };
    const one = { ...entry('0', 'same'), core: { ...entry('0', 'same').core, ...same } };
    const raced = await Promise.all([
      journal.compareAndAppend({ ledger: same, expectedHead: null, entry: one, idempotencyKey: `sha256:${'c'.repeat(64)}` }),
      journal.compareAndAppend({ ledger: same, expectedHead: null, entry: one, idempotencyKey: `sha256:${'c'.repeat(64)}` }),
    ]);
    expect(raced.map((result) => result.kind).sort()).toEqual(['appended', 'duplicate']);
    const changed = { ...one, eventDigest: `sha256:${'f'.repeat(64)}` as const };
    const different = await Promise.all([
      journal.compareAndAppend({ ledger: { ...same, ledgerEpochId: 'epoch-diff' }, expectedHead: null, entry: { ...one, core: { ...one.core, ledgerEpochId: 'epoch-diff' } }, idempotencyKey: `sha256:${'d'.repeat(64)}` }),
      journal.compareAndAppend({ ledger: { ...same, ledgerEpochId: 'epoch-diff2' }, expectedHead: null, entry: { ...changed, core: { ...changed.core, ledgerEpochId: 'epoch-diff2' } }, idempotencyKey: `sha256:${'d'.repeat(64)}` }),
    ]);
    expect(different.map((result) => result.kind).sort()).toEqual(['appended', 'idempotency_conflict']);
  });

  it('fails closed on a corrupt stored entry, and answers lookups, listings and seals truthfully', async () => {
    const { pool, journal } = await fresh();
    const recorder = new ManagedAuditRecorder({ store: journal, signer: testRecorderSigner() });
    const entry = await recorder.submit(submission(producerEvent('x')), contextFor(producerEvent('x')));
    const ledger = { ledgerId: entry.core.ledgerId, ledgerEpochId: entry.core.ledgerEpochId };
    expect(await journal.listEntries({ ledgerId: ledger.ledgerId, eventType: 'tool.call.completed', family: 'tool', correlationId: 'call-x', since: new Date(0), limit: 5 })).toHaveLength(1);
    expect(await journal.listEntries({ limit: 5 })).toHaveLength(2);
    expect(await journal.getLedger('none')).toBeNull();
    expect(await journal.findLedgerByTenant(TENANT)).toMatchObject({ ledgerId: ledger.ledgerId });
    expect(await journal.findLedgerByTenant(publicDid('did:web:nobody'))).toBeNull();
    await expect(journal.ensureLedger({ ledgerId: 'other-id', tenantRef: TENANT, createdAt: 1 })).rejects.toThrow(AuditProtocolError);
    const empty: SignedAuditEntry[] = [];
    for await (const e of journal.readRange({ ...ledger, ledgerEpochId: 'missing' })) empty.push(e);
    expect(empty).toEqual([]);
    const head = (await journal.getHead(ledger))!;
    await expect(journal.sealEpoch({ ledger, expectedHead: { ...head, sequence: '0' }, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).rejects.toThrow(/not its committed head/);
    expect(await journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).toBe('sealed');
    expect(await journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).toBe('already_sealed');
    await expect(journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 't' })).rejects.toThrow(/already sealed/);
    const client = await pool.connect();
    await client.query('BEGIN');
    await client.query('SET LOCAL session_replication_role = replica');
    await client.query(`UPDATE "audit_journal_entries" SET "entry" = 'not json' WHERE "sequence" = 1`);
    await client.query('COMMIT');
    client.release();
    await expect(journal.listEntries({ limit: 1 })).rejects.toThrow(/not a signed entry/);
  });

  it('keeps vault edges: missing and disposed objects, hold reuse, compensation', async () => {
    const { evidence } = await fresh();
    const object = new EvidenceEncryptor({ key: '78'.repeat(32), keyId: 'k' }).encrypt({ plaintext: 'x', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    expect(await evidence.get('evi_none')).toBeNull();
    expect(await evidence.has('evi_none')).toBe(false);
    expect(await evidence.evidenceState('evi_none')).toBeNull();
    expect(await evidence.disposeEvidence({ ledgerId: 'l', objectId: 'evi_none', disposedAt: 1, reason: 'x' })).toBe('missing');
    expect(await evidence.putIfAbsent(object)).toEqual(object.ref);
    expect(await evidence.putIfAbsent(object)).toMatchObject({ objectId: object.ref.objectId });
    await expect(evidence.putIfAbsent({ ...object, ciphertext: new Uint8Array([9]), ref: { ...object.ref, ciphertextDigest: `sha256:${'0'.repeat(64)}`, size: '1' } })).rejects.toThrow();
    await evidence.discardUncommitted(object.ref.objectId);
    expect(await evidence.get(object.ref.objectId)).toBeNull();
    expect(await evidence.has(object.ref.objectId)).toBe(true);
    expect((await evidence.evidenceState(object.ref.objectId))?.disposedAt).toBeGreaterThan(0);
    expect(await evidence.disposeEvidence({ ledgerId: 'l', objectId: object.ref.objectId, disposedAt: 2, reason: 'x' })).toBe('already_disposed');
    const hold = { holdId: 'h1', target: { kind: 'ledger' as const, ledgerId: 'l' }, appliedAt: 1, appliedBy: 't' };
    expect(await evidence.insertHold(hold)).toBe('inserted');
    expect(await evidence.insertHold(hold)).toBe('exists');
    await expect(evidence.insertHold({ ...hold, target: { kind: 'ledger', ledgerId: 'other' } })).rejects.toThrow(/already used/);
    await expect(evidence.insertHold({ ...hold, holdId: 'h2', appliedAt: Number.NaN })).rejects.toThrow();
    expect(await evidence.getHold('none')).toBeNull();
    expect(await evidence.releaseHold('h1', 2, 't')).toMatchObject({ holdId: 'h1', releasedBy: 't' });
    expect(await evidence.releaseHold('h1', 3, 't')).toBeNull();
  });
});
