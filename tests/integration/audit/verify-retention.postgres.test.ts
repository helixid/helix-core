// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * L3-F's Done-when on real PostgreSQL: altering any stored entry (its
 * content, a digest, its receipt, its link, or removing entries) makes the
 * verify command (`helix-audit verify`) fail at that entry. And A-2 point 6:
 * disposal under legal hold is refused and the refusal recorded, release
 * then disposal succeeds and is itself recorded, the retention floor (the
 * longest delegation lifetime) refuses younger targets; plus the evidence
 * retention contract on PostgreSQL.
 */

import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import {
  AuditProtocolError,
  EvidenceEncryptor,
  assertAuditProviderContract,
  auditEventDigest,
  auditReceiptPayload,
  buildAuditReceiptCore,
  canonicalize,
  digestAuditEntry,
  evaluateAuditEvidenceRetentionContract,
  evidenceAad,
  type SignedAuditEntry,
} from '../../../src/core/index.js';
import { createApiAudit, createApiAuditStorage, type ApiAudit } from '../../../src/audit/api-audit.js';
import { PostgresAuditEvidenceStore } from '../../../src/audit/postgres-evidence.js';
import { runAuditCli } from '../../../src/cli/audit.js';
import { loadConfigFromEnv } from '../../../src/core/index.js';
import { MemoryRecorderWitness } from '../../../src/core/index.js';
import { TENANT, contextFor, producerEvent, submission, testRecorderSigner } from '../../utils/auditLedger.js';
import { auditJournalDatabaseUrl, createMigratedSchema } from '../../utils/postgresSchema.js';

const url = auditJournalDatabaseUrl;
const cleanups: Array<() => Promise<void>> = [];

interface Fixture {
  pool: pg.Pool;
  schemaUrl: string;
  audit: ApiAudit;
  ledgerId: string;
  epochId: string;
  entries: SignedAuditEntry[];
}

async function ledgerWithEntries(count = 5): Promise<Fixture> {
  const migrated = await createMigratedSchema(url!);
  cleanups.push(() => migrated.drop());
  const config = { ...loadConfigFromEnv(), AUDIT_LOG_DESTINATION: 'none' as const };
  const deps = { pool: migrated.pool };
  const audit = createApiAudit(config, createApiAuditStorage(deps), { deps, signer: testRecorderSigner(), witness: new MemoryRecorderWitness() });
  const entries: SignedAuditEntry[] = [];
  for (let i = 1; i <= count; i += 1) {
    const event = producerEvent(`tamper-${i}`);
    entries.push(await audit.recorder.submit(submission(event), contextFor(event)));
  }
  const schemaUrl = `${url!}${url!.includes('?') ? '&' : '?'}options=${encodeURIComponent(`-c search_path=${migrated.schema}`)}`;
  return { pool: migrated.pool, schemaUrl, audit, ledgerId: entries[0]!.core.ledgerId, epochId: entries[0]!.core.ledgerEpochId, entries };
}

/** Rewrites stored rows as a database superuser would: triggers off. */
async function asSuperuser(pool: pg.Pool, statements: Array<[string, unknown[]]>): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET LOCAL session_replication_role = replica');
    for (const [sql, params] of statements) await client.query(sql, params);
    await client.query('COMMIT');
  } finally {
    client.release();
  }
}

async function storedEntry(fixture: Fixture, sequence: number): Promise<SignedAuditEntry> {
  const { rows } = await fixture.pool.query<{ entry: string }>(`SELECT "entry" FROM "audit_journal_entries" WHERE "ledgerEpochId" = $1 AND "sequence" = $2`, [
    fixture.epochId,
    sequence,
  ]);
  return JSON.parse(rows[0]!.entry) as SignedAuditEntry;
}

async function rewrite(fixture: Fixture, sequence: number, entry: SignedAuditEntry, columns: { entryDigest?: string; previousEntryDigest?: string } = {}): Promise<void> {
  await asSuperuser(fixture.pool, [
    [
      `UPDATE "audit_journal_entries" SET "entry" = $3, "entryDigest" = COALESCE($4, "entryDigest"), "previousEntryDigest" = COALESCE($5, "previousEntryDigest")
        WHERE "ledgerEpochId" = $1 AND "sequence" = $2`,
      [fixture.epochId, sequence, canonicalize(entry), columns.entryDigest ?? null, columns.previousEntryDigest ?? null],
    ],
  ]);
}

async function verifyCommand(fixture: Fixture, extra: string[] = []): Promise<{ code: number; out: string }> {
  const lines: string[] = [];
  const code = await runAuditCli(['verify', '--ledger', fixture.ledgerId, '--database-url', fixture.schemaUrl, ...extra], {
    out: (line) => lines.push(line),
    err: (line) => lines.push(line),
  });
  return { code, out: lines.join('\n') };
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

describe.skipIf(!url)('helix-audit verify on PostgreSQL: altering any stored entry fails at that entry', () => {
  afterAll(async () => {
    for (const cleanup of cleanups.reverse()) await cleanup();
  });

  it('passes on the untouched ledger, with the recorder pinned', async () => {
    const fixture = await ledgerWithEntries();
    const result = await verifyCommand(fixture, ['--trusted-recorder', testRecorderSigner().ref.did]);
    expect(result.code).toBe(0);
    expect(result.out).toContain(`ledger ${fixture.ledgerId}: OK, 1 epoch(s), 6 entries verified`);
  });

  const cases: Array<{ name: string; at: number; reason: string; tamper: (fixture: Fixture) => Promise<void> }> = [
    {
      name: 'content (an event member changed)',
      at: 3,
      reason: 'event_digest_mismatch',
      tamper: async (fixture) => {
        const entry = await storedEntry(fixture, 3);
        entry.core.event.outcome = 'failed';
        await rewrite(fixture, 3, entry);
      },
    },
    {
      name: 'content with every digest recomputed (no recorder key to re-sign)',
      at: 3,
      reason: 'receipt_signature_invalid',
      tamper: async (fixture) => {
        const entry = await storedEntry(fixture, 3);
        entry.core.event.outcome = 'denied';
        entry.core.eventDigest = auditEventDigest(entry.core.event);
        entry.eventDigest = entry.core.eventDigest;
        entry.entryDigest = digestAuditEntry(entry.core);
        entry.recorderReceipt.core = buildAuditReceiptCore(entry.core, entry.entryDigest);
        expect(auditReceiptPayload(entry.recorderReceipt.core).length).toBeGreaterThan(0);
        await rewrite(fixture, 3, entry, { entryDigest: entry.entryDigest });
        await asSuperuser(fixture.pool, [[`UPDATE "audit_journal_entries" SET "eventDigest" = $2 WHERE "ledgerEpochId" = $1 AND "sequence" = 3`, [fixture.epochId, entry.eventDigest]]]);
      },
    },
    {
      name: 'the entry digest (entry and index column)',
      at: 3,
      reason: 'entry_digest_mismatch',
      tamper: async (fixture) => {
        const entry = await storedEntry(fixture, 3);
        entry.entryDigest = `sha256:${'e'.repeat(64)}`;
        await rewrite(fixture, 3, entry, { entryDigest: entry.entryDigest });
      },
    },
    {
      name: 'a digest index column only',
      at: 3,
      reason: 'stored_columns_mismatch',
      tamper: async (fixture) => {
        await asSuperuser(fixture.pool, [[`UPDATE "audit_journal_entries" SET "entryDigest" = $2 WHERE "ledgerEpochId" = $1 AND "sequence" = 3`, [fixture.epochId, `sha256:${'d'.repeat(64)}`]]]);
      },
    },
    {
      name: 'the receipt signature',
      at: 3,
      reason: 'receipt_signature_invalid',
      tamper: async (fixture) => {
        const entry = await storedEntry(fixture, 3);
        const [header, payload, signature] = entry.recorderReceipt.jws.split('.');
        const flipped = `${signature!.startsWith('A') ? 'B' : 'A'}${signature!.slice(1)}`;
        entry.recorderReceipt.jws = `${header}.${payload}.${flipped}`;
        await rewrite(fixture, 3, entry);
      },
    },
    {
      name: 'the receipt core',
      at: 3,
      reason: 'receipt_core_mismatch',
      tamper: async (fixture) => {
        const entry = await storedEntry(fixture, 3);
        entry.recorderReceipt.core.recordedAt += 1;
        await rewrite(fixture, 3, entry);
      },
    },
    {
      name: 'the predecessor link',
      at: 3,
      reason: 'entry_digest_mismatch',
      tamper: async (fixture) => {
        const entry = await storedEntry(fixture, 3);
        entry.core.previousEntryDigest = `sha256:${'c'.repeat(64)}`;
        await rewrite(fixture, 3, entry, { previousEntryDigest: entry.core.previousEntryDigest });
      },
    },
    {
      name: 'an entry removed from the middle',
      at: 4,
      reason: 'sequence_gap',
      tamper: async (fixture) => {
        await asSuperuser(fixture.pool, [[`DELETE FROM "audit_journal_entries" WHERE "ledgerEpochId" = $1 AND "sequence" = 3`, [fixture.epochId]]]);
      },
    },
    {
      name: 'the tail removed with the head left in place',
      at: 5,
      reason: 'head_mismatch',
      tamper: async (fixture) => {
        await asSuperuser(fixture.pool, [[`DELETE FROM "audit_journal_entries" WHERE "ledgerEpochId" = $1 AND "sequence" >= 4`, [fixture.epochId]]]);
      },
    },
    {
      name: 'two entries swapped',
      at: 2,
      reason: 'stored_columns_mismatch',
      tamper: async (fixture) => {
        const two = await storedEntry(fixture, 2);
        const three = await storedEntry(fixture, 3);
        await rewrite(fixture, 2, three);
        await rewrite(fixture, 3, two);
      },
    },
    {
      name: 'the genesis replaced by a producer event',
      at: 0,
      reason: 'event_digest_mismatch',
      tamper: async (fixture) => {
        const genesis = await storedEntry(fixture, 0);
        genesis.core.event = (await storedEntry(fixture, 1)).core.event;
        await rewrite(fixture, 0, genesis);
      },
    },
  ];

  for (const testCase of cases) {
    it(`fails at sequence ${testCase.at} when ${testCase.name} is altered`, async () => {
      const fixture = await ledgerWithEntries();
      await testCase.tamper(fixture);
      const result = await verifyCommand(fixture);
      expect(result.code).toBe(1);
      expect(result.out).toContain(`BROKEN at epoch ${fixture.epochId} sequence ${testCase.at}: ${testCase.reason}`);
    });
  }

  it('refuses disposal under legal hold (recorded), then release and disposal succeed and are recorded', async () => {
    const fixture = await ledgerWithEntries(1);
    const { audit, ledgerId } = fixture;
    const encryptor = new EvidenceEncryptor({ key: 'ab'.repeat(32), keyId: 'evidence-test' });
    const encrypted = encryptor.encrypt({ plaintext: '{"exact":"payload"}', mediaType: 'application/json', aad: evidenceAad(TENANT, 'tool-response') });
    const event = { ...producerEvent('with-evidence'), evidence: [encrypted.ref] };
    const withEvidence = await audit.recorder.submit(submission(event, { encryptedEvidence: [encrypted] }), contextFor(event));
    expect(await audit.storage.evidence.get(encrypted.ref.objectId)).not.toBeNull();
    const target = { kind: 'entry' as const, ledgerId, ledgerEpochId: withEvidence.core.ledgerEpochId, sequence: withEvidence.core.sequence };

    await audit.retention.applyLegalHold({ holdId: 'case-42', target, authorizedBy: 'test' });
    const held = await rejection(audit.retention.dispose({ target, authorizedBy: 'test' }));
    expect(held.code).toBe('AUDIT_EVIDENCE_LEGAL_HOLD');
    expect(await audit.storage.evidence.get(encrypted.ref.objectId)).not.toBeNull();

    await audit.retention.releaseLegalHold({ holdId: 'case-42', authorizedBy: 'test' });
    const disposal = await audit.retention.dispose({ target, authorizedBy: 'test' });
    expect(disposal.disposedObjectIds).toEqual([encrypted.ref.objectId]);
    expect(await audit.storage.evidence.get(encrypted.ref.objectId)).toBeNull();
    expect((await audit.storage.evidence.evidenceState(encrypted.ref.objectId))?.ref).toEqual(encrypted.ref);

    const recorded = (await audit.storage.journal.listEntries({ ledgerId, limit: 20 })).reverse().map((entry) => [
      entry.core.event.eventType,
      entry.core.event.outcome,
      entry.core.event.action.category,
      entry.core.event.reason?.code ?? null,
    ]);
    expect(recorded.slice(-5)).toEqual([
      ['legal_hold.applied', 'succeeded', 'retention.legal_hold', null],
      ['retention.executed', 'denied', 'retention.dispose', 'legal_hold'],
      ['retention.executed', 'succeeded', 'retention.legal_hold_release', null],
      ['retention.executed', 'succeeded', 'retention.dispose', null],
      ['evidence.disposed', 'succeeded', 'retention.dispose', null],
    ]);
    expect((await verifyCommand(fixture)).code).toBe(0);
  });

  it('refuses disposal of an entry younger than the longest delegation lifetime, and an unbounded one entirely', async () => {
    const fixture = await ledgerWithEntries(1);
    const { audit, pool, ledgerId, entries } = fixture;
    await pool.query(
      `INSERT INTO "dids" ("id", "subjectType", "controller", "publicKey", "hederaTransactionId", "didDocument", "updatedAt")
       VALUES ('did:key:zRetention', 'agent', 'did:key:zRetention', 'aa', 'tx', '{}', CURRENT_TIMESTAMP)`,
    );
    await pool.query(
      `INSERT INTO "vcs" ("id", "vcId", "subjectDid", "subjectType", "vcJson", "statusListIndex", "createdAt", "expiresAt")
       VALUES ('vc1', 'urn:vc:1', 'did:key:zRetention', 'agent', '{}', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '1 day')`,
    );
    const target = { kind: 'entry' as const, ledgerId, ledgerEpochId: entries[0]!.core.ledgerEpochId, sequence: entries[0]!.core.sequence };
    expect(await audit.retention.retentionFloorMs(ledgerId)).toBe(86_400_000);
    const young = await rejection(audit.retention.dispose({ target, authorizedBy: 'test' }));
    expect(young.code).toBe('AUDIT_RETENTION_REFUSED');
    expect(young.details).toMatchObject({ floorMs: 86_400_000 });

    await pool.query(
      `INSERT INTO "vcs" ("id", "vcId", "subjectDid", "subjectType", "vcJson", "statusListIndex") VALUES ('vc2', 'urn:vc:2', 'did:key:zRetention', 'agent', '{}', 2)`,
    );
    expect(await audit.retention.retentionFloorMs(ledgerId)).toBe(Number.POSITIVE_INFINITY);
    const unbounded = await rejection(audit.retention.dispose({ target, authorizedBy: 'test' }));
    expect(unbounded.details).toMatchObject({ floorMs: 'unbounded' });
    const refusals = (await audit.storage.journal.listEntries({ ledgerId, eventType: 'retention.executed', limit: 10 })).map((entry) => entry.core.event.reason?.code);
    expect(refusals).toEqual(['retention_floor', 'retention_floor']);
  });

  it('passes the evidence retention contract on PostgreSQL, the trigger refusing a held object too', async () => {
    const migrated = await createMigratedSchema(url!);
    cleanups.push(() => migrated.drop());
    const store = new PostgresAuditEvidenceStore(migrated.pool);
    const report = await evaluateAuditEvidenceRetentionContract(() => ({ vault: store, retention: store }));
    for (const item of report.checks) if (!item.passed) console.error(item.name, item.error);
    expect(report.checks.map((item) => item.passed)).toEqual([true, true, true]);
    assertAuditProviderContract(report);

    const encrypted = new EvidenceEncryptor({ key: 'cd'.repeat(32), keyId: 'k' }).encrypt({ plaintext: 'x', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    await store.putIfAbsent(encrypted);
    await store.insertHold({ holdId: 'db-hold', target: { kind: 'evidence', ledgerId: 'l', objectId: encrypted.ref.objectId }, appliedAt: Date.now(), appliedBy: 't' });
    await expect(
      migrated.pool.query(`UPDATE "audit_evidence" SET "ciphertext" = NULL, "disposedAt" = CURRENT_TIMESTAMP WHERE "objectId" = $1`, [encrypted.ref.objectId]),
    ).rejects.toThrow(/legal hold/);
    await expect(migrated.pool.query(`DELETE FROM "audit_evidence" WHERE "objectId" = $1`, [encrypted.ref.objectId])).rejects.toThrow(/append-only/);
    await expect(migrated.pool.query(`DELETE FROM "audit_legal_holds" WHERE "holdId" = 'db-hold'`)).rejects.toThrow(/append-only/);
  });
});
