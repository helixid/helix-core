// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The API's audit storage (A-2): the SQLite and memory journals and vaults
 * against the provider contracts, SQLite's append-only triggers and its
 * migration from an A-1 file, the stream echo, and the API factory (storage
 * choice, recorder signer, self-hosted tenants, retention floor, the trail
 * through the recorder).
 */

import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterAll, describe, expect, it, vi } from 'vitest';
import {
  AuditProtocolError,
  FileRecorderWitness,
  MemoryAuditJournal,
  inPositionOrder,
  auditListCursorOf,
  compareAuditListOrder,
  MemoryAuditSink,
  MemoryRecorderWitness,
  assertAuditProviderContract,
  evaluateAuditEvidenceRetentionContract,
  evaluateAuditJournalProviderContract,
  pairwiseDid,
  publicDid,
  type AuditEventInput,
} from '../../../src/core/index.js';
import {
  MemoryAuditEvidenceStore,
  SqliteAuditEvidenceStore,
  SqliteAuditJournal,
  StreamAuditSink,
  apiPartyRef,
  auditLogRow,
  createApiAudit,
  createApiAuditStorage,
  createRecorderSigner,
  delegationRetentionFloor,
  type ApiAuditConfig,
} from '../../../src/audit/index.js';
import { PostgresAuditEvidenceStore } from '../../../src/audit/postgres-evidence.js';
import { PostgresAuditJournal } from '../../../src/audit/postgres-journal.js';
import { SqliteStore } from '../../../src/storage/sqlite.js';
import { TEST_RECORDER_KEYS, contextFor, producerEvent, submission, testRecorderSigner } from '../../utils/auditLedger.js';
import { fixture } from '../core/audit/fixture.js';

const dirs: string[] = [];
function sqliteFile(): string {
  const dir = mkdtempSync(join(tmpdir(), 'helix-a2-sqlite-'));
  dirs.push(dir);
  return join(dir, 'helix.sqlite');
}
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const minimal: AuditEventInput = {
  eventType: 'session.established',
  action: { category: 'session' },
  outcome: 'succeeded',
  details: { family: 'session', phase: 'established' },
};

const baseConfig: ApiAuditConfig = {
  NODE_ENV: 'test',
  AUDIT_LOG_DESTINATION: 'none',
  AUDIT_LOG_PATH: undefined,
  AUDIT_SOURCE_ID: 'helix-api',
  AUDIT_INCLUDE_TOOL_NAMES: false,
  AUDIT_EVIDENCE_KEY: undefined,
  AUDIT_EVIDENCE_KEY_ID: 'evidence-key-v1',
  HELIX_ISSUER_DID: 'did:web:issuer.example',
  HELIX_SIGNING_KEY: 'a'.repeat(64),
  AUDIT_RECORDER_SIGNING_KEY: TEST_RECORDER_KEYS.primary,
  AUDIT_RECORDER_DID: undefined,
  AUDIT_RECORDER_KID: undefined,
  AUDIT_RECORDER_MODE: 'managed',
  AUDIT_RECORDER_TENANTS: undefined,
  AUDIT_RECORDER_WITNESS_PATH: undefined,
  AUDIT_RETENTION_MIN_DAYS: 0,
};

describe('journal provider contract', () => {
  it('passes on the memory journal (ephemeral)', async () => {
    const report = await evaluateAuditJournalProviderContract(() => new MemoryAuditJournal());
    assertAuditProviderContract(report);
    expect(new MemoryAuditJournal().capabilities.durability).toBe('ephemeral');
  });

  it('passes on the SQLite journal (durable)', async () => {
    const report = await evaluateAuditJournalProviderContract(() => new SqliteAuditJournal(new SqliteStore(sqliteFile())));
    for (const item of report.checks) if (!item.passed) console.error(item.name, item.error);
    assertAuditProviderContract(report);
    expect(report.checks).toHaveLength(6);
  });

  it('fails, and says which checks, for a journal that does not serialize', async () => {
    const broken = new MemoryAuditJournal();
    const lax = Object.assign(Object.create(broken) as MemoryAuditJournal, {
      compareAndAppend: async (input: Parameters<MemoryAuditJournal['compareAndAppend']>[0]) =>
        broken.compareAndAppend({ ...input, expectedHead: await broken.getHead(input.ledger) }),
    });
    const report = await evaluateAuditJournalProviderContract(() => lax);
    expect(report.passed).toBe(false);
    expect(report.checks.filter((item) => !item.passed).map((item) => item.name)).toContain('atomically appends and rejects a stale head');
    expect(() => assertAuditProviderContract(report)).toThrow(/journal provider contract failed: atomically appends and rejects a stale head/);
  });
});

describe('evidence retention contract', () => {
  it('passes on the memory and SQLite vaults', async () => {
    const memory = new MemoryAuditEvidenceStore();
    assertAuditProviderContract(await evaluateAuditEvidenceRetentionContract(() => ({ vault: memory, retention: memory })));
    const sqlite = new SqliteAuditEvidenceStore(new SqliteStore(sqliteFile()));
    const report = await evaluateAuditEvidenceRetentionContract(() => ({ vault: sqlite, retention: sqlite }));
    for (const item of report.checks) if (!item.passed) console.error(item.name, item.error);
    assertAuditProviderContract(report);
  });

  it('fails on a vault that ignores holds', async () => {
    const store = new MemoryAuditEvidenceStore();
    const careless = Object.assign(Object.create(store) as MemoryAuditEvidenceStore, { activeHolds: async () => [] });
    const report = await evaluateAuditEvidenceRetentionContract(() => ({ vault: store, retention: careless }));
    expect(report.checks.find((item) => item.name === 'enforces legal hold before irreversible disposal')?.passed).toBe(false);
  });
});

describe('SQLite audit storage', () => {
  it('migrates an A-1 file: drops audit_events, adds the disposal columns, keeps evidence', () => {
    const path = sqliteFile();
    const legacy = new Database(path);
    legacy.exec(`CREATE TABLE audit_events (id INTEGER PRIMARY KEY);
      CREATE TABLE audit_evidence (object_id TEXT PRIMARY KEY, ciphertext_digest TEXT NOT NULL, size INTEGER NOT NULL, media_type TEXT NOT NULL,
        key_id TEXT NOT NULL, ref_json TEXT NOT NULL, ciphertext BLOB NOT NULL, stored_at TEXT NOT NULL);`);
    legacy.close();
    const sqlite = new SqliteStore(path);
    expect(sqlite.query(`SELECT name FROM sqlite_master WHERE name = 'audit_events'`)).toEqual([]);
    const columns = sqlite.query<{ name: string }>(`PRAGMA table_info(audit_evidence)`).map((column) => column.name);
    expect(columns).toEqual(expect.arrayContaining(['disposed_at', 'disposal_reason']));
    // Opening again is a no-op.
    expect(() => new SqliteStore(path)).not.toThrow();
  });

  it('refuses every mutation of the journal through its triggers, and keeps evidence and holds append-only', async () => {
    const sqlite = new SqliteStore(sqliteFile());
    const journal = new SqliteAuditJournal(sqlite);
    const audit = createApiAudit(baseConfig, { journal, evidence: new SqliteAuditEvidenceStore(sqlite) }, { signer: testRecorderSigner(), witness: new MemoryRecorderWitness() });
    const event = producerEvent('sqlite-locked');
    const entry = await audit.recorder.submit(submission(event), contextFor(event));
    expect(() => sqlite.execute(`UPDATE audit_journal_entries SET entry = '{}'`)).toThrow(/append-only/);
    expect(() => sqlite.execute(`DELETE FROM audit_journal_entries`)).toThrow(/append-only/);
    expect(() => sqlite.execute(`DELETE FROM audit_ledger_heads`)).toThrow(/append-only/);
    expect(() => sqlite.execute(`UPDATE audit_ledger_heads SET sequence = 0`)).toThrow(/advances by one/);
    expect(() => sqlite.execute(`UPDATE audit_ledger_heads SET recorder_did = 'did:key:zX'`)).toThrow(/never change/);
    expect(() => sqlite.execute(`UPDATE audit_ledgers SET tenant_key = 'x'`)).toThrow(/tenant never changes/);
    expect(() => sqlite.execute(`DELETE FROM audit_ledgers`)).toThrow(/append-only/);
    expect(() =>
      sqlite.write(
        `INSERT INTO audit_journal_entries (ledger_id, ledger_epoch_id, sequence, idempotency_key, event_id, source_id, event_type, family, event_digest, entry_digest, previous_entry_digest, recorded_at, entry)
         VALUES (?, ?, 9, 'k', 'x', 'x', 'x', 'x', 'x', 'x', ?, 0, '{}')`,
        entry.core.ledgerId,
        entry.core.ledgerEpochId,
        entry.entryDigest,
      ),
    ).toThrow(/genesis or the next one/);
    await audit.recorder.transition(entry.core.ledgerId, 'failover');
    expect(() => sqlite.execute(`UPDATE audit_ledger_heads SET status = 'active' WHERE status = 'sealed'`)).toThrow(/sealed epoch is final/);

    const evidence = new SqliteAuditEvidenceStore(sqlite);
    const object = { ref: fixture.evidence.ref, ciphertext: new Uint8Array(Buffer.from(fixture.evidence.ciphertext_b64url, 'base64url')) };
    await evidence.putIfAbsent(object);
    expect(() => sqlite.execute(`DELETE FROM audit_evidence`)).toThrow(/append-only/);
    expect(() => sqlite.execute(`UPDATE audit_evidence SET media_type = 'x'`)).toThrow(/disposed, once/);
    await evidence.insertHold({ holdId: 'h', target: { kind: 'evidence', ledgerId: 'l', objectId: object.ref.objectId }, appliedAt: 1, appliedBy: 't' });
    expect(() => sqlite.execute(`UPDATE audit_evidence SET ciphertext = X'', disposed_at = 'now'`)).toThrow(/legal hold/);
    expect(() => sqlite.execute(`DELETE FROM audit_legal_holds`)).toThrow(/append-only/);
    expect(await evidence.insertHold({ holdId: 'h', target: { kind: 'evidence', ledgerId: 'l', objectId: object.ref.objectId }, appliedAt: 2, appliedBy: 't' })).toBe('exists');
    await expect(evidence.insertHold({ holdId: 'h', target: { kind: 'ledger', ledgerId: 'l' }, appliedAt: 2, appliedBy: 't' })).rejects.toThrow(/already used/);
    expect(await evidence.releaseHold('h', 3, 't')).toMatchObject({ holdId: 'h', releasedAt: 3, releasedBy: 't' });
    expect(await evidence.releaseHold('h', 4, 't')).toBeNull();
    expect(() => sqlite.execute(`UPDATE audit_legal_holds SET released_at = 9`)).toThrow(/released, once/);
    await evidence.discardUncommitted(object.ref.objectId);
    expect(await evidence.get(object.ref.objectId)).toBeNull();
    expect(await evidence.has(object.ref.objectId)).toBe(true);
    expect(await evidence.disposeEvidence({ ledgerId: 'l', objectId: object.ref.objectId, disposedAt: 5, reason: 'x' })).toBe('already_disposed');
    expect(await evidence.disposeEvidence({ ledgerId: 'l', objectId: 'evi_none', disposedAt: 5, reason: 'x' })).toBe('missing');
    expect(await evidence.evidenceState('evi_none')).toBeNull();
    // A disposed object keeps its reference; putting the same bytes again is idempotent, other bytes collide.
    expect(await evidence.putIfAbsent(object)).toEqual(object.ref);
    await expect(evidence.putIfAbsent({ ...object, ref: { ...object.ref, ciphertextDigest: `sha256:${'0'.repeat(64)}` } })).rejects.toThrow();
  });

  it('lists entries newest first with filters, and parses a corrupt row as a journal failure', async () => {
    const sqlite = new SqliteStore(sqliteFile());
    const journal = new SqliteAuditJournal(sqlite);
    const audit = createApiAudit(baseConfig, { journal, evidence: new SqliteAuditEvidenceStore(sqlite) }, { signer: testRecorderSigner(), witness: new MemoryRecorderWitness() });
    for (const id of ['a', 'b']) await audit.recorder.submit(submission(producerEvent(id)), contextFor(producerEvent(id)));
    const ledgerId = (await journal.listLedgers())[0]!.ledgerId;
    const all = await journal.listEntries({ ledgerId, limit: 10 });
    expect(all.map((entry) => entry.core.sequence)).toEqual(['2', '1', '0']);
    expect(await journal.listEntries({ eventType: 'tool.call.completed', family: 'tool', correlationId: 'call-a', since: new Date(0), limit: 10 })).toHaveLength(1);
    // A page's cursor: strictly after the given entry in the listing order.
    expect((await journal.listEntries({ ledgerId, before: auditListCursorOf(all[0]!), limit: 10 })).map((entry) => entry.core.sequence)).toEqual(['1', '0']);
    expect((await journal.listEntries({ ledgerId, before: auditListCursorOf(all[2]!), limit: 10 }))).toEqual([]);
    // By position, in the order asked, a missing one left out; the memory journal answers the same.
    const positions = [all[2]!.core, { ...all[0]!.core, sequence: '99' }, all[0]!.core];
    expect((await journal.getEntries(positions)).map((entry) => entry.core.sequence)).toEqual(['0', '2']);
    const memory = new MemoryAuditJournal();
    const memoryAudit = createApiAudit(baseConfig, { journal: memory, evidence: new MemoryAuditEvidenceStore() }, { signer: testRecorderSigner(), witness: new MemoryRecorderWitness() });
    const recorded = await memoryAudit.recorder.submit(submission(producerEvent('m')), contextFor(producerEvent('m')));
    expect(await memory.getEntries([recorded.core, { ...recorded.core, ledgerEpochId: 'none' }])).toEqual([recorded]);
    expect(inPositionOrder([recorded.core], [])).toEqual([]);
    expect((await memory.listEntries({ before: auditListCursorOf(recorded), limit: 5 })).map((entry) => entry.core.sequence)).toEqual(['0']);
    // The listing order is total: time, then ledger, epoch and sequence, all descending.
    const at = (recordedAt: number, ledgerId: string, ledgerEpochId: string, sequence: string) => ({ recordedAt, ledgerId, ledgerEpochId, sequence });
    expect(compareAuditListOrder(at(2, 'a', 'e', '1'), at(1, 'z', 'z', '9'))).toBeLessThan(0);
    expect(compareAuditListOrder(at(1, 'b', 'e', '1'), at(1, 'a', 'e', '9'))).toBeLessThan(0);
    expect(compareAuditListOrder(at(1, 'a', 'f', '1'), at(1, 'a', 'e', '9'))).toBeLessThan(0);
    expect(compareAuditListOrder(at(1, 'a', 'e', '10'), at(1, 'a', 'e', '9'))).toBeLessThan(0);
    expect(compareAuditListOrder(at(1, 'a', 'e', '9'), at(1, 'a', 'e', '10'))).toBeGreaterThan(0);
    expect(compareAuditListOrder(at(1, 'a', 'e', '9'), at(1, 'a', 'e', '9'))).toBe(0);
    expect(compareAuditListOrder(at(1, 'a', 'e', '9'), at(1, 'b', 'e', '9'))).toBeGreaterThan(0);
    expect(compareAuditListOrder(at(1, 'a', 'e', '9'), at(1, 'a', 'f', '9'))).toBeGreaterThan(0);
    expect(await journal.findLedgerByTenant(all[0]!.core.event.tenantRef)).toMatchObject({ ledgerId });
    expect(await journal.findLedgerByTenant(publicDid('did:web:nobody'))).toBeNull();
    expect(await journal.getLedger('nope')).toBeNull();
    await expect(journal.ensureLedger({ ledgerId: 'other-id', tenantRef: all[0]!.core.event.tenantRef, createdAt: 1 })).rejects.toThrow(AuditProtocolError);
    expect(await journal.setActiveEpoch(ledgerId, 'not-active', 'x')).toBe(false);
    const ledger = { ledgerId, ledgerEpochId: all[0]!.core.ledgerEpochId };
    const head = (await journal.getHead(ledger))!;
    await expect(journal.sealEpoch({ ledger, expectedHead: { ...head, sequence: '0' }, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).rejects.toThrow(
      /not its committed head/,
    );
    expect(await journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).toBe('sealed');
    expect(await journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).toBe('already_sealed');
    await expect(journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 't' })).rejects.toThrow(/already sealed/);
    const ranged: string[] = [];
    for await (const entry of journal.readRange({ ...ledger, afterSequence: '0', limit: 1 })) ranged.push(entry.core.sequence);
    expect(ranged).toEqual(['1']);
    for await (const entry of journal.readRange({ ledgerId, ledgerEpochId: 'missing' })) ranged.push(entry.core.sequence);
    expect(ranged).toEqual(['1']);
    sqlite.execute(`DROP TRIGGER audit_journal_entries_no_update`);
    sqlite.execute(`UPDATE audit_journal_entries SET entry = 'not json' WHERE sequence = 2`);
    await expect(journal.listEntries({ ledgerId, limit: 1 })).rejects.toThrow(/not a signed entry/);
  });
});

describe('StreamAuditSink', () => {
  it('echoes one JSON line to stdout and/or a file and never fails the record', async () => {
    const lines: string[] = [];
    const dir = mkdtempSync(join(tmpdir(), 'helix-audit-stream-'));
    dirs.push(dir);
    const path = join(dir, 'nested', 'audit.log');
    const sink = new MemoryAuditSink();
    const { AuditTrail } = await import('../../../src/core/index.js');
    const entry = await new AuditTrail({ sink, sourceId: 'src', producer: pairwiseDid('did:key:zP'), tenantRef: publicDid('did:web:t.example') }).record(minimal);
    await new StreamAuditSink({ destination: 'both', path, write: (line) => lines.push(line) }).append(entry);
    expect(lines).toEqual([`{"eventDigest":"${entry.eventDigest}","event":${entry.canonical}}`]);
    expect(readFileSync(path, 'utf8')).toBe(`${lines[0]}\n`);
    await new StreamAuditSink({ destination: 'none', write: (line) => lines.push(line) }).append(entry);
    expect(lines).toHaveLength(1);
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await new StreamAuditSink({ destination: 'file', path, appendToFile: async () => { throw new Error('read-only'); } }).append(entry);
    expect(errors).toHaveBeenCalledWith('FAILED_TO_WRITE_AUDIT_LOG_FILE', 'read-only');
    await new StreamAuditSink({ destination: 'file', path, appendToFile: async () => { throw 'oops'; } }).append(entry);
    expect(errors).toHaveBeenCalledWith('FAILED_TO_WRITE_AUDIT_LOG_FILE', 'oops');
    const defaultPath: string[] = [];
    await new StreamAuditSink({ destination: 'file', appendToFile: async (target) => void defaultPath.push(target) }).append(entry);
    expect(defaultPath).toEqual(['./data/audit.log']);
    errors.mockRestore();
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    await new StreamAuditSink({ destination: 'stdout' }).append(entry);
    expect(log).toHaveBeenCalledTimes(1);
    log.mockRestore();
  });
});

describe('API audit factory', () => {
  it('picks the journal and vault for the storage adapter', () => {
    const memory = createApiAuditStorage({});
    expect(memory.journal).toBeInstanceOf(MemoryAuditJournal);
    expect(memory.evidence).toBeInstanceOf(MemoryAuditEvidenceStore);
    const sqlite = createApiAuditStorage({ sqlite: new SqliteStore(sqliteFile()) });
    expect(sqlite.journal).toBeInstanceOf(SqliteAuditJournal);
    expect(sqlite.evidence).toBeInstanceOf(SqliteAuditEvidenceStore);
    const pool = {} as never;
    const pg = createApiAuditStorage({ pool, sqlite: new SqliteStore(sqliteFile()) });
    expect(pg.journal).toBeInstanceOf(PostgresAuditJournal);
    expect(pg.evidence).toBeInstanceOf(PostgresAuditEvidenceStore);
  });

  it('names the deployment by its issuer DID or a fixed commitment', () => {
    expect(apiPartyRef({ HELIX_ISSUER_DID: 'did:web:issuer.example' })).toEqual(publicDid('did:web:issuer.example'));
    expect(apiPartyRef({ HELIX_ISSUER_DID: '' })).toMatchObject({ kind: 'keyed_commitment', keyId: 'helix-api-tenant-v1' });
  });

  it('signs receipts with a recorder key that is never the issuer key, did:key by default', () => {
    const signer = createRecorderSigner(baseConfig);
    expect(signer.ref).toEqual(testRecorderSigner().ref);
    expect(signer.ref.did).toMatch(/^did:key:z6Mk/);
    expect(createRecorderSigner({ ...baseConfig, AUDIT_RECORDER_DID: 'did:web:audit.example', AUDIT_RECORDER_KID: 'recorder-1' }).ref).toEqual({
      did: 'did:web:audit.example',
      kid: 'did:web:audit.example#recorder-1',
      alg: 'EdDSA',
    });
    expect(() => createRecorderSigner({ ...baseConfig, AUDIT_RECORDER_SIGNING_KEY: baseConfig.HELIX_SIGNING_KEY })).toThrow(/must not be the issuer key/);
    expect(() => createRecorderSigner({ ...baseConfig, NODE_ENV: 'production', AUDIT_RECORDER_SIGNING_KEY: undefined })).toThrow(/required in production/);
    const ephemeral = createRecorderSigner({ ...baseConfig, AUDIT_RECORDER_SIGNING_KEY: undefined });
    expect(ephemeral.ref.did).not.toBe(signer.ref.did);
  });

  it('records the API trail through the recorder, with the stream echo and the vault when configured', async () => {
    const storage = createApiAuditStorage({});
    const bare = createApiAudit(baseConfig, storage);
    expect(bare.evidenceEncryptor).toBeUndefined();
    await expect(bare.trail.evidence('x', 'text/plain', 'p')).rejects.toThrow(/no evidence vault/);
    const recorded = await bare.trail.record(minimal);
    expect(recorded.event.source).toMatchObject({ sourceId: 'helix-api', producer: publicDid('did:web:issuer.example') });
    expect(recorded.receipt?.core).toMatchObject({ sequence: '1', event: recorded.event });
    expect(auditLogRow(recorded.receipt!)).toMatchObject({ eventDigest: recorded.eventDigest, sequence: '1', ledgerId: recorded.receipt!.core.ledgerId });

    const lines: string[] = [];
    const extra = new MemoryAuditSink();
    const vaulted = createApiAudit({ ...baseConfig, AUDIT_LOG_DESTINATION: 'stdout', AUDIT_EVIDENCE_KEY: 'b'.repeat(64), AUDIT_INCLUDE_TOOL_NAMES: true }, createApiAuditStorage({}), {
      extraSinks: [extra],
      witness: new MemoryRecorderWitness(),
    });
    expect(vaulted.evidenceEncryptor?.keyId).toBe('evidence-key-v1');
    expect(vaulted.trail.includeToolNames).toBe(true);
    const log = vi.spyOn(console, 'log').mockImplementation((line: string) => void lines.push(line));
    const ref = await vaulted.trail.evidence('kept', 'text/plain', 'p');
    const second = await vaulted.trail.record({ ...minimal, evidence: [ref] });
    log.mockRestore();
    expect(lines).toHaveLength(1);
    expect(extra.entries).toHaveLength(1);
    expect(second.receipt?.core.event.evidence).toEqual([ref]);
    expect(await vaulted.storage.evidence.get(ref.objectId)).not.toBeNull();
  });

  it('keeps a durable journal\'s witness in a file, by default under data/', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'helix-a2-witness-'));
    dirs.push(dir);
    const sqlite = new SqliteStore(sqliteFile());
    const audit = createApiAudit(baseConfig, { journal: new SqliteAuditJournal(sqlite), evidence: new SqliteAuditEvidenceStore(sqlite) }, { baseDir: dir });
    const recorded = await audit.trail.record(minimal);
    await audit.recorder.settled();
    const witness = JSON.parse(readFileSync(join(dir, 'data', 'audit-recorder-witness.json'), 'utf8')) as Record<string, { sequence: string }>;
    expect(witness[recorded.receipt!.core.ledgerId]).toMatchObject({ sequence: '1' });
    const explicit = join(dir, 'explicit.json');
    createApiAudit({ ...baseConfig, AUDIT_RECORDER_WITNESS_PATH: explicit }, createApiAuditStorage({}));
    expect(new FileRecorderWitness(explicit)).toBeInstanceOf(FileRecorderWitness);
  });

  it('restricts a self-hosted recorder to its tenants', async () => {
    const own = createApiAudit({ ...baseConfig, AUDIT_RECORDER_MODE: 'self-hosted' }, createApiAuditStorage({}), { witness: new MemoryRecorderWitness() });
    expect(own.recorder.mode).toBe('self-hosted');
    await own.trail.record(minimal);
    const foreign = producerEvent('foreign');
    await expect(own.recorder.submit(submission(foreign), contextFor(foreign))).rejects.toThrow(/does not record for this tenant/);
    const listed = createApiAudit(
      { ...baseConfig, AUDIT_RECORDER_MODE: 'self-hosted', AUDIT_RECORDER_TENANTS: JSON.stringify([foreign.tenantRef]) },
      createApiAuditStorage({}),
      { witness: new MemoryRecorderWitness() },
    );
    expect((await listed.recorder.submit(submission(foreign), contextFor(foreign))).core.sequence).toBe('1');
    for (const tenants of ['not json', '[]', '[{"kind":"nope"}]']) {
      expect(() => createApiAudit({ ...baseConfig, AUDIT_RECORDER_MODE: 'self-hosted', AUDIT_RECORDER_TENANTS: tenants }, createApiAuditStorage({}))).toThrow(
        /AUDIT_RECORDER_TENANTS/,
      );
    }
  });

  it('derives the retention floor from the longest delegation lifetime on SQLite, unbounded for a delegation without expiry', async () => {
    expect(await delegationRetentionFloor({})()).toBe(0);
    const sqlite = new SqliteStore(sqliteFile());
    const floor = delegationRetentionFloor({ sqlite });
    expect(await floor()).toBe(0);
    sqlite.execute(`INSERT INTO dids (id, subject_type, controller, public_key, hedera_transaction_id, did_document, created_at, updated_at)
      VALUES ('did:key:zR', 'agent', 'did:key:zR', 'aa', 'tx', '{}', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`);
    const insertVc = (id: string, expires: string | null): void =>
      sqlite.write(
        `INSERT INTO vcs (vc_id, subject_did, subject_type, vc_json, status_list_index, expires_at, created_at, updated_at) VALUES (?, 'did:key:zR', 'agent', '{}', 0, ?, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`,
        id,
        expires,
      );
    insertVc('urn:a', '2026-01-03T00:00:00Z');
    expect(await floor()).toBe(2 * 86_400_000);
    insertVc('urn:b', null);
    expect(await floor()).toBe(Number.POSITIVE_INFINITY);
  });
});
