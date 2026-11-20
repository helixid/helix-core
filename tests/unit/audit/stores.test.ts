// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import {
  AuditTrail,
  EvidenceEncryptor,
  MemoryAuditSink,
  evidenceAad,
  pairwiseDid,
  publicDid,
  type AuditEventInput,
  type AuditTrailEntry,
} from '../../../src/core/index.js';
import {
  AuditEventConflictError,
  MemoryAuditStore,
  PrismaAuditSink,
  SqliteAuditSink,
  StreamAuditSink,
  apiPartyRef,
  createApiAudit,
  createApiAuditStore,
  entryColumns,
  partyRefKey,
  type AuditEventStore,
} from '../../../src/audit/index.js';
import { SqliteStore } from '../../../src/storage/sqlite.js';
import { fixture } from '../core/audit/fixture.js';

const minimal: AuditEventInput = {
  eventType: 'session.established',
  action: { category: 'session' },
  outcome: 'succeeded',
  details: { family: 'session', phase: 'established' },
};

function makeTrail(sink: AuditEventStore, sourceId = 'src'): AuditTrail {
  return new AuditTrail({ sink, sourceId, producer: pairwiseDid('did:key:zP'), tenantRef: publicDid('did:web:t.example') });
}

const evidenceObject = () => ({ ref: fixture.evidence.ref, ciphertext: new Uint8Array(Buffer.from(fixture.evidence.ciphertext_b64url, 'base64url')) });

/** The contract every store meets: append, idempotent replay, conflict, list filters, evidence. */
function describeStoreContract(name: string, open: () => Promise<AuditEventStore>, close: () => Promise<void> = async () => undefined): void {
  describe(`${name} store contract`, () => {
    let store: AuditEventStore;
    beforeEach(async () => {
      store = await open();
    });
    afterEach(close);

    it('appends, lists newest first and filters', async () => {
      const trail = makeTrail(store);
      const first = await trail.record({ ...minimal, correlationId: 'c-1', actor: publicDid('did:web:a') });
      const second = await trail.record({ ...minimal, eventType: 'tool.call.started', details: { family: 'tool', phase: 'started', attempt: '1' } });
      const all = await store.list({ limit: 10 });
      expect(all.map((row) => row.eventDigest)).toEqual([second.eventDigest, first.eventDigest]);
      expect(all[0]!.event).toEqual(second.event);
      expect(all[0]!.recordedAt).toBeInstanceOf(Date);
      expect(all[0]!.id).toEqual(expect.any(String));
      expect((await store.list({ eventType: 'session.established', limit: 10 })).map((row) => row.eventDigest)).toEqual([first.eventDigest]);
      expect((await store.list({ family: 'tool', limit: 10 })).map((row) => row.eventDigest)).toEqual([second.eventDigest]);
      expect((await store.list({ correlationId: 'c-1', limit: 10 })).map((row) => row.eventDigest)).toEqual([first.eventDigest]);
      expect(await store.list({ since: new Date(Date.now() + 60_000), limit: 10 })).toEqual([]);
      expect((await store.list({ since: new Date(Date.now() - 60_000), limit: 1 })).length).toBe(1);
    });

    it('replays the same event idempotently and refuses the same id with other content', async () => {
      const trail = makeTrail(store);
      const entry = await trail.record({ ...minimal, eventId: 'stable', occurredAt: 1 });
      await store.append(entry);
      expect((await store.list({ limit: 10 })).length).toBe(1);
      const changed: AuditTrailEntry = { ...entry, event: { ...entry.event, outcome: 'failed' }, eventDigest: `sha256:${'1'.repeat(64)}`, canonical: '{}' };
      await expect(store.append(changed)).rejects.toThrow(AuditEventConflictError);
    });

    it('keeps evidence by object id and refuses a collision', async () => {
      expect(await store.get(fixture.evidence.ref.objectId)).toBeNull();
      expect(await store.putIfAbsent(evidenceObject())).toEqual(fixture.evidence.ref);
      expect(await store.putIfAbsent(evidenceObject())).toEqual(fixture.evidence.ref);
      const got = (await store.get(fixture.evidence.ref.objectId))!;
      expect(got.ref).toEqual(fixture.evidence.ref);
      expect(Buffer.from(got.ciphertext)).toEqual(Buffer.from(fixture.evidence.ciphertext_b64url, 'base64url'));
      const encryptor = new EvidenceEncryptor({ key: fixture.evidence.key_hex, keyId: fixture.evidence.key_id });
      expect(Buffer.from(encryptor.decrypt(got, evidenceAad(fixture.evidence.tenant, fixture.evidence.purpose))).toString()).toBe(fixture.evidence.plaintext_utf8);
      const other = encryptor.encrypt({ plaintext: 'other', mediaType: 'text/plain', aad: evidenceAad(fixture.evidence.tenant, 'p') });
      await expect(store.putIfAbsent({ ...other, ref: { ...other.ref, objectId: fixture.evidence.ref.objectId } })).rejects.toThrow(/collision/);
      await expect(store.putIfAbsent({ ...evidenceObject(), ciphertext: new Uint8Array([1]) })).rejects.toThrow(/digest or size/);
    });
  });
}

describeStoreContract('MemoryAuditStore', async () => new MemoryAuditStore());

let sqliteDir: string | undefined;
describeStoreContract(
  'SqliteAuditSink',
  async () => {
    sqliteDir = mkdtempSync(join(tmpdir(), 'helix-audit-sqlite-'));
    return new SqliteAuditSink(new SqliteStore(join(sqliteDir, 'audit.sqlite')));
  },
  async () => {
    if (sqliteDir) rmSync(sqliteDir, { recursive: true, force: true });
  },
);

describe('SqliteAuditSink', () => {
  it('rethrows a non-unique failure and drops the legacy audit_log table', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'helix-audit-sqlite-'));
    try {
      const sqlite = new SqliteStore(join(dir, 'audit.sqlite'));
      expect(sqlite.query(`SELECT name FROM sqlite_master WHERE name = 'audit_log'`)).toEqual([]);
      const sink = new SqliteAuditSink(sqlite);
      const entry = await makeTrail(new MemoryAuditStore()).record(minimal);
      const source = { producer: entry.event.source.producer, sourceId: entry.event.source.sourceId };
      await sink.append({ ...entry, event: { ...entry.event, source }, eventDigest: `sha256:${'3'.repeat(64)}` });
      expect(sqlite.query<{ source_sequence: number | null }>('SELECT source_sequence FROM audit_events')).toEqual([{ source_sequence: null }]);
      sqlite.execute('DROP TABLE audit_events');
      await expect(sink.append(entry)).rejects.toThrow(/no such table/);
      sqlite.execute('DROP TABLE audit_evidence');
      await expect(sink.putIfAbsent(evidenceObject())).rejects.toThrow(/no such table/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

/** A Prisma client stub with the two models the sink uses, backed by arrays. */
function prismaStub(): { prisma: PrismaClient; events: Array<Record<string, unknown>>; evidence: Array<Record<string, unknown>> } {
  const events: Array<Record<string, unknown>> = [];
  const evidence: Array<Record<string, unknown>> = [];
  const unique = () => Object.assign(new Error('Unique constraint failed'), { code: 'P2002' });
  const prisma = {
    auditEvent: {
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        if (events.some((row) => row['eventDigest'] === data['eventDigest'] || (row['sourceId'] === data['sourceId'] && row['eventId'] === data['eventId']))) throw unique();
        events.push({ ...data, id: `row-${events.length + 1}`, recordedAt: new Date() });
      }),
      findUnique: vi.fn(async ({ where }: { where: { sourceId_eventId: { sourceId: string; eventId: string } } }) =>
        events.find((row) => row['sourceId'] === where.sourceId_eventId.sourceId && row['eventId'] === where.sourceId_eventId.eventId) ?? null,
      ),
      findMany: vi.fn(async ({ where, take }: { where: Record<string, unknown>; take: number }) =>
        events
          .filter((row) =>
            Object.entries(where).every(([key, value]) =>
              key === 'recordedAt' ? (row['recordedAt'] as Date).getTime() >= (value as { gte: Date }).gte.getTime() : row[key] === value,
            ),
          )
          .reverse()
          .slice(0, take),
      ),
    },
    auditEvidence: {
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        if (evidence.some((row) => row['objectId'] === data['objectId'])) throw unique();
        evidence.push(data);
      }),
      findUnique: vi.fn(async ({ where }: { where: { objectId: string } }) => evidence.find((row) => row['objectId'] === where.objectId) ?? null),
    },
  };
  return { prisma: prisma as unknown as PrismaClient, events, evidence };
}

describeStoreContract('PrismaAuditSink (stubbed client)', async () => new PrismaAuditSink(prismaStub().prisma));

describe('PrismaAuditSink', () => {
  it('writes the indexed columns beside the event and rethrows other failures', async () => {
    const { prisma, events } = prismaStub();
    const sink = new PrismaAuditSink(prisma);
    const entry = await makeTrail(sink, 'api').record({ ...minimal, correlationId: 'c', actor: publicDid('did:web:a') });
    expect(events[0]).toMatchObject({
      eventId: entry.event.eventId,
      eventType: 'session.established',
      family: 'session',
      sourceId: 'api',
      sourceSequence: 1n,
      previousSourceEventDigest: null,
      eventDigest: entry.eventDigest,
      correlationId: 'c',
      actorRef: 'public_did:did:web:a',
      canonical: entry.canonical,
      event: entry.event,
    });
    (prisma as unknown as { auditEvent: { create: ReturnType<typeof vi.fn> } }).auditEvent.create.mockRejectedValueOnce(new Error('connection lost'));
    await expect(sink.append(entry)).rejects.toThrow('connection lost');
    (prisma as unknown as { auditEvidence: { create: ReturnType<typeof vi.fn> } }).auditEvidence.create.mockRejectedValueOnce(new Error('connection lost'));
    await expect(sink.putIfAbsent(evidenceObject())).rejects.toThrow('connection lost');
    const { prisma: other } = prismaStub();
    (other as unknown as { auditEvent: { create: ReturnType<typeof vi.fn>; findUnique: ReturnType<typeof vi.fn> } }).auditEvent.create.mockRejectedValueOnce(Object.assign(new Error('dup'), { code: 'P2002' }));
    await expect(new PrismaAuditSink(other).append(entry)).rejects.toThrow(AuditEventConflictError);
    const { prisma: third } = prismaStub();
    (third as unknown as { auditEvidence: { create: ReturnType<typeof vi.fn> } }).auditEvidence.create.mockRejectedValueOnce(Object.assign(new Error('dup'), { code: 'P2002' }));
    await expect(new PrismaAuditSink(third).putIfAbsent(evidenceObject())).rejects.toThrow(/collision/);
  });
});

describe('store helpers', () => {
  it('keys every party reference form', () => {
    expect(partyRefKey(undefined)).toBeUndefined();
    expect(partyRefKey(publicDid('did:web:a'))).toBe('public_did:did:web:a');
    expect(partyRefKey(pairwiseDid('did:key:zB'))).toBe('pairwise_did:did:key:zB');
    expect(partyRefKey({ kind: 'keyed_commitment', value: `sha256:${'1'.repeat(64)}`, keyId: 'k' })).toBe(`keyed_commitment:k:sha256:${'1'.repeat(64)}`);
    expect(partyRefKey({ kind: 'evidence_ref', ref: fixture.evidence.ref })).toBe(`evidence_ref:${fixture.evidence.ref.objectId}`);
  });

  it('derives columns from an entry without a sequence', () => {
    const sample = fixture.events[0]!;
    const source = { producer: sample.event.source.producer, sourceId: sample.event.source.sourceId };
    const columns = entryColumns({ ...sample, eventDigest: sample.digest, event: { ...sample.event, source } });
    expect(columns).toMatchObject({ sourceSequence: null, previousSourceEventDigest: null, correlationId: 'call-0001', occurredAt: new Date(sample.event.occurredAt) });
  });
});

describe('StreamAuditSink', () => {
  it('echoes one JSON line to stdout and/or a file and never fails the record', async () => {
    const lines: string[] = [];
    const dir = mkdtempSync(join(tmpdir(), 'helix-audit-stream-'));
    const path = join(dir, 'nested', 'audit.log');
    try {
      const entry = await makeTrail(new MemoryAuditStore()).record(minimal);
      await new StreamAuditSink({ destination: 'both', path, write: (line) => lines.push(line) }).append(entry);
      expect(lines).toEqual([`{"eventDigest":"${entry.eventDigest}","event":${entry.canonical}}`]);
      expect(readFileSync(path, 'utf8')).toBe(`${lines[0]}\n`);
      expect(JSON.parse(lines[0]!)).toEqual({ eventDigest: entry.eventDigest, event: entry.event });
      await new StreamAuditSink({ destination: 'none', write: (line) => lines.push(line) }).append(entry);
      expect(lines).toHaveLength(1);
      const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      await new StreamAuditSink({ destination: 'file', path, appendToFile: async () => { throw new Error('read-only'); } }).append(entry);
      expect(errors).toHaveBeenCalledWith('FAILED_TO_WRITE_AUDIT_LOG_FILE', 'read-only');
      await new StreamAuditSink({ destination: 'file', path, appendToFile: async () => { throw 'oops'; } }).append(entry);
      const defaultPath: string[] = [];
      await new StreamAuditSink({ destination: 'file', appendToFile: async (target) => void defaultPath.push(target) }).append(entry);
      expect(defaultPath).toEqual(['./data/audit.log']);
      expect(errors).toHaveBeenCalledWith('FAILED_TO_WRITE_AUDIT_LOG_FILE', 'oops');
      errors.mockRestore();
      const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
      await new StreamAuditSink({ destination: 'stdout' }).append(entry);
      expect(log).toHaveBeenCalledTimes(1);
      log.mockRestore();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('API audit factory', () => {
  const config = {
    AUDIT_LOG_DESTINATION: 'none' as const,
    AUDIT_LOG_PATH: undefined,
    AUDIT_SOURCE_ID: 'helix-api',
    AUDIT_INCLUDE_TOOL_NAMES: false,
    AUDIT_EVIDENCE_KEY: undefined,
    AUDIT_EVIDENCE_KEY_ID: 'evidence-key-v1',
    HELIX_ISSUER_DID: 'did:web:issuer.example',
  };

  it('picks the store for the storage adapter', () => {
    expect(createApiAuditStore({})).toBeInstanceOf(MemoryAuditStore);
    const dir = mkdtempSync(join(tmpdir(), 'helix-audit-factory-'));
    try {
      expect(createApiAuditStore({ sqlite: new SqliteStore(join(dir, 'a.sqlite')) })).toBeInstanceOf(SqliteAuditSink);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    expect(createApiAuditStore({ prisma: prismaStub().prisma })).toBeInstanceOf(PrismaAuditSink);
  });

  it('names the deployment by its issuer DID or a fixed commitment', () => {
    expect(apiPartyRef({ HELIX_ISSUER_DID: 'did:web:issuer.example' })).toEqual(publicDid('did:web:issuer.example'));
    expect(apiPartyRef({ HELIX_ISSUER_DID: '' })).toMatchObject({ kind: 'keyed_commitment', keyId: 'helix-api-tenant-v1' });
  });

  it('builds the trail over the store, the stream echo and the vault when configured', async () => {
    const store = new MemoryAuditStore();
    const bare = createApiAudit(config, store);
    expect(bare.evidenceEncryptor).toBeUndefined();
    await expect(bare.trail.evidence('x', 'text/plain', 'p')).rejects.toThrow(/no evidence vault/);
    const entry = await bare.trail.record(minimal);
    expect(entry.event.source).toMatchObject({ sourceId: 'helix-api', producer: publicDid('did:web:issuer.example') });
    expect(entry.event.binding).toBe('urn:kya-os:audit-binding:helix:2026-11-20');
    expect(await store.list({ limit: 1 })).toHaveLength(1);

    const lines: string[] = [];
    const extra = new MemoryAuditSink();
    const vaulted = createApiAudit({ ...config, AUDIT_LOG_DESTINATION: 'stdout', AUDIT_EVIDENCE_KEY: 'b'.repeat(64), AUDIT_INCLUDE_TOOL_NAMES: true }, store, [extra]);
    expect(vaulted.evidenceEncryptor?.keyId).toBe('evidence-key-v1');
    expect(vaulted.trail.includeToolNames).toBe(true);
    const log = vi.spyOn(console, 'log').mockImplementation((line: string) => void lines.push(line));
    const ref = await vaulted.trail.evidence('kept', 'text/plain', 'p');
    const second = await vaulted.trail.record({ ...minimal, evidence: [ref] });
    log.mockRestore();
    expect(lines).toHaveLength(1);
    expect(extra.entries).toEqual([second]);
    expect(await store.get(ref.objectId)).not.toBeNull();
  });
});
