// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: custody_records, custody_keys and wrapped_keys on every storage backend.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { CustodyRepository, WrappedKeyRepository, type NewCustodyRecord } from '../../../src/repositories/custody.repository.js';
import {
  PrismaCustodyStorageDriver,
  PrismaWrappedKeyStorageDriver,
  createCustodyStorageDriver,
  createWrappedKeyStorageDriver,
} from '../../../src/repositories/drivers/custody.drivers.js';
import { SqliteStore } from '../../../src/storage/sqlite.js';

const JWK = { kty: 'OKP' as const, crv: 'Ed25519' as const, x: 'A'.repeat(43) };
const dir = mkdtempSync(join(tmpdir(), 'helix-custody-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function record(did: string, overrides: Partial<NewCustodyRecord> = {}): NewCustodyRecord {
  return {
    did,
    subjectType: 'agent',
    keyCustody: 'self',
    didHosting: 'helix',
    status: 'pending_key',
    kid: null,
    name: 'Bot',
    ownerDid: null,
    scopes: ['read:orders'],
    requestedDomains: null,
    maxDelegationDepth: 0,
    enrollmentTokenHash: `hash-${did}`,
    enrollmentExpiresAt: new Date('2026-12-01T00:00:00Z'),
    enrollmentNonce: null,
    enrollmentUsedAt: null,
    credentialVcId: null,
    activatedAt: null,
    ...overrides,
  };
}

const backends: [string, () => { custody: CustodyRepository; wrapped: WrappedKeyRepository }][] = [
  ['memory', () => ({ custody: new CustodyRepository(), wrapped: new WrappedKeyRepository() })],
  [
    'sqlite',
    () => {
      const store = new SqliteStore(join(dir, `${Math.random().toString(16).slice(2)}.sqlite`));
      return { custody: new CustodyRepository(undefined, store), wrapped: new WrappedKeyRepository(undefined, store) };
    },
  ],
];

describe.each(backends)('custody repositories (%s)', (_name, make) => {
  it('creates, finds, updates and lists custody records', async () => {
    const { custody } = make();
    const created = await custody.createRecord(record('did:web:h:o:a'));
    expect(created).toMatchObject({ did: 'did:web:h:o:a', keyCustody: 'self', scopes: ['read:orders'], status: 'pending_key' });
    expect(created.createdAt).toBeInstanceOf(Date);
    await custody.createRecord(record('did:web:h:o:b', { subjectType: 'service', keyCustody: 'helix', scopes: null, enrollmentTokenHash: null }));
    await expect(custody.createRecord(record('did:web:h:o:a', { enrollmentTokenHash: 'other' }))).rejects.toThrow();
    expect((await custody.findRecord('did:web:h:o:a'))?.name).toBe('Bot');
    expect(await custody.findRecord('did:web:h:o:none')).toBeNull();
    expect((await custody.findRecordByEnrollmentToken('hash-did:web:h:o:a'))?.did).toBe('did:web:h:o:a');
    expect(await custody.findRecordByEnrollmentToken('nope')).toBeNull();
    const updated = await custody.updateRecord('did:web:h:o:a', { status: 'active', kid: 'did:web:h:o:a#key-1', activatedAt: new Date('2026-11-21T00:00:00Z'), scopes: ['a', 'b'] });
    expect(updated).toMatchObject({ status: 'active', kid: 'did:web:h:o:a#key-1', scopes: ['a', 'b'] });
    expect(updated.activatedAt?.toISOString()).toBe('2026-11-21T00:00:00.000Z');
    await expect(custody.updateRecord('did:web:h:o:none', { status: 'active' })).rejects.toThrow(/not found/);
    expect((await custody.listRecords()).map((row) => row.did)).toEqual(['did:web:h:o:a', 'did:web:h:o:b']);
    expect((await custody.listRecords({ subjectType: 'service' })).map((row) => row.did)).toEqual(['did:web:h:o:b']);
    expect((await custody.listRecords({ dids: ['did:web:h:o:b', 'x'] })).map((row) => row.scopes)).toEqual([null]);
  });

  it('keeps requestedDomains and maxDelegationDepth (POST /v1/agents fields)', async () => {
    const { custody } = make();
    const created = await custody.createRecord(record('did:web:h:o:f', { requestedDomains: ['https://orders.example', 'https://api.example/v1'], maxDelegationDepth: 3 }));
    expect(created).toMatchObject({ requestedDomains: ['https://orders.example', 'https://api.example/v1'], maxDelegationDepth: 3 });
    expect(await custody.findRecord('did:web:h:o:f')).toMatchObject({ requestedDomains: ['https://orders.example', 'https://api.example/v1'], maxDelegationDepth: 3 });
    expect((await custody.updateRecord('did:web:h:o:f', { maxDelegationDepth: 1 })).maxDelegationDepth).toBe(1);
    expect((await custody.createRecord(record('did:web:h:o:g'))).requestedDomains).toBeNull();
  });

  it('claims an enrollment token once', async () => {
    const { custody } = make();
    await custody.createRecord(record('did:web:h:o:c'));
    expect(await custody.claimEnrollment('did:web:h:o:c', new Date())).toBe(true);
    expect(await custody.claimEnrollment('did:web:h:o:c', new Date())).toBe(false);
    expect(await custody.claimEnrollment('did:web:h:o:none', new Date())).toBe(false);
  });

  it('adds, lists and updates keys in sequence order', async () => {
    const { custody } = make();
    await custody.createRecord(record('did:web:h:o:d'));
    await custody.addKey({ did: 'did:web:h:o:d', kid: 'did:web:h:o:d#key-2', location: 'self', publicKeyJwk: JWK, status: 'active', sequence: 2, retiresAt: null, revokedAt: null });
    await custody.addKey({ did: 'did:web:h:o:d', kid: 'did:web:h:o:d#key-1', location: 'helix', publicKeyJwk: JWK, status: 'active', sequence: 1, retiresAt: null, revokedAt: null });
    await expect(
      custody.addKey({ did: 'did:web:h:o:d', kid: 'did:web:h:o:d#key-1', location: 'helix', publicKeyJwk: JWK, status: 'active', sequence: 3, retiresAt: null, revokedAt: null }),
    ).rejects.toThrow();
    const retiresAt = new Date('2026-11-22T00:00:00Z');
    const retiring = await custody.updateKey('did:web:h:o:d', 'did:web:h:o:d#key-1', { status: 'retiring', retiresAt });
    expect(retiring).toMatchObject({ status: 'retiring', location: 'helix', publicKeyJwk: JWK });
    expect(retiring.retiresAt?.toISOString()).toBe(retiresAt.toISOString());
    const keys = await custody.listKeys('did:web:h:o:d');
    expect(keys.map((key) => key.kid)).toEqual(['did:web:h:o:d#key-1', 'did:web:h:o:d#key-2']);
    expect(keys[1]!.createdAt).toBeInstanceOf(Date);
    await expect(custody.updateKey('did:web:h:o:d', 'did:web:h:o:d#key-9', { status: 'revoked' })).rejects.toThrow(/not found/);
    expect(await custody.listKeys('did:web:h:o:none')).toEqual([]);
  });

  it('stores wrapped keys and shreds them once', async () => {
    const { wrapped } = make();
    const row = await wrapped.insert({ did: 'did:web:h:o:e', kid: 'did:web:h:o:e#key-1', subjectType: 'agent', algorithm: 'A256GCM', kekId: 'kek-1', nonce: 'n', ciphertext: 'c', publicKeyJwk: JWK });
    expect(row).toMatchObject({ ciphertext: 'c', shreddedAt: null, publicKeyJwk: JWK });
    await expect(wrapped.insert({ did: 'did:web:h:o:e', kid: 'did:web:h:o:e#key-1', subjectType: 'agent', algorithm: 'A256GCM', kekId: 'kek-1', nonce: 'n', ciphertext: 'c', publicKeyJwk: JWK })).rejects.toThrow();
    expect((await wrapped.find('did:web:h:o:e', 'did:web:h:o:e#key-1'))?.nonce).toBe('n');
    expect(await wrapped.find('did:web:h:o:e', 'x')).toBeNull();
    expect(await wrapped.shred('did:web:h:o:e', 'did:web:h:o:e#key-1', new Date('2026-11-21T00:00:00Z'))).toBe(true);
    expect(await wrapped.shred('did:web:h:o:e', 'did:web:h:o:e#key-1', new Date())).toBe(false);
    const [shredded] = await wrapped.list('did:web:h:o:e');
    expect(shredded).toMatchObject({ ciphertext: '', nonce: '' });
    expect(shredded!.shreddedAt?.toISOString()).toBe('2026-11-21T00:00:00.000Z');
    expect(await wrapped.list('did:web:h:o:none')).toEqual([]);
  });
});

describe('custody drivers (sqlite upgrade)', () => {
  it('adds the requestedDomains and maxDelegationDepth columns to a custody_records table created before them', async () => {
    const store = new SqliteStore(join(dir, 'upgrade.sqlite'));
    store.execute(`CREATE TABLE custody_records (
      did TEXT PRIMARY KEY, subject_type TEXT NOT NULL, key_custody TEXT NOT NULL, did_hosting TEXT NOT NULL, status TEXT NOT NULL,
      kid TEXT, name TEXT, owner_did TEXT, scopes TEXT, enrollment_token_hash TEXT UNIQUE, enrollment_expires_at TEXT,
      enrollment_nonce TEXT, enrollment_used_at TEXT, credential_vc_id TEXT, activated_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`);
    store.execute(`INSERT INTO custody_records (did, subject_type, key_custody, did_hosting, status, created_at, updated_at)
      VALUES ('did:web:h:o:old', 'agent', 'helix', 'helix', 'active', '2026-11-21T00:00:00.000Z', '2026-11-21T00:00:00.000Z')`);
    const custody = new CustodyRepository(undefined, store);
    expect(await custody.findRecord('did:web:h:o:old')).toMatchObject({ requestedDomains: null, maxDelegationDepth: 0 });
    await custody.createRecord(record('did:web:h:o:new', { requestedDomains: ['https://a.example'], maxDelegationDepth: 2 }));
    expect(await custody.findRecord('did:web:h:o:new')).toMatchObject({ requestedDomains: ['https://a.example'], maxDelegationDepth: 2 });
    expect(new CustodyRepository(undefined, store)).toBeInstanceOf(CustodyRepository);
  });
});

describe('custody drivers (postgres)', () => {
  function delegate(result: unknown) {
    return {
      create: vi.fn(async () => result),
      findUnique: vi.fn(async () => result),
      findMany: vi.fn(async () => [result]),
      update: vi.fn(async () => result),
      updateMany: vi.fn(async () => ({ count: 1 })),
    };
  }

  it('maps custody records and keys through Prisma', async () => {
    const recordRow = { ...record('did:web:h:o:p'), scopes: 'not-an-array', requestedDomains: ['https://a.example'], createdAt: new Date(), updatedAt: new Date() };
    const keyRow = { id: 'k1', did: 'did:web:h:o:p', kid: 'did:web:h:o:p#key-1', location: 'helix', publicKeyJwk: JWK, status: 'active', sequence: 1, createdAt: new Date(), retiresAt: null, revokedAt: null };
    const prisma = { custodyRecord: delegate(recordRow), custodyKey: delegate(keyRow), wrappedKey: delegate(null) };
    const driver = new PrismaCustodyStorageDriver(prisma as unknown as PrismaClient);
    expect((await driver.createRecord(record('did:web:h:o:p')))!.scopes).toBeNull();
    expect((await driver.findRecord('did:web:h:o:p'))!.requestedDomains).toEqual(['https://a.example']);
    await driver.updateRecord('did:web:h:o:p', { requestedDomains: null });
    expect(prisma.custodyRecord.update).toHaveBeenLastCalledWith({ where: { did: 'did:web:h:o:p' }, data: { requestedDomains: undefined } });
    expect(prisma.custodyRecord.create).toHaveBeenCalledWith({ data: expect.objectContaining({ did: 'did:web:h:o:p', scopes: ['read:orders'] }) });
    expect((await driver.findRecord('did:web:h:o:p'))?.did).toBe('did:web:h:o:p');
    expect((await driver.findRecordByEnrollmentToken('h'))?.did).toBe('did:web:h:o:p');
    await driver.updateRecord('did:web:h:o:p', { scopes: null, status: 'active' });
    expect(prisma.custodyRecord.update).toHaveBeenCalledWith({ where: { did: 'did:web:h:o:p' }, data: { scopes: undefined, status: 'active' } });
    expect(await driver.claimEnrollment('did:web:h:o:p', new Date())).toBe(true);
    await driver.listRecords({ subjectType: 'agent', dids: ['did:web:h:o:p'] });
    expect(prisma.custodyRecord.findMany).toHaveBeenCalledWith(expect.objectContaining({ where: { subjectType: 'agent', did: { in: ['did:web:h:o:p'] } } }));
    await driver.listRecords({});
    expect(await driver.addKey({ ...keyRow, location: 'helix', status: 'active' } as never)).not.toHaveProperty('id');
    expect((await driver.listKeys('did:web:h:o:p'))[0]).not.toHaveProperty('id');
    await driver.updateKey('did:web:h:o:p', 'did:web:h:o:p#key-1', { status: 'revoked' });
    expect(prisma.custodyKey.update).toHaveBeenCalledWith({ where: { did_kid: { did: 'did:web:h:o:p', kid: 'did:web:h:o:p#key-1' } }, data: { status: 'revoked' } });
    prisma.custodyRecord.findUnique.mockResolvedValueOnce(null);
    expect(await driver.findRecord('x')).toBeNull();
  });

  it('maps wrapped keys through Prisma', async () => {
    const row = { id: 'w1', did: 'did:web:h:o:p', kid: 'did:web:h:o:p#key-1', subjectType: 'agent', algorithm: 'A256GCM', kekId: 'kek-1', nonce: 'n', ciphertext: 'c', publicKeyJwk: JWK, createdAt: new Date(), shreddedAt: null };
    const prisma = { custodyRecord: delegate(null), custodyKey: delegate(null), wrappedKey: delegate(row) };
    const driver = new PrismaWrappedKeyStorageDriver(prisma as unknown as PrismaClient);
    expect(await driver.insert(row as never)).not.toHaveProperty('id');
    expect((await driver.find('did:web:h:o:p', 'did:web:h:o:p#key-1'))?.ciphertext).toBe('c');
    expect(await driver.list('did:web:h:o:p')).toHaveLength(1);
    expect(await driver.shred('did:web:h:o:p', 'did:web:h:o:p#key-1', new Date())).toBe(true);
    expect(prisma.wrappedKey.updateMany).toHaveBeenCalledWith(expect.objectContaining({ data: expect.objectContaining({ ciphertext: '', nonce: '' }) }));
    prisma.wrappedKey.findUnique.mockResolvedValueOnce(null);
    expect(await driver.find('x', 'y')).toBeNull();
  });

  it('requires the backend each kind names', () => {
    expect(() => createCustodyStorageDriver('postgres', {})).toThrow(/prisma/);
    expect(() => createCustodyStorageDriver('sqlite', {})).toThrow(/sqlite/);
    expect(() => createWrappedKeyStorageDriver('postgres', {})).toThrow(/prisma/);
    expect(() => createWrappedKeyStorageDriver('sqlite', {})).toThrow(/sqlite/);
    expect(() => createCustodyStorageDriver('mongo' as never, {})).toThrow(/no storage driver/);
    expect(() => createWrappedKeyStorageDriver('mongo' as never, {})).toThrow(/no storage driver/);
    expect(new CustodyRepository({ custodyRecord: {} } as unknown as PrismaClient)).toBeInstanceOf(CustodyRepository);
    expect(new WrappedKeyRepository({ wrappedKey: {} } as unknown as PrismaClient)).toBeInstanceOf(WrappedKeyRepository);
  });
});
