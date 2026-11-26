// Copyright 2026 DgVerse LLP
// KYA-OS story L3-H: consent_requests, user_keys and user_consents on every storage backend. The Prisma
// driver runs the same contract over a small in-memory stand-in for the Prisma delegates it calls.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { ConsentRepository, type NewConsentRequest, type NewUserConsent } from '../../../src/repositories/consent.repository.js';
import { InMemoryConsentStorageDriver, PrismaConsentStorageDriver, SqliteConsentStorageDriver, createConsentStorageDriver } from '../../../src/repositories/drivers/consent.drivers.js';
import { SqliteStore } from '../../../src/storage/sqlite.js';
import { UnsupportedStorageDriverError } from '../../../src/storage/driver-registry.js';

const dir = mkdtempSync(join(tmpdir(), 'helix-consent-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

type Row = Record<string, unknown>;

/** Just enough of a Prisma model delegate: equality and null `where`, `orderBy` createdAt, unique keys. */
function delegate(key: string) {
  const rows = new Map<string, Row>();
  let tick = 0;
  const matches = (row: Row, where: Row): boolean => Object.entries(where).every(([field, value]) => (value === null ? row[field] === null || row[field] === undefined : row[field] === value));
  const ordered = (orderBy?: { createdAt: 'asc' | 'desc' }): Row[] => {
    const all = [...rows.values()].sort((a, b) => (a['createdAt'] as Date).getTime() - (b['createdAt'] as Date).getTime());
    return orderBy?.createdAt === 'desc' ? all.reverse() : all;
  };
  const defined = (data: Row): Row => Object.fromEntries(Object.entries(data).filter(([, value]) => value !== undefined));
  return {
    async create({ data }: { data: Row }) {
      if (rows.has(data[key] as string)) throw new Error('unique constraint');
      tick += 1;
      const row = { withdrawnAt: null, shreddedAt: null, decidedAt: null, consentId: null, pageTokenHash: null, display: null, caveats: null, ...defined(data), createdAt: new Date(Date.now() + tick) };
      rows.set(data[key] as string, row);
      return { ...row };
    },
    async findUnique({ where }: { where: Row }) {
      const row = rows.get(where[key] as string);
      return row ? { ...row } : null;
    },
    async findFirst({ where, orderBy }: { where: Row; orderBy?: { createdAt: 'asc' | 'desc' } }) {
      const row = ordered(orderBy).find((candidate) => matches(candidate, where));
      return row ? { ...row } : null;
    },
    async findMany({ where, orderBy }: { where: Row; orderBy?: { createdAt: 'asc' | 'desc' } }) {
      return ordered(orderBy).filter((row) => matches(row, where)).map((row) => ({ ...row }));
    },
    async update({ where, data }: { where: Row; data: Row }) {
      const row = rows.get(where[key] as string);
      if (!row) throw new Error('record not found');
      Object.assign(row, defined(data));
      return { ...row };
    },
    async updateMany({ where, data }: { where: Row; data: Row }) {
      let count = 0;
      for (const row of rows.values()) {
        if (!matches(row, where)) continue;
        Object.assign(row, defined(data));
        count += 1;
      }
      return { count };
    },
  };
}

const fakePrisma = (): PrismaClient => ({ consentRequest: delegate('id'), userKey: delegate('did'), userConsent: delegate('id') }) as unknown as PrismaClient;

const backends: [string, () => ConsentRepository][] = [
  ['memory', () => new ConsentRepository()],
  ['sqlite', () => new ConsentRepository(undefined, new SqliteStore(join(dir, `${Math.random().toString(16).slice(2)}.sqlite`)))],
  ['postgres (Prisma driver)', () => new ConsentRepository(fakePrisma())],
];

const GRANT = { invoker: 'did:web:a:agents:1', invocationTarget: 'did:web:s:services:1', parentCapability: 'did:web:s:services:1', allowedAction: ['orders:read'], validUntil: '2027-01-01T00:00:00.000Z' };

function request(id: string, overrides: Partial<NewConsentRequest> = {}): NewConsentRequest {
  return {
    id,
    serviceDid: 'did:web:s:services:1',
    serviceUserRef: 'sha256:u1',
    agentDid: 'did:web:a:agents:1',
    grant: GRANT,
    grantDigest: 'sha256:g',
    windowUntil: new Date('2027-01-01T00:00:00Z'),
    hopLifetimeSeconds: 3600,
    display: { serviceName: 'Shop' },
    returnUrl: 'https://s.example/back',
    expiresAt: new Date('2026-12-01T00:10:00Z'),
    ...overrides,
  };
}

function consent(id: string, overrides: Partial<NewUserConsent> = {}): NewUserConsent {
  return {
    id,
    requestId: 'req-1',
    userDid: 'did:key:z6Mkuser1',
    serviceDid: 'did:web:s:services:1',
    serviceUserRef: 'sha256:u1',
    agentDid: 'did:web:a:agents:1',
    invocationTarget: 'did:web:s:services:1',
    allowedAction: ['orders:read'],
    caveats: [{ type: 'Expiry' }],
    windowUntil: new Date('2027-01-01T00:00:00Z'),
    hopLifetimeSeconds: null,
    consentType: 'user-signed',
    latestHopId: 'urn:zcap:1',
    lastHopUntil: new Date('2026-12-01T01:00:00Z'),
    ...overrides,
  };
}

describe.each(backends)('consent repository (%s)', (_name, make) => {
  it('creates, finds and moves consent requests by compare-and-set', async () => {
    const repo = make();
    const created = await repo.createRequest(request('r1'));
    expect(created).toMatchObject({ id: 'r1', status: 'pending', pageTokenHash: null, decidedAt: null, consentId: null, grant: GRANT, display: { serviceName: 'Shop' }, hopLifetimeSeconds: 3600 });
    expect(created.createdAt).toBeInstanceOf(Date);
    expect(created.windowUntil.toISOString()).toBe('2027-01-01T00:00:00.000Z');
    await expect(repo.createRequest(request('r1'))).rejects.toThrow();
    await repo.createRequest(request('r2', { display: null, returnUrl: null, hopLifetimeSeconds: null, agentDid: 'did:web:a:agents:2' }));
    expect(await repo.findRequest('r2')).toMatchObject({ display: null, returnUrl: null, hopLifetimeSeconds: null });
    expect(await repo.findRequest('none')).toBeNull();
    const opened = await repo.transitionRequest('r1', 'pending', { pageTokenHash: 'h1' });
    expect(opened?.pageTokenHash).toBe('h1');
    expect(await repo.transitionRequest('r1', 'pending', {})).toMatchObject({ status: 'pending' });
    const decided = new Date('2026-12-01T00:05:00Z');
    const approved = await repo.transitionRequest('r1', 'pending', { status: 'approved', decidedAt: decided, pageTokenHash: null });
    expect(approved).toMatchObject({ status: 'approved', pageTokenHash: null });
    expect(approved?.decidedAt?.toISOString()).toBe(decided.toISOString());
    expect(await repo.transitionRequest('r1', 'pending', { status: 'denied' })).toBeNull();
    expect(await repo.transitionRequest('none', 'pending', { status: 'denied' })).toBeNull();
    expect((await repo.transitionRequest('r1', 'approved', { consentId: 'c1' }))?.consentId).toBe('c1');
    expect(await repo.hasRequestForAgent('did:web:a:agents:1')).toBe(true);
    expect(await repo.hasRequestForAgent('did:web:a:agents:9')).toBe(false);
  });

  it('keeps user keys per (service, user), newest live one first, and marks them shredded once', async () => {
    const repo = make();
    const first = await repo.createUserKey({ did: 'did:key:z1', kid: 'did:key:z1#z1', serviceDid: 'did:web:s', serviceUserRef: 'u' });
    expect(first).toMatchObject({ did: 'did:key:z1', shreddedAt: null });
    await expect(repo.createUserKey({ did: 'did:key:z1', kid: 'x', serviceDid: 'did:web:s', serviceUserRef: 'u' })).rejects.toThrow();
    await repo.createUserKey({ did: 'did:key:z2', kid: 'did:key:z2#z2', serviceDid: 'did:web:s', serviceUserRef: 'u' });
    await repo.createUserKey({ did: 'did:key:z3', kid: 'did:key:z3#z3', serviceDid: 'did:web:other', serviceUserRef: 'u' });
    expect((await repo.findLiveUserKey('did:web:s', 'u'))?.did).toBe('did:key:z2');
    expect(await repo.findLiveUserKey('did:web:s', 'nobody')).toBeNull();
    expect((await repo.listLiveUserKeys()).map((key) => key.did)).toEqual(['did:key:z1', 'did:key:z2', 'did:key:z3']);
    const at = new Date('2026-12-02T00:00:00Z');
    expect(await repo.markUserKeyShredded('did:key:z2', at)).toBe(true);
    expect(await repo.markUserKeyShredded('did:key:z2', at)).toBe(false);
    expect(await repo.markUserKeyShredded('did:key:none', at)).toBe(false);
    expect((await repo.findUserKey('did:key:z2'))?.shreddedAt?.toISOString()).toBe(at.toISOString());
    expect(await repo.findUserKey('did:key:none')).toBeNull();
    expect((await repo.findLiveUserKey('did:web:s', 'u'))?.did).toBe('did:key:z1');
    expect((await repo.listLiveUserKeys()).map((key) => key.did)).toEqual(['did:key:z1', 'did:key:z3']);
  });

  it('records consents, updates them and lists them by any filter, oldest first', async () => {
    const repo = make();
    const created = await repo.createConsent(consent('c1'));
    expect(created).toMatchObject({ id: 'c1', withdrawnAt: null, allowedAction: ['orders:read'], caveats: [{ type: 'Expiry' }], consentType: 'user-signed', hopLifetimeSeconds: null });
    await expect(repo.createConsent(consent('c1'))).rejects.toThrow();
    await repo.createConsent(consent('c2', { agentDid: 'did:web:a:agents:2', caveats: null, hopLifetimeSeconds: 60 }));
    await repo.createConsent(consent('c3', { userDid: 'did:key:z6Mkuser2', serviceDid: 'did:web:other' }));
    expect(await repo.findConsent('c2')).toMatchObject({ caveats: null, hopLifetimeSeconds: 60 });
    expect(await repo.findConsent('none')).toBeNull();
    const at = new Date('2026-12-01T02:00:00Z');
    const updated = await repo.updateConsent('c1', { withdrawnAt: at, latestHopId: 'urn:zcap:2', lastHopUntil: at });
    expect(updated).toMatchObject({ latestHopId: 'urn:zcap:2' });
    expect(updated.withdrawnAt?.toISOString()).toBe(at.toISOString());
    expect((await repo.updateConsent('c2', {})).id).toBe('c2');
    await expect(repo.updateConsent('none', { withdrawnAt: at })).rejects.toThrow();
    expect((await repo.listConsents({})).map((row) => row.id)).toEqual(['c1', 'c2', 'c3']);
    expect((await repo.listConsents({ userDid: 'did:key:z6Mkuser1' })).map((row) => row.id)).toEqual(['c1', 'c2']);
    expect((await repo.listConsents({ userDid: 'did:key:z6Mkuser1', agentDid: 'did:web:a:agents:2' })).map((row) => row.id)).toEqual(['c2']);
    expect((await repo.listConsents({ serviceDid: 'did:web:other', serviceUserRef: 'sha256:u1', agentDid: undefined })).map((row) => row.id)).toEqual(['c3']);
  });
});

describe('consent storage drivers', () => {
  it('picks the driver by kind and refuses a missing dependency or an unknown kind', () => {
    expect(createConsentStorageDriver('memory', {})).toBeInstanceOf(InMemoryConsentStorageDriver);
    expect(createConsentStorageDriver('postgres', { prisma: fakePrisma() })).toBeInstanceOf(PrismaConsentStorageDriver);
    expect(createConsentStorageDriver('sqlite', { sqlite: new SqliteStore(join(dir, 'kind.sqlite')) })).toBeInstanceOf(SqliteConsentStorageDriver);
    expect(() => createConsentStorageDriver('postgres', {})).toThrow(/deps.prisma/);
    expect(() => createConsentStorageDriver('sqlite', {})).toThrow(/deps.sqlite/);
    expect(() => createConsentStorageDriver('mongo' as never, {})).toThrow(UnsupportedStorageDriverError);
  });

  it('reads Prisma rows whose JSON members are missing as empty', async () => {
    const prisma = fakePrisma() as unknown as { userConsent: { create(args: unknown): Promise<unknown> }; consentRequest: { create(args: unknown): Promise<unknown> } };
    await prisma.userConsent.create({ data: { ...consent('c9'), allowedAction: 'not-an-array', caveats: 'x' } });
    await prisma.consentRequest.create({ data: { ...request('r9'), display: undefined } });
    const driver = new PrismaConsentStorageDriver(prisma as unknown as PrismaClient);
    expect(await driver.findConsent('c9')).toMatchObject({ allowedAction: [], caveats: null });
    expect((await driver.findRequest('r9'))?.display).toBeNull();
  });
});
