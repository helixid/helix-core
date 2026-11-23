// Copyright 2026 DgVerse LLP
// The services registry on every storage backend (enrolled and custody-created services; story L3-H's
// consent requests look services up by DID). The Prisma driver runs against a small stand-in.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { ServiceRepository, type ServiceCreateData } from '../../../src/repositories/service.repository.js';
import { createServiceStorageDriver, InMemoryServiceStorageDriver, PrismaServiceStorageDriver, SqliteServiceStorageDriver } from '../../../src/repositories/drivers/service.drivers.js';
import { SqliteStore } from '../../../src/storage/sqlite.js';
import { UnsupportedStorageDriverError } from '../../../src/storage/driver-registry.js';

const dir = mkdtempSync(join(tmpdir(), 'helix-services-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

type Row = Record<string, unknown>;
function fakePrisma(): PrismaClient {
  const rows: Row[] = [];
  let tick = 0;
  const matches = (row: Row, where: Row): boolean => Object.entries(where).every(([k, v]) => (v === null ? row[k] == null : row[k] === v));
  const service = {
    async create({ data }: { data: Row }) {
      tick += 1;
      const row = { revokedAt: null, ...data, createdAt: new Date(Date.now() + tick) };
      rows.push(row);
      return { ...row };
    },
    async findUnique({ where }: { where: Row }) {
      return rows.find((row) => matches(row, where)) ?? null;
    },
    async findFirst({ where }: { where: Row }) {
      return rows.find((row) => matches(row, where)) ?? null;
    },
    async findMany() {
      return [...rows].sort((a, b) => (b['createdAt'] as Date).getTime() - (a['createdAt'] as Date).getTime());
    },
    async updateMany({ where, data }: { where: Row; data: Row }) {
      let count = 0;
      for (const row of rows) if (matches(row, where)) { Object.assign(row, data); count += 1; }
      return { count };
    },
  };
  return { service } as unknown as PrismaClient;
}

const backends: [string, () => ServiceRepository][] = [
  ['memory', () => new ServiceRepository()],
  ['sqlite', () => new ServiceRepository(undefined, new SqliteStore(join(dir, `${Math.random().toString(16).slice(2)}.sqlite`)))],
  ['postgres (Prisma driver)', () => new ServiceRepository(fakePrisma())],
];

const data = (id: string, overrides: Partial<ServiceCreateData> = {}): ServiceCreateData => ({
  id,
  did: `did:web:h:services:${id}`,
  name: `service-${id}`,
  domain: 'shop.example',
  requiredScopes: ['a', 'b'],
  description: null,
  framework: null,
  ...overrides,
});

describe.each(backends)('service repository (%s)', (_name, make) => {
  it('creates, finds by id, DID and name, lists newest first and revokes', async () => {
    const repo = make();
    const first = await repo.create(data('s1'));
    expect(first).toMatchObject({ id: 's1', did: 'did:web:h:services:s1', requiredScopes: ['a', 'b'], revokedAt: null });
    await repo.create(data('s2', { description: 'second', framework: 'express' }));
    expect((await repo.findById('s2'))?.description).toBe('second');
    expect((await repo.findByDid('did:web:h:services:s1'))?.id).toBe('s1');
    expect((await repo.findByName('service-s2'))?.id).toBe('s2');
    expect(await repo.findById('none')).toBeNull();
    expect(await repo.findByDid('did:web:none')).toBeNull();
    expect((await repo.list()).map((service) => service.id).sort()).toEqual(['s1', 's2']);
    await repo.revoke('s1');
    expect((await repo.findById('s1'))?.revokedAt).toBeInstanceOf(Date);
  });
});

describe('service storage drivers', () => {
  it('picks the driver by kind and refuses a missing dependency or an unknown kind', () => {
    expect(createServiceStorageDriver('memory', {})).toBeInstanceOf(InMemoryServiceStorageDriver);
    expect(createServiceStorageDriver('postgres', { prisma: fakePrisma() })).toBeInstanceOf(PrismaServiceStorageDriver);
    expect(createServiceStorageDriver('sqlite', { sqlite: new SqliteStore(join(dir, 'kind.sqlite')) })).toBeInstanceOf(SqliteServiceStorageDriver);
    expect(() => createServiceStorageDriver('postgres', {})).toThrow(/deps.prisma/);
    expect(() => createServiceStorageDriver('sqlite', {})).toThrow(/deps.sqlite/);
    expect(() => createServiceStorageDriver('mongo' as never, {})).toThrow(UnsupportedStorageDriverError);
  });
});
