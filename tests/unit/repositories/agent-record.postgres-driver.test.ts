// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// The Postgres driver's SQL contract, against a recording stand-in for
// PrismaClient: which statements run, with which bound parameters, and that
// caller input (the search term above all) only ever travels as a parameter.

import { describe, expect, it } from 'vitest';
import { UnsupportedStorageDriverError } from '../../../src/storage/driver-registry.js';
import { AgentRecordRepository } from '../../../src/repositories/agent-record.repository.js';
import {
  PrismaAgentRecordStorageDriver,
  createAgentRecordStorageDriver,
} from '../../../src/repositories/drivers/agent-record.drivers.js';

const NOW = new Date('2026-10-01T12:00:00.000Z');

class RecordingPrisma {
  readonly calls: Array<{ kind: 'query' | 'execute'; sql: string; params: unknown[] }> = [];
  /** Results handed to successive $queryRawUnsafe calls. */
  readonly results: unknown[][] = [];

  async $queryRawUnsafe(sql: string, ...params: unknown[]): Promise<unknown[]> {
    this.calls.push({ kind: 'query', sql, params });
    return this.results.shift() ?? [];
  }

  async $executeRawUnsafe(sql: string, ...params: unknown[]): Promise<number> {
    this.calls.push({ kind: 'execute', sql, params });
    return 1;
  }
}

function pgRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    did: 'did:key:z1',
    name: 'Agent',
    visibility: 'private',
    visibilityChangedAt: null,
    publishedAt: null,
    credentialVcId: 'vc-1',
    credentialExpiresAt: NOW,
    revokedAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function setup(): { prisma: RecordingPrisma; driver: PrismaAgentRecordStorageDriver } {
  const prisma = new RecordingPrisma();
  return { prisma, driver: new PrismaAgentRecordStorageDriver(prisma as never) };
}

/** Collapses whitespace so assertions read like the SQL they check. */
function sqlOf(call: { sql: string } | undefined): string {
  return (call?.sql ?? '').replace(/\s+/g, ' ').trim();
}

describe('PrismaAgentRecordStorageDriver', () => {
  it('inserts with every value bound, skips an existing DID, and reads the stored row back', async () => {
    const { prisma, driver } = setup();
    prisma.results.push([pgRow({ visibility: 'public' })]);

    const row = await driver.create({
      did: 'did:key:z1',
      name: "O'Brien's agent",
      visibility: 'public',
      credentialVcId: 'vc-1',
      credentialExpiresAt: NOW,
      revokedAt: null,
      publishedAt: NOW,
      createdAt: NOW,
    });

    const [insert, select] = prisma.calls;
    expect(insert?.kind).toBe('execute');
    expect(sqlOf(insert)).toContain('INSERT INTO "agents"');
    expect(sqlOf(insert)).toContain('ON CONFLICT ("did") DO NOTHING');
    expect(insert?.sql).not.toContain("O'Brien");
    expect(insert?.params).toEqual(['did:key:z1', "O'Brien's agent", 'public', NOW, NOW, 'vc-1', NOW, null, NOW, NOW]);
    expect(sqlOf(select)).toBe('SELECT * FROM "agents" WHERE "did" = $1 LIMIT 1');
    expect(row.visibility).toBe('public');
  });

  it('fails loudly if the insert leaves no row', async () => {
    const { driver } = setup();

    await expect(
      driver.create({
        did: 'did:key:z1',
        name: null,
        visibility: 'private',
        credentialVcId: null,
        credentialExpiresAt: null,
        revokedAt: null,
        publishedAt: null,
        createdAt: NOW,
      }),
    ).rejects.toThrow('Agent insert left no row');
  });

  it('reads unknown visibility values as private', async () => {
    const { prisma, driver } = setup();
    prisma.results.push([pgRow({ visibility: 'PUBLIC' })], []);

    expect((await driver.findByDid('did:key:z1'))?.visibility).toBe('private');
    expect(await driver.findByDid('did:key:none')).toBeNull();
  });

  it('clears publishedAt when going private and reports an unknown DID as null', async () => {
    const { prisma, driver } = setup();
    prisma.results.push([pgRow({ visibility: 'public', publishedAt: NOW })], []);

    const made = await driver.setVisibility('did:key:z1', 'public', NOW);
    const unknown = await driver.setVisibility('did:key:none', 'private', NOW);

    expect(made?.visibility).toBe('public');
    expect(unknown).toBeNull();
    expect(sqlOf(prisma.calls[0])).toContain('WHERE "did" = $4 RETURNING *');
    expect(prisma.calls[0]?.params).toEqual(['public', NOW, NOW, 'did:key:z1']);
    expect(prisma.calls[1]?.params).toEqual(['private', NOW, null, 'did:key:none']);
  });

  it('updates credential state and marks revocation only on rows not yet revoked', async () => {
    const { prisma, driver } = setup();

    await driver.updateCredentialState('did:key:z1', { credentialVcId: 'vc-2', credentialExpiresAt: NOW, revokedAt: null });
    await driver.markRevokedByCredential('vc-2', NOW);

    expect(sqlOf(prisma.calls[0])).toContain('WHERE "did" = $5');
    expect(prisma.calls[0]?.params.slice(0, 3)).toEqual(['vc-2', NOW, null]);
    expect(prisma.calls[0]?.params[4]).toBe('did:key:z1');
    expect(sqlOf(prisma.calls[1])).toBe(
      'UPDATE "agents" SET "revokedAt" = $1, "updatedAt" = $1 WHERE "credentialVcId" = $2 AND "revokedAt" IS NULL',
    );
    expect(prisma.calls[1]?.params).toEqual([NOW, 'vc-2']);
  });

  describe('listPublic', () => {
    it('always selects public, published rows, and works out status in SQL against the bound instant', async () => {
      const { prisma, driver } = setup();
      prisma.results.push([
        { did: 'did:key:a', name: 'A', publishedAt: NOW, status: 'active' },
        { did: 'did:key:b', name: 'B', publishedAt: NOW, status: 'something-else' },
      ]);

      const rows = await driver.listPublic({ status: 'all', limit: 25, now: NOW });

      const sql = sqlOf(prisma.calls[0]);
      expect(sql).toContain(`WHERE "visibility" = 'public' AND "publishedAt" IS NOT NULL ORDER BY`);
      expect(sql).toContain(
        `CASE WHEN ("revokedAt" IS NULL AND "credentialExpiresAt" IS NOT NULL AND "credentialExpiresAt" > $1) THEN 'active' ELSE 'revoked' END AS "status"`,
      );
      expect(sql).toContain('ORDER BY "publishedAt" DESC, "did" ASC LIMIT $2');
      expect(prisma.calls[0]?.params).toEqual([NOW, 25]);
      expect(rows.map((row) => row.status)).toEqual(['active', 'revoked']);
    });

    it.each([
      ['active', `AND ("revokedAt" IS NULL AND "credentialExpiresAt" IS NOT NULL AND "credentialExpiresAt" > $1)`],
      ['revoked', `AND NOT ("revokedAt" IS NULL AND "credentialExpiresAt" IS NOT NULL AND "credentialExpiresAt" > $1)`],
    ] as const)('filters %s agents in the WHERE clause', async (status, predicate) => {
      const { prisma, driver } = setup();

      await driver.listPublic({ status, limit: 10, now: NOW });

      expect(sqlOf(prisma.calls[0])).toContain(predicate);
    });

    it('binds the search term, escaped for LIKE, and never splices it into the SQL', async () => {
      const { prisma, driver } = setup();
      const q = "50%_off' OR '1'='1";

      await driver.listPublic({ q, status: 'all', limit: 10, now: NOW });

      const call = prisma.calls[0];
      expect(call?.sql).not.toContain("OR '1'");
      expect(call?.sql).not.toContain('50%');
      expect(sqlOf(call)).toContain(`AND ("name" ILIKE $2 ESCAPE '\\' OR "did" = $3)`);
      expect(call?.params).toEqual([NOW, "%50\\%\\_off' OR '1'='1%", q, 10]);
    });

    it('continues after a keyset position, with ties broken by DID', async () => {
      const { prisma, driver } = setup();
      const after = { publishedAt: NOW, did: 'did:key:m' };

      await driver.listPublic({ q: 'x', status: 'all', limit: 5, after, now: NOW });

      expect(sqlOf(prisma.calls[0])).toContain('AND ("publishedAt" < $4 OR ("publishedAt" = $4 AND "did" > $5))');
      expect(prisma.calls[0]?.params).toEqual([NOW, '%x%', 'x', NOW, 'did:key:m', 5]);
      expect(sqlOf(prisma.calls[0])).toContain('LIMIT $6');
    });
  });
});

describe('AgentRecordRepository with a PrismaClient', () => {
  it('uses the Postgres driver', async () => {
    const prisma = new RecordingPrisma();

    await new AgentRecordRepository(prisma as never).findByDid('did:key:z1');

    expect(sqlOf(prisma.calls[0])).toBe('SELECT * FROM "agents" WHERE "did" = $1 LIMIT 1');
  });
});

describe('createAgentRecordStorageDriver', () => {
  it('refuses a backend without its client, and an unknown backend', () => {
    expect(() => createAgentRecordStorageDriver('postgres', {})).toThrow('requires deps.prisma');
    expect(() => createAgentRecordStorageDriver('sqlite', {})).toThrow('requires deps.sqlite');
    expect(() => createAgentRecordStorageDriver('mongo' as never, {})).toThrow(UnsupportedStorageDriverError);
  });
});
