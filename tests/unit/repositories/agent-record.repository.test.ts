// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// The `agents` table, on the in-memory driver and on a real SqliteStore in a
// temp directory (the SQL only proves itself against real SQLite). The
// Postgres driver runs the same queries with bound parameters; see
// agent-record.postgres-driver.test.ts.

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore } from '../../../src/storage/sqlite.js';
import {
  AgentRecordRepository,
  type AgentCreateData,
} from '../../../src/repositories/agent-record.repository.js';
import { escapeLikePattern } from '../../../src/repositories/drivers/agent-record.drivers.js';

const NOW = new Date('2026-10-01T12:00:00.000Z');
const LATER = new Date('2027-10-01T00:00:00.000Z');
const EARLIER = new Date('2026-09-01T00:00:00.000Z');

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function sqliteStore(): SqliteStore {
  const dir = mkdtempSync(join(tmpdir(), 'helix-agents-'));
  dirs.push(dir);
  return new SqliteStore(join(dir, 'helixid.sqlite'));
}

function agent(overrides: Partial<AgentCreateData> & { did: string }): AgentCreateData {
  return {
    name: 'Agent',
    visibility: 'private',
    credentialVcId: `vc:${overrides.did}`,
    credentialExpiresAt: LATER,
    revokedAt: null,
    publishedAt: null,
    createdAt: EARLIER,
    ...overrides,
  };
}

/** A public agent published at minute `minute` past NOW's hour. */
function published(did: string, minute: number, overrides: Partial<AgentCreateData> = {}): AgentCreateData {
  return agent({
    did,
    visibility: 'public',
    publishedAt: new Date(NOW.getTime() - (60 - minute) * 60_000),
    ...overrides,
  });
}

describe.each([
  ['memory', () => new AgentRecordRepository()],
  ['sqlite', () => new AgentRecordRepository(undefined, sqliteStore())],
])('AgentRecordRepository (%s)', (_kind, makeRepository) => {
  it('creates a row and returns it, and leaves an existing row for the DID untouched', async () => {
    const repository = makeRepository();

    const created = await repository.create(agent({ did: 'did:key:z1', name: 'First' }));
    const again = await repository.create(agent({ did: 'did:key:z1', name: 'Second', visibility: 'public' }));

    expect(created).toMatchObject({
      did: 'did:key:z1',
      name: 'First',
      visibility: 'private',
      visibilityChangedAt: null,
      publishedAt: null,
      credentialVcId: 'vc:did:key:z1',
      revokedAt: null,
    });
    expect(created.credentialExpiresAt?.toISOString()).toBe(LATER.toISOString());
    expect(created.createdAt.toISOString()).toBe(EARLIER.toISOString());
    expect(again.name).toBe('First');
    expect(again.visibility).toBe('private');
  });

  it('stamps an agent created as public with its publication time', async () => {
    const repository = makeRepository();

    const created = await repository.create(published('did:key:zpub', 30));

    expect(created.visibility).toBe('public');
    expect(created.publishedAt).not.toBeNull();
    expect(created.visibilityChangedAt?.toISOString()).toBe(created.publishedAt?.toISOString());
  });

  it('finds by DID', async () => {
    const repository = makeRepository();
    await repository.create(agent({ did: 'did:key:z1' }));

    expect(await repository.findByDid('did:key:missing')).toBeNull();
    expect((await repository.findByDid('did:key:z1'))?.name).toBe('Agent');
  });

  it('publishes and unpublishes, and reports an unknown DID as null', async () => {
    const repository = makeRepository();
    await repository.create(agent({ did: 'did:key:z1' }));

    expect(await repository.setVisibility('did:key:missing', 'public', NOW)).toBeNull();

    const made = await repository.setVisibility('did:key:z1', 'public', NOW);
    expect(made).toMatchObject({ visibility: 'public' });
    expect(made?.publishedAt?.toISOString()).toBe(NOW.toISOString());
    expect(made?.visibilityChangedAt?.toISOString()).toBe(NOW.toISOString());

    const back = await repository.setVisibility('did:key:z1', 'private', LATER);
    expect(back).toMatchObject({ visibility: 'private', publishedAt: null });
    expect(back?.visibilityChangedAt?.toISOString()).toBe(LATER.toISOString());
  });

  it('updates the credential state and marks revocation by credential, keeping the first time', async () => {
    const repository = makeRepository();
    await repository.create(agent({ did: 'did:key:z1', credentialVcId: 'vc-1' }));
    await repository.create(agent({ did: 'did:key:z2', credentialVcId: 'vc-2' }));

    await repository.updateCredentialState('did:key:z1', {
      credentialVcId: 'vc-1b',
      credentialExpiresAt: NOW,
      revokedAt: null,
    });
    await repository.markRevokedByCredential('vc-2', EARLIER);
    await repository.markRevokedByCredential('vc-2', NOW);
    await repository.markRevokedByCredential('vc-unknown', NOW);

    const first = await repository.findByDid('did:key:z1');
    expect(first?.credentialVcId).toBe('vc-1b');
    expect(first?.credentialExpiresAt?.toISOString()).toBe(NOW.toISOString());
    expect(first?.revokedAt).toBeNull();
    expect((await repository.findByDid('did:key:z2'))?.revokedAt?.toISOString()).toBe(EARLIER.toISOString());
  });

  describe('listPublic', () => {
    async function seeded(): Promise<AgentRecordRepository> {
      const repository = makeRepository();
      await repository.create(published('did:key:a-active', 50, { name: 'Travel Concierge' }));
      await repository.create(published('did:key:b-revoked', 40, { name: 'Booking Bot', revokedAt: EARLIER }));
      await repository.create(published('did:key:c-expired', 30, { name: 'Old travel agent', credentialExpiresAt: EARLIER }));
      // No credential linked at all.
      await repository.create(
        published('did:key:d-nocred', 20, { name: '100% sure_agent', credentialVcId: null, credentialExpiresAt: null }),
      );
      // A credential that never expires (no expiry at enrolment, the default): active.
      await repository.create(published('did:key:f-forever', 10, { name: 'Standing order bot', credentialExpiresAt: null }));
      await repository.create(agent({ did: 'did:key:e-private', name: 'Travel secret' }));
      return repository;
    }

    it('reads public rows only, newest publication first, with each status worked out', async () => {
      const repository = await seeded();

      const rows = await repository.listPublic({ status: 'all', limit: 10, now: NOW });

      expect(rows.map((row) => [row.did, row.status])).toEqual([
        ['did:key:a-active', 'active'],
        ['did:key:b-revoked', 'revoked'],
        ['did:key:c-expired', 'revoked'],
        ['did:key:d-nocred', 'revoked'],
        ['did:key:f-forever', 'active'],
      ]);
      expect(rows[0]).toEqual({
        did: 'did:key:a-active',
        name: 'Travel Concierge',
        publishedAt: expect.any(Date),
        status: 'active',
      });
    });

    it('filters on status in the query', async () => {
      const repository = await seeded();

      const active = await repository.listPublic({ status: 'active', limit: 10, now: NOW });
      const revoked = await repository.listPublic({ status: 'revoked', limit: 10, now: NOW });

      expect(active.map((row) => row.did)).toEqual(['did:key:a-active', 'did:key:f-forever']);
      expect(revoked.map((row) => row.did)).toEqual(['did:key:b-revoked', 'did:key:c-expired', 'did:key:d-nocred']);
    });

    it('treats expiry as of the given instant; a credential with no expiry never lapses', async () => {
      const repository = await seeded();

      const rows = await repository.listPublic({ status: 'active', limit: 10, now: new Date('2028-01-01T00:00:00Z') });

      expect(rows.map((row) => row.did)).toEqual(['did:key:f-forever']);
    });

    it('searches names case-insensitively, or one exact DID, and never a private agent', async () => {
      const repository = await seeded();

      const byName = await repository.listPublic({ q: 'TRAVEL', status: 'all', limit: 10, now: NOW });
      const byDid = await repository.listPublic({ q: 'did:key:b-revoked', status: 'all', limit: 10, now: NOW });
      const partialDid = await repository.listPublic({ q: 'did:key:b', status: 'all', limit: 10, now: NOW });

      expect(byName.map((row) => row.did)).toEqual(['did:key:a-active', 'did:key:c-expired']);
      expect(byDid.map((row) => row.did)).toEqual(['did:key:b-revoked']);
      expect(partialDid).toEqual([]);
    });

    it('matches LIKE wildcards in the search term literally', async () => {
      const repository = await seeded();

      const percent = await repository.listPublic({ q: '%', status: 'all', limit: 10, now: NOW });
      const underscore = await repository.listPublic({ q: '_', status: 'all', limit: 10, now: NOW });
      const quote = await repository.listPublic({ q: "it's", status: 'all', limit: 10, now: NOW });

      expect(percent.map((row) => row.did)).toEqual(['did:key:d-nocred']);
      expect(underscore.map((row) => row.did)).toEqual(['did:key:d-nocred']);
      expect(quote).toEqual([]);
    });

    it('pages with a keyset that breaks publication-time ties by DID', async () => {
      const repository = makeRepository();
      const at = new Date('2026-09-30T10:00:00.000Z');
      await repository.create(published('did:key:z-tie', 0, { publishedAt: at }));
      await repository.create(published('did:key:a-tie', 0, { publishedAt: at }));
      await repository.create(published('did:key:newest', 0, { publishedAt: NOW }));

      const first = await repository.listPublic({ status: 'all', limit: 2, now: NOW });
      const last = first[first.length - 1]!;
      const second = await repository.listPublic({
        status: 'all',
        limit: 2,
        after: { publishedAt: last.publishedAt, did: last.did },
        now: NOW,
      });

      expect(first.map((row) => row.did)).toEqual(['did:key:newest', 'did:key:a-tie']);
      expect(second.map((row) => row.did)).toEqual(['did:key:z-tie']);
    });
  });
});

describe('escapeLikePattern', () => {
  it('escapes the LIKE wildcards and the escape character itself', () => {
    expect(escapeLikePattern('50%_off\\now')).toBe('50\\%\\_off\\\\now');
    expect(escapeLikePattern('plain')).toBe('plain');
  });
});

describe('unknown visibility values', () => {
  it('read as private', async () => {
    const store = sqliteStore();
    const repository = new AgentRecordRepository(undefined, store);
    await repository.create(published('did:key:odd', 10));
    store.execute(`UPDATE agents SET visibility = 'PUBLIC' WHERE did = 'did:key:odd'`);

    expect((await repository.findByDid('did:key:odd'))?.visibility).toBe('private');
  });
});
