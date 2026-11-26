// Copyright 2026 DgVerse LLP
// Registry v3 (2026-11-24): the Helix agent registry's pieces -- helpers, signed registrations,
// the registry service, helixid's source, the Helix registry inbox and the deployment publisher.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { buildDIDDocument, EnvSigner, generateKeyPair, signJws } from '../../../../src/core/index.js';
import {
  HELIX_REGISTRY_ORIGIN,
  NotListedError,
  TEST_ONLY_HELIX_REGISTRY_ORIGIN_ENV,
  agentMatches,
  byName,
  helixRegistryOrigin,
  matchesWords,
  originOf,
  pageOf,
  parseRegistrySearch,
  readDiscoverable,
  type AgentRegistryEntry,
} from '../../../../src/services/registry/registry.js';
import { REGISTRATION_TYP, signRegistration, verifyRegistration } from '../../../../src/services/registry/registration.js';
import { RegistryService, type RegistrySource } from '../../../../src/services/registry/registry.service.js';
import { deploymentRegistrySource } from '../../../../src/services/registry/deployment-registry.source.js';
import { HelixRegistryInbox, MemoryPublishedStore } from '../../../../src/services/registry/helix-registry.inbox.js';
import { HelixRegistryPublisher, describeRegistration } from '../../../../src/services/registry/helix-registry.publisher.js';
import { RegistryEntryRepository } from '../../../../src/repositories/registry-entry.repository.js';
import { SqliteStore } from '../../../../src/storage/sqlite.js';

const HELIX = 'http://127.0.0.1:3880';
const C = 'http://127.0.0.1:3980';
const NOW = new Date('2026-11-24T12:00:00Z');

function agent(did: string, name: string | null, overrides: Partial<AgentRegistryEntry> = {}): AgentRegistryEntry {
  return { agentDid: did, name, status: 'active', owner: { did: 'did:web:o', name: 'Owner' }, publishedAt: NOW.toISOString(), deployment: HELIX, ...overrides };
}

/** A did:web with its key and document, as a resolver would return it. */
function identity(did: string): { signer: EnvSigner; resolve: (d: string) => Promise<ReturnType<typeof buildDIDDocument> | null> } {
  const keys = generateKeyPair();
  const document = buildDIDDocument(did, keys.publicKey);
  return { signer: new EnvSigner({ did, env: { HELIX_SIGNING_KEY: keys.privateKey } }), resolve: async (d) => (d === did ? document : null) };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

describe('registry helpers', () => {
  it('fixes the Helix registry origin, overridable only by the test-only variable', () => {
    expect(helixRegistryOrigin({})).toBe(HELIX_REGISTRY_ORIGIN);
    expect(helixRegistryOrigin({ [TEST_ONLY_HELIX_REGISTRY_ORIGIN_ENV]: 'http://127.0.0.1:3880/x' })).toBe(HELIX);
    expect(typeof helixRegistryOrigin()).toBe('string');
    expect(originOf('https://a.example/b?c')).toBe('https://a.example');
    expect(() => originOf('not a url')).toThrow(/Not an absolute URL/);
    expect(() => originOf('ftp://a.example')).toThrow(/Not an http/);
  });

  it('parses ?q=&limit=&cursor= and pages with an opaque cursor', () => {
    expect(parseRegistrySearch(undefined)).toEqual({ q: undefined, limit: 24, offset: 0 });
    expect(parseRegistrySearch({ q: '  ', limit: '2' })).toEqual({ q: undefined, limit: 2, offset: 0 });
    expect(parseRegistrySearch({ q: ' air ', limit: 3 }).q).toBe('air');
    const page = pageOf([1, 2, 3, 4, 5], parseRegistrySearch({ limit: 2 }));
    expect(page.items).toEqual([1, 2]);
    expect(pageOf([1, 2, 3, 4, 5], parseRegistrySearch({ limit: 2, cursor: page.nextCursor })).items).toEqual([3, 4]);
    expect(pageOf([1, 2], parseRegistrySearch({ limit: 2 })).nextCursor).toBeNull();
    for (const bad of [{ q: ['a'] }, { q: 'x'.repeat(65) }, { limit: '0' }, { limit: 51 }, { limit: true }, { cursor: 'zz' }, { cursor: 5 }, { cursor: 'x'.repeat(65) }]) {
      expect(() => parseRegistrySearch(bad)).toThrow();
    }
  });

  it('matches any word in the name or owner, or the exact DID, and sorts by name', () => {
    expect(matchesWords(undefined, [])).toBe(true);
    expect(matchesWords('travel paris', ['Travel Desk', 'Client B'])).toBe(true);
    expect(matchesWords('train', ['Helix Air', null])).toBe(false);
    expect(agentMatches(agent('did:web:b', 'Agent B'), 'owner')).toBe(true);
    expect(agentMatches(agent('did:web:b', 'Agent B'), 'did:web:b')).toBe(true);
    expect(agentMatches(agent('did:web:b', null, { owner: { did: null, name: null } }), 'x')).toBe(false);
    expect([agent('did:web:2', 'B'), agent('did:web:1', 'B'), agent('did:web:0', 'A'), agent('did:web:3', null)].sort(byName).map((a) => a.agentDid)).toEqual([
      'did:web:3',
      'did:web:0',
      'did:web:1',
      'did:web:2',
    ]);
  });

  it('reads the "Make discoverable" choice: a boolean, on by default', () => {
    expect(readDiscoverable(undefined)).toBe(true);
    expect(readDiscoverable(null)).toBe(true);
    expect(readDiscoverable(false)).toBe(false);
    expect(readDiscoverable(true)).toBe(true);
    expect(() => readDiscoverable('public')).toThrow(/discoverable must be true or false/);
  });
});

describe('signed registrations', () => {
  const did = 'did:web:127.0.0.1%3A3980:agents:c2';
  const { signer, resolve } = identity(did);
  const verify = (jws: string, now = NOW) => verifyRegistration(jws, { resolveDid: resolve, audience: HELIX, now });

  it('round-trips: signed by the agent, checked against its DID document', async () => {
    const jws = await signRegistration(signer, { deployment: `${C}/x`, audience: HELIX, now: NOW });
    const claims = await verify(jws);
    expect(claims).toMatchObject({ iss: did, sub: did, aud: HELIX, deployment: C, kid: `${did}#key-1` });
    expect(claims).not.toHaveProperty('kind');
    expect(claims.exp - claims.iat).toBe(300);
    expect(describeRegistration(jws)).toContain(REGISTRATION_TYP);
    expect(describeRegistration('a.b')).toContain('?');
    await expect(verifyRegistration(await signRegistration(signer, { deployment: C, audience: HELIX }), { resolveDid: resolve, audience: HELIX })).resolves.toBeTruthy();
  });

  it('refuses a bad signature, another typ, foreign claims and stale or overlong validity', async () => {
    const other = identity(did);
    await expect(verifyRegistration(await signRegistration(other.signer, { deployment: C, audience: HELIX, now: NOW }), { resolveDid: resolve, audience: HELIX, now: NOW })).rejects.toThrow(/Registration refused/);
    const iat = Math.floor(NOW.getTime() / 1000);
    const base = { iss: did, sub: did, aud: HELIX, deployment: C, iat, exp: iat + 300, jti: 'j' };
    const signed = (claims: Record<string, unknown>, typ = REGISTRATION_TYP) => signJws(claims as never, signer, { header: { typ } });
    const cases: Array<[Promise<string>, RegExp, Date?]> = [
      [signed(base, 'JWT'), /typ must be/],
      [signed({ ...base, sub: 'did:web:other' }), /iss and sub/],
      [signed({ ...base, aud: C }), /aud is not this registry/],
      [signed({ ...base, deployment: 5 }), /deployment is missing/],
      [signed({ ...base, iat: 'x' }), /expired/],
      [signed(base), /expired/, new Date(NOW.getTime() + 3600_000)],
      [signed({ ...base, iat: iat + 3600 }), /expired/],
      [signed({ ...base, exp: iat + 7200 }), /more than an hour/],
      [signed({ ...base, jti: undefined }), /jti is missing/],
    ];
    for (const [jws, message, at] of cases) await expect(verify(await jws, at)).rejects.toThrow(message);
  });
});

describe('RegistryService', () => {
  const own: RegistrySource = { agents: async () => [agent('did:web:b', 'Agent B')] };
  const published = new MemoryPublishedStore();
  const inbox = { entries: async () => (await published.list()).map((row) => row.entry) };

  it('lists own agents first, then published ones it does not list itself', async () => {
    await published.put({ did: 'did:web:c2', deployment: C, entry: agent('did:web:c2', 'Agent C2', { deployment: C }), registeredAt: NOW });
    await published.put({ did: 'did:web:b', deployment: C, entry: agent('did:web:b', 'Shadow B', { deployment: C }), registeredAt: NOW });
    const registry = new RegistryService(own, inbox);
    expect((await registry.searchAgents(parseRegistrySearch({}))).agents.map((a) => a.name)).toEqual(['Agent B', 'Agent C2']);
    expect((await registry.searchAgents(parseRegistrySearch({ q: 'c2' }))).agents.map((a) => a.name)).toEqual(['Agent C2']);
    expect((await registry.getAgent('did:web:c2')).deployment).toBe(C);
    await expect(registry.getAgent('did:web:none')).rejects.toBeInstanceOf(NotListedError);
    // Its own agents only: what another registry checks a registration against.
    expect((await registry.getOwnAgent('did:web:b')).name).toBe('Agent B');
    await expect(registry.getOwnAgent('did:web:c2')).rejects.toThrow('Agent is not listed');
    expect((await new RegistryService(own).searchAgents(parseRegistrySearch({}))).agents).toHaveLength(1);
  });
});

describe('deploymentRegistrySource (helixid)', () => {
  const entries = new RegistryEntryRepository();
  const source = deploymentRegistrySource({
    deployment: 'http://127.0.0.1:3200',
    owner: { did: 'did:web:h', name: null },
    entries,
    custody: {
      custodyOf: async (dids) =>
        dids.filter((did) => !did.endsWith('unknown')).map((did) => ({ did, name: did.endsWith('pending') ? 'Pending' : `Agent ${did.slice(-1)}`, status: did.endsWith('pending') ? 'pending_key' : 'active' })),
    },
    didRepository: { findDidById: async (did) => (did.endsWith('nodid') ? null : { deactivatedAt: did.endsWith('gone') ? NOW : null }) },
  });

  it('lists discoverable agents that are active and not deactivated', async () => {
    await entries.set('did:web:h:agents:a', false);
    await entries.set('did:web:h:agents:p', true);
    await entries.set('did:web:h:agents:pending', true);
    await entries.set('did:web:h:agents:gone', true);
    await entries.set('did:web:h:agents:unknown', true);
    await entries.set('did:web:h:agents:nodid', true);
    const listed = await source.agents();
    expect(listed.map((a) => a.agentDid).sort()).toEqual(['did:web:h:agents:nodid', 'did:web:h:agents:p']);
    expect(listed.find((a) => a.agentDid === 'did:web:h:agents:p')).toEqual({
      agentDid: 'did:web:h:agents:p',
      name: 'Agent p',
      status: 'active',
      owner: { did: 'did:web:h', name: null },
      publishedAt: expect.any(String),
      deployment: 'http://127.0.0.1:3200',
    });
    const withoutDids = deploymentRegistrySource({ deployment: 'http://h', owner: { did: null, name: null }, entries, custody: { custodyOf: async () => [{ did: 'did:web:h:agents:p', name: null, status: 'active' }] } });
    expect((await withoutDids.agents()).map((a) => a.agentDid)).toEqual(['did:web:h:agents:p']);
  });
});

describe('HelixRegistryInbox (the Helix registry)', () => {
  const did = 'did:web:127.0.0.1%3A3980:agents:c2';
  const { signer, resolve } = identity(did);
  const make = (fetch: ReturnType<typeof vi.fn>) => {
    const log = vi.fn();
    const store = new MemoryPublishedStore();
    return { store, log, inbox: new HelixRegistryInbox({ store, resolveDid: resolve, origin: HELIX, fetch: fetch as never, log, now: () => NOW }) };
  };
  const registration = (deployment = C) => signRegistration(signer, { deployment, audience: HELIX, now: NOW });

  it("lists what the agent's own deployment lists as discoverable, its allowlisted fields only, and logs the check", async () => {
    const fetch = vi.fn(async () => json(200, { agent: { ...agent(did, 'Agent C2', { deployment: C }), secret: 'x' } }));
    const { inbox, log, store } = make(fetch);
    const row = await inbox.publish(await registration());
    expect(fetch).toHaveBeenCalledWith(`${C}/agent/registry/${encodeURIComponent(did)}`, expect.anything());
    expect(row.entry).not.toHaveProperty('secret');
    expect(row.entry.deployment).toBe(C);
    expect((await inbox.entries()).map((a) => a.name)).toEqual(['Agent C2']);
    expect(log.mock.calls[0]![0]).toContain('checked against its DID document');
    expect(await store.get('did:web:none')).toBeNull();
  });

  it('refuses what it cannot check', async () => {
    const missing = make(vi.fn(async () => json(404, {})));
    await expect(missing.inbox.publish(await registration())).rejects.toMatchObject({ code: 'REGISTRATION_NOT_LISTED', httpStatus: 403 });
    const broken = make(vi.fn(async () => json(500, {})));
    await expect(broken.inbox.publish(await registration())).rejects.toMatchObject({ code: 'REGISTRY_UPSTREAM_FAILED', httpStatus: 502 });
    const down = make(vi.fn(async () => { throw new Error('ECONNREFUSED'); }));
    await expect(down.inbox.publish(await registration())).rejects.toThrow(/ECONNREFUSED/);
    const thrownString = make(vi.fn(async () => { throw 'boom'; }));
    await expect(thrownString.inbox.publish(await registration())).rejects.toThrow(/boom/);
    const wrongDid = make(vi.fn(async () => json(200, { agent: agent('did:web:else', 'Else') })));
    await expect(wrongDid.inbox.publish(await registration())).rejects.toThrow(/did not answer with the agent/);
    const empty = make(vi.fn(async () => json(200, null)));
    await expect(empty.inbox.publish(await registration())).rejects.toThrow(/did not answer with the agent/);
    const anything = make(vi.fn());
    await expect(anything.inbox.publish(42)).rejects.toThrow(/compact JWS/);
    await expect(anything.inbox.publish(await registration(HELIX))).rejects.toThrow(/its own deployment/);
    const defaults = new HelixRegistryInbox({ store: new MemoryPublishedStore(), resolveDid: resolve, origin: HELIX });
    await expect(defaults.publish('a.b.c')).rejects.toThrow(/Registration refused/);
  });

  it('withdraws only once the deployment no longer lists it', async () => {
    let listed = true;
    const fetch = vi.fn(async () => (listed ? json(200, { agent: agent(did, 'C2') }) : json(404, {})));
    const { inbox, store } = make(fetch);
    await store.put({ did, deployment: C, entry: agent(did, 'C2'), registeredAt: NOW });
    expect(await inbox.withdraw('did:web:unknown')).toEqual({ removed: false });
    await expect(inbox.withdraw(did)).rejects.toMatchObject({ code: 'REGISTRY_STILL_LISTED', httpStatus: 409 });
    listed = false;
    expect(await inbox.withdraw(did)).toEqual({ removed: true });
    expect(await inbox.entries()).toEqual([]);
  });
});

describe('HelixRegistryPublisher (another deployment)', () => {
  const did = 'did:web:127.0.0.1%3A3980:agents:c2';
  const { signer } = identity(did);

  it('does nothing on the Helix registry itself', async () => {
    const fetch = vi.fn();
    const publisher = new HelixRegistryPublisher({ deployment: HELIX, helixOrigin: `${HELIX}/`, signerFor: async () => signer, fetch });
    expect(publisher.isHelixRegistry).toBe(true);
    expect(await publisher.publish(did)).toBe('is_helix_registry');
    expect(await publisher.withdraw(did)).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('signs with a key held here, and leaves a self-custody agent to its holder', async () => {
    const log = vi.fn();
    const fetch = vi.fn(async () => json(201, {}));
    const publisher = new HelixRegistryPublisher({ deployment: C, helixOrigin: HELIX, signerFor: async (d) => (d === did ? signer : undefined), fetch, log });
    expect(await publisher.publish(did)).toBe('published');
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${HELIX}/agent/registry`);
    const { registration } = JSON.parse(String(init.body)) as { registration: string };
    expect(log.mock.calls[0]![0]).toContain('"typ":"helix-registration+jwt"');
    expect(registration.split('.')).toHaveLength(3);
    expect(await publisher.publish('did:web:self')).toBe('holder_signs');
    const throwing = new HelixRegistryPublisher({ deployment: C, helixOrigin: HELIX, signerFor: async () => { throw new Error('AGENT_KEY_NOT_FOUND'); }, fetch, log });
    expect(await throwing.publish('did:web:self')).toBe('holder_signs');
    expect(new HelixRegistryPublisher({ deployment: C, helixOrigin: HELIX, signerFor: async () => undefined }).isHelixRegistry).toBe(false);
  });

  it('reports refusals and failures without throwing, and withdraws', async () => {
    const refused = new HelixRegistryPublisher({ deployment: C, helixOrigin: HELIX, signerFor: async () => signer, fetch: vi.fn(async () => json(403, { error: 'no' })), log: vi.fn() });
    expect(await refused.publish(did)).toBe('failed');
    expect(await refused.withdraw(did)).toBe(false);
    const down = new HelixRegistryPublisher({ deployment: C, helixOrigin: HELIX, signerFor: async () => signer, fetch: vi.fn(async () => { throw new Error('down'); }), log: vi.fn() });
    expect(await down.publish(did)).toBe('failed');
    expect(await down.withdraw(did)).toBe(false);
    const downString = new HelixRegistryPublisher({ deployment: C, helixOrigin: HELIX, signerFor: async () => signer, fetch: vi.fn(async () => { throw 'down'; }), log: vi.fn() });
    expect(await downString.publish(did)).toBe('failed');
    expect(await downString.withdraw(did)).toBe(false);
    const fetch = vi.fn(async () => json(200, { removed: true }));
    const ok = new HelixRegistryPublisher({ deployment: C, helixOrigin: HELIX, signerFor: async () => undefined, fetch, log: vi.fn() });
    expect(await ok.withdraw(did)).toBe(true);
    expect(fetch).toHaveBeenCalledWith(`${HELIX}/agent/registry/${encodeURIComponent(did)}`, expect.objectContaining({ method: 'DELETE' }));
  });
});

const dir = mkdtempSync(join(tmpdir(), 'helix-registry-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe.each([
  ['memory', () => new RegistryEntryRepository()],
  ['sqlite', () => new RegistryEntryRepository(undefined, new SqliteStore(join(dir, `${Math.random().toString(16).slice(2)}.sqlite`)))],
])('RegistryEntryRepository (%s)', (_name, make) => {
  it('sets, updates, reads and lists the discoverable choice', async () => {
    const repo = make();
    expect(await repo.get('did:web:none')).toBeNull();
    const first = await repo.set('did:web:a', true);
    await repo.set('did:web:b', false);
    expect(await repo.get('did:web:b')).toMatchObject({ did: 'did:web:b', discoverable: false });
    expect((await repo.listDiscoverable()).map((row) => row.did)).toEqual(['did:web:a']);
    await repo.set('did:web:a', false);
    await repo.set('did:web:b', true);
    const b = await repo.get('did:web:b');
    expect(b!.discoverable).toBe(true);
    expect((await repo.get('did:web:a'))!.createdAt.getTime()).toBe(first.createdAt.getTime());
    expect((await repo.listDiscoverable()).map((row) => row.did)).toEqual(['did:web:b']);
  });
});

describe('RegistryEntryRepository on Postgres (Prisma raw)', () => {
  it('sends the queries a Prisma client runs', async () => {
    const queries: string[] = [];
    const prisma = {
      $queryRawUnsafe: vi.fn(async (query: string) => {
        queries.push(query);
        return [{ did: 'did:web:a', discoverable: true, createdAt: NOW, updatedAt: NOW }];
      }),
      $executeRawUnsafe: vi.fn(async (query: string) => {
        queries.push(query);
        return 1;
      }),
    };
    const repo = new RegistryEntryRepository(prisma as never);
    expect((await repo.listDiscoverable())[0]).toMatchObject({ did: 'did:web:a', discoverable: true });
    await repo.set('did:web:a', false);
    expect(queries.some((q) => q.includes('ON CONFLICT ("did")'))).toBe(true);
    expect(queries.some((q) => q.includes('"discoverable" = true'))).toBe(true);
  });
});
