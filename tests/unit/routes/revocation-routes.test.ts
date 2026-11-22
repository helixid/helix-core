// Copyright 2026 DgVerse LLP
// KYA-OS story L3-C over HTTP: POST /v1/revocations, GET /v1/events/revocations (SSE) and its webhook registry,
// the signed status-list routes, and the RevocationSignalPublisher's delivery (buses, RFC 8935 push, replay).
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import {
  DEFAULT_STATUS_LIST_ID,
  EnvSigner,
  ErrorCode,
  buildDIDDocument,
  derivePublicKey,
  publicKeyToMultibase,
  signDataIntegrity,
  statusListIdFor,
  type DIDDocument,
} from '../../../src/core/index.js';
import type { DidResolver } from '../../../src/core/credentials/index.js';
import { errorHandler } from '../../../src/middleware/errorHandler.js';
import { VcRepository } from '../../../src/repositories/vc.repository.js';
import { StatusListPublisher, StatusListService } from '../../../src/services/status-lists/status-list.service.js';
import { RevocationService } from '../../../src/services/revocation/revocation.service.js';
import { InProcessSignalBus, RedisSignalBus, RevocationSignalPublisher, type RedisPubSubLike, type RevocationEvent } from '../../../src/services/revocation/signal-publisher.js';
import revocationRoutes from '../../../src/routes/revocations/index.js';
import eventRoutes from '../../../src/routes/events/index.js';
import statusListRoutes from '../../../src/routes/status-list/index.js';

const API = 'https://api.helix.test';
const ADMIN = 'admin-key';
const HELIX_KEY = '3'.repeat(64);
const OWNER_KEY = '4'.repeat(64);
const helixDid = `did:key:${publicKeyToMultibase(derivePublicKey(HELIX_KEY))}`;
const ownerDid = `did:key:${publicKeyToMultibase(derivePublicKey(OWNER_KEY))}`;
const helixSigner = new EnvSigner({ did: helixDid, envVar: 'K', env: { K: HELIX_KEY } });
const ownerSigner = new EnvSigner({ did: ownerDid, envVar: 'K', env: { K: OWNER_KEY } });
const documents: Record<string, DIDDocument> = {
  [helixDid]: buildDIDDocument(helixDid, derivePublicKey(HELIX_KEY)),
  [ownerDid]: buildDIDDocument(ownerDid, derivePublicKey(OWNER_KEY)),
};
const resolve = (async (did: string) => documents[did] ?? null) as unknown as DidResolver;

interface Stack {
  app: FastifyInstance;
  repo: VcRepository;
  statusLists: StatusListService;
  signals: RevocationSignalPublisher;
  revocations: RevocationService;
  identityId: string;
}

async function stack(options: { listen?: boolean; heartbeatMs?: number; signerFor?: boolean } = {}): Promise<Stack> {
  const repo = new VcRepository();
  const audit = { log: vi.fn() };
  const publisher = new StatusListPublisher({
    repo,
    helixIssuerDid: helixDid,
    apiBaseUrl: API,
    signerFor: async (did) => (did === helixDid ? helixSigner : undefined),
    resolveDid: resolve,
  });
  const signals = new RevocationSignalPublisher({ signer: helixSigner, audit: audit as never });
  const statusLists = new StatusListService({ publisher, repo, audit: audit as never, signals });
  const revocations = new RevocationService({ repo, statusLists, resolveDid: resolve, audience: `${API}/v1/revocations` });
  const entry = await statusLists.statusEntryFor(helixDid);
  const identityId = 'urn:uuid:identity-1';
  await repo.createVc({
    vcId: identityId,
    subjectDid: 'did:key:z6MkAgent',
    subjectType: 'agent',
    statusListIndex: Number(entry.statusListIndex),
    expiresAt: null,
    issuerDid: helixDid,
    vcType: 'AgentIdentityCredential',
    vcJson: { type: ['VerifiableCredential', 'AgentIdentityCredential'], issuer: helixDid, credentialSubject: { id: 'did:key:z6MkAgent', responsibleParty: ownerDid }, credentialStatus: entry },
  });
  const app = Fastify({ logger: false });
  app.setErrorHandler(errorHandler);
  await app.register(statusListRoutes, { prefix: '/v1/status-list', statusLists, adminApiKey: ADMIN });
  await app.register(revocationRoutes, {
    prefix: '/v1/revocations',
    revocations,
    adminApiKey: ADMIN,
    ...(options.signerFor === false ? {} : { signerFor: async (did: string) => (did === ownerDid ? ownerSigner : helixSigner) }),
  });
  await app.register(eventRoutes, { prefix: '/v1/events', signals, adminApiKey: ADMIN, ...(options.heartbeatMs === undefined ? {} : { heartbeatMs: options.heartbeatMs }) });
  if (options.listen) await app.listen({ port: 0, host: '127.0.0.1' });
  else await app.ready();
  return { app, repo, statusLists, signals, revocations, identityId };
}

const apps: FastifyInstance[] = [];
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe('POST /v1/revocations', () => {
  let s: Stack;
  beforeEach(async () => {
    s = await stack();
    apps.push(s.app);
  });

  it('accepts a request the revoker signed, with no API key', async () => {
    const request = await s.revocations.signRequest(s.identityId, ownerSigner);
    const res = await s.app.inject({ method: 'POST', url: '/v1/revocations', payload: { request } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ credentialId: s.identityId, revoker: ownerDid, revoked: [s.identityId] });
    const again = await s.app.inject({ method: 'POST', url: '/v1/revocations', payload: { request: await s.revocations.signRequest(s.identityId, ownerSigner) } });
    expect(again.statusCode).toBe(409);
  });

  it('signs for a custodial revoker with the admin API key, and refuses without it', async () => {
    expect((await s.app.inject({ method: 'POST', url: '/v1/revocations', payload: { credentialId: s.identityId, revoker: ownerDid } })).statusCode).toBe(403);
    const res = await s.app.inject({ method: 'POST', url: '/v1/revocations', headers: { 'x-admin-api-key': ADMIN }, payload: { credentialId: s.identityId, revoker: ownerDid } });
    expect(res.statusCode).toBe(200);
    expect(res.json().revoker).toBe(ownerDid);
  });

  it('refuses a body that is neither form, or both', async () => {
    const both = await s.app.inject({ method: 'POST', url: '/v1/revocations', payload: { request: 'a.b.c', credentialId: 'x', revoker: ownerDid } });
    expect(both.json().error.code).toBe(ErrorCode.REVOCATION_REQUEST_INVALID);
    expect((await s.app.inject({ method: 'POST', url: '/v1/revocations', payload: {} })).statusCode).toBe(400);
    expect((await s.app.inject({ method: 'POST', url: '/v1/revocations', payload: { request: 'x.y.z' } })).json().error.code).toBe(ErrorCode.REVOCATION_REQUEST_INVALID);
    const plain = await stack({ signerFor: false });
    apps.push(plain.app);
    const res = await plain.app.inject({ method: 'POST', url: '/v1/revocations', headers: { 'x-admin-api-key': ADMIN }, payload: { credentialId: plain.identityId, revoker: ownerDid } });
    expect(res.json().error.message).toMatch(/signs for no revoker/);
  });
});

describe('status-list routes', () => {
  let s: Stack;
  beforeEach(async () => {
    s = await stack();
    apps.push(s.app);
  });

  it('serves the signed list with no-cache and an ETag, and 304 for a match', async () => {
    const res = await s.app.inject({ method: 'GET', url: `/v1/status-list/${DEFAULT_STATUS_LIST_ID}` });
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toBe('no-cache');
    expect(res.headers['content-type']).toMatch(/application\/vc\+json/);
    const read = await kyaos.verifier.readBitstringStatusList(res.json(), { resolveDid: resolve as never });
    expect(read.issuer).toBe(helixDid);
    const cached = await s.app.inject({ method: 'GET', url: `/v1/status-list/${DEFAULT_STATUS_LIST_ID}`, headers: { 'if-none-match': res.headers['etag'] as string } });
    expect(cached.statusCode).toBe(304);
    expect((await s.app.inject({ method: 'GET', url: '/v1/status-list/unknown' })).statusCode).toBe(404);
  });

  it('lets a self-custody issuer read its list unsigned and hand it back signed', async () => {
    await s.statusLists.claimStatusListEntry(ownerDid);
    const listId = statusListIdFor(ownerDid, helixDid);
    expect((await s.app.inject({ method: 'GET', url: `/v1/status-list/${listId}` })).statusCode).toBe(503);
    const unsigned = await s.app.inject({ method: 'GET', url: `/v1/status-list/${listId}/unsigned` });
    expect(unsigned.headers['cache-control']).toBe('no-store');
    const signed = await signDataIntegrity(unsigned.json(), ownerSigner);
    const put = await s.app.inject({ method: 'PUT', url: `/v1/status-list/${listId}`, payload: signed });
    expect(put.statusCode).toBe(200);
    expect((await s.app.inject({ method: 'GET', url: `/v1/status-list/${listId}` })).json().issuer).toBe(ownerDid);
    expect((await s.app.inject({ method: 'PUT', url: `/v1/status-list/${listId}`, payload: { ...signed, issuer: helixDid } })).statusCode).toBe(400);
  });

  it('hands a self-custody issuer an entry on its own list, with the admin API key only', async () => {
    expect((await s.app.inject({ method: 'POST', url: '/v1/status-list/entries', payload: { issuer: ownerDid } })).statusCode).toBe(403);
    const entry = await s.app.inject({ method: 'POST', url: '/v1/status-list/entries', headers: { 'x-admin-api-key': ADMIN }, payload: { issuer: ownerDid } });
    expect(entry.statusCode).toBe(201);
    expect(entry.json()).toMatchObject({ type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: `${API}/v1/status-list/${statusListIdFor(ownerDid, helixDid)}` });
    expect((await s.app.inject({ method: 'POST', url: '/v1/status-list/entries', headers: { 'x-admin-api-key': ADMIN }, payload: { issuer: 'nope' } })).statusCode).toBe(400);
  });

  it('creates a list with the admin API key only', async () => {
    expect((await s.app.inject({ method: 'POST', url: '/v1/status-list', payload: {} })).statusCode).toBe(403);
    const created = await s.app.inject({ method: 'POST', url: '/v1/status-list', headers: { 'x-admin-api-key': ADMIN }, payload: {} });
    expect(created.statusCode).toBe(201);
    expect(created.json().issuer).toBe(helixDid);
    const named = await s.app.inject({ method: 'POST', url: '/v1/status-list', headers: { 'x-admin-api-key': ADMIN }, payload: { listId: DEFAULT_STATUS_LIST_ID } });
    expect(named.statusCode).toBe(201);
  });
});

describe('GET /v1/events/revocations (SSE) and the webhook registry', () => {
  it('streams each revocation as an SSE event, replays what a reconnecting client missed, and keeps the stream alive', async () => {
    const s = await stack({ listen: true, heartbeatMs: 20 });
    apps.push(s.app);
    const base = `http://127.0.0.1:${(s.app.server.address() as { port: number }).port}`;
    const controller = new AbortController();
    const response = await fetch(`${base}/v1/events/revocations`, { signal: controller.signal });
    expect(response.headers.get('content-type')).toMatch(/text\/event-stream/);
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let text = '';
    const readUntil = async (needle: string): Promise<void> => {
      while (!text.includes(needle)) text += decoder.decode((await reader.read()).value, { stream: true });
    };
    await readUntil('retry: 2000');
    const first = await s.signals.publish('urn:uuid:first');
    await readUntil(first.id);
    expect(text).toContain(`id: ${first.id}\nevent: revocation\ndata: ${first.set}\n\n`);
    await readUntil(': keep-alive');
    controller.abort();
    await vi.waitFor(() => expect(s.signals.subscriberCount).toBe(0));
    const second = await s.signals.publish('urn:uuid:second');
    const replay = await fetch(`${base}/v1/events/revocations`, { headers: { 'last-event-id': first.id } });
    const replayReader = replay.body!.getReader();
    let replayed = '';
    while (!replayed.includes(second.id)) replayed += decoder.decode((await replayReader.read()).value, { stream: true });
    expect(replayed).toContain(`data: ${second.set}`);
    await replayReader.cancel();
    // Closing the server ends any stream still open instead of waiting on it.
    const open = await fetch(`${base}/v1/events/revocations`);
    const openReader = open.body!.getReader();
    await openReader.read();
    await s.app.close();
    apps.splice(apps.indexOf(s.app), 1);
    let done = false;
    while (!done) done = (await openReader.read()).done;
    expect(done).toBe(true);
  });

  it('registers, lists and removes push endpoints with the admin API key only', async () => {
    const s = await stack();
    apps.push(s.app);
    expect((await s.app.inject({ method: 'GET', url: '/v1/events/revocations/webhooks' })).statusCode).toBe(403);
    const added = await s.app.inject({ method: 'POST', url: '/v1/events/revocations/webhooks', headers: { 'x-admin-api-key': ADMIN }, payload: { url: 'https://svc.example/signals' } });
    expect(added.statusCode).toBe(201);
    expect(added.json()).toEqual({ webhooks: ['https://svc.example/signals'] });
    expect((await s.app.inject({ method: 'GET', url: '/v1/events/revocations/webhooks', headers: { 'x-admin-api-key': ADMIN } })).json().webhooks).toHaveLength(1);
    const bad = await s.app.inject({ method: 'POST', url: '/v1/events/revocations/webhooks', headers: { 'x-admin-api-key': ADMIN }, payload: { url: 'http://svc.example/x' } });
    expect(bad.statusCode).toBe(400);
    const removed = await s.app.inject({ method: 'DELETE', url: '/v1/events/revocations/webhooks', headers: { 'x-admin-api-key': ADMIN }, payload: { url: 'https://svc.example/signals' } });
    expect(removed.json()).toEqual({ webhooks: [] });
    const missing = await s.app.inject({ method: 'DELETE', url: '/v1/events/revocations/webhooks', headers: { 'x-admin-api-key': ADMIN }, payload: { url: 'https://svc.example/signals' } });
    expect(missing.statusCode).toBe(404);
  });
});

describe('RevocationSignalPublisher delivery', () => {
  it('pushes each SET to every webhook (RFC 8935): 202 is delivery, errors retry with backoff, 400 does not, and failures are audited', async () => {
    const audit = { log: vi.fn() };
    const calls: Array<{ url: string; type: string | null; body: string }> = [];
    const answers: Record<string, number[]> = { 'https://ok.example/s': [202], 'https://flaky.example/s': [500, 202], 'https://down.example/s': [503, 503], 'https://bad.example/s': [400] };
    const fetchStub = (async (url: string, init: RequestInit) => {
      calls.push({ url, type: new Headers(init.headers).get('content-type'), body: String(init.body) });
      if (url === 'https://throws.example/s') throw new Error('connection refused');
      return new Response(null, { status: answers[url]!.shift() ?? 500 });
    }) as unknown as typeof fetch;
    const signals = new RevocationSignalPublisher({
      signer: helixSigner,
      webhooks: ['https://ok.example/s', 'https://flaky.example/s', 'https://down.example/s', 'https://bad.example/s', 'https://throws.example/s'],
      fetch: fetchStub,
      maxAttempts: 2,
      retryDelayMs: 1,
      audit: audit as never,
    });
    const event = await signals.publish('urn:uuid:c');
    await signals.drain();
    expect(calls.filter((call) => call.url === 'https://ok.example/s')).toHaveLength(1);
    expect(calls.filter((call) => call.url === 'https://flaky.example/s')).toHaveLength(2);
    expect(calls.filter((call) => call.url === 'https://bad.example/s')).toHaveLength(1);
    expect(calls[0]).toMatchObject({ type: 'application/secevent+jwt', body: event.set });
    const failures = audit.log.mock.calls.filter(([name]) => name === 'VC_REVOCATION_FAILED').map(([, payload]) => (payload as { endpoint: string }).endpoint);
    expect(failures.sort()).toEqual(['https://bad.example/s', 'https://down.example/s', 'https://throws.example/s']);
    expect(signals.removeWebhook('not a url')).toBe(false);
    expect(() => signals.addWebhook('nope')).toThrow(/not a URL/);
    signals.addWebhook('http://127.0.0.1:9/s');
    expect(signals.webhooks).toContain('http://127.0.0.1:9/s');
    expect(signals.issuer).toBe(helixDid);
    await signals.close();
  });

  it('replays only events after a known id, and carries events between instances over a bus', async () => {
    const bus = new InProcessSignalBus();
    const a = new RevocationSignalPublisher({ signer: helixSigner, bus, bufferSize: 2 });
    const b = new RevocationSignalPublisher({ signer: helixSigner, bus });
    await b.start();
    const seenByB: RevocationEvent[] = [];
    b.subscribe((event) => seenByB.push(event));
    const one = await a.publish('urn:uuid:1');
    const two = await a.publish('urn:uuid:2');
    const three = await a.publish('urn:uuid:3');
    expect(seenByB.map((event) => event.credentialId)).toEqual(['urn:uuid:1', 'urn:uuid:2', 'urn:uuid:3']);
    // a's buffer holds two: the first fell out, so it cannot be placed and nothing is replayed after it.
    expect(a.subscribe(() => undefined, one.id).missed).toEqual([]);
    expect(a.subscribe(() => undefined, two.id).missed.map((event) => event.id)).toEqual([three.id]);
    expect(a.subscribe(() => undefined, 'unknown').missed).toEqual([]);
    expect(a.subscribe(() => undefined).missed).toEqual([]);
  });

  it('RedisSignalBus publishes to and listens on one channel, ignoring what is not an event', async () => {
    const listeners: Array<(channel: string, message: string) => void> = [];
    const published: Array<[string, string]> = [];
    const client: RedisPubSubLike = {
      publish: async (channel, message) => {
        published.push([channel, message]);
        for (const listener of listeners) listener(channel, message);
        return 1;
      },
      subscribe: async () => 1,
      on: (_event, listener) => listeners.push(listener),
      quit: async () => 'OK',
    };
    const bus = new RedisSignalBus({ publisher: client, subscriber: client, channel: 'c' });
    const received: RevocationEvent[] = [];
    await bus.subscribe((event) => received.push(event));
    await bus.publish({ id: 'j', credentialId: 'urn:uuid:x', set: 'a.b.c' });
    for (const listener of listeners) {
      listener('other', JSON.stringify({ id: 'j2', credentialId: 'x', set: 's' }));
      listener('c', 'not json');
      listener('c', JSON.stringify({ id: 1 }));
    }
    expect(published[0]![0]).toBe('c');
    expect(received).toEqual([{ id: 'j', credentialId: 'urn:uuid:x', set: 'a.b.c' }]);
    await bus.close();
    expect(new RedisSignalBus({ publisher: client, subscriber: client })).toBeDefined();
  });
});
