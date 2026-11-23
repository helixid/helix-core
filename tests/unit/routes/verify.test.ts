// Copyright 2026 DgVerse LLP
// KYA-OS story F-2: POST /v1/verify wraps @helixid/sdk-js's local verifier and reads no database.
import { readFileSync } from 'node:fs';
import Fastify, { type FastifyInstance } from 'fastify';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import { EnvSigner, buildDIDDocument, generateKeyPair, signDataIntegrity } from '../../../src/core/index.js';
import verifyRoutes, { cardEndpointOf, memoryNonceStore, readableUrl, type VerifyRouteOptions } from '../../../src/routes/verify/index.js';

const fixturesDir = new URL('../../../fixtures/verifier/', import.meta.url);
const env = JSON.parse(readFileSync(new URL('environment.json', fixturesDir), 'utf8')) as {
  keys: Record<string, { did: string; private_key_hex: string }>;
  did_documents: Record<string, unknown>;
  status_lists: Record<string, { encoded_list: string; issuer?: string; status_purpose?: string; id?: string; valid_from?: string; valid_until?: string }>;
  cards: Record<string, unknown>;
};
const valid = (JSON.parse(readFileSync(new URL('valid.json', fixturesDir), 'utf8')) as { cases: { name: string; input: { chain?: unknown } }[] }).cases;
const NOW = Date.parse('2026-06-01T00:00:00Z');
const SERVICE = env.keys['service']!.did;
const AGENT = env.keys['agent']!.did;
const agentSigner = new EnvSigner({ did: AGENT, envVar: 'K', env: { K: env.keys['agent']!.private_key_hex } });
const request = { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1001' } } };

/** Seams over the fixture environment: DID documents, decoded lists and cards from local data. */
const fixtureSeams: VerifyRouteOptions = {
  clock: () => NOW,
  resolveDid: async (did) => (env.did_documents[did] as never) ?? null,
  fetchStatusList: async (url) => {
    const list = env.status_lists[url];
    if (list === undefined) return undefined;
    return {
      bits: kyaos.verifier.decodeStatusListBits(list.encoded_list),
      ...(list.issuer ? { issuer: list.issuer } : {}),
      ...(list.status_purpose ? { statusPurpose: list.status_purpose } : {}),
      ...(list.id ? { id: list.id } : {}),
      ...(list.valid_from ? { validFrom: list.valid_from } : {}),
      ...(list.valid_until ? { validUntil: list.valid_until } : {}),
    };
  },
  resolveCard: async (did) => (did === AGENT ? env.cards['attested'] : undefined),
};

let app: FastifyInstance | undefined;
afterEach(async () => {
  await app?.close();
  app = undefined;
});

async function start(options: VerifyRouteOptions): Promise<FastifyInstance> {
  app = Fastify({ logger: false });
  await app.register(verifyRoutes, { prefix: '/v1/verify', ...options });
  await app.ready();
  return app;
}

const proofFor = (audience = SERVICE) => kyaos.verifier.signRequestProof(request, agentSigner, { audience, now: NOW });

describe('POST /v1/verify', () => {
  it('verifies a request proof with its carried chain and the agent card: L3 and both scopes', async () => {
    const server = await start(fixtureSeams);
    const chain = valid.find((c) => c.name === 'two_hop_chain')!.input.chain;
    const res = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: await proofFor(), chain, request, expectedAudience: SERVICE } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ ok: true, level: 'L3', effectiveScopes: ['read:orders', 'write:orders'], reasons: [], proofDid: AGENT, chainSummary: { depth: 2, fresh: true } });
  });

  it('answers a refusal as 200 with the reason codes, and refuses a replay', async () => {
    const server = await start(fixtureSeams);
    const proof = await proofFor();
    const first = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof, request, expectedAudience: SERVICE, catalog: ['read:orders'] } });
    expect(first.json()).toMatchObject({ ok: true, effectiveScopes: [] });
    const replay = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof, request, expectedAudience: SERVICE } });
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ ok: false, reasons: ['nonce_replayed'], level: 'L1' });
    const elsewhere = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: await proofFor('did:web:other.example'), request, expectedAudience: SERVICE } });
    expect(elsewhere.json().reasons).toEqual(['audience_mismatch']);
  });

  it('never raises the chain bound past its own, and refuses an over-long chain before resolving anything', async () => {
    const resolved: string[] = [];
    const server = await start({ ...fixtureSeams, maxChainLength: 2, resolveDid: async (did) => (resolved.push(did), (env.did_documents[did] as never) ?? null) });
    const res = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: await proofFor(), chain: [1, 2, 3], request, expectedAudience: SERVICE, maxChainLength: 50 } });
    expect(res.json().reasons).toEqual(['chain_too_long']);
    expect(resolved).toEqual([]);
    const lowered = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: await proofFor(), chain: [1, 2], request, expectedAudience: SERVICE, maxChainLength: 1 } });
    expect(lowered.json().reasons).toEqual(['chain_too_long']);
  });

  it('passes the request options through', async () => {
    const server = await start(fixtureSeams);
    const chain = valid.find((c) => c.name === 'two_hop_chain')!.input.chain;
    const payload = { proof: await proofFor(), chain, request, expectedAudience: SERVICE, resource: SERVICE, resourceOwner: env.keys['owner']!.did, trustedRootIssuers: [env.keys['owner']!.did], action: 'refund:orders', tokenCnfJkt: 'abc' };
    const res = await server.inject({ method: 'POST', url: '/v1/verify', payload });
    expect(res.json().reasons).toEqual(['cnf_required_by_token']);
    const action = await server.inject({ method: 'POST', url: '/v1/verify', payload: { ...payload, proof: await proofFor(), tokenCnfJkt: undefined } });
    expect(action.json().reasons).toEqual(['action_not_delegated']);
  });

  it('refuses a body that is not a verification request with 400', async () => {
    const server = await start(fixtureSeams);
    expect((await server.inject({ method: 'POST', url: '/v1/verify', payload: { request } })).statusCode).toBe(400);
    expect((await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: {}, request, expectedAudience: 'not-a-did' } })).statusCode).toBe(400);
    // Fastify drops a member the schema does not name (removeAdditional) rather than refuse the body.
    expect((await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: {}, request, expectedAudience: SERVICE, extra: 1 } })).json().reasons).toEqual(['malformed_proof']);
  });

  it('builds its default seams from public resolution alone: did:web over the injected fetch, cards from the DID document', async () => {
    const keys = generateKeyPair();
    const did = 'did:web:127.0.0.1%3A4100:agents:a1';
    const signer = new EnvSigner({ did, envVar: 'K', env: { K: keys.privateKey } });
    const document = { ...buildDIDDocument(did, keys.publicKey), service: [{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://127.0.0.1:4100/agents/a1/card.json' }] };
    const list = { id: 'https://127.0.0.1:4100/status/1', issuer: did, credentialSubject: { statusPurpose: 'revocation', encodedList: `u${gzipSync(new Uint8Array(16)).toString('base64url')}` } };
    const served: Record<string, unknown> = {
      'http://127.0.0.1:4100/agents/a1/did.json': document,
      'http://127.0.0.1:4100/agents/a1/card.json': { id: did, entityType: 'agent', name: 'a1', capabilities: ['read:orders'] },
      'http://127.0.0.1:4100/status/1': list,
    };
    const asked: string[] = [];
    const fetch = async (url: string) => (asked.push(url), { ok: url in served, status: url in served ? 200 : 404, json: async () => served[url] });
    const server = await start({ fetch, allowLoopbackHttp: true, clock: () => NOW });
    const proof = await kyaos.verifier.signRequestProof(request, signer, { audience: SERVICE, now: NOW });
    const res = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof, request, expectedAudience: SERVICE } });
    expect(res.json()).toMatchObject({ ok: true, level: 'L1', proofDid: did });
    expect(asked).toContain('http://127.0.0.1:4100/agents/a1/card.json');

    // Outside development an http loopback document is never read.
    asked.length = 0;
    await app!.close();
    const strict = await start({ fetch, clock: () => NOW });
    const refused = await strict.inject({ method: 'POST', url: '/v1/verify', payload: { proof: await kyaos.verifier.signRequestProof(request, signer, { audience: SERVICE, now: NOW }), request, expectedAudience: SERVICE } });
    expect(refused.json().reasons).toEqual(['did_unresolved']);
    expect(asked).toEqual(['https://127.0.0.1:4100/agents/a1/did.json']);
  });
});

describe('POST /v1/verify default status and card seams', () => {
  afterEach(() => vi.unstubAllGlobals());

  /** The fixture lists as their issuers publish them (signed Bitstring Status List v1.0, story L3-C), served by a stubbed global fetch. */
  const servedLists = (missing: string[] = []) => {
    const asked: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      asked.push(url);
      const list = missing.includes(url) ? undefined : env.status_lists[url];
      const key = list && Object.values(env.keys).find((entry) => entry.did === list.issuer);
      const body =
        list &&
        key &&
        (await signDataIntegrity(
          {
            '@context': ['https://www.w3.org/ns/credentials/v2'],
            id: list.id,
            type: ['VerifiableCredential', 'BitstringStatusListCredential'],
            issuer: list.issuer,
            validFrom: list.valid_from,
            validUntil: list.valid_until,
            credentialSubject: { id: `${url}#list`, type: 'BitstringStatusList', statusPurpose: list.status_purpose, encodedList: list.encoded_list },
          },
          new EnvSigner({ did: key.did, envVar: 'L', env: { L: key.private_key_hex } }),
        ));
      return { ok: body !== undefined, status: body ? 200 : 404, json: async () => body };
    });
    return asked;
  };

  it('fetches each status list over https with the global fetch; a DID document with no card service means no card', async () => {
    const asked = servedLists();
    const server = await start({ clock: () => NOW, resolveDid: fixtureSeams.resolveDid });
    const chain = valid.find((c) => c.name === 'two_hop_chain')!.input.chain;
    const res = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: await proofFor(), chain, request, expectedAudience: SERVICE } });
    expect(res.json()).toMatchObject({ ok: true, proofDid: AGENT, chainSummary: { depth: 2, fresh: true } });
    expect(asked.length).toBeGreaterThan(0);
    // The same chain again is served from the status cache: allowed, not fresh (story L3-C).
    const again = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: await proofFor(), chain, request, expectedAudience: SERVICE } });
    expect(again.json()).toMatchObject({ ok: true, fresh: false, chainSummary: { fresh: false } });
    for (const url of asked) expect(url).toMatch(/^https:\/\/[a-z]+\.example\/status\//);
  });

  it('refuses the chain when a status list answers an error', async () => {
    const chain = valid.find((c) => c.name === 'two_hop_chain')!.input.chain as { credentialStatus: { statusListCredential: string } }[];
    servedLists([chain[0]!.credentialStatus.statusListCredential]);
    const server = await start({ clock: () => NOW, resolveDid: fixtureSeams.resolveDid });
    const res = await server.inject({ method: 'POST', url: '/v1/verify', payload: { proof: await proofFor(), chain, request, expectedAudience: SERVICE } });
    expect(res.json().ok).toBe(false);
    expect(res.json().reasons[0]).toMatch(/^status_/);
  });
});

describe('verify route helpers', () => {
  it('reads https, and http on loopback only in development', () => {
    expect(readableUrl('https://example.com/x', false)).toBe('https://example.com/x');
    expect(readableUrl('http://example.com/x', true)).toBeUndefined();
    expect(readableUrl('http://localhost:1/x', true)).toBe('http://localhost:1/x');
    expect(readableUrl('not a url', true)).toBeUndefined();
  });

  it('finds the card service and keeps a replay store per agent', async () => {
    expect(cardEndpointOf({ service: [null, { type: ['X', 'KyaOsEntityCard'], serviceEndpoint: 'https://c' }] })).toBe('https://c');
    expect(cardEndpointOf({ service: 'x' })).toBeUndefined();
    expect(cardEndpointOf(null)).toBeUndefined();
    let now = 0;
    const store = memoryNonceStore(() => now);
    expect(await store.insert('n', 'did:a', 10)).toBe(true);
    expect(await store.insert('n', 'did:a', 10)).toBe(false);
    expect(await store.insert('n', undefined, 10)).toBe(true);
    now = 10;
    expect(await store.insert('n', 'did:a', 20)).toBe(true);
  });
});
