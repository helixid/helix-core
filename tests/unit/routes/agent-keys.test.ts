// Copyright 2026 DgVerse LLP
// KYA-OS story L1-A: POST /v1/agents/:did/keys takes a public JWK only and republishes the did:web document.
import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import {
  buildDIDDocument,
  clearDIDCache,
  derivePublicKey,
  didKeyFromPublicKey,
  publicKeyBytesToJwk,
  resolveDid,
} from '../../../src/core/index.js';
import { errorHandler } from '../../../src/middleware/errorHandler.js';
import agentKeyRoutes, { AGENT_KEY_UPDATE_TYPE, readRegisterAgentKeyBody, type AgentKeyRouteOptions } from '../../../src/routes/agent-keys/index.js';

const ADMIN = 'test-admin-key';
const AGENT_DID = 'did:web:agents.example.com:agents:abc';
const SEED = '33'.repeat(32);
const PUBLIC_KEY = new Uint8Array(Buffer.from(derivePublicKey(SEED), 'hex'));
const JWK = publicKeyBytesToJwk(PUBLIC_KEY);
const PRIVATE_D = Buffer.from(SEED, 'hex').toString('base64url');

interface Harness {
  app: ReturnType<typeof Fastify>;
  repository: { findDidById: ReturnType<typeof vi.fn>; updateDidDocument: ReturnType<typeof vi.fn> };
  didCache: { delete: ReturnType<typeof vi.fn> };
  rawBodies: string[];
}

async function harness(options: Partial<AgentKeyRouteOptions> & { records?: Record<string, unknown> } = {}): Promise<Harness> {
  const records: Record<string, { didDocument: unknown; deactivatedAt?: Date | null }> = {
    [AGENT_DID]: { didDocument: buildDIDDocument(AGENT_DID, 'a'.repeat(64), [{ id: '#home', type: 'LinkedDomains', serviceEndpoint: 'https://agent.example.com' }]) },
    'did:web:agents.example.com:agents:gone': { didDocument: {}, deactivatedAt: new Date() },
    'did:web:agents.example.com:agents:bare': { didDocument: null },
    ...(options.records as Record<string, { didDocument: unknown }> | undefined),
  };
  const repository = {
    findDidById: vi.fn(async (did: string) => records[did] ?? null),
    updateDidDocument: vi.fn(async (did: string, didDocument: unknown) => {
      records[did] = { ...records[did], didDocument };
      return [records[did]];
    }),
  };
  const didCache = { delete: vi.fn(async () => undefined) };
  const rawBodies: string[] = [];
  const app = Fastify({ logger: false });
  app.setErrorHandler(errorHandler);
  app.addHook('preParsing', async (_request, _reply, payload) => {
    const chunks: Buffer[] = [];
    for await (const chunk of payload) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks);
    rawBodies.push(raw.toString('utf8'));
    const { Readable } = await import('node:stream');
    return Readable.from([raw]);
  });
  await app.register(agentKeyRoutes, { prefix: '/v1', didRepository: repository, didCache, adminApiKey: ADMIN, ...options });
  await app.ready();
  return { app, repository, didCache, rawBodies };
}

function post(h: Harness, did: string, payload: unknown, headers: Record<string, string> = { 'x-admin-api-key': ADMIN }) {
  return h.app.inject({ method: 'POST', url: `/v1/agents/${encodeURIComponent(did)}/keys`, headers, payload: payload as Record<string, unknown> });
}

describe('POST /v1/agents/:did/keys', () => {
  it('stores the public key by republishing the did:web document with <did>#<kid> as its one key, and drops caches', async () => {
    clearDIDCache();
    const h = await harness();
    const response = await post(h, AGENT_DID, { publicKeyJwk: JWK, kid: 'key-1' });
    expect(response.statusCode, response.body).toBe(201);
    const body = response.json() as { did: string; kid: string; didKey: string; didDocument: Record<string, unknown> };
    expect(body.did).toBe(AGENT_DID);
    expect(body.kid).toBe(`${AGENT_DID}#key-1`);
    expect(body.didKey).toBe(didKeyFromPublicKey(PUBLIC_KEY));
    expect(body.didDocument).toMatchObject({
      id: AGENT_DID,
      alsoKnownAs: [body.didKey],
      verificationMethod: [{ id: body.kid, publicKeyJwk: JWK, controller: AGENT_DID }],
      authentication: [body.kid],
      assertionMethod: [body.kid],
      service: [{ id: '#home' }],
    });
    expect(h.repository.updateDidDocument).toHaveBeenCalledWith(AGENT_DID, body.didDocument, {
      updateType: AGENT_KEY_UPDATE_TYPE,
      hederaTransactionId: '',
      payload: { kid: body.kid, publicKeyJwk: JWK, didKey: body.didKey },
    });
    expect(h.didCache.delete).toHaveBeenCalledWith(AGENT_DID);
    expect(JSON.stringify(body)).not.toContain(PRIVATE_D);
    expect(JSON.stringify(body)).not.toContain(SEED);

    // What was stored resolves (through the did:web route's serving of it) to the same key did:key gives.
    const served = (await h.repository.findDidById(AGENT_DID)) as { didDocument: unknown };
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(served.didDocument), { status: 200 })));
    try {
      const viaWeb = await resolveDid(AGENT_DID);
      const viaKey = await resolveDid(body.didKey);
      expect(viaWeb.rawKey).toEqual(viaKey.rawKey);
      expect(viaWeb.jwk.x).toBe(viaKey.jwk.x);
      expect(viaWeb.kid).toBe(body.kid);
    } finally {
      vi.unstubAllGlobals();
      clearDIDCache();
    }
    await h.app.close();
  });

  it('defaults the kid, takes it from the JWK, and works without a document cache or services', async () => {
    const h = await harness({ didCache: undefined });
    expect((await post(h, AGENT_DID, { publicKeyJwk: JWK })).json().kid).toBe(`${AGENT_DID}#key-1`);
    expect((await post(h, AGENT_DID, { publicKeyJwk: { ...JWK, kid: 'from-jwk' } })).json().kid).toBe(`${AGENT_DID}#from-jwk`);
    expect((await post(h, AGENT_DID, { publicKeyJwk: { ...JWK, kid: 'from-jwk' }, kid: 'explicit' })).json().kid).toBe(`${AGENT_DID}#explicit`);
    const bare = await post(h, 'did:web:agents.example.com:agents:bare', { publicKeyJwk: JWK, kid: `did:web:agents.example.com:agents:bare#k` });
    expect(bare.statusCode).toBe(201);
    expect(bare.json().didDocument.service).toBeUndefined();
    await h.app.close();
  });

  it('refuses any private material with 400 before touching storage', async () => {
    const h = await harness();
    const cases: [unknown, RegExp][] = [
      [{ publicKeyJwk: { ...JWK, d: PRIVATE_D } }, /private key material \(publicKeyJwk\.d\)/],
      [{ publicKeyJwk: JWK, privateKey: SEED }, /private key material \(privateKey\)/],
      [{ publicKeyJwk: JWK, kid: 'k', extra: { nested: { seed: SEED } } }, /private key material \(extra\.nested\.seed\)/],
      [{ publicKeyJwk: { ...JWK, use: 'sig' } }, /unexpected members \(use\)/],
      [{ publicKeyJwk: JWK, publicKeyHex: 'aa' }, /unexpected members \(publicKeyHex\)/],
      [{ publicKeyJwk: { kty: 'EC', crv: 'P-256', x: JWK.x } }, /OKP/],
      [{ publicKeyJwk: { ...JWK, x: 'not base64url!' } }, /32-byte/],
      [{ publicKeyJwk: JWK, kid: '' }, /kid must be a non-empty string/],
      [{ publicKeyJwk: JWK, kid: 5 }, /kid must be a non-empty string/],
      [{ publicKeyJwk: JWK, kid: 'did:web:other.example.com#k' }, /does not belong/],
      [{}, /32-byte|JSON object/],
      [[], /JSON object/],
    ];
    for (const [payload, message] of cases) {
      const response = await post(h, AGENT_DID, payload);
      expect(response.statusCode, JSON.stringify(payload)).toBe(400);
      expect(response.json().error.code).toBe('VALIDATION_ERROR');
      expect(response.json().error.message, JSON.stringify(payload)).toMatch(message);
    }
    expect(h.repository.updateDidDocument).not.toHaveBeenCalled();
    expect(h.didCache.delete).not.toHaveBeenCalled();
    expect(() => readRegisterAgentKeyBody('text')).toThrow(/JSON object/);
    expect(() => readRegisterAgentKeyBody(null)).toThrow(/JSON object/);
    await h.app.close();
  });

  it('refuses without the admin key, for a DID that is not did:web, unknown, or deactivated', async () => {
    const h = await harness();
    expect((await post(h, AGENT_DID, { publicKeyJwk: JWK }, {})).statusCode).toBe(403);
    expect((await post(h, AGENT_DID, { publicKeyJwk: JWK }, { 'x-admin-api-key': 'wrong' })).statusCode).toBe(403);
    const notWeb = await post(h, didKeyFromPublicKey(PUBLIC_KEY), { publicKeyJwk: JWK });
    expect(notWeb.statusCode).toBe(400);
    expect(notWeb.json().error.message).toMatch(/did:web/);
    const unknown = await post(h, 'did:web:agents.example.com:agents:nobody', { publicKeyJwk: JWK });
    expect(unknown.statusCode).toBe(404);
    expect(unknown.json().error.code).toBe('DID_NOT_FOUND');
    const gone = await post(h, 'did:web:agents.example.com:agents:gone', { publicKeyJwk: JWK });
    expect(gone.statusCode).toBe(410);
    expect(gone.json().error.code).toBe('DID_DEACTIVATED');
    expect(h.repository.updateDidDocument).not.toHaveBeenCalled();
    await h.app.close();
  });

  it('refuses when no admin key is configured at all, and lets non-Helix errors reach the error handler', async () => {
    const h = await harness({ adminApiKey: undefined });
    expect((await post(h, AGENT_DID, { publicKeyJwk: JWK })).statusCode).toBe(403);
    await h.app.close();
    const broken = await harness();
    broken.repository.findDidById.mockRejectedValueOnce(new Error('storage down'));
    const response = await post(broken, AGENT_DID, { publicKeyJwk: JWK });
    expect(response.statusCode).toBe(500);
    await broken.app.close();
  });

  it('self-custody invariant: the request on the wire carries the public JWK and never a d member or the seed', async () => {
    const h = await harness();
    const response = await post(h, AGENT_DID, { publicKeyJwk: JWK, kid: 'key-1' });
    expect(response.statusCode).toBe(201);
    expect(h.rawBodies).toHaveLength(1);
    const wire = JSON.parse(h.rawBodies[0]!) as Record<string, unknown>;
    expect(Object.keys(wire).sort()).toEqual(['kid', 'publicKeyJwk']);
    expect(Object.keys(wire['publicKeyJwk'] as object).sort()).toEqual(['crv', 'kty', 'x']);
    expect(h.rawBodies[0]).not.toMatch(/"d"/);
    expect(h.rawBodies[0]).not.toContain(SEED);
    expect(h.rawBodies[0]).not.toContain(PRIVATE_D);
    await h.app.close();
  });
});
