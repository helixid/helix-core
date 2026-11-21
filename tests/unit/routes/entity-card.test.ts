// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: GET /{path}/did.json, /{path}/card.json and /.well-known/kya-os-card.json serve
// Helix-hosted DID documents (anchoring the card) and cards built on every read.
import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { buildDidDocument, publicKeyBytesToJwk, resolveEntityCard, validateEntityCard } from '../../../src/core/index.js';
import { errorHandler } from '../../../src/middleware/errorHandler.js';
import entityCardRoutes, { hostedUrls, type EntityCardRecord, type EntityCardSource } from '../../../src/routes/entity-card/index.js';

const HOST = 'helix.test';
const JWK = publicKeyBytesToJwk(new Uint8Array(32).fill(5));
const AGENT = 'did:web:helix.test:acme:ledger-agent';
const ORG = 'did:web:helix.test:acme';
const ROOT = 'did:web:helix.test';

const records: Record<string, EntityCardRecord> = {
  [AGENT]: {
    didDocument: buildDidDocument({ did: AGENT, publicKeyJwk: JWK, alsoKnownAs: ['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'], service: [{ id: '#home', type: 'LinkedDomains', serviceEndpoint: 'https://acme.example' }] }),
    card: { entityType: 'agent', name: 'Ledger', kid: 'key-1', publicKeyJwk: JWK, capabilities: ['handshake'], responsibleParty: ORG, revocation: { statusListCredential: 'https://helix.test/v1/status-list/cards', statusListIndex: '7' } },
  },
  [ORG]: { didDocument: buildDidDocument({ did: ORG, publicKeyJwk: JWK, cardServiceEndpoint: 'https://stale.example/card.json' }), card: { entityType: 'verifier', name: 'Acme' } },
  [ROOT]: { didDocument: buildDidDocument({ did: ROOT, publicKeyJwk: JWK }), card: { entityType: 'verifier', name: 'Helix' } },
  'did:web:helix.test:acme:gone': { didDocument: {}, deactivatedAt: new Date(), card: { entityType: 'agent', name: 'Gone' } },
  'did:web:helix.test:acme:bad': { didDocument: null, card: { entityType: 'agent', name: '' } },
  'did:web:127.0.0.1%3A3580:acme:ledger-agent': { didDocument: buildDidDocument({ did: 'did:web:127.0.0.1%3A3580:acme:ledger-agent', publicKeyJwk: JWK }), card: { entityType: 'agent', name: 'Local' } },
};

async function harness(options: { publicOrigin?: string; host?: string } = {}) {
  const find = vi.fn(async (did: string) => records[did] ?? null);
  const source: EntityCardSource = { host: options.host ?? HOST, find };
  const app = Fastify({ logger: false });
  app.setErrorHandler(errorHandler);
  app.get('/.well-known/did.json', async () => ({ id: ROOT, static: true }));
  app.get('/v1/agents', async () => ({ agents: [] }));
  await app.register(entityCardRoutes, { source, publicOrigin: options.publicOrigin });
  await app.ready();
  return { app, find };
}

describe('entity-card routes', () => {
  let h: Awaited<ReturnType<typeof harness>>;
  beforeAll(async () => {
    h = await harness();
  });
  afterAll(() => h.app.close());

  it('serves the DID document with the KyaOsEntityCard service entry added, other services kept', async () => {
    const response = await h.app.inject({ method: 'GET', url: '/acme/ledger-agent/did.json' });
    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toMatch(/application\/json/);
    expect(response.headers['cache-control']).toBe('public, max-age=300');
    const document = response.json();
    expect(document.id).toBe(AGENT);
    expect(document.alsoKnownAs).toEqual(['did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK']);
    expect(document.service).toEqual([
      { id: '#home', type: 'LinkedDomains', serviceEndpoint: 'https://acme.example' },
      { id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://helix.test/acme/ledger-agent/card.json' },
    ]);
    expect(h.find).toHaveBeenCalledWith(AGENT);
  });

  it('replaces a stale card service entry with where the card is actually served', async () => {
    const document = (await h.app.inject({ method: 'GET', url: '/acme/did.json' })).json();
    expect(document.service).toEqual([{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://helix.test/acme/card.json' }]);
  });

  it('serves the card, built on read, validating against the schema, with the hosted didDocument URL', async () => {
    const response = await h.app.inject({ method: 'GET', url: '/acme/ledger-agent/card.json' });
    expect(response.statusCode).toBe(200);
    const card = response.json();
    expect(validateEntityCard(card)).toEqual([]);
    expect(card).toMatchObject({ id: AGENT, entityType: 'agent', name: 'Ledger', kid: `${AGENT}#key-1`, responsibleParty: ORG, didDocument: 'https://helix.test/acme/ledger-agent/did.json', proofProfile: 'org.kya-os/proof.v1', revocation: { statusListIndex: '7' } });
    expect('conformanceLevel' in card).toBe(false);
  });

  it('serves the bare-host org card at /.well-known/kya-os-card.json while the static /.well-known/did.json keeps its own route', async () => {
    const card = (await h.app.inject({ method: 'GET', url: '/.well-known/kya-os-card.json' })).json();
    expect(card).toMatchObject({ id: ROOT, entityType: 'verifier', name: 'Helix', didDocument: 'https://helix.test/.well-known/did.json' });
    expect((await h.app.inject({ method: 'GET', url: '/.well-known/did.json' })).json()).toEqual({ id: ROOT, static: true });
    expect((await h.app.inject({ method: 'GET', url: '/v1/agents' })).json()).toEqual({ agents: [] });
  });

  it('the served pair resolves in two steps through the card resolver', async () => {
    const resolved = await resolveEntityCard(AGENT, {
      fetch: async (url) => {
        const response = await h.app.inject({ method: 'GET', url: new URL(url).pathname });
        return new Response(response.body, { status: response.statusCode });
      },
    });
    expect(resolved.card.id).toBe(AGENT);
    expect(resolved.cardUrl).toBe('https://helix.test/acme/ledger-agent/card.json');
  });

  it('answers 404 for an unknown DID, 410 for a deactivated one, 400 for a record that builds no card, and the usual 404 for any other path', async () => {
    expect((await h.app.inject({ method: 'GET', url: '/acme/stranger/card.json' })).statusCode).toBe(404);
    expect((await h.app.inject({ method: 'GET', url: '/acme/stranger/card.json' })).json().error.code).toBe('DID_NOT_FOUND');
    expect((await h.app.inject({ method: 'GET', url: '/acme/gone/did.json' })).statusCode).toBe(410);
    expect((await h.app.inject({ method: 'GET', url: '/acme/bad/card.json' })).statusCode).toBe(400);
    expect((await h.app.inject({ method: 'GET', url: '/acme/bad/did.json' })).json().service).toHaveLength(1);
    for (const url of ['/acme/ledger-agent/other.json', '/acme/ledger-agent/', '/did.json', '/v1/nothing', '/a/../did.json']) {
      const response = await h.app.inject({ method: 'GET', url });
      expect(response.statusCode, url).toBe(404);
      expect(response.body, url).not.toContain('DID_NOT_FOUND');
    }
  });

  it('builds the service endpoint and didDocument URL on publicOrigin when the stack is not at https://<host>', async () => {
    const local = await harness({ publicOrigin: 'http://127.0.0.1:3580/', host: '127.0.0.1%3A3580' });
    try {
      const document = (await local.app.inject({ method: 'GET', url: '/acme/ledger-agent/did.json' })).json();
      expect(local.find).toHaveBeenCalledWith('did:web:127.0.0.1%3A3580:acme:ledger-agent');
      expect(document.id).toBe('did:web:127.0.0.1%3A3580:acme:ledger-agent');
      expect(document.service).toEqual([{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'http://127.0.0.1:3580/acme/ledger-agent/card.json' }]);
      const card = (await local.app.inject({ method: 'GET', url: '/acme/ledger-agent/card.json' })).json();
      expect(card.didDocument).toBe('http://127.0.0.1:3580/acme/ledger-agent/did.json');
    } finally {
      await local.app.close();
    }
    expect(hostedUrls('did:web:127.0.0.1%3A3580:acme:x', 'http://127.0.0.1:3580')).toEqual({ didDocument: 'http://127.0.0.1:3580/acme/x/did.json', card: 'http://127.0.0.1:3580/acme/x/card.json' });
    expect(hostedUrls('did:web:helix.test', undefined)).toEqual({ didDocument: 'https://helix.test/.well-known/did.json', card: 'https://helix.test/.well-known/kya-os-card.json' });
    expect(() => hostedUrls('did:key:z6Mk', undefined)).toThrow(/not found/);
  });
});
