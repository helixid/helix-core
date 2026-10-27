import { describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import { buildDIDDocument } from '../../src/core/index.js';

import didWebRoutes from '../../src/routes/did-web/index.js';

describe('did:web hosting route', () => {
  it('serves the issuer DID document with JSON content type and cache headers', async () => {
    const issuerDid = 'did:web:api.example.com';
    const didDocument = buildDIDDocument(issuerDid, 'a'.repeat(64));
    const app = Fastify({ logger: false });

    await app.register(didWebRoutes, {
      issuerDid,
      didDomain: 'example.com',
      didRepository: {
        async findDidById(did: string) {
          return did === issuerDid ? { didDocument } : null;
        },
      },
    });
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/.well-known/did.json' });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('application/json');
    expect(response.headers['cache-control']).toBe('public, max-age=3600');
    expect(response.json()).toMatchObject({ id: issuerDid });

    await app.close();
  });

  it('answers 410 for a deactivated agent or service DID, so verifiers stop resolving it', async () => {
    const agentDid = 'did:web:example.com:agents:abc123';
    const serviceDid = 'did:web:example.com:services:def456';
    const app = Fastify({ logger: false });

    await app.register(didWebRoutes, {
      issuerDid: 'did:web:example.com',
      didDomain: 'example.com',
      didRepository: {
        async findDidById(did: string) {
          if (did !== agentDid && did !== serviceDid) return null;
          return { didDocument: buildDIDDocument(did, 'b'.repeat(64)), deactivatedAt: new Date() };
        },
      },
    });
    await app.ready();

    for (const url of ['/agents/abc123/did.json', '/services/def456/did.json']) {
      const response = await app.inject({ method: 'GET', url });
      expect(response.statusCode).toBe(410);
      expect(response.json()).toMatchObject({ error: { code: 'DID_DEACTIVATED' } });
    }

    await app.close();
  });
});
