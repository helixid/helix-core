// One did:web shape (2026-11-23): the issuer at /.well-known/did.json only
// when it is this domain's did:web; agents, services and accounts at
// /<kind>/<hex>/did.json (and card.json) through the entity-card route.
import { describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import { buildDIDDocument, issueDidWeb } from '../../src/core/index.js';

import didWebRoutes from '../../src/routes/did-web/index.js';
import entityCardRoutes from '../../src/routes/entity-card/index.js';
import { createEntityCardSource } from '../../src/services/entity-card/entity-card.source.js';

type Row = { subjectType: string; didDocument: unknown; deactivatedAt?: Date | null };

async function stack(issuerDid: string, didDomain: string, rows: Record<string, Row>) {
  const didRepository = { async findDidById(did: string) { return rows[did] ?? null; } };
  const app = Fastify({ logger: false });
  await app.register(didWebRoutes, { issuerDid, didDomain, didRepository });
  await app.register(entityCardRoutes, { source: createEntityCardSource({ host: didDomain, didRepository }) });
  await app.ready();
  return app;
}

describe('did:web hosting route', () => {
  it('serves the issuer DID document with JSON content type and cache headers', async () => {
    const issuerDid = 'did:web:api.example.com';
    const app = await stack(issuerDid, 'api.example.com', { [issuerDid]: { subjectType: 'issuer', didDocument: buildDIDDocument(issuerDid, 'a'.repeat(64)) } });

    const response = await app.inject({ method: 'GET', url: '/.well-known/did.json' });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('application/json');
    expect(response.headers['cache-control']).toBe('public, max-age=3600');
    expect(response.json()).toMatchObject({ id: issuerDid });
    await app.close();
  });

  it('serves the issuer of a domain with a port under its encoded did:web', async () => {
    const issuerDid = issueDidWeb({ host: 'localhost:3680' });
    expect(issuerDid).toBe('did:web:localhost%3A3680');
    const app = await stack(issuerDid, 'localhost:3680', { [issuerDid]: { subjectType: 'issuer', didDocument: buildDIDDocument(issuerDid, 'a'.repeat(64)) } });
    expect((await app.inject({ method: 'GET', url: '/.well-known/did.json' })).json()).toMatchObject({ id: issuerDid });
    await app.close();
  });

  it('claims no did:web id when the issuer is not this domain\'s did:web (DID_METHOD=key)', async () => {
    const keyIssuer = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    const app = await stack(keyIssuer, 'api.example.com', { [keyIssuer]: { subjectType: 'issuer', didDocument: buildDIDDocument(keyIssuer, 'a'.repeat(64)) } });
    const response = await app.inject({ method: 'GET', url: '/.well-known/did.json' });
    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: 'DID_NOT_FOUND' } });
    await app.close();

    const noDomain = await stack(keyIssuer, '', {});
    expect((await noDomain.inject({ method: 'GET', url: '/.well-known/did.json' })).statusCode).toBe(404);
    await noDomain.close();
  });

  it('serves agents, services and accounts at /<kind>/<hex>/did.json with their card, and 410 once deactivated', async () => {
    const host = 'localhost:3680';
    const agent = issueDidWeb({ host, kind: 'agents' });
    const service = issueDidWeb({ host, kind: 'services' });
    const account = issueDidWeb({ host, kind: 'accounts' });
    const gone = issueDidWeb({ host, kind: 'agents' });
    const row = (did: string, subjectType: string, deactivatedAt: Date | null = null): Row => ({ subjectType, didDocument: buildDIDDocument(did, 'b'.repeat(64)), deactivatedAt });
    const app = await stack(issueDidWeb({ host }), host, { [agent]: row(agent, 'agent'), [service]: row(service, 'service'), [account]: row(account, 'user'), [gone]: row(gone, 'agent', new Date()) });

    for (const [did, entityType] of [[agent, 'agent'], [service, 'mcp'], [account, 'verifier']] as const) {
      const path = did.split(':').slice(3).join('/');
      const document = await app.inject({ method: 'GET', url: `/${path}/did.json` });
      expect(document.statusCode, did).toBe(200);
      expect(document.json()).toMatchObject({ id: did, service: [{ type: 'KyaOsEntityCard', serviceEndpoint: `http://localhost:3680/${path}/card.json` }] });
      const card = await app.inject({ method: 'GET', url: `/${path}/card.json` });
      expect(card.json()).toMatchObject({ id: did, entityType });
    }
    const deactivated = await app.inject({ method: 'GET', url: `/agents/${gone.split(':').pop()}/did.json` });
    expect(deactivated.statusCode).toBe(410);
    expect(deactivated.json()).toMatchObject({ error: { code: 'DID_DEACTIVATED' } });
    expect((await app.inject({ method: 'GET', url: '/accounts/acct%3Af61a7e0a9c25/did.json' })).statusCode, 'the old acct: form names nothing').toBe(404);
    await app.close();
  });
});
