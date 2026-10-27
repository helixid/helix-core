import { describe, expect, it } from 'vitest';
import Fastify, { type FastifyRequest } from 'fastify';
import { HelixError, ErrorCode, buildDIDDocument } from '../../src/core/index.js';
import { errorHandler } from '../../src/middleware/errorHandler.js';
import didRoutes, { type DIDRouteAction, type DIDRouteOptions } from '../../src/routes/did/index.js';
import type { IDIDService } from '../../src/services/did/did.service.js';

const DID = 'did:key:z6MkgHKqmKyCQroyo3RVx3gM1LXwUNwzZkynmsqwhYNqNjdn';
const PUBLIC_KEY = 'a'.repeat(64);
const ENDPOINT = { id: '#s1', type: 'LinkedDomains', serviceEndpoint: 'https://a.example' };

/** Every write the plugin exposes, so each authorization rule is checked on all of them. */
const WRITES = [
  { name: 'create', method: 'POST' as const, url: '/v1/dids', payload: { publicKeyHex: PUBLIC_KEY, subjectType: 'agent' } },
  { name: 'add endpoint', method: 'POST' as const, url: `/v1/dids/${encodeURIComponent(DID)}/services`, payload: ENDPOINT },
  { name: 'remove endpoint', method: 'DELETE' as const, url: `/v1/dids/${encodeURIComponent(DID)}/services/s1`, payload: undefined },
  { name: 'deactivate', method: 'POST' as const, url: `/v1/dids/${encodeURIComponent(DID)}/deactivate`, payload: undefined },
];

async function makeApp(options: Omit<DIDRouteOptions, 'didService'>) {
  const performed: string[] = [];
  const document = buildDIDDocument(DID, PUBLIC_KEY);
  const didService = {
    createDID: async () => {
      performed.push('create');
      return { did: DID, didDocument: document, hederaTransactionId: null };
    },
    addServiceEndpoint: async () => {
      performed.push('add endpoint');
      return document;
    },
    removeServiceEndpoint: async () => {
      performed.push('remove endpoint');
      return document;
    },
    deactivateDID: async () => {
      performed.push('deactivate');
    },
  } as unknown as IDIDService;
  const app = Fastify({ logger: false });
  app.addSchema({
    $id: 'Error',
    type: 'object',
    properties: { error: { type: 'object', additionalProperties: true } },
  });
  app.addSchema({ $id: 'NotFound', type: 'object', $ref: 'Error#' });
  app.addSchema({ $id: 'BadRequest', type: 'object', $ref: 'Error#' });
  app.addSchema({ $id: 'Conflict', type: 'object', $ref: 'Error#' });
  app.setErrorHandler(errorHandler);
  await app.register(didRoutes, { didService, ...options });
  await app.ready();
  return { app, performed };
}

describe('DID write routes: authorization', () => {
  it('self-hosted default: every write works with the admin key', async () => {
    const { app, performed } = await makeApp({ adminApiKey: 'k'.repeat(20) });
    for (const write of WRITES) {
      const res = await app.inject({ method: write.method, url: write.url, headers: { 'x-admin-api-key': 'k'.repeat(20) }, payload: write.payload });
      expect(res.statusCode, write.name).toBeLessThan(300);
    }
    expect(performed).toEqual(WRITES.map((write) => write.name));
    await app.close();
  });

  it('self-hosted default: every write refuses a missing or wrong admin key', async () => {
    const { app, performed } = await makeApp({ adminApiKey: 'k'.repeat(20) });
    for (const write of WRITES) {
      expect((await app.inject({ method: write.method, url: write.url, payload: write.payload })).statusCode, write.name).toBe(403);
      const wrong = await app.inject({ method: write.method, url: write.url, headers: { 'x-admin-api-key': 'wrong' }, payload: write.payload });
      expect(wrong.statusCode, write.name).toBe(403);
    }
    expect(performed).toEqual([]);
    // Reads stay open.
    expect((await app.inject({ method: 'GET', url: `/v1/dids/${encodeURIComponent(DID)}` })).statusCode).not.toBe(403);
    await app.close();
  });

  it('fails closed when no admin key and no authorizer are configured', async () => {
    const { app, performed } = await makeApp({});
    for (const write of WRITES) {
      expect((await app.inject({ method: write.method, url: write.url, headers: { 'x-admin-api-key': '' }, payload: write.payload })).statusCode, write.name).toBe(403);
    }
    expect(performed).toEqual([]);
    await app.close();
  });

  it('a custom authorizer sees each write as an action and decides', async () => {
    const seen: DIDRouteAction[] = [];
    const { app, performed } = await makeApp({
      authorize: (request: FastifyRequest, action: DIDRouteAction) => {
        seen.push(action);
        if (request.headers['x-owner'] !== 'yes') {
          throw new HelixError(ErrorCode.ACCOUNT_FORBIDDEN, 'not yours', 403);
        }
      },
    });
    for (const write of WRITES) {
      expect((await app.inject({ method: write.method, url: write.url, payload: write.payload })).statusCode, write.name).toBe(403);
      expect((await app.inject({ method: write.method, url: write.url, headers: { 'x-owner': 'yes' }, payload: write.payload })).statusCode, write.name).toBeLessThan(300);
    }
    expect(seen.filter((_, index) => index % 2 === 1)).toEqual([
      { action: 'create', subjectType: 'agent' },
      { action: 'update', did: DID },
      { action: 'update', did: DID },
      { action: 'deactivate', did: DID },
    ]);
    expect(performed).toEqual(WRITES.map((write) => write.name));
    await app.close();
  });
});
