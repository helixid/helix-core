import { describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import { ErrorCode } from '../../src/core/index.js';

import vcRoutes from '../../src/routes/vc/index.js';
import { MockVCService } from '../mocks/MockVCService.js';
import { errorHandler } from '../../src/middleware/errorHandler.js';

type RenewIdentity = (vcId: string, input: { expiresInSeconds?: number | undefined }, requestId: string) => Promise<unknown>;

async function makeApp(renewIdentity?: RenewIdentity): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({ logger: false });
  app.setErrorHandler(errorHandler);
  const vcService = Object.assign(new MockVCService(), {
    renewVC: vi.fn(async (vcId: string) => ({ vcId: `${vcId}:renewed`, previousVcId: vcId })),
  });
  await app.register(vcRoutes, {
    prefix: '/v1/vcs',
    vcService: vcService as never,
    ...(renewIdentity ? { credentialService: { renewIdentity } as never } : {}),
    adminApiKey: 'test-admin-key-0001',
  });
  await app.ready();
  return app;
}

describe('VC route surface', () => {
  it('lists VCs behind admin auth', async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: 'GET',
      url: '/v1/vcs?status=active&limit=10',
      headers: { 'x-admin-api-key': 'test-admin-key-0001' },
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual([
      expect.objectContaining({
        vcId: 'vc:test:1',
        subjectDid: 'did:web:agent.example.com',
        agentName: 'Test Agent',
        scopes: ['read'],
        status: 'active',
      }),
    ]);
    await app.close();
  });

  it('requires admin auth for VC listing', async () => {
    const app = await makeApp();

    const response = await app.inject({ method: 'GET', url: '/v1/vcs' });

    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error.code).toBe(ErrorCode.ADMIN_AUTH_REQUIRED);
    await app.close();
  });

  it('requires admin auth to register an externally-signed VC', async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: 'POST',
      url: '/v1/vcs/register',
      payload: { vc: { id: 'vc:grant:1' } },
    });

    expect(response.statusCode).toBe(403);
    expect(JSON.parse(response.body).error.code).toBe(ErrorCode.ADMIN_AUTH_REQUIRED);
    await app.close();
  });

  it('rejects a register call with no vc in the body', async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: 'POST',
      url: '/v1/vcs/register',
      headers: { 'x-admin-api-key': 'test-admin-key-0001' },
      payload: {},
    });

    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).error.code).toBe(ErrorCode.VALIDATION_ERROR);
    await app.close();
  });

  it('registers an externally-signed VC, and is idempotent on the same vcId', async () => {
    const app = await makeApp();
    const vc = { id: 'vc:grant:1', issuer: 'did:web:airline.example.com' };

    const first = await app.inject({
      method: 'POST',
      url: '/v1/vcs/register',
      headers: { 'x-admin-api-key': 'test-admin-key-0001' },
      payload: { vc },
    });

    expect(first.statusCode).toBe(201);
    expect(JSON.parse(first.body)).toEqual({ vcId: 'vc:grant:1', alreadyRegistered: false });

    // A retried consent callback must not fail or duplicate the grant.
    const second = await app.inject({
      method: 'POST',
      url: '/v1/vcs/register',
      headers: { 'x-admin-api-key': 'test-admin-key-0001' },
      payload: { vc },
    });

    expect(second.statusCode).toBe(200);
    expect(JSON.parse(second.body)).toEqual({ vcId: 'vc:grant:1', alreadyRegistered: true });
    await app.close();
  });

  it('renews an F-1 identity credential through the credential service when the id is one', async () => {
    const renewIdentity = vi.fn(async (vcId: string) => ({ vcId: 'urn:uuid:new', vc: { id: 'urn:uuid:new' }, previousVcId: vcId, expiresAt: null, statusListIndex: 3 }));
    const app = await makeApp(renewIdentity);

    const response = await app.inject({
      method: 'POST',
      url: '/v1/vcs/urn:uuid:old/renew',
      headers: { 'x-admin-api-key': 'test-admin-key-0001' },
      payload: { expiresInSeconds: 60 },
    });

    expect(response.statusCode).toBe(201);
    expect(JSON.parse(response.body)).toMatchObject({ vcId: 'urn:uuid:new', previousVcId: 'urn:uuid:old' });
    expect(renewIdentity).toHaveBeenCalledWith('urn:uuid:old', { expiresInSeconds: 60 }, expect.any(String));
    await app.close();
  });

  it('falls back to the VC service for ids that are not identity credentials, and without a credential service', async () => {
    const renewIdentity = vi.fn(async () => null);
    const withService = await makeApp(renewIdentity);
    const fallback = await withService.inject({
      method: 'POST',
      url: '/v1/vcs/vc:test:1/renew',
      headers: { 'x-admin-api-key': 'test-admin-key-0001' },
    });
    expect(fallback.statusCode).toBe(201);
    expect(renewIdentity).toHaveBeenCalledWith('vc:test:1', {}, expect.any(String));
    expect(JSON.parse(fallback.body)).toEqual({ vcId: 'vc:test:1:renewed', previousVcId: 'vc:test:1' });
    await withService.close();

    const withoutService = await makeApp();
    const legacy = await withoutService.inject({
      method: 'POST',
      url: '/v1/vcs/vc:test:1/renew',
      headers: { 'x-admin-api-key': 'test-admin-key-0001' },
      payload: {},
    });
    expect(legacy.statusCode).toBe(201);
    expect(JSON.parse(legacy.body)).toEqual({ vcId: 'vc:test:1:renewed', previousVcId: 'vc:test:1' });
    await withoutService.close();
  });

  it('does not expose API-side delegation', async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: 'POST',
      url: '/v1/vcs/delegate',
      headers: { 'x-admin-api-key': 'test-admin-key-0001' },
      payload: {
        delegatorVP: {},
        delegateeAgentDid: 'did:web:agent.example.com',
        requestedScopes: ['read:orders'],
      },
    });

    expect(response.statusCode).toBe(404);
    await app.close();
  });
});
