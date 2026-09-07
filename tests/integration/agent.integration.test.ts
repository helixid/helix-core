import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import agentRoutes from '../../src/routes/agent/index.js';
import { AgentRepository } from '../../src/repositories/agent.repository.js';
import { AgentKeyRepository } from '../../src/repositories/agent-key.repository.js';
import { AgentService } from '../../src/services/agent/agent.service.js';
import { AesGcmKeyCustody } from '../../src/services/key-custody/key-custody.js';
import { MockDIDService } from '../mocks/MockDIDService.js';
import { MockVCService } from '../mocks/MockVCService.js';
import { TestAuditLogger } from '../utils/TestAuditLogger.js';

const TEST_ADMIN_KEY = 'test-admin-key';

function makeApp() {
  const app = Fastify();
  const service = new AgentService(
    new AgentRepository(),
    new MockDIDService({
      id: 'did:hedera:testnet:user-1',
      verificationMethod: [
        {
          id: 'did:hedera:testnet:user-1#key-1',
          type: 'Ed25519VerificationKey2020',
          publicKeyHex: 'a'.repeat(64)
        }
      ]
    }),
    new MockVCService(),
    new TestAuditLogger(),
    new AgentKeyRepository(),
    new AesGcmKeyCustody('11'.repeat(32)),
  );
  app.register(agentRoutes, { prefix: '/v1', agentService: service, adminApiKey: TEST_ADMIN_KEY });
  return app;
}

describe('agent integration', () => {
  it('completes onboarding in one call, with no key material returned', async () => {
    const app = makeApp();
    const tokenRes = await app.inject({
      method: 'POST',
      url: '/v1/enrollment-tokens',
      payload: {
        agentName: 'My Agent',
        requestedScopes: ['read:orders'],
        requestedDomains: ['https://myagent.example.com']
      }
    });
    expect(tokenRes.statusCode).toBe(201);
    const tokenBody = tokenRes.json();

    const onboard = await app.inject({
      method: 'POST',
      url: '/v1/onboard',
      payload: {
        enrollmentToken: tokenBody.token,
        domains: ['https://myagent.example.com']
      }
    });
    expect(onboard.statusCode).toBe(201);
    const onboardBody = onboard.json();
    expect(onboardBody.agentDid).toContain('did:hedera:testnet:');
    expect(onboardBody.vcId).toBeTruthy();
    // No key material — not a publicKeyHex/privateKeyHex, wallet path, or anything else.
    expect(Object.keys(onboardBody).sort()).toEqual(['agentDid', 'vcId']);
  });

  it('returns used-token error on second onboard call', async () => {
    const app = makeApp();
    const tokenRes = await app.inject({
      method: 'POST',
      url: '/v1/enrollment-tokens',
      payload: { agentName: 'My Agent', requestedScopes: ['read:orders'] }
    });
    const token = tokenRes.json().token as string;
    await app.inject({
      method: 'POST',
      url: '/v1/onboard',
      payload: { enrollmentToken: token, domains: [] }
    });
    const second = await app.inject({
      method: 'POST',
      url: '/v1/onboard',
      payload: { enrollmentToken: token, domains: [] }
    });
    expect(second.statusCode).toBe(409);
    expect(second.json().error.code).toBe('ENROLLMENT_TOKEN_ALREADY_USED');
  });

  it('signs a VP for an onboarded agent when authenticated with the admin key', async () => {
    const app = makeApp();
    const tokenRes = await app.inject({
      method: 'POST',
      url: '/v1/enrollment-tokens',
      payload: { agentName: 'My Agent', requestedScopes: ['read:orders'] }
    });
    const token = tokenRes.json().token as string;
    const onboard = await app.inject({
      method: 'POST',
      url: '/v1/onboard',
      payload: { enrollmentToken: token, domains: [] }
    });
    const { agentDid } = onboard.json();

    const vp = await app.inject({
      method: 'POST',
      url: `/v1/agents/${encodeURIComponent(agentDid)}/vp`,
      headers: { 'x-admin-api-key': TEST_ADMIN_KEY },
      payload: { targetService: 'https://service.example.com' }
    });
    expect(vp.statusCode).toBe(200);
    expect(vp.json().signedVP.holder).toBe(agentDid);
    expect(vp.json().signedVP.proof).toBeTruthy();
  });

  it('rejects signing a VP without the admin key', async () => {
    const app = makeApp();
    const vp = await app.inject({
      method: 'POST',
      url: '/v1/agents/did:hedera:testnet:testid/vp',
      payload: { targetService: 'https://service.example.com' }
    });
    expect(vp.statusCode).toBe(403);
  });

});
