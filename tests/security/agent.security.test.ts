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

function makeApp(auditLogger = new TestAuditLogger()) {
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
    auditLogger,
    new AgentKeyRepository(),
    new AesGcmKeyCustody('11'.repeat(32)),
  );
  app.register(agentRoutes, { prefix: '/v1', agentService: service, adminApiKey: 'test-admin-key' });
  return { app, auditLogger };
}

describe('agent security', () => {
  it('prevents enrollment token replay', async () => {
    const { app } = makeApp();
    const tokenRes = await app.inject({
      method: 'POST',
      url: '/v1/enrollment-tokens',
      payload: { agentName: 'Agent', requestedScopes: ['read:orders'] }
    });
    const token = tokenRes.json().token as string;
    const first = await app.inject({
      method: 'POST',
      url: '/v1/onboard',
      payload: { enrollmentToken: token, domains: [] }
    });
    expect(first.statusCode).toBe(201);
    const second = await app.inject({
      method: 'POST',
      url: '/v1/onboard',
      payload: { enrollmentToken: token, domains: [] }
    });
    expect(second.statusCode).toBe(409);
    expect(second.json().error.code).toBe('ENROLLMENT_TOKEN_ALREADY_USED');
  });

  it('does not leak raw enrollment token in audit log payloads', async () => {
    const { app, auditLogger } = makeApp();
    const tokenRes = await app.inject({
      method: 'POST',
      url: '/v1/enrollment-tokens',
      payload: { agentName: 'Agent', requestedScopes: ['read:orders'] }
    });
    const token = tokenRes.json().token as string;
    await app.inject({
      method: 'POST',
      url: '/v1/onboard',
      payload: { enrollmentToken: token, domains: [] }
    });
    const allLogs = JSON.stringify(auditLogger.events);
    expect(allLogs.includes(token)).toBe(false);
  });

  it('rejects VP signing for an agent DID that has no server-held key', async () => {
    const { app } = makeApp();
    const vp = await app.inject({
      method: 'POST',
      url: '/v1/agents/did:hedera:testnet:unknown/vp',
      headers: { 'x-admin-api-key': 'test-admin-key' },
      payload: { targetService: 'https://svc.example.com' }
    });
    expect(vp.statusCode).toBe(404);
    expect(vp.json().error.code).toBe('AGENT_KEY_NOT_FOUND');
  });
});
