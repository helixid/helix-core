import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import agentRoutes from '../../src/routes/agent/index.js';
import { AgentRepository } from '../../src/repositories/agent.repository.js';
import { DidKeyRepository } from '../../src/repositories/did-key.repository.js';
import { AgentService } from '../../src/services/agent/agent.service.js';
import { CredentialService } from '../../src/services/credentials/credential.service.js';
import { AesGcmKeyCustody } from '../../src/services/key-custody/key-custody.js';
import { EnvSigner, derivePublicKey, publicKeyToMultibase } from '../../src/core/index.js';
import { VcRepository } from '../../src/repositories/vc.repository.js';
import { MockDIDService } from '../mocks/MockDIDService.js';
import { MockVCService } from '../mocks/MockVCService.js';
import { TestAuditTrail } from '../utils/TestAuditTrail.js';

const ISSUER_KEY = 'a'.repeat(64);
const ISSUER_DID = `did:key:${publicKeyToMultibase(derivePublicKey(ISSUER_KEY))}`;

function makeApp(auditLogger = new TestAuditTrail()) {
  const app = Fastify();
  const didService = new MockDIDService({
    id: 'did:hedera:testnet:user-1',
    verificationMethod: [
      {
        id: 'did:hedera:testnet:user-1#key-1',
        type: 'Ed25519VerificationKey2020',
        publicKeyHex: 'a'.repeat(64)
      }
    ]
  });
  const keyRepository = new DidKeyRepository();
  const keyCustody = new AesGcmKeyCustody('11'.repeat(32));
  let nextIndex = 0;
  // KYA-OS story F-1: onboarding issues the split credential set through this service.
  const credentialService = new CredentialService(
    new VcRepository(),
    {
      claimStatusListEntry: async () => ({ statusListCredentialUrl: 'http://localhost:3000/v1/status-list/helix-status-list-1', statusListIndex: (nextIndex += 1) }),
      revokeVC: async (vcId) => ({ vcId, revoked: true, revokedAt: new Date().toISOString() }),
    },
    didService,
    new EnvSigner({ did: ISSUER_DID, envVar: 'TEST_ISSUER_KEY', env: { TEST_ISSUER_KEY: ISSUER_KEY } }),
    keyRepository,
    keyCustody,
    auditLogger,
  );
  const service = new AgentService(
    new AgentRepository(),
    didService,
    new MockVCService(),
    auditLogger,
    keyRepository,
    keyCustody,
    credentialService,
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
    await auditLogger.flush();
    // The onboarding did record: a token digest, never the token.
    expect(auditLogger.eventTypes).toEqual(
      expect.arrayContaining(['credential.required', 'credential.verified']),
    );
    const allLogs = JSON.stringify(auditLogger.events);
    expect(allLogs.includes(token)).toBe(false);
  });

  it('rejects VP signing for an agent DID that has no server-held key', async () => {
    const { app } = makeApp();
    const vp = await app.inject({
      method: 'POST',
      url: '/v1/agents/did:hedera:testnet:unknown/vp',
      headers: { 'x-admin-api-key': 'test-admin-key' },
      payload: { targetService: 'did:web:svc.example.com' }
    });
    expect(vp.statusCode).toBe(404);
    expect(vp.json().error.code).toBe('AGENT_KEY_NOT_FOUND');
  });
});
