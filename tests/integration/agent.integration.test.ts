import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import agentRoutes from '../../src/routes/agent/index.js';
import { AgentRepository } from '../../src/repositories/agent.repository.js';
import { AgentKeyRepository } from '../../src/repositories/agent-key.repository.js';
import { PreparedPayloadRepository } from '../../src/repositories/prepared-payload.repository.js';
import { AgentService } from '../../src/services/agent/agent.service.js';
import { PreparedPayloadService } from '../../src/services/prepared-payload/prepared-payload.service.js';
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

  describe('delegate', () => {
    // Builds an app around an agent whose custodial key is real (genuinely
    // generated + AES-GCM encrypted) and whose DID document actually
    // resolves to that key's public half — unlike makeApp()'s shared
    // MockDIDService (fixed document, used only for signVP which never
    // verifies against it). Delegation's finalize step does verify the
    // signature against DID resolution, so the mock has to be honest here.
    function makeDelegationApp(delegatorDid: string) {
      const keyCustody = new AesGcmKeyCustody('11'.repeat(32));
      const { publicKey, encrypted } = keyCustody.generateAndEncrypt();

      const didService = new MockDIDService({
        id: delegatorDid,
        verificationMethod: [
          { id: `${delegatorDid}#key-1`, type: 'Ed25519VerificationKey2020', publicKeyHex: publicKey },
        ],
      });

      const agentKeyRepository = new AgentKeyRepository();
      const vcService = new MockVCService();
      const preparedPayloadService = new PreparedPayloadService(new PreparedPayloadRepository(), didService);
      const service = new AgentService(
        new AgentRepository(),
        didService,
        vcService,
        new TestAuditLogger(),
        agentKeyRepository,
        keyCustody,
        preparedPayloadService,
      );

      const app = Fastify();
      app.register(agentRoutes, { prefix: '/v1', agentService: service, adminApiKey: TEST_ADMIN_KEY });
      return { app, agentKeyRepository, vcService, encrypted };
    }

    it('delegates a scope from an onboarded agent to another DID, admin-key gated', async () => {
      const delegatorDid = 'did:hedera:testnet:delegator-1';
      const subAgentDid = 'did:key:z6MkSubAgentPlaceholder';
      const { app, agentKeyRepository, vcService, encrypted } = makeDelegationApp(delegatorDid);
      await agentKeyRepository.create({ did: delegatorDid, ...encrypted });
      vcService.setActiveVC({
        id: 'vc:test:delegator',
        type: ['VerifiableCredential', 'HelixAgentCredential'],
        credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders'], maxDelegationDepth: 1 },
      });

      const res = await app.inject({
        method: 'POST',
        url: `/v1/agents/${encodeURIComponent(delegatorDid)}/delegate`,
        headers: { 'x-admin-api-key': TEST_ADMIN_KEY },
        payload: { to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600 },
      });

      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.delegatedVC.credentialSubject.id).toBe(subAgentDid);
      expect(body.delegatedVC.credentialSubject.privilegeScopes).toEqual(['read:orders']);
      expect(body.delegatedVC.credentialSubject.delegationDepth).toBe(1);
      expect(body.delegatedVC.proof).toBeTruthy();
    });

    it('rejects delegating without the admin key', async () => {
      const delegatorDid = 'did:hedera:testnet:delegator-2';
      const { app, agentKeyRepository, vcService, encrypted } = makeDelegationApp(delegatorDid);
      await agentKeyRepository.create({ did: delegatorDid, ...encrypted });
      vcService.setActiveVC({
        id: 'vc:test:delegator',
        type: ['VerifiableCredential', 'HelixAgentCredential'],
        credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders'], maxDelegationDepth: 1 },
      });

      const res = await app.inject({
        method: 'POST',
        url: `/v1/agents/${encodeURIComponent(delegatorDid)}/delegate`,
        payload: { to: 'did:key:z6MkSubAgentPlaceholder', scopes: ['read:orders'], expiresIn: 3600 },
      });

      expect(res.statusCode).toBe(403);
    });

    it('blocks delegation when the delegator\'s only credential has no remaining depth budget', async () => {
      const delegatorDid = 'did:hedera:testnet:delegator-3';
      const { app, agentKeyRepository, vcService, encrypted } = makeDelegationApp(delegatorDid);
      await agentKeyRepository.create({ did: delegatorDid, ...encrypted });
      // maxDelegationDepth: 0 -- this agent has no delegation authority, so
      // the default (no-vcId) auto-resolution filters this credential out
      // of the candidate list entirely rather than reaching
      // prepareDelegation's own depth check -- from the caller's point of
      // view, there's simply no eligible credential to delegate from.
      vcService.setActiveVC({
        id: 'vc:test:delegator',
        type: ['VerifiableCredential', 'HelixAgentCredential'],
        credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders'], maxDelegationDepth: 0 },
      });

      const res = await app.inject({
        method: 'POST',
        url: `/v1/agents/${encodeURIComponent(delegatorDid)}/delegate`,
        headers: { 'x-admin-api-key': TEST_ADMIN_KEY },
        payload: { to: 'did:key:z6MkSubAgentPlaceholder', scopes: ['read:orders'], expiresIn: 3600 },
      });

      expect(res.statusCode).toBe(404);
      expect(res.json().error.code).toBe('AGENT_ACTIVE_CREDENTIAL_NOT_FOUND');
    });

    it('surfaces MAX_DELEGATION_DEPTH_EXCEEDED when a depth-exhausted credential is pinned explicitly by vcId', async () => {
      const delegatorDid = 'did:hedera:testnet:delegator-4';
      const { app, agentKeyRepository, vcService, encrypted } = makeDelegationApp(delegatorDid);
      await agentKeyRepository.create({ did: delegatorDid, ...encrypted });
      vcService.setActiveVC({
        id: 'vc:test:delegator-4',
        type: ['VerifiableCredential', 'HelixAgentCredential'],
        credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders'], maxDelegationDepth: 0 },
      });

      const res = await app.inject({
        method: 'POST',
        url: `/v1/agents/${encodeURIComponent(delegatorDid)}/delegate`,
        headers: { 'x-admin-api-key': TEST_ADMIN_KEY },
        payload: {
          to: 'did:key:z6MkSubAgentPlaceholder',
          scopes: ['read:orders'],
          expiresIn: 3600,
          vcId: 'vc:test:delegator-4',
        },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().error.code).toBe('MAX_DELEGATION_DEPTH_EXCEEDED');
    });
  });

});
