import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import supertest from 'supertest';
import { HelixClient } from '@helixid/sdk-js';
import {
  LIVE_HEDERA_TIMEOUT_MS,
  onboardLiveAgent,
  resetLiveTestDatabase,
  signLiveVP,
  startLiveApi,
  type LiveApi,
} from '../utils/liveApi.js';

describe('Onboarding Live Integration', () => {
  let api: LiveApi;

  beforeAll(async () => {
    await resetLiveTestDatabase();
    api = await startLiveApi();
  });

  afterAll(async () => {
    await api?.stop();
  });

  it('onboards an agent server-side in one call and persists DID, VC, key, and audit state — no wallet', async () => {
    const client = new HelixClient(api.baseUrl, { adminApiKey: api.adminApiKey });
    const agent = await onboardLiveAgent(api, {
      agentName: 'Live Onboarding Agent',
      requestedScopes: ['read:orders', 'write:orders'],
      requestedDomains: ['https://live-onboarding.agent.example.com'],
    });

    // Agent DIDs are minted per the server's configured DID_METHOD (see
    // DIDService.createDID) — did:hedera in production, but did:key/did:web
    // work equally well and need no Hedera network at all, so this only
    // pins the shape, not a specific method.
    expect(agent.did).toMatch(/^did:(hedera:testnet:[a-zA-Z0-9._-]+|key:z\w+|web:[\w.:%-]+)$/);
    expect(agent.vcId).toMatch(/^vc:helix:/);

    const didRes = await supertest(api.baseUrl).get(`/v1/dids/${agent.did}`);
    expect(didRes.statusCode).toBe(200);
    expect(didRes.body.id).toBe(agent.did);
    expect(didRes.body.service[0].serviceEndpoint).toBe('https://live-onboarding.agent.example.com');

    // Storage-agnostic: goes through the public API rather than a raw
    // Prisma/Postgres query, so this passes under any configured storage
    // adapter (sqlite in this sandbox, Postgres elsewhere).
    const vcRecord = await client.getVC(agent.vcId);
    expect((vcRecord.vc as Record<string, unknown>)['issuer']).toBe(api.issuerDid);
    expect(vcRecord.status).toBe('active');
    expect((vcRecord.vc as { credentialSubject: { id: string; type: string } })['credentialSubject']).toMatchObject({
      id: agent.did,
      type: 'HelixAgent',
    });
    expect((vcRecord.vc as { proof: { verificationMethod: string } })['proof'].verificationMethod).toBe(
      `${api.issuerDid}#key-1`,
    );

    // No wallet file, no client-held key — the server generated and holds
    // the agent's private key itself (AgentKey table). The only way to act
    // as this agent afterward is the server-side sign API.
    const signedVP = await signLiveVP(api, agent.did, { targetService: 'amazon' });
    expect(signedVP.holder).toBe(agent.did);
    expect(signedVP.proof).toBeTruthy();

    const auditLog = await client.getAuditLog({ limit: 100 });
    const auditTypes = auditLog.map((entry) => entry.eventType);
    expect(auditTypes).toEqual(expect.arrayContaining([
      'ENROLLMENT_TOKEN_GENERATED',
      'ENROLLMENT_TOKEN_CONSUMED',
      'CHALLENGE_ISSUED',
      'CHALLENGE_VERIFIED',
      'DID_CREATED',
      'VC_ISSUED',
      'AGENT_ONBOARDED',
      'AGENT_VP_SIGNED',
    ]));
  }, LIVE_HEDERA_TIMEOUT_MS);
});
