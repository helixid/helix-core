// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: the credential-split routes end to end over in-memory storage.
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import agentRoutes from '../../src/routes/agent/index.js';
import credentialRoutes, { type CredentialRouteAction } from '../../src/routes/credentials/index.js';
import {
  EnvSigner,
  buildCapabilityAttestation,
  derivePublicKey,
  evaluateDelegationChain,
  isCapabilityAttestation,
  isDelegationHop,
  isIdentityCredential,
  publicKeyToMultibase,
  resolveDID,
  verifyCapabilityAttestation,
  verifyIdentityCredential,
  type JwsDidDocument,
} from '../../src/core/index.js';
import { AgentRepository } from '../../src/repositories/agent.repository.js';
import { DidKeyRepository } from '../../src/repositories/did-key.repository.js';
import { VcRepository } from '../../src/repositories/vc.repository.js';
import { AgentService } from '../../src/services/agent/agent.service.js';
import { CredentialService } from '../../src/services/credentials/credential.service.js';
import { AesGcmKeyCustody } from '../../src/services/key-custody/key-custody.js';
import { MockDIDService } from '../mocks/MockDIDService.js';
import { MockVCService } from '../mocks/MockVCService.js';
import { TestAuditTrail } from '../utils/TestAuditTrail.js';

const ADMIN = 'test-admin-key';
const ISSUER_KEY = 'a'.repeat(64);
const OWNER_KEY = 'b'.repeat(64);
const ISSUER_DID = `did:key:${publicKeyToMultibase(derivePublicKey(ISSUER_KEY))}`;
const OWNER_DID = `did:key:${publicKeyToMultibase(derivePublicKey(OWNER_KEY))}`;
const LIST_URL = 'http://localhost:3000/v1/status-list/helix-status-list-1';
const RESOURCE = 'did:web:service.example:orders';
const resolve = async (did: string): Promise<JwsDidDocument> => (await resolveDID(did)) as unknown as JwsDidDocument;

function makeApp(withCredentials = true, hook?: { authorize: (request: unknown, action: CredentialRouteAction) => void; actions: CredentialRouteAction[] }) {
  const app = Fastify();
  const didService = new MockDIDService({ id: 'did:hedera:testnet:user-1', verificationMethod: [{ id: 'did:hedera:testnet:user-1#key-1', type: 'Ed25519VerificationKey2020', publicKeyHex: 'a'.repeat(64) }] });
  const keyRepository = new DidKeyRepository();
  const keyCustody = new AesGcmKeyCustody('11'.repeat(32));
  const audit = new TestAuditTrail();
  const vcRepository = new VcRepository();
  void vcRepository.createStatusList('helix-status-list-1', 'list');
  let nextIndex = 0;
  const credentialService = new CredentialService(
    vcRepository,
    {
      claimStatusListEntry: async () => ({ statusListCredentialUrl: LIST_URL, statusListIndex: (nextIndex += 1) }),
      revokeVC: async (vcId) => {
        await vcRepository.revokeVc(vcId, 'helix-status-list-1', 'list');
        return { vcId, revoked: true, revokedAt: new Date().toISOString() };
      },
    },
    didService,
    new EnvSigner({ did: ISSUER_DID, envVar: 'TEST_ISSUER_KEY', env: { TEST_ISSUER_KEY: ISSUER_KEY } }),
    keyRepository,
    keyCustody,
    audit,
  );
  const agentService = new AgentService(new AgentRepository(), didService, new MockVCService(), audit, keyRepository, keyCustody, credentialService);
  if (hook) {
    // A build with accounts: the agent routes without the credential routes, which it mounts with its own gate.
    app.register(agentRoutes, { prefix: '/v1', agentService, adminApiKey: ADMIN, credentialRoutes: false });
    app.register(credentialRoutes, { prefix: '/v1', credentialService, authorize: (request, action) => { hook.actions.push(action); hook.authorize(request, action); } });
  } else {
    app.register(agentRoutes, { prefix: '/v1', agentService, ...(withCredentials ? { credentialService } : {}), adminApiKey: ADMIN });
  }
  return app;
}

type App = ReturnType<typeof makeApp>;
const admin = { 'x-admin-api-key': ADMIN };

async function onboard(app: App, scopes: string[], ownerDid?: string) {
  const token = (await app.inject({ method: 'POST', url: '/v1/enrollment-tokens', payload: { agentName: 'orders-agent', requestedScopes: scopes } })).json().token as string;
  const response = await app.inject({ method: 'POST', url: '/v1/agents', payload: { enrollmentToken: token, ...(ownerDid ? { ownerDid } : {}) } });
  expect(response.statusCode).toBe(201);
  return response.json() as { agentDid: string; identity: Record<string, unknown>; attestations: Record<string, unknown>[] };
}

describe('POST /v1/agents', () => {
  it('returns an identity with no scopes and one attestation per scope, all valid against their schemas and proofs', async () => {
    const app = makeApp();
    const { agentDid, identity, attestations } = await onboard(app, ['read:orders', 'read:catalog'], OWNER_DID);
    expect(Object.keys(identity.credentialSubject as object).sort()).toEqual(['id', 'name', 'responsibleParty']);
    expect(identity.credentialSubject).toEqual({ id: agentDid, name: 'orders-agent', responsibleParty: OWNER_DID });
    expect(isIdentityCredential(identity)).toBe(true);
    expect((await verifyIdentityCredential(identity, resolve, { agentDid })).ok).toBe(true);
    expect(attestations.map((a) => (a.credentialSubject as { capability: string }).capability)).toEqual(['read:orders', 'read:catalog']);
    for (const attestation of attestations) {
      expect(isCapabilityAttestation(attestation)).toBe(true);
      expect((await verifyCapabilityAttestation(attestation, resolve, { subjectDid: agentDid })).ok).toBe(true);
    }
    // The responsible party is the Helix issuer when the request names no owner.
    const second = await onboard(app, ['read:orders']);
    expect((second.identity.credentialSubject as { responsibleParty: string }).responsibleParty).toBe(ISSUER_DID);
  });

  it('keeps POST /v1/onboard answering { agentDid, vcId } with the identity id', async () => {
    const app = makeApp();
    const token = (await app.inject({ method: 'POST', url: '/v1/enrollment-tokens', payload: { agentName: 'a', requestedScopes: ['read:orders'] } })).json().token as string;
    const response = await app.inject({ method: 'POST', url: '/v1/onboard', payload: { enrollmentToken: token } });
    expect(response.statusCode).toBe(201);
    expect(Object.keys(response.json()).sort()).toEqual(['agentDid', 'vcId']);
    const credentials = (await app.inject({ method: 'GET', url: `/v1/agents/${encodeURIComponent(response.json().agentDid)}/credentials`, headers: admin })).json();
    expect(credentials.identity.vcId).toBe(response.json().vcId);
  });

  it('relays an onboarding failure', async () => {
    const app = makeApp();
    const response = await app.inject({ method: 'POST', url: '/v1/agents', payload: { enrollmentToken: 'enroll:nope' } });
    expect(response.statusCode).toBe(404);
    expect(response.json().error.code).toBe('ENROLLMENT_TOKEN_NOT_FOUND');
  });
});

describe('attestations', () => {
  it('revoking one scope leaves the identity valid and drops only that scope; the Helix copy shows it revoked', async () => {
    const app = makeApp();
    const { agentDid, identity } = await onboard(app, ['read:orders', 'write:orders']);
    const revoke = await app.inject({ method: 'DELETE', url: `/v1/agents/${encodeURIComponent(agentDid)}/attestations/${encodeURIComponent('write:orders')}`, headers: admin });
    expect(revoke.statusCode).toBe(200);
    expect(revoke.json()).toMatchObject({ agentDid, capability: 'write:orders', revokedVcIds: [expect.any(String)] });
    const copies = (await app.inject({ method: 'GET', url: `/v1/agents/${encodeURIComponent(agentDid)}/credentials`, headers: admin })).json();
    expect(copies.identity).toMatchObject({ vcId: identity.id, status: 'active' });
    const statusByScope = Object.fromEntries(
      copies.attestations.map((a: { status: string; credential: { credentialSubject: { capability: string } } }) => [a.credential.credentialSubject.capability, a.status]),
    );
    expect(statusByScope).toEqual({ 'read:orders': 'active', 'write:orders': 'revoked' });
    const active = copies.attestations.filter((a: { status: string }) => a.status === 'active').map((a: { credential: { credentialSubject: { capability: string } } }) => a.credential.credentialSubject.capability);
    expect(active).toEqual(['read:orders']);
    expect((await app.inject({ method: 'DELETE', url: `/v1/agents/${encodeURIComponent(agentDid)}/attestations/write%3Aorders`, headers: admin })).statusCode).toBe(404);
  });

  it('issues a Helix-signed attestation, keeps an owner-signed one, and validates the body', async () => {
    const app = makeApp();
    const { agentDid } = await onboard(app, ['read:orders']);
    const url = `/v1/agents/${encodeURIComponent(agentDid)}/attestations`;
    const issued = await app.inject({ method: 'POST', url, headers: admin, payload: { capability: 'read:catalog', validUntil: '2027-01-01T00:00:00Z' } });
    expect(issued.statusCode).toBe(201);
    expect(issued.json().attestation).toMatchObject({ issuer: ISSUER_DID, validUntil: '2027-01-01T00:00:00.000Z', credentialSubject: { id: agentDid, capability: 'read:catalog' } });
    const ownerSigner = new EnvSigner({ did: OWNER_DID, envVar: 'K', env: { K: OWNER_KEY } });
    const signed = await buildCapabilityAttestation(
      { subjectDid: agentDid, capability: 'write:orders', validUntil: '2027-01-01T00:00:00Z', statusEntry: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '77', statusListCredential: LIST_URL } },
      ownerSigner,
    );
    const kept = await app.inject({ method: 'POST', url, headers: admin, payload: { attestation: signed } });
    expect(kept.statusCode).toBe(201);
    expect(kept.json().attestation.issuer).toBe(OWNER_DID);
    expect((await app.inject({ method: 'POST', url, headers: admin, payload: { attestation: { ...signed, issuer: ISSUER_DID } } })).statusCode).toBe(400);
    expect((await app.inject({ method: 'POST', url, headers: admin, payload: {} })).statusCode).toBe(400);
    expect((await app.inject({ method: 'POST', url, headers: admin, payload: { capability: 'x', validUntil: 'soon' } })).statusCode).toBe(400);
    expect((await app.inject({ method: 'POST', url, payload: { capability: 'x' } })).statusCode).toBe(403);
    const copies = (await app.inject({ method: 'GET', url: `/v1/agents/${encodeURIComponent(agentDid)}/credentials`, headers: admin })).json();
    expect(copies.attestations).toHaveLength(3);
  });
});

describe('grants (delegation hops)', () => {
  it('re-delegates to a sub-agent: the parent-issued hop verifies, and a broadening, caveat-dropping or extended hop is refused', async () => {
    const app = makeApp();
    const parent = await onboard(app, ['read:orders', 'write:orders']);
    const child = await onboard(app, ['read:orders']);
    const grandchild = await onboard(app, ['read:orders']);
    // The child's identity is Helix-issued once; authority arrives as hops.
    expect(child.identity.issuer).toBe(ISSUER_DID);

    const root = await app.inject({
      method: 'POST',
      url: '/v1/grants',
      headers: admin,
      payload: { issuer: ISSUER_DID, invoker: parent.agentDid, invocationTarget: RESOURCE, allowedAction: ['read:orders', 'write:orders'], caveats: [{ type: 'MaxAmount', limit: '100', currency: 'USD' }], validUntil: '2027-01-01T00:00:00Z' },
    });
    expect(root.statusCode).toBe(201);
    const rootHop = root.json().hop;
    expect(isDelegationHop(rootHop)).toBe(true);

    const hop = await app.inject({ method: 'POST', url: `/v1/grants/${encodeURIComponent(rootHop.id)}/hops`, headers: admin, payload: { invoker: child.agentDid, allowedAction: ['read:orders'], caveats: [{ type: 'MaxAmount', limit: '50', currency: 'USD' }] } });
    expect(hop.statusCode).toBe(201);
    expect(hop.json().hop.issuer).toBe(parent.agentDid);
    expect(hop.json().chain.map((h: { id: string }) => h.id)).toEqual([rootHop.id, hop.json().hop.id]);
    // The DID service mock mints one fixed did:hedera for every agent, which no resolver can read,
    // so the proofs of custody-signed hops are verified in credential.service.test.ts (did:key agents).
    for (const h of hop.json().chain) expect(isDelegationHop(h)).toBe(true);
    expect(evaluateDelegationChain(hop.json().chain, { resource: RESOURCE })).toMatchObject({ ok: true, leafInvoker: child.agentDid, allowedAction: ['read:orders'] });

    const refused = async (payload: Record<string, unknown>): Promise<string> => {
      const response = await app.inject({ method: 'POST', url: `/v1/grants/${encodeURIComponent(hop.json().hop.id)}/hops`, headers: admin, payload });
      expect(response.statusCode).toBe(400);
      return response.json().error.message as string;
    };
    expect(await refused({ invoker: grandchild.agentDid, allowedAction: ['read:orders', 'write:orders'], caveats: [{ type: 'MaxAmount', limit: '1', currency: 'USD' }] })).toContain('allowedAction escalation');
    expect(await refused({ invoker: grandchild.agentDid, allowedAction: ['read:orders'] })).toContain('caveat "MaxAmount"');
    expect(await refused({ invoker: grandchild.agentDid, allowedAction: ['read:orders'], caveats: [{ type: 'MaxAmount', limit: '1', currency: 'USD' }], validUntil: '2028-01-01T00:00:00Z' })).toContain('validUntil broadened');
    expect(await refused({ invoker: grandchild.agentDid, allowedAction: 'read:orders' })).toContain('allowedAction');
    expect(await refused({ invoker: grandchild.agentDid, allowedAction: ['read:orders'], caveats: 'none' })).toContain('caveats');
    expect(await refused({ allowedAction: ['read:orders'] })).toContain('invoker');

    const chain = await app.inject({ method: 'GET', url: `/v1/grants/${encodeURIComponent(hop.json().hop.id)}/chain`, headers: admin });
    expect(chain.json().chain).toHaveLength(2);
    expect((await app.inject({ method: 'GET', url: '/v1/grants/urn:zcap:missing/chain', headers: admin })).statusCode).toBe(404);

    const revoke = await app.inject({ method: 'DELETE', url: `/v1/grants/${encodeURIComponent(rootHop.id)}`, headers: admin });
    expect(revoke.json().revokedVcIds).toEqual([hop.json().hop.id, rootHop.id]);
    expect((await app.inject({ method: 'DELETE', url: '/v1/grants/urn:zcap:missing', headers: admin })).statusCode).toBe(404);
  });

  it('validates the root body and gates every route on the admin key', async () => {
    const app = makeApp();
    expect((await app.inject({ method: 'POST', url: '/v1/grants', headers: admin, payload: { invoker: 'did:key:z6Mk1', invocationTarget: RESOURCE, allowedAction: [] } })).json().error.message).toContain('issuer is required');
    expect((await app.inject({ method: 'POST', url: '/v1/grants', headers: admin, payload: { issuer: 'did:key:z6MkNobody', invoker: 'did:key:z6Mk1', invocationTarget: RESOURCE, allowedAction: [] } })).statusCode).toBe(404);
    for (const [method, url] of [
      ['POST', '/v1/grants'],
      ['POST', '/v1/grants/x/hops'],
      ['GET', '/v1/grants/x/chain'],
      ['DELETE', '/v1/grants/x'],
      ['GET', '/v1/agents/did:x/credentials'],
      ['DELETE', '/v1/agents/did:x/attestations/y'],
    ] as const) {
      expect((await app.inject({ method, url })).statusCode, `${method} ${url}`).toBe(403);
    }
  });

  it('answers 503 when the server is not configured for credential issuance', async () => {
    const app = makeApp(false);
    const response = await app.inject({ method: 'GET', url: '/v1/agents/did:x/credentials', headers: admin });
    expect(response.statusCode).toBe(503);
  });
});

describe('credential routes behind a host authorize hook (F-3 parity: an account-scoped build)', () => {
  it('asks the hook with what each request would do, hop actions with their stored chain, and stops on a refusal before anything is issued', async () => {
    const owners = new Set<string>();
    const hook = {
      actions: [] as CredentialRouteAction[],
      authorize: (_request: unknown, action: CredentialRouteAction) => {
        const did = 'agentDid' in action ? action.agentDid : action.action === 'issueRootHop' ? action.issuer : action.action === 'issueHop' ? action.delegator : action.chain[0]?.issuer;
        if (did === undefined || !owners.has(did)) throw Object.assign(new Error('not yours'), { code: 'VC_NOT_FOUND', httpStatus: 404 });
      },
    };
    const app = makeApp(true, hook);
    // Onboard through the hooked app's own agent routes (still admin-free enrollment).
    // The mock DID service gives every onboarded agent the same DID; "someone else's" is a DID the hook does not own.
    const parent = await onboard(app as App, ['read:orders']);
    const child = { agentDid: 'did:key:z6MkSomeoneElsesAgent' };
    owners.add(ISSUER_DID);
    owners.add(parent.agentDid);

    const listed = await app.inject({ method: 'GET', url: `/v1/agents/${encodeURIComponent(parent.agentDid)}/credentials` });
    expect(listed.statusCode, listed.body).toBe(200);
    expect((await app.inject({ method: 'GET', url: `/v1/agents/${encodeURIComponent(child.agentDid)}/credentials` })).statusCode).toBe(404);
    expect((await app.inject({ method: 'POST', url: `/v1/agents/${encodeURIComponent(parent.agentDid)}/attestations`, payload: { capability: 'read:catalog' } })).statusCode).toBe(201);
    expect((await app.inject({ method: 'DELETE', url: `/v1/agents/${encodeURIComponent(parent.agentDid)}/attestations/read%3Acatalog` })).statusCode).toBe(200);

    const root = await app.inject({ method: 'POST', url: '/v1/grants', payload: { issuer: ISSUER_DID, invoker: parent.agentDid, invocationTarget: RESOURCE, allowedAction: ['read:orders'] } });
    expect(root.statusCode, root.body).toBe(201);
    const rootId = root.json().hop.id as string;
    const refusedRoot = await app.inject({ method: 'POST', url: '/v1/grants', payload: { issuer: child.agentDid, invoker: parent.agentDid, invocationTarget: RESOURCE, allowedAction: ['read:orders'] } });
    expect(refusedRoot.statusCode).toBe(404);
    // The parent's invoker (parent agent, a did_keys custodial key) re-delegates.
    const hop = await app.inject({ method: 'POST', url: `/v1/grants/${encodeURIComponent(rootId)}/hops`, payload: { invoker: child.agentDid, allowedAction: ['read:orders'] } });
    expect(hop.statusCode, hop.body).toBe(201);
    expect((await app.inject({ method: 'GET', url: `/v1/grants/${encodeURIComponent(hop.json().hop.id)}/chain` })).statusCode).toBe(200);
    expect((await app.inject({ method: 'POST', url: '/v1/grants/urn:zcap:missing/hops', payload: { invoker: child.agentDid, allowedAction: ['read:orders'] } })).statusCode).toBe(404);
    expect((await app.inject({ method: 'GET', url: '/v1/grants/urn:zcap:missing/chain' })).statusCode).toBe(404);
    expect((await app.inject({ method: 'DELETE', url: `/v1/grants/${encodeURIComponent(rootId)}` })).statusCode).toBe(200);

    expect(hook.actions.map((action) => action.action)).toEqual([
      'readCredentials', 'readCredentials', 'attest', 'revokeAttestation', 'issueRootHop', 'issueRootHop', 'issueHop', 'readChain', 'revokeHop',
    ]);
    const issueHop = hook.actions.find((action) => action.action === 'issueHop') as Extract<CredentialRouteAction, { action: 'issueHop' }>;
    expect(issueHop).toMatchObject({ parentId: rootId, delegator: parent.agentDid, invoker: child.agentDid });
    expect(issueHop.chain.map((entry) => entry.id)).toEqual([rootId]);
    // The refused root issued nothing: one root, one hop.
    expect((await app.inject({ method: 'GET', url: `/v1/agents/${encodeURIComponent(parent.agentDid)}/credentials` })).json().hops).toHaveLength(1);
  });

  it('the host gate needs no admin key, and the agent routes alone no longer serve the credential paths', async () => {
    const app = makeApp(true, { actions: [], authorize: () => undefined });
    expect((await app.inject({ method: 'GET', url: '/v1/agents/did:x/credentials' })).statusCode).toBe(200);
    const bare = Fastify();
    bare.register(agentRoutes, { prefix: '/v1', agentService: {} as never, adminApiKey: ADMIN, credentialRoutes: false });
    expect((await bare.inject({ method: 'GET', url: '/v1/agents/did:x/credentials', headers: admin })).statusCode).toBe(404);
  });
});
