// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: agents and services created through the custody routes sign VPs, delegations and consent grants
// through the KeyStore (stories rule 8), are recognised as onboarded, and log the enrollment event.
import * as ed25519 from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import {
  AgentKeyNotFoundError,
  AuditEvents,
  DelegateeNotAnAgentError,
  ServiceKeyNotFoundError,
  createEd25519Proof,
  derivePublicKey,
  proofKeyOf,
  verificationMethodOfKey,
  verifyEd25519Proof,
  type DIDDocument,
} from '../../../../src/core/index.js';
import { AgentRepository } from '../../../../src/repositories/agent.repository.js';
import { DidKeyRepository } from '../../../../src/repositories/did-key.repository.js';
import { AgentService } from '../../../../src/services/agent/agent.service.js';
import { AesGcmKeyCustody } from '../../../../src/services/key-custody/key-custody.js';
import { ServiceProviderService } from '../../../../src/services/service-provider/service-provider.service.js';
import { MockVCService } from '../../../mocks/MockVCService.js';
import { clientKey, enrollmentSignature, events, harness, type Harness } from './harness.js';

const MASTER = 'b'.repeat(64);

function agentVC(did: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `vc:helix:${did.slice(-8)}`,
    type: ['VerifiableCredential', 'HelixAgentCredential'],
    issuer: 'did:web:helix.example',
    validFrom: '2026-11-22T00:00:00.000Z',
    credentialSubject: { id: did, type: 'HelixAgent', agentName: 'A', privilegeScopes: ['read:orders'], delegationDepth: 0, maxDelegationDepth: 1, ...extra },
    proof: { type: 'Ed25519Signature2020', created: '2026-11-22T00:00:00.000Z', verificationMethod: 'did:web:helix.example#key-1', proofPurpose: 'assertionMethod', proofValue: 'z1' },
  };
}

async function documentOf(h: Harness, did: string): Promise<DIDDocument> {
  return (await h.dids.findDidById(did))!.didDocument as DIDDocument;
}

function agentServiceFor(h: Harness, vcService: MockVCService, attach = true): { agents: AgentService; didKeys: DidKeyRepository } {
  const didKeys = new DidKeyRepository();
  const agents = new AgentService(new AgentRepository(), {} as never, vcService as never, { log: () => undefined } as never, didKeys, new AesGcmKeyCustody(MASTER));
  if (attach) agents.attachCustodialKeys(h.service);
  return { agents, didKeys };
}

describe('createEd25519Proof with a Signer', () => {
  it('makes the same proof as the raw key, and refuses a signer that returns no signature', async () => {
    const seed = '7d'.repeat(32);
    const payload = { a: 1, b: ['x'] };
    const at = new Date('2026-11-22T00:00:00Z');
    const signer = { did: 'did:web:h:o:a', kid: 'key-1', sign: async (data: Uint8Array) => ed25519.sign(data, Buffer.from(seed, 'hex')) };
    expect(await createEd25519Proof(payload, signer, 'did:web:h:o:a#key-1', at)).toEqual(await createEd25519Proof(payload, seed, 'did:web:h:o:a#key-1', at));
    await expect(createEd25519Proof(payload, { ...signer, sign: async () => new Uint8Array(3) }, 'v', at)).rejects.toThrow(/64-byte/);
    expect(verificationMethodOfKey({ did: 'did:web:h:o:a', signer: { ...signer, kid: '#key-2' } })).toBe('did:web:h:o:a#key-2');
    expect(verificationMethodOfKey({ did: 'did:web:h:o:a', privateKeyHex: seed })).toBe('did:web:h:o:a#key-1');
    expect(proofKeyOf({ did: 'd', privateKeyHex: seed })).toBe(seed);
    expect(proofKeyOf({ did: 'd', signer })).toBe(signer);
    expect(derivePublicKey(seed)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('VP signing for agents created through POST /v1/agents', () => {
  it('a custodial agent: signVP signs through its KeyStore key, under its current kid, and the proof verifies against its DID document', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Presenter', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const vcService = new MockVCService();
    vcService.setActiveVC(agentVC(agent.did));
    const { agents } = agentServiceFor(h, vcService);
    const { signedVP } = await agents.signVP({ did: agent.did, targetService: 'did:web:orders.example' }, 'req');
    expect(signedVP.proof.verificationMethod).toBe(`${agent.did}#key-1`);
    const { proof, ...payload } = signedVP as unknown as Record<string, unknown> & { proof: { proofValue: string } };
    expect(await verifyEd25519Proof(payload, proof, await documentOf(h, agent.did))).toBe(true);
    expect(events(h, AuditEvents.CUSTODIAL_SIGNATURE)).toEqual([
      expect.objectContaining({ requestId: 'req', actor: 'custodial-vp', subjectType: 'agent', did: agent.did, kid: `${agent.did}#key-1`, payloadBytes: 32 }),
    ]);
  });

  it('is AGENT_KEY_NOT_FOUND for a self-custody agent (its key never reaches Helix), for an unknown agent, and without the KeyStore attached', async () => {
    const h = harness();
    const key = clientKey();
    const created = await h.service.createAgent({ name: 'Own keys', keyCustody: 'self' }, h.context());
    const challenge = await h.service.enrollmentChallenge(created.enrollmentToken);
    await h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, challenge.nonce) }, h.context());
    const custodial = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    const vcService = new MockVCService();
    vcService.setActiveVC(agentVC(created.did));
    const { agents } = agentServiceFor(h, vcService);
    await expect(agents.signVP({ did: created.did, targetService: 'did:web:s' }, 'req')).rejects.toThrow(AgentKeyNotFoundError);
    await expect(agents.signVP({ did: 'did:web:nobody', targetService: 'did:web:s' }, 'req')).rejects.toThrow(AgentKeyNotFoundError);
    const { agents: unattached } = agentServiceFor(h, vcService, false);
    await expect(unattached.signVP({ did: custodial.did, targetService: 'did:web:s' }, 'req')).rejects.toThrow(AgentKeyNotFoundError);
  });

  it('after a change to self custody, Helix no longer signs for the agent', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Mover', keyCustody: 'helix' }, h.context());
    const key = clientKey();
    const { rotationProof } = await import('./harness.js');
    await h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: rotationProof(key, agent.did, `${agent.did}#key-2`, h.now.value.toISOString()) }, h.context());
    expect(await h.service.signerFor(agent.did, 'agent', { requestId: 'req', purpose: 'vp' })).toBeUndefined();
    expect(await h.service.isActiveAgent(agent.did)).toBe(true);
  });
});

describe('delegation for agents created through POST /v1/agents', () => {
  it('a custodial agent delegates to another custody agent, signing the delegation through its KeyStore key', async () => {
    const h = harness();
    const delegator = await h.service.createAgent({ name: 'Delegator', scopes: ['read:orders'], keyCustody: 'helix', maxDelegationDepth: 1 }, h.context());
    const delegatee = await h.service.createAgent({ name: 'Delegatee', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const vcService = new MockVCService();
    const source = agentVC(delegator.did);
    vcService.setActiveVC(source);
    const { agents } = agentServiceFor(h, vcService);
    const { delegatedVC } = await agents.delegateAuthority({ did: delegator.did, to: delegatee.did, scopes: ['read:orders'], expiresIn: 3600, vcId: source['id'] as string }, 'req');
    expect(delegatedVC.issuer).toBe(delegator.did);
    expect(delegatedVC.proof.verificationMethod).toBe(`${delegator.did}#key-1`);
    const { proof, ...payload } = delegatedVC as unknown as Record<string, unknown> & { proof: { proofValue: string } };
    expect(await verifyEd25519Proof(payload, proof, await documentOf(h, delegator.did))).toBe(true);
    expect(events(h, AuditEvents.CUSTODIAL_SIGNATURE)).toEqual([expect.objectContaining({ actor: 'custodial-delegation', did: delegator.did })]);
  });

  it('refuses a delegatee that is neither a did_keys agent nor an active custody agent, and a did_keys key of another kind', async () => {
    const h = harness();
    const delegator = await h.service.createAgent({ name: 'Delegator', scopes: ['read:orders'], keyCustody: 'helix', maxDelegationDepth: 1 }, h.context());
    const pending = await h.service.createAgent({ name: 'Pending', keyCustody: 'self' }, h.context());
    const vcService = new MockVCService();
    const source = agentVC(delegator.did);
    vcService.setActiveVC(source);
    const { agents, didKeys } = agentServiceFor(h, vcService);
    for (const to of [pending.did, 'did:web:nobody']) {
      await expect(agents.delegateAuthority({ did: delegator.did, to, scopes: ['read:orders'], expiresIn: 3600, vcId: source['id'] as string }, 'req')).rejects.toThrow(DelegateeNotAnAgentError);
    }
    await didKeys.create({ did: 'did:web:a-service', subjectType: 'service', encryptedPrivateKey: 'x', iv: 'x', authTag: 'x', algorithm: 'aes-256-gcm' });
    await expect(agents.delegateAuthority({ did: delegator.did, to: 'did:web:a-service', scopes: ['read:orders'], expiresIn: 3600, vcId: source['id'] as string }, 'req')).rejects.toThrow(DelegateeNotAnAgentError);
    const { agents: unattached } = agentServiceFor(h, vcService, false);
    await expect(unattached.delegateAuthority({ did: delegator.did, to: pending.did, scopes: ['read:orders'], expiresIn: 3600 }, 'req')).rejects.toThrow(AgentKeyNotFoundError);
  });
});

describe('consent grants for services and agents created through the custody routes', () => {
  function grantsFor(h: Harness, vcService: MockVCService, didKeys = new DidKeyRepository(), attach = true): ServiceProviderService {
    const sp = new ServiceProviderService({} as never, vcService, h.services, didKeys, new AesGcmKeyCustody(MASTER), { log: () => undefined } as never);
    if (attach) sp.attachCustodialKeys(h.service);
    return sp;
  }

  it('a custodial service grants consent to a custodial agent, signing through its KeyStore key', async () => {
    const h = harness();
    const svc = await h.service.createService({ name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const agent = await h.service.createAgent({ name: 'Shopper', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const vcService = new MockVCService();
    vcService.setActiveVC(agentVC(agent.did));
    const sp = grantsFor(h, vcService);
    expect(await sp.getAgentScopes(agent.did)).toEqual({ agentDid: agent.did, scopes: ['read:orders'] });
    const { grantVC } = await sp.issueDelegationGrant({ serviceDid: svc.did, agentDid: agent.did, userDid: 'did:key:z6MkuserUser', scopes: ['read:orders'] }, 'req');
    expect(grantVC.issuer).toBe(svc.did);
    expect(grantVC.proof.verificationMethod).toBe(`${svc.did}#key-1`);
    const { proof, ...payload } = grantVC as unknown as Record<string, unknown> & { proof: { proofValue: string } };
    expect(await verifyEd25519Proof(payload, proof, await documentOf(h, svc.did))).toBe(true);
    expect(events(h, AuditEvents.CUSTODIAL_SIGNATURE)).toEqual([expect.objectContaining({ actor: 'custodial-grant', subjectType: 'service', did: svc.did })]);
  });

  it('a self-custody service has no Helix key to sign with; a pending agent or a did_keys key of another kind is refused', async () => {
    const h = harness();
    const selfService = await h.service.createService({ name: 'billing', domain: 'billing.example', requiredScopes: ['read:orders'], keyCustody: 'self', publicKeyJwk: clientKey().publicKeyJwk }, h.context());
    const agent = await h.service.createAgent({ name: 'Shopper', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const pending = await h.service.createAgent({ name: 'Pending', keyCustody: 'self' }, h.context());
    const vcService = new MockVCService();
    vcService.setActiveVC(agentVC(agent.did));
    const didKeys = new DidKeyRepository();
    const sp = grantsFor(h, vcService, didKeys);
    await expect(sp.issueDelegationGrant({ serviceDid: selfService.did, agentDid: agent.did, userDid: 'did:key:z6Mkuser', scopes: ['read:orders'] }, 'req')).rejects.toThrow(ServiceKeyNotFoundError);
    await expect(sp.getAgentScopes(pending.did)).rejects.toThrow(DelegateeNotAnAgentError);
    const wrongKind = await h.service.createService({ name: 'odd', domain: 'odd.example', requiredScopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    await didKeys.create({ did: wrongKind.did, subjectType: 'agent', encryptedPrivateKey: 'x', iv: 'x', authTag: 'x', algorithm: 'aes-256-gcm' });
    await expect(sp.issueDelegationGrant({ serviceDid: wrongKind.did, agentDid: agent.did, userDid: 'did:key:z6Mkuser', scopes: ['read:orders'] }, 'req')).rejects.toThrow(ServiceKeyNotFoundError);
    const unattached = grantsFor(h, vcService, new DidKeyRepository(), false);
    await expect(unattached.getAgentScopes(agent.did)).rejects.toThrow(DelegateeNotAnAgentError);
  });
});

describe('the enrollment event', () => {
  it('AGENT_ONBOARDED is logged when an agent becomes active, custodial or self-custody, and not for services', async () => {
    const h = harness();
    const custodial = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    const key = clientKey();
    const created = await h.service.createAgent({ name: 'Own keys', keyCustody: 'self' }, h.context());
    expect(events(h, AuditEvents.AGENT_ONBOARDED).map((event) => event['agentDid'])).toEqual([custodial.did]);
    const challenge = await h.service.enrollmentChallenge(created.enrollmentToken);
    await h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, challenge.nonce) }, h.context({ actor: 'enrollment-token' }));
    await h.service.createService({ name: 'svc', domain: 'svc.example', requiredScopes: ['a'], keyCustody: 'helix' }, h.context());
    expect(events(h, AuditEvents.AGENT_ONBOARDED)).toEqual([
      expect.objectContaining({ agentDid: custodial.did, agentName: 'Custodial', keyCustody: 'helix', didHosting: 'helix' }),
      expect.objectContaining({ agentDid: created.did, agentName: 'Own keys', keyCustody: 'self' }),
    ]);
  });
});
