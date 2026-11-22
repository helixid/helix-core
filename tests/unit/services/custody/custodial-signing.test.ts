// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: services created through the custody routes sign consent grants through the KeyStore (stories
// rule 8); custodial agents sign KYA-OS delegation hops through the generic /sign route; agents log the enrollment event.
import * as ed25519 from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import {
  CustodialSigningRefusedError,
  DelegateeNotAnAgentError,
  ServiceKeyNotFoundError,
  createEd25519Proof,
  base64UrlDecodeStrict,
  base64UrlEncode,
  buildDelegationHop,
  derivePublicKey,
  proofKeyOf,
  rootHopInput,
  verificationMethodOfKey,
  verifyDelegationHop,
  type Signer,
  verifyEd25519Proof,
  type DIDDocument,
} from '../../../../src/core/index.js';
import { DidKeyRepository } from '../../../../src/repositories/did-key.repository.js';
import { AesGcmKeyCustody } from '../../../../src/services/key-custody/key-custody.js';
import { ServiceProviderService } from '../../../../src/services/service-provider/service-provider.service.js';
import { MockVCService } from '../../../mocks/MockVCService.js';
import { TestAuditTrail } from '../../../utils/TestAuditTrail.js';
import { clientKey, enrollmentSignature, CustodyEvents, events, harness, type Harness } from './harness.js';

const MASTER = 'b'.repeat(64);

/** Story F-1's credentials of an onboarded agent: its identity credential and one capability attestation per scope. */
function agentCredentials(did: string, scopes: string[] = ['read:orders']): Record<string, unknown>[] {
  return [
    { id: `vc:helix:${did.slice(-8)}`, type: ['VerifiableCredential', 'AgentIdentityCredential'], issuer: 'did:web:helix.example', credentialSubject: { id: did, name: 'A' } },
    ...scopes.map((capability) => ({
      id: `att:helix:${did.slice(-8)}:${capability}`,
      type: ['VerifiableCredential', 'CapabilityAttestationCredential'],
      issuer: 'did:web:helix.example',
      credentialSubject: { id: did, capability },
    })),
  ];
}

async function documentOf(h: Harness, did: string): Promise<DIDDocument> {
  return (await h.dids.findDidById(did))!.didDocument as DIDDocument;
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

describe('KYA-OS delegation for custodial agents: signed through the generic /sign route', () => {
  /** What HelixCustodialSigner does in the SDKs: POST /v1/agents/{did}/sign, here the service method behind it. */
  function custodialSigner(h: Harness, did: string): Signer {
    return {
      did,
      kid: 'key-1',
      sign: async (data: Uint8Array) => base64UrlDecodeStrict((await h.service.sign(did, { payload: base64UrlEncode(data) }, h.context({ actor: 'account:acc_1' }), 'agent')).signature)!,
    };
  }

  it('a custodial agent signs a delegation hop with its KeyStore key; the hop verifies against its DID document and the signature is audited', async () => {
    const h = harness();
    const delegator = await h.service.createAgent({ name: 'Delegator', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const delegatee = await h.service.createAgent({ name: 'Delegatee', keyCustody: 'helix' }, h.context());
    const hop = await buildDelegationHop(
      rootHopInput({
        invoker: delegatee.did,
        invocationTarget: 'did:web:orders.example',
        allowedAction: ['read:orders'],
        validUntil: '2027-01-01T00:00:00Z',
        statusEntry: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: 'https://helix.example/v1/status-list/1' },
      }),
      custodialSigner(h, delegator.did),
    );
    expect(hop.issuer).toBe(delegator.did);
    const verified = await verifyDelegationHop(hop, async (did) => (await documentOf(h, did)) as never);
    expect(verified).toMatchObject({ ok: true, issuer: delegator.did, invoker: delegatee.did });
    expect(events(h, CustodyEvents.CUSTODIAL_SIGNATURE)).toEqual([expect.objectContaining({ actor: 'account:acc_1', did: delegator.did, kid: `${delegator.did}#key-1` })]);
  });

  it('after a change to self custody, Helix no longer signs for the agent, through /sign or for a grant', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Mover', keyCustody: 'helix' }, h.context());
    const key = clientKey();
    const { rotationProof } = await import('./harness.js');
    await h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: rotationProof(key, agent.did, `${agent.did}#key-2`, h.now.value.toISOString()) }, h.context());
    await expect(custodialSigner(h, agent.did).sign(new Uint8Array([1]))).rejects.toThrow(CustodialSigningRefusedError);
    expect(await h.service.signerFor(agent.did, 'agent', { requestId: 'req', purpose: 'grant' })).toBeUndefined();
    expect(await h.service.isActiveAgent(agent.did)).toBe(true);
  });
});

describe('consent grants for services and agents created through the custody routes', () => {
  function grantsFor(h: Harness, vcService: MockVCService, didKeys = new DidKeyRepository(), attach = true): ServiceProviderService {
    const sp = new ServiceProviderService({} as never, vcService, h.services, didKeys, new AesGcmKeyCustody(MASTER), new TestAuditTrail());
    if (attach) sp.attachCustodialKeys(h.service);
    return sp;
  }

  it('a custodial service grants consent to a custodial agent, signing through its KeyStore key', async () => {
    const h = harness();
    const svc = await h.service.createService({ name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const agent = await h.service.createAgent({ name: 'Shopper', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const vcService = new MockVCService();
    vcService.setActiveVCs(agentCredentials(agent.did));
    const sp = grantsFor(h, vcService);
    expect(await sp.getAgentScopes(agent.did)).toEqual({ agentDid: agent.did, scopes: ['read:orders'] });
    const { grantVC } = await sp.issueDelegationGrant({ serviceDid: svc.did, agentDid: agent.did, userDid: 'did:key:z6MkuserUser', scopes: ['read:orders'] }, 'req');
    expect(grantVC.issuer).toBe(svc.did);
    expect(grantVC.proof.verificationMethod).toBe(`${svc.did}#key-1`);
    const { proof, ...payload } = grantVC as unknown as Record<string, unknown> & { proof: { proofValue: string } };
    expect(await verifyEd25519Proof(payload, proof, await documentOf(h, svc.did))).toBe(true);
    expect(events(h, CustodyEvents.CUSTODIAL_SIGNATURE)).toEqual([expect.objectContaining({ actor: 'custodial-grant', subjectType: 'service', did: svc.did })]);
  });

  it('a self-custody service has no Helix key to sign with; a pending agent or a did_keys key of another kind is refused', async () => {
    const h = harness();
    const selfService = await h.service.createService({ name: 'billing', domain: 'billing.example', requiredScopes: ['read:orders'], keyCustody: 'self', publicKeyJwk: clientKey().publicKeyJwk }, h.context());
    const agent = await h.service.createAgent({ name: 'Shopper', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const pending = await h.service.createAgent({ name: 'Pending', keyCustody: 'self' }, h.context());
    const vcService = new MockVCService();
    vcService.setActiveVCs(agentCredentials(agent.did));
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
    expect(events(h, CustodyEvents.AGENT_ONBOARDED).map((event) => event['agentDid'])).toEqual([custodial.did]);
    const challenge = await h.service.enrollmentChallenge(created.enrollmentToken);
    await h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, challenge.nonce) }, h.context({ actor: 'enrollment-token' }));
    await h.service.createService({ name: 'svc', domain: 'svc.example', requiredScopes: ['a'], keyCustody: 'helix' }, h.context());
    expect(events(h, CustodyEvents.AGENT_ONBOARDED)).toEqual([
      expect.objectContaining({ agentDid: custodial.did, credentialId: 'vc:test:1' }),
      expect.objectContaining({ agentDid: created.did, credentialId: 'vc:test:2' }),
    ]);
  });
});
