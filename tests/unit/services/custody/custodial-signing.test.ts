// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: services created through the custody routes sign consent grants through the KeyStore (stories
// rule 8); custodial agents sign KYA-OS delegation hops through the generic /sign route; agents log the enrollment event.
import * as ed25519 from '@noble/ed25519';
import { describe, expect, it, vi } from 'vitest';
import {
  CustodialSigningRefusedError,
  createEd25519Proof,
  base64UrlDecodeStrict,
  base64UrlEncode,
  buildDelegationHop,
  derivePublicKey,
  proofKeyOf,
  rootHopInput,
  verificationMethodOfKey,
  verifyDelegationHop,
  verifyDelegationChainProofs,
  EnvSigner,
  type Signer,
  type DIDDocument,
} from '../../../../src/core/index.js';
import { DidKeyRepository } from '../../../../src/repositories/did-key.repository.js';
import { VcRepository } from '../../../../src/repositories/vc.repository.js';
import { CredentialService } from '../../../../src/services/credentials/credential.service.js';
import { AesGcmKeyCustody } from '../../../../src/services/key-custody/key-custody.js';
import { TestAuditTrail } from '../../../utils/TestAuditTrail.js';
import { clientKey, enrollmentSignature, CustodyEvents, events, harness, type Harness } from './harness.js';

const MASTER = 'b'.repeat(64);

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

describe('delegation hops Helix issues for custodial agents and services (F-3 parity)', () => {
  /** A CredentialService over an in-memory store, its custodial keys from the harness's CustodyService. */
  async function credentialsFor(h: Harness, attach = true): Promise<CredentialService> {
    const vcRepo = new VcRepository();
    await vcRepo.createStatusList('helix-status-list-1', 'list');
    let index = 0;
    const statusStore = {
      claimStatusListEntry: async () => ({ statusListCredentialUrl: 'https://helix.example/v1/status-list/helix-status-list-1', statusListIndex: (index += 1) }),
      revokeVC: async () => ({}),
    };
    const helix = new EnvSigner({ did: 'did:web:helix.example', envVar: 'K', env: { K: '5c'.repeat(32) } });
    const credentials = new CredentialService(
      vcRepo,
      statusStore as never,
      { resolveDID: async () => ({}), registerResolvedDID: async () => undefined } as never,
      helix,
      new DidKeyRepository(),
      new AesGcmKeyCustody(MASTER),
      new TestAuditTrail(),
    );
    if (attach) credentials.attachCustodialKeys(h.service);
    return credentials;
  }

  it('a custodial service roots authority over itself and a custodial agent re-delegates it, each signed with its KeyStore key and audited', async () => {
    const h = harness();
    const svc = await h.service.createService({ name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const delegator = await h.service.createAgent({ name: 'Delegator', scopes: ['read:orders'], keyCustody: 'helix', maxDelegationDepth: 1 }, h.context());
    const delegatee = await h.service.createAgent({ name: 'Delegatee', keyCustody: 'helix' }, h.context());
    const credentials = await credentialsFor(h);
    const root = await credentials.issueRootHop({ issuer: svc.did, invoker: delegator.did, invocationTarget: svc.did, allowedAction: ['read:orders'] }, 'req-root');
    const { chain } = await credentials.issueHop(root.id, { invoker: delegatee.did, allowedAction: ['read:orders'] }, 'req-hop');
    expect(chain.map((hop) => hop.issuer)).toEqual([svc.did, delegator.did]);
    expect(await verifyDelegationChainProofs(chain, async (did) => (await documentOf(h, did)) as never)).toEqual({ ok: true });
    expect(events(h, CustodyEvents.CUSTODIAL_SIGNATURE)).toEqual([
      expect.objectContaining({ actor: 'custodial-hop', subjectType: 'service', did: svc.did, requestId: 'req-root' }),
      expect.objectContaining({ actor: 'custodial-hop', subjectType: 'agent', did: delegator.did, requestId: 'req-hop' }),
    ]);
  });

  it('an owner (an account) roots its agent\'s hop with its KeyStore key, ahead of any did_keys key, audited as an owner signature (stories rule 8)', async () => {
    const h = harness();
    const owner = await h.service.createOwner({ name: 'Acme', keyCustody: 'helix', didHosting: 'helix' }, h.context());
    expect(owner.did).toMatch(/:accounts:[0-9a-f]{32}$/);
    const svc = await h.service.createService({ name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const agent = await h.service.createAgent({ name: 'Agent', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const credentials = await credentialsFor(h);
    const root = await credentials.issueRootHop({ issuer: owner.did, invoker: agent.did, invocationTarget: svc.did, allowedAction: ['read:orders'] }, 'req-owner');
    expect(await verifyDelegationChainProofs([root], async (did) => (await documentOf(h, did)) as never)).toEqual({ ok: true });
    expect(events(h, CustodyEvents.CUSTODIAL_SIGNATURE)).toEqual([expect.objectContaining({ actor: 'custodial-hop', subjectType: 'owner', did: owner.did, requestId: 'req-owner' })]);
    // A self-custody owner signs its own hops: Helix has no key for it.
    const selfOwner = await h.service.createOwner({ name: 'Own keys', keyCustody: 'self', didHosting: 'helix', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'kcfr0m8Bx1JeMSWgQd5zIlPAMv4YtBtQ_8fHQyGa9u8' } }, h.context());
    await expect(credentials.signerFor(selfOwner.did, 'req')).rejects.toMatchObject({ code: 'AGENT_KEY_NOT_FOUND' });
  });

  it('has no key for a self-custody agent (it signs its own hops), nor without the custodial keys attached', async () => {
    const h = harness();
    const self = await h.service.createAgent({ name: 'Own keys', keyCustody: 'self' }, h.context());
    const custodial = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    const credentials = await credentialsFor(h);
    await expect(credentials.signerFor(self.did, 'req')).rejects.toMatchObject({ code: 'AGENT_KEY_NOT_FOUND' });
    await expect((await credentialsFor(h, false)).signerFor(custodial.did)).rejects.toMatchObject({ code: 'AGENT_KEY_NOT_FOUND' });
    expect((await credentials.signerFor(custodial.did)).did).toBe(custodial.did);
  });

  describe('maxDelegationDepth (Hop-Guard, rule C): each agent allows at most its depth of hops below it', () => {
    async function setup(depths: Array<number | undefined>) {
      const h = harness();
      const svc = await h.service.createService({ name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'], keyCustody: 'helix' }, h.context());
      const agents: string[] = [];
      for (const [index, depth] of depths.entries()) {
        agents.push((await h.service.createAgent({ name: `Agent ${index}`, scopes: ['read:orders'], keyCustody: 'helix', ...(depth === undefined ? {} : { maxDelegationDepth: depth }) }, h.context())).did);
      }
      const credentials = await credentialsFor(h);
      const root = await credentials.issueRootHop({ issuer: svc.did, invoker: agents[0]!, invocationTarget: svc.did, allowedAction: ['read:orders'] }, 'req');
      /** One child hop under `parentId`; the new hop's id. */
      const delegate = async (parentId: string, invoker: string) => (await credentials.issueHop(parentId, { invoker, allowedAction: ['read:orders'] }, 'req')).hop.id;
      return { h, svc, agents, credentials, root, delegate };
    }
    const exceeded = (message: string) => ({ code: 'MAX_DELEGATION_DEPTH_EXCEEDED', httpStatus: 400, message: expect.stringContaining(message) });

    it('an agent with depth 2 then 1 passes authority on twice; the third hop is refused by the first agent, before signing', async () => {
      const { agents, credentials, root, delegate } = await setup([2, 1, 0, 0]);
      const first = await delegate(root.id, agents[1]!);
      const second = await delegate(first, agents[2]!);
      const signerFor = vi.spyOn(credentials, 'signerFor');
      await expect(delegate(second, agents[3]!)).rejects.toMatchObject(exceeded(`${agents[0]} allows 2 delegation hop(s) below it`));
      expect(signerFor).not.toHaveBeenCalled();
    });

    it('the default depth 0 means the agent cannot delegate, whatever the agents above it allow', async () => {
      const { agents, root, delegate } = await setup([5, undefined, 0]);
      const first = await delegate(root.id, agents[1]!);
      await expect(delegate(first, agents[2]!)).rejects.toMatchObject(exceeded(`${agents[1]} allows 0 delegation hop(s) below it`));
      await expect(delegate(root.id, agents[2]!)).resolves.toBeDefined();
    });

    it('an agent upstream bounds its whole subtree, however much a later agent allows', async () => {
      const { agents, root, delegate } = await setup([1, 5, 0]);
      const first = await delegate(root.id, agents[1]!);
      await expect(delegate(first, agents[2]!)).rejects.toMatchObject(exceeded(`${agents[0]} allows 1 delegation hop(s) below it; this hop would be 2 below it`));
    });

    it('a root hop issued by an agent counts as one hop below it', async () => {
      const { svc, agents, credentials, delegate } = await setup([0, 1, 1]);
      await expect(credentials.issueRootHop({ issuer: agents[0]!, invoker: agents[1]!, invocationTarget: svc.did, allowedAction: ['read:orders'] }, 'req')).rejects.toMatchObject(exceeded(`${agents[0]} allows 0`));
      const root = await credentials.issueRootHop({ issuer: agents[1]!, invoker: agents[2]!, invocationTarget: svc.did, allowedAction: ['read:orders'] }, 'req');
      await expect(delegate(root.id, agents[0]!)).rejects.toMatchObject(exceeded(`${agents[1]} allows 1 delegation hop(s) below it; this hop would be 2 below it`));
    });

    it('an agent with no custody record here is not limited, nor is anyone when the custody keys give no depth', async () => {
      const { agents, credentials, root, delegate } = await setup([2, 1]);
      const first = await delegate(root.id, agents[1]!);
      vi.spyOn(credentials, 'signerFor');
      // A foreign or did_keys invoker has no record: it adds no limit of its own.
      const foreign = 'did:web:elsewhere.example:agents:x';
      await expect(credentials.issueHop(first, { invoker: foreign, allowedAction: ['read:orders'] }, 'req')).resolves.toBeDefined();
      const keys = { signerFor: async () => undefined, isActiveAgent: async () => true };
      credentials.attachCustodialKeys(keys);
      await expect(credentials.issueRootHop({ issuer: 'did:web:helix.example', invoker: agents[0]!, invocationTarget: root.credentialSubject.invocationTarget, allowedAction: ['read:orders'] }, 'req')).resolves.toBeDefined();
    });
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
