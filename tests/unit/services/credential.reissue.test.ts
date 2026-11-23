// Copyright 2026 DgVerse LLP
// KYA-OS story C-E point 4 and 5: CredentialService reissues, expires and revokes the hops bound to a key.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  EnvSigner,
  derivePublicKey,
  evaluateDelegationChain,
  publicKeyToMultibase,
  verifyDelegationChainProofs,
  type DIDDocument,
  type SignedDelegationHop,
} from '../../../src/core/index.js';
import { VcRepository } from '../../../src/repositories/vc.repository.js';
import { DidKeyRepository } from '../../../src/repositories/did-key.repository.js';
import { AesGcmKeyCustody } from '../../../src/services/key-custody/key-custody.js';
import { CredentialService, type CredentialStatusStore } from '../../../src/services/credentials/credential.service.js';
import { TestAuditTrail } from '../../utils/TestAuditTrail.js';
import type { DidResolver } from '../../../src/core/credentials/index.js';
import { testDidDocument } from '../../utils/didDocuments.js';

const HELIX_KEY = '1'.repeat(64);
const helixDid = `did:key:${publicKeyToMultibase(derivePublicKey(HELIX_KEY))}`;
const helixSigner = new EnvSigner({ did: helixDid, envVar: 'K', env: { K: HELIX_KEY } });
const RESOURCE = 'did:web:service.example:orders';
const LIST_URL = 'http://localhost:3000/v1/status-list/helix-status-list-1';

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 5));

describe('CredentialService as the hop reissuer (story C-E)', () => {
  let vcRepo: VcRepository;
  let keyRepo: DidKeyRepository;
  let custody: AesGcmKeyCustody;
  let audit: TestAuditTrail;
  let service: CredentialService;
  let agentDid: string;
  let delegateDid: string;
  const documents: Record<string, DIDDocument> = {};
  const resolve = (async (did: string) => documents[did]) as unknown as DidResolver;

  async function custodialAgent(): Promise<string> {
    const { publicKey, encrypted } = custody.generateAndEncrypt();
    const did = `did:key:${publicKeyToMultibase(publicKey)}`;
    await keyRepo.create({ did, subjectType: 'agent', ...encrypted });
    documents[did] = testDidDocument(did, publicKey);
    return did;
  }

  beforeEach(async () => {
    vcRepo = new VcRepository();
    await vcRepo.createStatusList('helix-status-list-1', 'list');
    keyRepo = new DidKeyRepository();
    custody = new AesGcmKeyCustody('22'.repeat(32));
    let index = 0;
    const statusStore = {
      claimStatusListEntry: vi.fn(async () => ({ statusListCredentialUrl: LIST_URL, statusListIndex: (index += 1) })),
      revokeVC: vi.fn(async (vcId: string) => {
        await vcRepo.revokeVc(vcId, 'helix-status-list-1', 'list');
        return { vcId, revoked: true as const, revokedAt: new Date().toISOString() };
      }),
    };
    audit = new TestAuditTrail();
    service = new CredentialService(
      vcRepo,
      statusStore as unknown as CredentialStatusStore,
      { resolveDID: vi.fn(async () => ({})), registerResolvedDID: vi.fn(async () => undefined) } as unknown as ConstructorParameters<typeof CredentialService>[2],
      helixSigner,
      keyRepo,
      custody,
      audit as unknown as ConstructorParameters<typeof CredentialService>[6],
    );
    documents[helixDid] = testDidDocument(helixDid, derivePublicKey(HELIX_KEY));
    agentDid = await custodialAgent();
    delegateDid = await custodialAgent();
  });

  /** The agent's hops before its rotation: a leaf root hop, and a root hop it re-delegated below. */
  async function hopsBeforeRotation() {
    const leaf = await service.issueRootHop({ issuer: helixDid, invoker: agentDid, invocationTarget: RESOURCE, allowedAction: ['orders:read'], caveats: [{ type: 'ValidUntil', date: '2030-01-01T00:00:00Z' }] }, 'r1');
    const parent = await service.issueRootHop({ issuer: helixDid, invoker: agentDid, invocationTarget: RESOURCE, allowedAction: ['orders:read', 'orders:write'] }, 'r2');
    const { hop: child } = await service.issueHop(parent.id, { invoker: delegateDid, allowedAction: ['orders:read'] }, 'r3');
    await tick();
    const rotatedAt = new Date();
    await tick();
    return { leaf, parent, child, bound: { from: new Date(0), until: rotatedAt } };
  }

  it('reissues each leaf hop of the agent from its issuer: same grant, new id and status entry, a chain that verifies', async () => {
    const { leaf, parent, bound } = await hopsBeforeRotation();
    const result = await service.reissueHopsForKid({ did: agentDid, oldKid: `${agentDid}#key-1`, newKid: `${agentDid}#key-2`, requestId: 'rot', bound });
    expect(result).toMatchObject({ reissued: 1, pending: false, pendingIssuers: [] });
    // The hop the agent re-delegated under stays as it is: its child was signed by the agent's key while it was current.
    expect(Object.keys(result.reissuedHops!)).toEqual([leaf.id]);
    const fresh = (await vcRepo.findByVcId(result.reissuedHops![leaf.id]!))!;
    const hop = fresh.vcJson as SignedDelegationHop;
    expect(hop.id).not.toBe(leaf.id);
    expect(hop.credentialStatus.statusListIndex).not.toBe(leaf.credentialStatus.statusListIndex);
    expect(hop.credentialSubject).toMatchObject({ invoker: agentDid, parentCapability: RESOURCE, invocationTarget: RESOURCE, allowedAction: ['orders:read'], caveats: leaf.credentialSubject.caveats });
    expect(hop.validUntil).toBe(leaf.validUntil);
    expect(evaluateDelegationChain([hop]).ok).toBe(true);
    expect((await verifyDelegationChainProofs([hop], resolve)).ok).toBe(true);
    expect((await vcRepo.findByVcId(parent.id))!.revokedAt).toBeNull();
    await audit.flush();
    expect(audit.ofType('delegation.issued').at(-1)).toMatchObject({ correlationId: 'rot', action: { name: 'reissued' }, details: { delegationRef: hop.id } });
  });

  it('reports a hop whose issuer holds its own key, for its SDK to reissue', async () => {
    const { leaf, bound } = await hopsBeforeRotation();
    vi.spyOn(service, 'signerFor').mockRejectedValue(new Error('No key held'));
    const result = await service.reissueHopsForKid({ did: agentDid, oldKid: 'a', newKid: 'b', requestId: 'rot', bound });
    expect(result).toMatchObject({ reissued: 0, pendingIssuers: [{ hopId: leaf.id, issuer: helixDid }] });
  });

  it('reads only hops issued while the old key was current, and only hops delegated to the agent', async () => {
    await hopsBeforeRotation();
    const future = { from: new Date(Date.now() + 60_000), until: null };
    expect(await service.reissueHopsForKid({ did: agentDid, oldKid: 'a', newKid: 'b', requestId: 'rot', bound: future })).toMatchObject({ reissued: 0 });
    // The delegate's own hop is its leaf; with no window it is reissued by its issuer, the agent.
    const forDelegate = await service.reissueHopsForKid({ did: delegateDid, oldKid: 'a', newKid: 'b', requestId: 'rot' });
    expect(forDelegate.reissued).toBe(1);
    const reissued = (await vcRepo.findByVcId(Object.values(forDelegate.reissuedHops!)[0]!))!;
    expect((reissued.vcJson as SignedDelegationHop).issuer).toBe(agentDid);
  });

  it('when the overlap ends, the old hops that were reissued expire; the others run to their own validUntil', async () => {
    const { leaf, parent, child, bound } = await hopsBeforeRotation();
    expect(await service.expireHopsForKid({ did: agentDid, kid: 'a', requestId: 'fin', bound })).toEqual([]);
    const result = await service.reissueHopsForKid({ did: agentDid, oldKid: 'a', newKid: 'b', requestId: 'rot', bound });
    expect(await service.expireHopsForKid({ did: agentDid, kid: 'a', requestId: 'fin', bound })).toEqual([leaf.id]);
    expect((await vcRepo.findByVcId(leaf.id))!.revokedAt).not.toBeNull();
    expect((await vcRepo.findByVcId(result.reissuedHops![leaf.id]!))!.revokedAt).toBeNull();
    expect((await vcRepo.findByVcId(parent.id))!.revokedAt).toBeNull();
    expect((await vcRepo.findByVcId(child.id))!.revokedAt).toBeNull();
    // Nothing is due without a window that ended, nor for a DID with no hops.
    expect(await service.expireHopsForKid({ did: agentDid, kid: 'a', requestId: 'fin', bound: { from: new Date(0), until: null } })).toEqual([]);
    expect(await service.expireHopsForKid({ did: 'did:key:z6MkNobody', kid: 'a', requestId: 'fin' })).toEqual([]);
  });

  it('a compromised key: every hop bound to it is revoked, with the hops below it', async () => {
    const { leaf, parent, child, bound } = await hopsBeforeRotation();
    const revoked = await service.revokeHopsForKid({ did: agentDid, kid: 'a', requestId: 'cmp', bound });
    expect(revoked.sort()).toEqual([leaf.id, parent.id, child.id].sort());
    for (const id of [leaf.id, parent.id, child.id]) expect((await vcRepo.findByVcId(id))!.revokedAt).not.toBeNull();
    expect(await service.revokeHopsForKid({ did: agentDid, kid: 'a', requestId: 'cmp', bound })).toEqual([]);
  });

  it('a hop without a proof time is placed by its row time', async () => {
    const hop = await service.issueRootHop({ issuer: helixDid, invoker: agentDid, invocationTarget: RESOURCE, allowedAction: ['orders:read'] }, 'r');
    const { proof: _proof, ...unsigned } = hop as unknown as Record<string, unknown>;
    await vcRepo.createVc({ vcId: 'urn:zcap:legacy', subjectDid: agentDid, subjectType: 'agent', vcJson: { ...unsigned, id: 'urn:zcap:legacy' }, statusListIndex: 99, expiresAt: null, vcType: 'DelegationCredential', issuerDid: helixDid });
    const revoked = await service.revokeHopsForKid({ did: agentDid, kid: 'a', requestId: 'cmp', bound: { from: new Date(Date.now() - 60_000), until: new Date(Date.now() + 60_000) } });
    expect(revoked.sort()).toEqual([hop.id, 'urn:zcap:legacy'].sort());
  });

  it('reissues the identity credential after a compromise; anything else is not an identity', async () => {
    const identity = await service.issueIdentity({ agentDid, name: 'bot', ownerDid: helixDid }, 'i');
    const renewed = await service.reissueIdentity({ vcId: identity.id }, 'cmp');
    expect(renewed).toMatch(/^urn:uuid:/);
    expect(renewed).not.toBe(identity.id);
    expect(await service.reissueIdentity({ vcId: 'urn:uuid:none' }, 'cmp')).toBeNull();
  });
});
