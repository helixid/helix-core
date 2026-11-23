// Copyright 2026 DgVerse LLP
// KYA-OS story L3-C: signed per-issuer status lists, the revocation API's service (signed requests, the revoker
// check against the chain, the cascade) and the revocation signal, over the in-memory repository with real keys.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import {
  DEFAULT_STATUS_LIST_ID,
  EnvSigner,
  ErrorCode,
  derivePublicKey,
  generateKeyPair,
  publicKeyToMultibase,
  signDataIntegrity,
  signJws,
  statusListIdFor,
  type DIDDocument,
  type SignedDelegationHop,
} from '../../../src/core/index.js';
import type { DidResolver } from '../../../src/core/credentials/index.js';
import { VcRepository } from '../../../src/repositories/vc.repository.js';
import { DidKeyRepository } from '../../../src/repositories/did-key.repository.js';
import { AesGcmKeyCustody } from '../../../src/services/key-custody/key-custody.js';
import { CredentialService } from '../../../src/services/credentials/credential.service.js';
import { StatusListPublisher, StatusListService } from '../../../src/services/status-lists/status-list.service.js';
import { REVOCATION_REQUEST_TYP, RevocationService } from '../../../src/services/revocation/revocation.service.js';
import { RevocationSignalPublisher, type RevocationEvent } from '../../../src/services/revocation/signal-publisher.js';
import { InProcessCache } from '../../../src/cache/InProcessCache.js';
import { TestAuditTrail } from '../../utils/TestAuditTrail.js';
import { CustodyEvents, clientKey, events as custodyEvents, harness as custodyHarness } from './custody/harness.js';
import { testDidDocument } from '../../utils/didDocuments.js';

const API = 'https://api.helix.test';
const AUDIENCE = `${API}/v1/revocations`;
const RESOURCE = 'did:web:service.example:orders';
const HELIX_KEY = '1'.repeat(64);
const OWNER_KEY = '2'.repeat(64);
const helixDid = `did:key:${publicKeyToMultibase(derivePublicKey(HELIX_KEY))}`;
const ownerDid = `did:key:${publicKeyToMultibase(derivePublicKey(OWNER_KEY))}`;
const helixSigner = new EnvSigner({ did: helixDid, envVar: 'K', env: { K: HELIX_KEY } });
const ownerSigner = new EnvSigner({ did: ownerDid, envVar: 'K', env: { K: OWNER_KEY } });

function world() {
  const documents: Record<string, DIDDocument> = {
    [helixDid]: testDidDocument(helixDid, derivePublicKey(HELIX_KEY)),
    [ownerDid]: testDidDocument(ownerDid, derivePublicKey(OWNER_KEY)),
  };
  const resolve = (async (did: string) => documents[did] ?? null) as unknown as DidResolver;
  const vcRepo = new VcRepository();
  const keyRepo = new DidKeyRepository();
  const custody = new AesGcmKeyCustody('22'.repeat(32));
  const audit = new TestAuditTrail();
  let now = Date.parse('2026-06-01T00:00:00Z');
  const clock = (): number => now;
  // eslint-disable-next-line prefer-const -- assigned after the publisher that closes over it
  let credentials: CredentialService;
  const publisher = new StatusListPublisher({
    repo: vcRepo,
    helixIssuerDid: helixDid,
    apiBaseUrl: API,
    signerFor: async (did) => {
      try {
        return await credentials.signerFor(did);
      } catch {
        return undefined;
      }
    },
    resolveDid: resolve,
    listTtlSeconds: 600,
    refreshBeforeSeconds: 60,
    signedCache: new InProcessCache<string>(),
    audit,
    clock,
  });
  const signals = new RevocationSignalPublisher({ signer: helixSigner, audit, clock });
  const statusLists = new StatusListService({ publisher, repo: vcRepo, audit, signals });
  credentials = new CredentialService(
    vcRepo,
    statusLists,
    { resolveDID: vi.fn(async () => ({})), registerResolvedDID: vi.fn(async () => undefined) } as never,
    helixSigner,
    keyRepo,
    custody,
    audit,
  );
  const revocations = new RevocationService({ repo: vcRepo, statusLists, resolveDid: resolve, audience: AUDIENCE, clock });
  const custodial = async (): Promise<{ did: string; signer: Awaited<ReturnType<CredentialService['signerFor']>> }> => {
    const { publicKey, encrypted } = custody.generateAndEncrypt();
    const did = `did:key:${publicKeyToMultibase(publicKey)}`;
    await keyRepo.create({ did, subjectType: 'agent', ...encrypted });
    documents[did] = testDidDocument(did, publicKey);
    return { did, signer: await credentials.signerFor(did) };
  };
  /** Reads a served list the way a verifier does: proof first, then bits (the SDK reader). */
  const served = async (listId: string) => kyaos.verifier.readBitstringStatusList(await statusLists.getSigned(listId), { resolveDid: resolve as never });
  const bitOf = async (credential: { credentialStatus: { statusListCredential: string; statusListIndex: string } }) => {
    const listId = publisher.listIdOfUrl(credential.credentialStatus.statusListCredential)!;
    return kyaos.verifier.readStatusBit((await served(listId)).bits, Number(credential.credentialStatus.statusListIndex));
  };
  return {
    documents,
    resolve,
    vcRepo,
    audit,
    publisher,
    signals,
    statusLists,
    credentials,
    revocations,
    custodial,
    served,
    bitOf,
    advance: (seconds: number) => {
      now += seconds * 1000;
    },
    now: () => now,
  };
}

type World = ReturnType<typeof world>;

/** A root hop by the Helix issuer to `parent`, a child hop by `parent` to `child`, a grandchild by `child` to `grand`. */
async function chainOf(w: World): Promise<{ root: SignedDelegationHop; child: SignedDelegationHop; grand: SignedDelegationHop; parent: string; childDid: string; grandDid: string }> {
  const parent = await w.custodial();
  const childAgent = await w.custodial();
  const grandAgent = await w.custodial();
  const root = await w.credentials.issueRootHop({ issuer: helixDid, invoker: parent.did, invocationTarget: RESOURCE, allowedAction: ['orders:read'] }, 'req');
  const { hop: child } = await w.credentials.issueHop(root.id, { invoker: childAgent.did, allowedAction: ['orders:read'] }, 'req');
  const { hop: grand } = await w.credentials.issueHop(child.id, { invoker: grandAgent.did, allowedAction: ['orders:read'] }, 'req');
  return { root, child, grand, parent: parent.did, childDid: childAgent.did, grandDid: grandAgent.did };
}

describe('signed per-issuer status lists', () => {
  let w: World;
  beforeEach(() => {
    w = world();
  });

  it('puts each credential on its issuer\'s own list, signed by that issuer, with a window', async () => {
    const { root, child } = await chainOf(w);
    expect(root.credentialStatus.statusListCredential).toBe(`${API}/v1/status-list/${DEFAULT_STATUS_LIST_ID}`);
    expect(child.credentialStatus.statusListCredential).toBe(`${API}/v1/status-list/${statusListIdFor(child.issuer, helixDid)}`);
    const rootList = await w.statusLists.getSigned(DEFAULT_STATUS_LIST_ID);
    expect(rootList).toMatchObject({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: root.credentialStatus.statusListCredential,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: helixDid,
      validFrom: '2026-06-01T00:00:00.000Z',
      validUntil: '2026-06-01T00:10:00.000Z',
      credentialSubject: { type: 'BitstringStatusList', statusPurpose: 'revocation' },
      proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: `${helixDid}#${helixDid.slice('did:key:'.length)}`, proofPurpose: 'assertionMethod' },
    });
    expect(rootList.credentialSubject.encodedList.startsWith('u')).toBe(true);
    const childList = await w.served(statusListIdFor(child.issuer, helixDid));
    expect(childList.issuer).toBe(child.issuer);
    expect(await w.bitOf(child)).toBe(0);
    const identity = await w.credentials.issueIdentity({ agentDid: child.credentialSubject.invoker!, name: 'a', ownerDid }, 'req');
    expect(identity.credentialStatus.statusListCredential).toBe(root.credentialStatus.statusListCredential);
  });

  it('republishes on change and before expiry, and serves the same version in between', async () => {
    const { root } = await chainOf(w);
    const first = await w.statusLists.getSigned(DEFAULT_STATUS_LIST_ID);
    expect(await w.statusLists.getSigned(DEFAULT_STATUS_LIST_ID)).toBe(first);
    w.advance(541);
    const refreshed = await w.statusLists.getSigned(DEFAULT_STATUS_LIST_ID);
    expect(refreshed.validFrom).not.toBe(first.validFrom);
    await w.statusLists.revokeVC(root.id, 'req');
    const changed = await w.statusLists.getSigned(DEFAULT_STATUS_LIST_ID);
    expect(changed.proof.proofValue).not.toBe(refreshed.proof.proofValue);
    expect(await w.bitOf(root)).toBe(1);
    w.advance(541);
    expect(await w.publisher.refreshDue()).toEqual(expect.arrayContaining([DEFAULT_STATUS_LIST_ID]));
    w.publisher.startRefresh(10_000);
    w.publisher.startRefresh(10_000);
    w.publisher.stopRefresh();
    w.publisher.stopRefresh();
  });

  it('refuses unknown lists, ids that name no issuer, and URLs of other parties', async () => {
    await expect(w.statusLists.getSigned('nope')).rejects.toMatchObject({ code: ErrorCode.STATUS_LIST_NOT_FOUND, httpStatus: 404 });
    await expect(w.statusLists.getSigned(statusListIdFor(ownerDid, helixDid))).rejects.toMatchObject({ code: ErrorCode.STATUS_LIST_NOT_FOUND });
    await expect(w.publisher.unsignedList('nope')).rejects.toMatchObject({ httpStatus: 404 });
    await expect(w.publisher.submitSigned('nope', {})).rejects.toMatchObject({ httpStatus: 404 });
    expect(w.publisher.listIdOfUrl('https://elsewhere.example/v1/status-list/x')).toBeUndefined();
    expect(w.publisher.listIdOfUrl(`${API}/v1/status-list/not-a-list`)).toBeUndefined();
    expect(await w.publisher.publish('nope')).toBe(false);
    expect(await w.publisher.publish(statusListIdFor(ownerDid, helixDid))).toBe(false);
    expect(() => new StatusListPublisher({ repo: w.vcRepo, helixIssuerDid: helixDid, apiBaseUrl: API, signerFor: async () => undefined, resolveDid: w.resolve, listTtlSeconds: 60, refreshBeforeSeconds: 60 })).toThrow(/must exceed/);
  });

  it('a self-custody issuer\'s list is not served until it signs the current bits itself', async () => {
    const listId = statusListIdFor(ownerDid, helixDid);
    const entry = await w.statusLists.statusEntryFor(ownerDid);
    expect(entry).toMatchObject({ type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: w.publisher.urlFor(listId) });
    await expect(w.statusLists.getSigned(listId)).rejects.toMatchObject({ code: ErrorCode.STATUS_LIST_UNSIGNED, httpStatus: 503 });
    const unsigned = await w.publisher.unsignedList(listId);
    expect(unsigned.proof).toBeUndefined();
    const signed = await signDataIntegrity(unsigned as unknown as Record<string, unknown>, ownerSigner);
    const accepted = await w.publisher.submitSigned(listId, signed);
    expect(accepted.issuer).toBe(ownerDid);
    expect((await w.served(listId)).issuer).toBe(ownerDid);
    // A revocation on its list waits for its signature again: fail closed, never a stale "clear".
    const owned = { vcId: 'urn:uuid:owner-attestation', subjectDid: 'did:key:z6MkAgent', subjectType: 'agent', statusListIndex: 0, expiresAt: null, issuerDid: ownerDid, vcJson: { issuer: ownerDid, credentialSubject: { id: 'did:key:z6MkAgent' }, credentialStatus: entry } };
    await w.vcRepo.createVc(owned);
    await w.statusLists.revokeVC(owned.vcId, 'req');
    await expect(w.statusLists.getSigned(listId)).rejects.toMatchObject({ httpStatus: 503 });
    const resigned = await signDataIntegrity((await w.publisher.unsignedList(listId)) as unknown as Record<string, unknown>, ownerSigner);
    await w.publisher.submitSigned(listId, resigned);
    expect(kyaos.verifier.readStatusBit((await w.served(listId)).bits, 0)).toBe(1);
  });

  it('a custodial issuer (F-3 KeyStore key) has its list signed through its KeyStore key, audited as a status_list signature', async () => {
    const h = custodyHarness();
    const svc = await h.service.createService({ name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const agent = await h.service.createAgent({ name: 'Shopper', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    // An account (an owner) keeps its own list too: it roots its agents' hops.
    const owner = await h.service.createOwner({ name: 'Acme', keyCustody: 'helix', didHosting: 'helix' }, h.context());
    const selfService = await h.service.createService({ name: 'billing', domain: 'billing.example', requiredScopes: ['read:orders'], keyCustody: 'self', publicKeyJwk: clientKey().publicKeyJwk }, h.context());
    for (const did of [svc.did, agent.did, owner.did]) w.documents[did] = (await h.dids.findDidById(did))!.didDocument as DIDDocument;
    const custodyLookups = vi.spyOn(h.service, 'signerFor');
    w.publisher.attachCustodialKeys(h.service);

    // Without the KeyStore, these issuers' lists could not be signed; with it, each is signed by its own key.
    for (const did of [svc.did, agent.did, owner.did]) {
      const entry = await w.statusLists.statusEntryFor(did);
      const listId = w.publisher.listIdOfUrl(entry.statusListCredential)!;
      expect((await w.served(listId)).issuer).toBe(did);
    }
    expect(custodyLookups.mock.calls.map(([did, subjectType, use]) => [did, subjectType, use.purpose])).toEqual([
      [svc.did, 'agent', 'status_list'],
      [svc.did, 'service', 'status_list'],
      [agent.did, 'agent', 'status_list'],
      [owner.did, 'agent', 'status_list'],
      [owner.did, 'service', 'status_list'],
      [owner.did, 'owner', 'status_list'],
    ]);
    expect(custodyEvents(h, CustodyEvents.CUSTODIAL_SIGNATURE)).toEqual([
      expect.objectContaining({ actor: 'custodial-status_list', subjectType: 'service', did: svc.did }),
      expect.objectContaining({ actor: 'custodial-status_list', subjectType: 'agent', did: agent.did }),
      expect.objectContaining({ actor: 'custodial-status_list', subjectType: 'owner', did: owner.did }),
    ]);

    // A revocation on the service's list is republished at once, signed by the service again.
    const entry = await w.statusLists.statusEntryFor(svc.did);
    const granted = { vcId: 'urn:uuid:svc-grant', subjectDid: agent.did, subjectType: 'agent', statusListIndex: Number(entry.statusListIndex), expiresAt: null, issuerDid: svc.did, vcJson: { issuer: svc.did, credentialSubject: { id: agent.did }, credentialStatus: entry } };
    await w.vcRepo.createVc(granted);
    await w.statusLists.revokeVC(granted.vcId, 'req');
    expect(await w.bitOf(granted.vcJson)).toBe(1);

    // The Helix issuer's list never asks the KeyStore; a self-custody service still signs its own (503 until it does).
    custodyLookups.mockClear();
    await w.statusLists.statusEntryFor(helixDid);
    expect((await w.served(DEFAULT_STATUS_LIST_ID)).issuer).toBe(helixDid);
    expect(custodyLookups).not.toHaveBeenCalled();
    const selfList = w.publisher.listIdOfUrl((await w.statusLists.statusEntryFor(selfService.did)).statusListCredential)!;
    await expect(w.statusLists.getSigned(selfList)).rejects.toMatchObject({ code: ErrorCode.STATUS_LIST_UNSIGNED, httpStatus: 503 });
  });

  it('refuses an issuer-signed list that is not this list as it stands', async () => {
    const listId = statusListIdFor(ownerDid, helixDid);
    await w.statusLists.claimStatusListEntry(ownerDid);
    const unsigned = (await w.publisher.unsignedList(listId)) as unknown as Record<string, unknown>;
    const sign = (overrides: Record<string, unknown>) => signDataIntegrity({ ...unsigned, ...overrides }, ownerSigner);
    const refused = async (value: unknown, words: RegExp) => expect(w.publisher.submitSigned(listId, value)).rejects.toThrow(words);
    await refused(null, /not a JSON object/);
    await refused(await sign({ id: 'https://x.example/l' }), /id must be/);
    await refused({ ...unsigned, issuer: helixDid }, /issuer must be/);
    await refused(await sign({ type: ['VerifiableCredential'] }), /Bitstring Status List/);
    await refused(await sign({ credentialSubject: { ...(unsigned['credentialSubject'] as object), statusPurpose: 'suspension' } }), /statusPurpose/);
    await refused(await sign({ credentialSubject: { ...(unsigned['credentialSubject'] as object), encodedList: 'uH4sIAAAAAAAAA2NgAAIAAAD__w' } }), /as it stands/);
    await refused(await sign({ validFrom: 'soon' }), /date-times/);
    await refused(await sign({ validUntil: '2026-05-01T00:00:00Z' }), /outside the window/);
    await refused(await sign({ validUntil: '2026-06-02T00:00:00Z' }), /longer than/);
    await refused({ ...unsigned, proof: { type: 'DataIntegrityProof' } }, /status list refused/);
    const helixSigned = await signDataIntegrity({ ...unsigned, issuer: helixDid }, helixSigner);
    await refused({ ...helixSigned, issuer: ownerDid }, /status list refused/);
  });

  it('revokes a credential on another party\'s list by its row alone', async () => {
    const foreign = { vcId: 'urn:uuid:foreign', subjectDid: 'did:key:z6MkAgent', subjectType: 'agent', statusListIndex: 3, expiresAt: null, vcJson: JSON.stringify({ credentialStatus: { statusListCredential: 'https://elsewhere.example/l', statusListIndex: '3' } }) };
    await w.vcRepo.createVc(foreign);
    expect(w.statusLists.bitOf((await w.vcRepo.findByVcId(foreign.vcId))!)).toBeUndefined();
    const result = await w.statusLists.revokeVC(foreign.vcId, 'req');
    expect(result).toMatchObject({ vcId: foreign.vcId, revoked: true });
    expect((await w.vcRepo.findByVcId(foreign.vcId))!.revokedAt).not.toBeNull();
    await expect(w.statusLists.revokeVC(foreign.vcId, 'req')).rejects.toMatchObject({ code: ErrorCode.VC_ALREADY_REVOKED });
    await expect(w.statusLists.revokeVC('urn:uuid:none', 'req')).rejects.toMatchObject({ code: ErrorCode.VC_NOT_FOUND });
    // Descendants that are gone or already revoked are skipped.
    const other = { ...foreign, vcId: 'urn:uuid:other', vcJson: { credentialStatus: { statusListCredential: `${API}/v1/status-list/${DEFAULT_STATUS_LIST_ID}`, statusListIndex: 'x' } } };
    await w.vcRepo.createVc(other);
    expect((await w.statusLists.revokeMany([other.vcId, 'urn:uuid:none', foreign.vcId], { requestId: 'r' })).map((r) => r.vcId)).toEqual([other.vcId]);
  });

  it('audits a signal it could not emit, and still revokes', async () => {
    const { root } = await chainOf(w);
    w.statusLists.setSignals({ publish: async () => Promise.reject(new Error('bus down')) });
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    await w.statusLists.revokeVC(root.id, 'req');
    await w.audit.flush();
    expect(errors).toHaveBeenCalledWith('REVOCATION_SIGNAL_FAILED', root.id, 'bus down');
    errors.mockRestore();
    // The revocation itself, then the lost signal: no exception text in the event core.
    expect(w.audit.ofType('delegation.revoked')).toEqual([
      expect.objectContaining({ outcome: 'succeeded', correlationId: 'req', action: { category: 'credential', name: 'revoked' } }),
      expect.objectContaining({
        outcome: 'failed',
        correlationId: 'req',
        action: { category: 'revocation_signal', name: 'emit' },
        reason: { code: 'revocation_signal_failed' },
        details: { family: 'delegation', phase: 'revoked', delegationRef: root.id },
      }),
    ]);
    expect(JSON.stringify(w.audit.events)).not.toContain('bus down');
    expect(await w.bitOf(root)).toBe(1);
  });
});

describe('POST /v1/revocations service: revoke(credentialId, revokerSigner)', () => {
  let w: World;
  let events: RevocationEvent[];
  beforeEach(async () => {
    w = world();
    events = [];
    await w.signals.start();
    w.signals.subscribe((event) => events.push(event));
  });

  it('cascade: revoking the root marks every descendant revoked, flips each bit, audits and signals each', async () => {
    const { root, child, grand } = await chainOf(w);
    const outcome = await w.revocations.revoke(root.id, helixSigner, 'req-r');
    expect(outcome).toEqual({ credentialId: root.id, revoker: helixDid, revoked: [root.id, child.id, grand.id] });
    for (const hop of [root, child, grand]) {
      expect((await w.vcRepo.findByVcId(hop.id))!.revokedAt).not.toBeNull();
      expect(await w.bitOf(hop)).toBe(1);
    }
    // One audit event per credential: the target revoked, each descendant cascade_revoked under it.
    await w.audit.flush();
    expect(w.audit.ofType('delegation.revoked')).toEqual([
      expect.objectContaining({
        outcome: 'succeeded',
        correlationId: 'req-r',
        actor: { kind: 'public_did', did: helixDid },
        details: { family: 'delegation', phase: 'revoked', delegationRef: root.id },
      }),
    ]);
    const cascaded = w.audit.ofType('delegation.cascade_revoked');
    expect(cascaded.map((event) => event.details)).toEqual([
      { family: 'delegation', phase: 'cascade_revoked', delegationRef: child.id, parentRef: root.id },
      { family: 'delegation', phase: 'cascade_revoked', delegationRef: grand.id, parentRef: root.id },
    ]);
    for (const event of cascaded) {
      expect(event).toMatchObject({ actor: { kind: 'public_did', did: helixDid }, reason: { code: 'ancestor_revoked' }, action: { category: 'credential', name: 'cascade_revoked' } });
    }
    expect(events.map((event) => event.credentialId)).toEqual([root.id, child.id, grand.id]);
    for (const event of events) {
      const verdict = await kyaos.verifier.verifyRevocationSignal(event.set, { trustedIssuers: [helixDid], resolveDid: w.resolve as never, now: w.now() });
      expect(verdict).toMatchObject({ ok: true, signal: { credentialId: event.credentialId, jti: event.id } });
    }
  });

  it('revoking a parent hop leaves the hops above it and the agent identity alone', async () => {
    const { root, child, grand, childDid } = await chainOf(w);
    const identity = await w.credentials.issueIdentity({ agentDid: childDid, name: 'child', ownerDid }, 'req');
    // The direct issuer of the child hop is its parent's delegate.
    const outcome = await w.revocations.revoke(child.id, await w.credentials.signerFor(child.issuer), 'req');
    expect(outcome.revoked).toEqual([child.id, grand.id]);
    expect(await w.bitOf(root)).toBe(0);
    expect(await w.bitOf(identity)).toBe(0);
  });

  it('allows the direct issuer, an ancestor issuer and the root; refuses the subject and strangers', async () => {
    const { root, child, grand, grandDid } = await chainOf(w);
    const subjectSigner = await w.credentials.signerFor(grandDid);
    await expect(w.revocations.revoke(grand.id, subjectSigner, 'req')).rejects.toMatchObject({ code: ErrorCode.REVOCATION_FORBIDDEN, httpStatus: 403 });
    const stranger = await w.custodial();
    await expect(w.revocations.revoke(grand.id, stranger.signer, 'req')).rejects.toMatchObject({ code: ErrorCode.REVOCATION_FORBIDDEN });
    // Ancestor issuer: the root's issuer (the Responsible Party) revokes the grandchild directly.
    expect((await w.revocations.revoke(grand.id, helixSigner, 'req')).revoked).toEqual([grand.id]);
    // Direct issuer of the child hop.
    expect((await w.revocations.revoke(child.id, await w.credentials.signerFor(child.issuer), 'req')).revoked).toEqual([child.id]);
    await expect(w.revocations.revoke(child.id, helixSigner, 'req')).rejects.toMatchObject({ code: ErrorCode.VC_ALREADY_REVOKED, httpStatus: 409 });
    await expect(w.revocations.revoke('urn:zcap:none', helixSigner, 'req')).rejects.toMatchObject({ code: ErrorCode.VC_NOT_FOUND, httpStatus: 404 });
    expect((await w.revocations.revoke(root.id, helixSigner, 'req')).revoked).toEqual([root.id]);
  });

  it('an identity credential: its issuer and its responsibleParty may revoke it, the agent may not', async () => {
    const agent = await w.custodial();
    const identity = await w.credentials.issueIdentity({ agentDid: agent.did, name: 'a', ownerDid }, 'req');
    await expect(w.revocations.revoke(identity.id, agent.signer, 'req')).rejects.toMatchObject({ httpStatus: 403 });
    expect((await w.revocations.revoke(identity.id, ownerSigner, 'req')).revoked).toEqual([identity.id]);
    const [attestation] = await w.credentials.issueAttestations({ agentDid: agent.did, capabilities: ['orders:read'] }, 'req');
    await expect(w.revocations.revoke(attestation!.id, ownerSigner, 'req')).rejects.toMatchObject({ httpStatus: 403 });
    expect((await w.revocations.revoke(attestation!.id, helixSigner, 'req')).revoked).toEqual([attestation!.id]);
  });

  it('checks the request: a compact JWS of the right type, audience and time, signed by the revoker', async () => {
    const { root } = await chainOf(w);
    const claims = { iss: helixDid, credentialId: root.id, iat: Math.floor(w.now() / 1000), jti: 'urn:uuid:j', aud: AUDIENCE };
    const sign = (payload: Record<string, unknown>, typ: string | null = REVOCATION_REQUEST_TYP, signer = helixSigner) =>
      signJws(payload, signer, typ === null ? {} : { header: { typ } });
    const refused = async (request: unknown, code: string) => expect(w.revocations.revokeSigned(request, 'req')).rejects.toMatchObject({ code });
    await refused(42, ErrorCode.REVOCATION_REQUEST_INVALID);
    await refused('a.b.c', ErrorCode.REVOCATION_REQUEST_INVALID);
    await refused(await sign(claims, null), ErrorCode.REVOCATION_REQUEST_INVALID);
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: `${helixDid}#key-1`, typ: REVOCATION_REQUEST_TYP })).toString('base64url');
    await refused(`${header}.${Buffer.from('not json').toString('base64url')}.${Buffer.alloc(64).toString('base64url')}`, ErrorCode.REVOCATION_REQUEST_INVALID);
    await refused(await sign({ ...claims, iss: 'helix' }), ErrorCode.REVOCATION_REQUEST_INVALID);
    await refused(await sign({ ...claims, credentialId: '' }), ErrorCode.REVOCATION_REQUEST_INVALID);
    await refused(await sign({ ...claims, jti: '' }), ErrorCode.REVOCATION_REQUEST_INVALID);
    await refused(await sign({ ...claims, aud: 'https://elsewhere' }), ErrorCode.REVOCATION_REQUEST_INVALID);
    await refused(await sign({ ...claims, iat: claims.iat - 600 }), ErrorCode.REVOCATION_REQUEST_INVALID);
    // Claims Helix, signed by the owner's key.
    const forged = await sign(claims, REVOCATION_REQUEST_TYP, { did: helixDid, kid: 'key-1', sign: (data: Uint8Array) => ownerSigner.sign(data) } as never);
    await expect(w.revocations.revokeSigned(forged, 'req')).rejects.toMatchObject({ code: ErrorCode.REVOCATION_SIGNATURE_INVALID, httpStatus: 401 });
    const unknownKey = generateKeyPair();
    const unknownDid = `did:key:${publicKeyToMultibase(unknownKey.publicKey)}`;
    const unresolved = await sign({ ...claims, iss: unknownDid }, REVOCATION_REQUEST_TYP, new EnvSigner({ did: unknownDid, envVar: 'U', env: { U: unknownKey.privateKey } }));
    await expect(w.revocations.revokeSigned(unresolved, 'req')).rejects.toMatchObject({ code: ErrorCode.REVOCATION_SIGNATURE_INVALID });
    expect((await w.revocations.revokeSigned(await w.revocations.signRequest(root.id, helixSigner), 'req')).revoked).toHaveLength(3);
  });
});
