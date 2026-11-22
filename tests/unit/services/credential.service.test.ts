// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: CredentialService over the in-memory VC repository.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  EnvSigner,
  ErrorCode,
  HelixError,
  buildCapabilityAttestation,
  buildDIDDocument,
  derivePublicKey,
  evaluateDelegationChain,
  publicKeyToMultibase,
  verifyCapabilityAttestation,
  verifyDelegationChainProofs,
  verifyIdentityCredential,
  type BitstringStatusEntry,
  type DIDDocument,
} from '../../../src/core/index.js';
import { VcRepository } from '../../../src/repositories/vc.repository.js';
import { DidKeyRepository } from '../../../src/repositories/did-key.repository.js';
import { AesGcmKeyCustody } from '../../../src/services/key-custody/key-custody.js';
import { CredentialService } from '../../../src/services/credentials/credential.service.js';
import { CustodySigner } from '../../../src/services/credentials/custody-signer.js';
import { TestAuditTrail } from '../../utils/TestAuditTrail.js';
import type { DidResolver } from '../../../src/core/credentials/index.js';
import type { CredentialStatusStore } from '../../../src/services/credentials/credential.service.js';

const HELIX_KEY = '1'.repeat(64);
const OWNER_KEY = '2'.repeat(64);
const helixDid = `did:key:${publicKeyToMultibase(derivePublicKey(HELIX_KEY))}`;
const ownerDid = `did:key:${publicKeyToMultibase(derivePublicKey(OWNER_KEY))}`;
const helixSigner = new EnvSigner({ did: helixDid, envVar: 'K', env: { K: HELIX_KEY } });
const ownerSigner = new EnvSigner({ did: ownerDid, envVar: 'K', env: { K: OWNER_KEY } });
const RESOURCE = 'did:web:service.example:orders';
const LIST_URL = 'http://localhost:3000/v1/status-list/helix-status-list-1';

describe('CredentialService', () => {
  let vcRepo: VcRepository;
  let keyRepo: DidKeyRepository;
  let custody: AesGcmKeyCustody;
  let statusStore: { claimStatusListEntry: ReturnType<typeof vi.fn>; revokeVC: ReturnType<typeof vi.fn> };
  let didService: { resolveDID: ReturnType<typeof vi.fn>; registerResolvedDID: ReturnType<typeof vi.fn> };
  let audit: TestAuditTrail;
  let service: CredentialService;
  let parentDid: string;
  let childDid: string;
  const documents: Record<string, DIDDocument> = {};
  const resolve = (async (did: string) => documents[did]) as unknown as DidResolver;

  async function custodialAgent(): Promise<string> {
    const { publicKey, encrypted } = custody.generateAndEncrypt();
    const did = `did:key:${publicKeyToMultibase(publicKey)}`;
    await keyRepo.create({ did, subjectType: 'agent', ...encrypted });
    documents[did] = buildDIDDocument(did, publicKey);
    return did;
  }

  beforeEach(async () => {
    vcRepo = new VcRepository();
    await vcRepo.createStatusList('helix-status-list-1', 'list');
    keyRepo = new DidKeyRepository();
    custody = new AesGcmKeyCustody('22'.repeat(32));
    let index = 0;
    statusStore = {
      claimStatusListEntry: vi.fn(async () => ({ statusListCredentialUrl: LIST_URL, statusListIndex: (index += 1) })),
      revokeVC: vi.fn(async (vcId: string) => {
        await vcRepo.revokeVc(vcId, 'helix-status-list-1', 'list');
        return { vcId, revoked: true as const, revokedAt: new Date().toISOString() };
      }),
    };
    didService = { resolveDID: vi.fn(async () => ({})), registerResolvedDID: vi.fn(async () => undefined) };
    audit = new TestAuditTrail();
    service = new CredentialService(
      vcRepo,
      statusStore as unknown as CredentialStatusStore,
      didService as unknown as ConstructorParameters<typeof CredentialService>[2],
      helixSigner,
      keyRepo,
      custody,
      audit as unknown as ConstructorParameters<typeof CredentialService>[6],
    );
    documents[helixDid] = buildDIDDocument(helixDid, derivePublicKey(HELIX_KEY));
    documents[ownerDid] = buildDIDDocument(ownerDid, derivePublicKey(OWNER_KEY));
    parentDid = await custodialAgent();
    childDid = await custodialAgent();
  });

  describe('signerFor', () => {
    it('is the Helix issuer for its own DID, a custody signer for a held key, and refuses the rest', async () => {
      expect(service.issuerDid).toBe(helixDid);
      expect(await service.signerFor(helixDid)).toBe(helixSigner);
      const signer = await service.signerFor(parentDid);
      expect(signer).toBeInstanceOf(CustodySigner);
      expect(signer.did).toBe(parentDid);
      await expect(service.signerFor('did:key:z6MkNobody')).rejects.toMatchObject({ code: ErrorCode.AGENT_KEY_NOT_FOUND, httpStatus: 404 });
    });
  });

  describe('issueIdentity', () => {
    it('issues, stores a copy with its status index, audits, and the copy verifies', async () => {
      const identity = await service.issueIdentity({ agentDid: childDid, name: 'orders-agent', ownerDid }, 'req-1');
      expect(identity.credentialSubject).toEqual({ id: childDid, name: 'orders-agent', responsibleParty: ownerDid });
      expect(identity.validUntil).toBeUndefined();
      expect(identity.credentialStatus).toMatchObject({ statusListIndex: '1', statusListCredential: LIST_URL, id: `${LIST_URL}#1` });
      const record = await vcRepo.findByVcId(identity.id);
      expect(record).toMatchObject({ subjectDid: childDid, vcType: 'AgentIdentityCredential', issuerDid: helixDid, statusListIndex: 1, expiresAt: null, scopeKey: null });
      await audit.flush();
      expect(audit.ofType('delegation.issued')[0]).toMatchObject({
        correlationId: 'req-1',
        action: { category: 'credential', name: 'issued' },
        actor: { kind: 'public_did', did: helixDid },
        resource: { kind: 'public_did', did: childDid },
        details: { family: 'delegation', phase: 'issued', delegationRef: identity.id },
      });
      expect(JSON.stringify(audit.events)).not.toContain('orders-agent');
      expect((await verifyIdentityCredential(identity, resolve)).ok).toBe(true);
      const bounded = await service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid, validUntil: new Date('2027-01-01T00:00:00Z') }, 'req-2');
      expect(bounded.validUntil).toBe('2027-01-01T00:00:00.000Z');
      expect((await vcRepo.findByVcId(bounded.id))!.expiresAt).toEqual(new Date('2027-01-01T00:00:00Z'));
    });

    it('registers a subject DID this server has not seen, through the core resolver', async () => {
      didService.resolveDID.mockRejectedValueOnce(new HelixError(ErrorCode.DID_NOT_FOUND, 'nope', 404));
      await service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid }, 'req');
      expect(didService.registerResolvedDID).toHaveBeenCalledWith(childDid, expect.objectContaining({ id: childDid }), 'agent', 'req');
    });

    it('refuses a subject DID nobody can resolve, and relays other resolution failures', async () => {
      didService.resolveDID.mockRejectedValueOnce(new HelixError(ErrorCode.DID_NOT_FOUND, 'nope', 404));
      await expect(service.issueIdentity({ agentDid: 'did:web:unreachable.invalid', name: 'x', ownerDid }, 'req')).rejects.toMatchObject({ code: ErrorCode.VC_SUBJECT_DID_NOT_FOUND });
      didService.resolveDID.mockRejectedValueOnce(new Error('database down'));
      await expect(service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid }, 'req')).rejects.toThrow('database down');
    });
  });

  describe('renewIdentity', () => {
    it('re-issues the same agent, name and responsible party with a fresh id, links the old record and audits', async () => {
      const first = await service.issueIdentity({ agentDid: childDid, name: 'orders-agent', ownerDid, validUntil: new Date('2027-01-01T00:00:00Z') }, 'req-1');
      const renewed = await service.renewIdentity(first.id, {}, 'req-2');
      expect(renewed).not.toBeNull();
      expect(renewed!.vcId).not.toBe(first.id);
      expect(renewed!.previousVcId).toBe(first.id);
      expect(renewed!.vc.credentialSubject).toEqual(first.credentialSubject);
      // Without an override the renewed credential keeps the previous validity.
      expect(renewed!.vc.validUntil).toBe('2027-01-01T00:00:00.000Z');
      expect(renewed!.expiresAt).toBe('2027-01-01T00:00:00.000Z');
      expect(renewed!.statusListIndex).toBe(Number(renewed!.vc.credentialStatus.statusListIndex));
      expect((await vcRepo.findByVcId(first.id))!.renewedByVcId).toBe(renewed!.vcId);
      await audit.flush();
      expect(audit.ofType('delegation.issued').find((event) => event.action.name === 'renewed')).toMatchObject({
        resource: { kind: 'public_did', did: childDid },
        details: { delegationRef: renewed!.vcId, parentRef: first.id },
      });
      // The listing now leads with the renewed identity; the old one stays active.
      expect((await service.listAgentCredentials(childDid)).identity).toMatchObject({ vcId: renewed!.vcId, status: 'active' });
      expect((await vcRepo.findByVcId(first.id))!.revokedAt).toBeNull();
      expect(await verifyIdentityCredential(renewed!.vc, resolve, { agentDid: childDid })).toMatchObject({ ok: true });
    });

    it('honours expiresInSeconds and carries no validity when the previous had none', async () => {
      const open = await service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid }, 'req');
      const before = Date.now();
      const bounded = await service.renewIdentity(open.id, { expiresInSeconds: 3600 }, 'req');
      const until = new Date(bounded!.vc.validUntil!).getTime();
      expect(until).toBeGreaterThanOrEqual(before + 3_600_000);
      expect(until).toBeLessThanOrEqual(Date.now() + 3_600_000);
      const carried = await service.renewIdentity(open.id, {}, 'req');
      expect(carried!.vc.validUntil).toBeUndefined();
      expect(carried!.expiresAt).toBeNull();
    });

    it('returns null for an unknown id or a credential that is not an identity, and refuses a revoked identity', async () => {
      expect(await service.renewIdentity('urn:uuid:missing', {}, 'req')).toBeNull();
      const [attestation] = await service.issueAttestations({ agentDid: childDid, capabilities: ['read:orders'] }, 'req');
      expect(await service.renewIdentity(attestation!.id, {}, 'req')).toBeNull();
      const identity = await service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid }, 'req');
      await vcRepo.revokeVc(identity.id, 'helix-status-list-1', 'list');
      await expect(service.renewIdentity(identity.id, {}, 'req')).rejects.toMatchObject({ code: ErrorCode.VC_ALREADY_REVOKED, httpStatus: 409 });
    });
  });

  describe('attestations', () => {
    it('issues one per capability, Helix-signed by default, two years by default, and the copies carry the scope', async () => {
      const issued = await service.issueAttestations({ agentDid: childDid, capabilities: ['read:orders', 'write:orders'] }, 'req');
      expect(issued.map((a) => a.credentialSubject)).toEqual([
        { id: childDid, capability: 'read:orders' },
        { id: childDid, capability: 'write:orders' },
      ]);
      expect(issued.every((a) => a.issuer === helixDid)).toBe(true);
      expect(Date.parse(issued[0]!.validUntil) - Date.now()).toBeGreaterThan(700 * 24 * 3600 * 1000);
      expect(await vcRepo.findByVcId(issued[1]!.id)).toMatchObject({ vcType: 'CapabilityAttestationCredential', privilegeScopes: ['write:orders'], scopeKey: 'write:orders', statusListIndex: 2 });
      const none = await service.issueAttestations({ agentDid: childDid, capabilities: [], validUntil: null }, 'req');
      expect(none).toEqual([]);
    });

    it('signs with the given signer and honours validUntil', async () => {
      const [owned] = await service.issueAttestations({ agentDid: childDid, capabilities: ['read:catalog'], signer: ownerSigner, validUntil: new Date('2026-12-31T00:00:00Z') }, 'req');
      expect(owned!.issuer).toBe(ownerDid);
      expect(owned!.validUntil).toBe('2026-12-31T00:00:00.000Z');
      expect(await verifyCapabilityAttestation(owned, resolve, { trustedIssuers: [ownerDid] })).toMatchObject({ ok: true });
    });

    it('registers an owner-signed attestation after verifying it, once', async () => {
      const entry: BitstringStatusEntry = { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '9', statusListCredential: LIST_URL };
      const attestation = await buildCapabilityAttestation({ subjectDid: childDid, capability: 'read:catalog', validUntil: '2027-01-01T00:00:00Z', statusEntry: entry }, ownerSigner);
      const kept = await service.registerAttestation(childDid, attestation, 'req');
      expect(kept).toEqual(attestation);
      expect(await vcRepo.findByVcId(attestation.id)).toMatchObject({ issuerDid: ownerDid, statusListIndex: 9 });
      await audit.flush();
      expect(audit.ofType('delegation.issued').at(-1)).toMatchObject({
        action: { category: 'credential', name: 'registered' },
        actor: { kind: 'public_did', did: ownerDid },
        details: { delegationRef: attestation.id },
      });
      await expect(service.registerAttestation(childDid, attestation, 'req')).rejects.toMatchObject({ httpStatus: 409 });
      await expect(service.registerAttestation(parentDid, attestation, 'req')).rejects.toMatchObject({ code: ErrorCode.VALIDATION_ERROR, message: expect.stringContaining('subject_mismatch') });
      await expect(service.registerAttestation(childDid, { ...attestation, issuer: helixDid }, 'req')).rejects.toMatchObject({ message: expect.stringContaining('proof_issuer_mismatch') });
    });

    it('revokes every active attestation of one capability and nothing else', async () => {
      const identity = await service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid }, 'req');
      const [read, write] = await service.issueAttestations({ agentDid: childDid, capabilities: ['read:orders', 'write:orders'] }, 'req');
      const revoked = await service.revokeAttestation(childDid, 'write:orders', 'req');
      expect(revoked).toEqual([write!.id]);
      expect(statusStore.revokeVC).toHaveBeenCalledWith(write!.id, 'req');
      const copies = await service.listAgentCredentials(childDid);
      expect(copies.identity).toMatchObject({ vcId: identity.id, status: 'active' });
      const byId = Object.fromEntries(copies.attestations.map((a) => [a.vcId, a]));
      expect(byId[read!.id]).toMatchObject({ status: 'active', revokedAt: null });
      expect(byId[write!.id]).toMatchObject({ status: 'revoked', revokedAt: expect.any(String) });
      await expect(service.revokeAttestation(childDid, 'write:orders', 'req')).rejects.toMatchObject({ code: ErrorCode.VC_NOT_FOUND });
    });
  });

  describe('hops', () => {
    it('issues a root hop signed by a custodial key or by Helix, refusing an unknown issuer and an invalid root', async () => {
      const root = await service.issueRootHop({ issuer: parentDid, invoker: childDid, invocationTarget: RESOURCE, allowedAction: ['read:orders'], caveats: [{ type: 'MaxAmount', limit: '10', currency: 'USD' }] }, 'req');
      expect(root.issuer).toBe(parentDid);
      expect(root.credentialSubject).toMatchObject({ invoker: childDid, parentCapability: RESOURCE, invocationTarget: RESOURCE, allowedAction: ['read:orders'] });
      expect(await verifyDelegationChainProofs([root], resolve)).toEqual({ ok: true });
      expect(await vcRepo.findByVcId(root.id)).toMatchObject({ subjectDid: childDid, vcType: 'DelegationCredential', privilegeScopes: ['read:orders'] });
      expect((await vcRepo.findByVcId(root.id))!.parentVcId ?? null).toBeNull();
      const byHelix = await service.issueRootHop({ issuer: helixDid, invoker: childDid, invocationTarget: RESOURCE, allowedAction: ['read:orders'], validUntil: '2027-01-01T00:00:00Z' }, 'req');
      expect(byHelix.issuer).toBe(helixDid);
      expect(byHelix.validUntil).toBe('2027-01-01T00:00:00Z');
      await expect(service.issueRootHop({ issuer: 'did:key:z6MkNobody', invoker: childDid, invocationTarget: RESOURCE, allowedAction: [] }, 'req')).rejects.toMatchObject({ code: ErrorCode.AGENT_KEY_NOT_FOUND });
      await expect(service.issueRootHop({ issuer: helixDid, invoker: childDid, invocationTarget: RESOURCE, allowedAction: ['read:orders'], validUntil: '2020-01-01T00:00:00Z' }, 'req')).rejects.toMatchObject({ code: ErrorCode.DELEGATION_CHAIN_INVALID, httpStatus: 400 });
    });

    it('issues a child hop signed by the parent invoker, refuses a broadening one, and walks the stored chain', async () => {
      const grandchildDid = await custodialAgent();
      const root = await service.issueRootHop({ issuer: helixDid, invoker: parentDid, invocationTarget: RESOURCE, allowedAction: ['read:orders', 'write:orders'], caveats: [{ type: 'MaxAmount', limit: '100', currency: 'USD' }], validUntil: '2027-01-01T00:00:00Z' }, 'req');
      const { hop, chain } = await service.issueHop(root.id, { invoker: childDid, allowedAction: ['read:orders'], caveats: [{ type: 'MaxAmount', limit: '50', currency: 'USD' }] }, 'req');
      expect(hop.issuer).toBe(parentDid);
      expect(hop.validUntil).toBe(root.validUntil);
      expect(hop.credentialSubject).toMatchObject({ invoker: childDid, parentCapability: root.credentialSubject.id, invocationTarget: RESOURCE });
      expect(chain.map((h) => h.id)).toEqual([root.id, hop.id]);
      expect(evaluateDelegationChain(chain, { resource: RESOURCE })).toMatchObject({ ok: true, leafInvoker: childDid, responsibleParty: helixDid });
      expect(await verifyDelegationChainProofs(chain, resolve)).toEqual({ ok: true });
      expect((await vcRepo.findByVcId(hop.id))!.parentVcId).toBe(root.id);
      const grand = await service.issueHop(hop.id, { invoker: grandchildDid, allowedAction: ['read:orders'], caveats: [{ type: 'MaxAmount', limit: '5', currency: 'USD' }], validUntil: '2026-12-01T00:00:00Z' }, 'req');
      expect(grand.hop.issuer).toBe(childDid);
      expect((await service.chainOf(grand.hop.id)).map((h) => h.id)).toEqual([root.id, hop.id, grand.hop.id]);
      // Broadening, a dropped caveat and an extended validUntil are refused before anything is stored.
      await expect(service.issueHop(hop.id, { invoker: grandchildDid, allowedAction: ['write:orders'] }, 'req')).rejects.toMatchObject({ code: ErrorCode.DELEGATION_CHAIN_INVALID, message: expect.stringContaining('allowedAction escalation') });
      await expect(service.issueHop(hop.id, { invoker: grandchildDid, allowedAction: ['read:orders'] }, 'req')).rejects.toMatchObject({ message: expect.stringContaining('caveat "MaxAmount"') });
      await expect(service.issueHop(hop.id, { invoker: grandchildDid, allowedAction: ['read:orders'], caveats: [{ type: 'MaxAmount', limit: '1', currency: 'USD' }], validUntil: '2028-01-01T00:00:00Z' }, 'req')).rejects.toMatchObject({ message: expect.stringContaining('validUntil broadened') });
      expect((await service.listAgentCredentials(grandchildDid)).hops).toHaveLength(1);
    });

    it('refuses a hop under a missing, foreign or revoked parent, and a parent that names a controller only', async () => {
      await expect(service.issueHop('urn:zcap:missing', { invoker: childDid, allowedAction: [] }, 'req')).rejects.toMatchObject({ code: ErrorCode.DELEGATION_PARENT_VC_NOT_FOUND });
      const identity = await service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid }, 'req');
      await expect(service.issueHop(identity.id, { invoker: childDid, allowedAction: [] }, 'req')).rejects.toMatchObject({ code: ErrorCode.DELEGATION_PARENT_VC_NOT_FOUND });
      const root = await service.issueRootHop({ issuer: helixDid, invoker: parentDid, invocationTarget: RESOURCE, allowedAction: ['read:orders'] }, 'req');
      await service.revokeHop(root.id, 'req');
      await expect(service.issueHop(root.id, { invoker: childDid, allowedAction: ['read:orders'] }, 'req')).rejects.toMatchObject({ code: ErrorCode.DELEGATION_CHAIN_INVALID, message: expect.stringContaining('revoked') });
      // A parent written with `controller` instead of `invoker` still names the delegate.
      const controlled = await service.issueRootHop({ issuer: helixDid, invoker: parentDid, invocationTarget: RESOURCE, allowedAction: ['read:orders'] }, 'req');
      const record = (await vcRepo.findByVcId(controlled.id))!;
      const json = record.vcJson as { credentialSubject: Record<string, unknown> };
      json.credentialSubject['controller'] = json.credentialSubject['invoker'];
      delete json.credentialSubject['invoker'];
      const { hop } = await service.issueHop(controlled.id, { invoker: childDid, allowedAction: ['read:orders'] }, 'req');
      expect(hop.issuer).toBe(parentDid);
    });

    it('revokes a hop and cascades to every hop below it; a missing or non-hop id is refused', async () => {
      const grandchildDid = await custodialAgent();
      const root = await service.issueRootHop({ issuer: helixDid, invoker: parentDid, invocationTarget: RESOURCE, allowedAction: ['read:orders'] }, 'req');
      const { hop } = await service.issueHop(root.id, { invoker: childDid, allowedAction: ['read:orders'] }, 'req');
      const grand = await service.issueHop(hop.id, { invoker: grandchildDid, allowedAction: ['read:orders'] }, 'req');
      const revoked = await service.revokeHop(hop.id, 'req');
      expect(revoked).toEqual([grand.hop.id, hop.id]);
      expect((await vcRepo.findByVcId(root.id))!.revokedAt).toBeNull();
      expect(await service.revokeHop(hop.id, 'req')).toEqual([]);
      await expect(service.revokeHop('urn:zcap:missing', 'req')).rejects.toMatchObject({ code: ErrorCode.VC_NOT_FOUND });
    });

    it('refuses to walk a stored chain deeper than the maximum', async () => {
      const findByVcId = vi.spyOn(vcRepo, 'findByVcId').mockImplementation(async (vcId: string) => ({
        vcId,
        subjectDid: childDid,
        subjectType: 'agent',
        vcJson: JSON.stringify({ id: vcId }),
        privilegeScopes: null,
        statusListIndex: 0,
        expiresAt: null,
        revokedAt: null,
        renewedByVcId: null,
        parentVcId: `${vcId}-parent`,
      }));
      await expect(service.chainOf('urn:zcap:loop')).rejects.toMatchObject({ code: ErrorCode.DELEGATION_CHAIN_INVALID });
      findByVcId.mockRestore();
    });
  });

  describe('listAgentCredentials', () => {
    it('groups by kind, prefers the active identity and falls back to the latest one', async () => {
      expect(await service.listAgentCredentials(childDid)).toEqual({ agentDid: childDid, identity: null, attestations: [], hops: [] });
      const first = await service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid, validUntil: new Date(Date.now() - 1000) }, 'req');
      expect((await service.listAgentCredentials(childDid)).identity).toMatchObject({ vcId: first.id, status: 'expired' });
      const second = await service.issueIdentity({ agentDid: childDid, name: 'x', ownerDid }, 'req');
      expect((await service.listAgentCredentials(childDid)).identity).toMatchObject({ vcId: second.id, status: 'active' });
    });

    it('orders credentials stored in the same millisecond by id', async () => {
      vi.useFakeTimers({ toFake: ['Date'] });
      try {
        vi.setSystemTime(new Date('2026-11-22T00:00:00.000Z'));
        await service.issueAttestations({ agentDid: childDid, capabilities: ['read:a', 'read:b', 'read:c'] }, 'req');
      } finally {
        vi.useRealTimers();
      }
      const ids = (await service.listAgentCredentials(childDid)).attestations.map((entry) => entry.vcId);
      expect(ids).toHaveLength(3);
      expect(ids).toEqual([...ids].sort((a, b) => a.localeCompare(b)));
    });
  });
  describe('audit (KYA-OS A-1)', () => {
    function withTrail(trail: { record: (input: unknown) => Promise<unknown> }) {
      return new CredentialService(
        vcRepo,
        statusStore as unknown as CredentialStatusStore,
        didService as unknown as ConstructorParameters<typeof CredentialService>[2],
        helixSigner,
        keyRepo,
        custody,
        trail as unknown as ConstructorParameters<typeof CredentialService>[6],
      );
    }

    it('never fails an issuance because the event could not be recorded, rejected or thrown', async () => {
      const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      try {
        const rejecting = withTrail({ record: async () => { throw new Error('sink down'); } });
        expect((await rejecting.issueIdentity({ agentDid: childDid, name: 'a', ownerDid }, 'req-r')).id).toMatch(/^urn:uuid:/);
        const throwing = withTrail({ record: () => { throw 'not an error'; } });
        expect((await throwing.issueIdentity({ agentDid: childDid, name: 'b', ownerDid }, 'req-t')).id).toMatch(/^urn:uuid:/);
        await vi.waitFor(() => expect(errors).toHaveBeenCalledWith('AUDIT_RECORD_FAILED', 'sink down'));
        expect(errors).toHaveBeenCalledWith('AUDIT_RECORD_FAILED', 'not an error');
      } finally {
        errors.mockRestore();
      }
    });

    it('names no party that is not a DID, and a credential that shows no id as unknown, with no digest', async () => {
      const unsigned = { issuer: 'not a did' };
      (service as unknown as { auditIssued(c: unknown, s: string, n: string, r: string): void }).auditIssued(unsigned, 'not a did either', 'issued', 'req-u');
      await audit.flush();
      const [event] = audit.ofType('delegation.issued');
      expect(event).toBeDefined();
      expect(event).not.toHaveProperty('actor');
      expect(event).not.toHaveProperty('resource');
      expect(event!.authorization).not.toHaveProperty('delegationCredentialDigest');
      expect(event!.details).toMatchObject({ delegationRef: 'unknown' });
    });
  });
});

describe('CustodySigner', () => {
  it('signs through the custody and never exposes the key', async () => {
    const custody = new AesGcmKeyCustody('33'.repeat(32));
    const { publicKey, encrypted } = custody.generateAndEncrypt();
    const did = `did:key:${publicKeyToMultibase(publicKey)}`;
    const signer = new CustodySigner(did, encrypted, custody);
    expect(signer.kid).toBe('key-1');
    expect(new CustodySigner(did, encrypted, custody, 'key-2').kid).toBe('key-2');
    const signature = await signer.sign(new Uint8Array([1, 2, 3]));
    expect(signature).toHaveLength(64);
    expect(JSON.stringify(signer)).toBe(JSON.stringify({ did, kid: 'key-1' }));
    expect(JSON.stringify(signer)).not.toContain('33333333');
  });
});
