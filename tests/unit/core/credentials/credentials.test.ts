// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: identity credential, capability attestations, delegation hops and card level.
import { describe, expect, it } from 'vitest';
import {
  EnvSigner,
  attestedCapabilityEntry,
  buildCapabilityAttestation,
  buildDIDDocument,
  buildDelegationHop,
  buildIdentityCredential,
  buildIdentityVerificationCredential,
  capabilityName,
  checkCapabilities,
  clockSkewMs,
  createStatusList,
  deriveConformanceLevel,
  derivePublicKey,
  isRevokedIn,
  isTrustedIssuer,
  publicKeyToMultibase,
  requireCapability,
  requireDid,
  rootHopInput,
  setBit,
  verifyCapabilityAttestation,
  verifyDelegationHop,
  verifyIdentityCredential,
  verifyIdentityVerificationCredential,
  windowVerdict,
  type BitstringStatusEntry,
  type DIDDocument,
} from '../../../../src/core/index.js';
import type { DidResolver } from '../../../../src/core/credentials/index.js';

const NOW = Date.parse('2026-06-01T00:00:00Z');
const LIST_URL = 'https://helix.example/v1/status-list/1';

function actor(seed: string): { did: string; signer: EnvSigner; document: DIDDocument } {
  const key = seed.repeat(64).slice(0, 64);
  const did = `did:key:${publicKeyToMultibase(derivePublicKey(key))}`;
  return { did, signer: new EnvSigner({ did, envVar: 'K', env: { K: key } }), document: buildDIDDocument(did, derivePublicKey(key)) };
}
const helix = actor('1');
const owner = actor('2');
const agent = actor('3');
const stranger = actor('4');
const documents: Record<string, DIDDocument> = Object.fromEntries([helix, owner, agent, stranger].map((a) => [a.did, a.document]));
const resolve = (async (did: string) => documents[did]) as unknown as DidResolver;

function entry(index: number): BitstringStatusEntry {
  return { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: LIST_URL };
}

describe('windowVerdict and clockSkewMs', () => {
  it('holds each bound with the clock tolerance and fails closed on a malformed or offset-less date', () => {
    expect(windowVerdict('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z', NOW)).toBe('inside');
    expect(windowVerdict(undefined, undefined, NOW)).toBe('inside');
    expect(windowVerdict(undefined, '2026-05-31T23:59:00Z', NOW)).toBe('inside');
    expect(windowVerdict(undefined, '2026-05-31T23:57:00Z', NOW)).toBe('expired');
    expect(windowVerdict('2026-06-01T00:01:00Z', undefined, NOW)).toBe('inside');
    expect(windowVerdict('2026-06-01T00:03:00Z', undefined, NOW)).toBe('not_yet_valid');
    expect(windowVerdict('2026-06-01T00:00:30Z', undefined, NOW, 0)).toBe('not_yet_valid');
    expect(windowVerdict('2026-01-01T00:00:00', undefined, NOW)).toBe('malformed');
    expect(windowVerdict(undefined, 'soon', NOW)).toBe('malformed');
    expect(windowVerdict(undefined, undefined, NOW, -1)).toBe('skew_invalid');
    expect(clockSkewMs(undefined)).toBe(120_000);
    expect(clockSkewMs(600_000)).toBe(600_000);
    expect(clockSkewMs(600_001)).toBeUndefined();
    expect(clockSkewMs('120')).toBeUndefined();
    expect(clockSkewMs(Number.NaN)).toBeUndefined();
  });
});

describe('identity credential', () => {
  const input = { agentDid: agent.did, name: 'orders-agent', ownerDid: owner.did, statusEntry: entry(1), validFrom: '2026-01-01T00:00:00Z' };

  it('carries the agent DID, name and responsible party, no scopes, and verifies', async () => {
    const identity = await buildIdentityCredential({ ...input, validUntil: '2027-01-01T00:00:00Z', id: 'urn:uuid:x', proofCreated: '2026-01-01T00:00:00Z' }, helix.signer);
    expect(identity.type).toEqual(['VerifiableCredential', 'AgentIdentityCredential']);
    expect(identity.credentialSubject).toEqual({ id: agent.did, name: 'orders-agent', responsibleParty: owner.did });
    expect(identity.issuer).toBe(helix.did);
    expect(identity.id).toBe('urn:uuid:x');
    expect(identity.proof.created).toBe('2026-01-01T00:00:00Z');
    const verdict = await verifyIdentityCredential(identity, resolve, { now: NOW, agentDid: agent.did });
    expect(verdict).toMatchObject({ ok: true, agentDid: agent.did, responsibleParty: owner.did });
  });

  it('defaults id and validFrom, accepts no validUntil, and verifies with the real clock', async () => {
    const identity = await buildIdentityCredential(input, helix.signer);
    expect(identity.id).toMatch(/^urn:uuid:/);
    expect(identity.validUntil).toBeUndefined();
    expect((await verifyIdentityCredential(identity, resolve)).ok).toBe(true);
  });

  it('refuses bad inputs before signing', async () => {
    await expect(buildIdentityCredential({ ...input, agentDid: 'agent' }, helix.signer)).rejects.toThrow('agentDid must be a DID');
    await expect(buildIdentityCredential({ ...input, ownerDid: 'owner' }, helix.signer)).rejects.toThrow('ownerDid must be a DID');
    await expect(buildIdentityCredential({ ...input, name: ' ' }, helix.signer)).rejects.toThrow('name must be');
    expect(() => requireDid('x', 'thing')).toThrow('thing must be a DID');
  });

  it('refuses on schema, subject, window and proof, in that order', async () => {
    const identity = await buildIdentityCredential({ ...input, validUntil: '2026-07-01T00:00:00Z' }, helix.signer);
    expect(await verifyIdentityCredential({ ...identity, credentialSubject: { ...identity.credentialSubject, scopes: [] } }, resolve, { now: NOW })).toMatchObject({ ok: false, reason: 'schema_invalid' });
    expect(await verifyIdentityCredential(identity, resolve, { now: NOW, agentDid: stranger.did })).toMatchObject({ ok: false, reason: 'subject_mismatch' });
    expect(await verifyIdentityCredential(identity, resolve, { now: Date.parse('2026-08-01T00:00:00Z') })).toMatchObject({ ok: false, reason: 'credential_expired' });
    expect(await verifyIdentityCredential(identity, resolve, { now: NOW, maxClockSkewMs: -5 })).toMatchObject({ ok: false, reason: 'credential_skew_invalid' });
    expect(await verifyIdentityCredential({ ...identity, issuer: stranger.did }, resolve, { now: NOW })).toMatchObject({ ok: false, reason: 'proof_issuer_mismatch' });
    expect(await verifyIdentityCredential({ ...identity, credentialSubject: { ...identity.credentialSubject, name: 'renamed' } }, resolve, { now: NOW })).toMatchObject({ ok: false, reason: 'signature_invalid' });
  });
});

describe('identity verification credential (KYC/KYB)', () => {
  const input = { subjectDid: owner.did, subjectType: 'organization' as const, verificationLevel: 'enhanced' as const, validUntil: '2027-01-01T00:00:00Z', statusEntry: entry(2) };

  it('states the fact and level only and verifies', async () => {
    const credential = await buildIdentityVerificationCredential({ ...input, provider: 'kyb.example', id: 'urn:uuid:v', validFrom: '2026-01-01T00:00:00Z', proofCreated: '2026-01-01T00:00:00Z' }, helix.signer);
    expect(credential.type).toContain('IdentityVerificationCredential');
    expect(credential.credentialSubject).toEqual({ id: owner.did, subjectType: 'organization', verificationLevel: 'enhanced', provider: 'kyb.example' });
    expect(await verifyIdentityVerificationCredential(credential, resolve, { now: NOW, subjectDid: owner.did })).toMatchObject({ ok: true, verificationLevel: 'enhanced' });
    const bare = await buildIdentityVerificationCredential(input, helix.signer);
    expect(bare.credentialSubject.provider).toBeUndefined();
    expect((await verifyIdentityVerificationCredential(bare, resolve)).ok).toBe(true);
  });

  it('refuses bad inputs and bad credentials', async () => {
    await expect(buildIdentityVerificationCredential({ ...input, subjectDid: 'x' }, helix.signer)).rejects.toThrow('subjectDid must be a DID');
    await expect(buildIdentityVerificationCredential({ ...input, verificationLevel: 'gold' as never }, helix.signer)).rejects.toThrow('verificationLevel');
    await expect(buildIdentityVerificationCredential({ ...input, subjectType: 'robot' as never }, helix.signer)).rejects.toThrow('subjectType');
    const credential = await buildIdentityVerificationCredential(input, helix.signer);
    expect(await verifyIdentityVerificationCredential({ ...credential, type: ['VerifiableCredential'] }, resolve)).toMatchObject({ ok: false, reason: 'schema_invalid' });
    expect(await verifyIdentityVerificationCredential(null, resolve)).toMatchObject({ ok: false, reason: 'schema_invalid' });
    expect(await verifyIdentityVerificationCredential(credential, resolve, { subjectDid: agent.did })).toMatchObject({ ok: false, reason: 'subject_mismatch' });
    expect(await verifyIdentityVerificationCredential(credential, resolve, { now: Date.parse('2028-01-01T00:00:00Z') })).toMatchObject({ ok: false, reason: 'credential_expired' });
    expect(await verifyIdentityVerificationCredential({ ...credential, issuer: stranger.did }, resolve)).toMatchObject({ ok: false, reason: 'proof_issuer_mismatch' });
  });
});

describe('capability attestation', () => {
  const input = { subjectDid: agent.did, capability: 'read:orders', validUntil: '2026-12-31T00:00:00Z', statusEntry: entry(3), validFrom: '2026-01-01T00:00:00Z' };

  it('names the agent and one capability, signed by the owner or by Helix', async () => {
    const byOwner = await buildCapabilityAttestation({ ...input, id: 'urn:uuid:a', proofCreated: '2026-01-01T00:00:00Z' }, owner.signer);
    expect(byOwner.type).toEqual(['VerifiableCredential', 'CapabilityAttestationCredential']);
    expect(byOwner.credentialSubject).toEqual({ id: agent.did, capability: 'read:orders' });
    expect(byOwner.issuer).toBe(owner.did);
    expect(await verifyCapabilityAttestation(byOwner, resolve, { now: NOW, subjectDid: agent.did, capability: 'read:orders' })).toMatchObject({ ok: true, capability: 'read:orders', issuer: owner.did });
    const byHelix = await buildCapabilityAttestation(input, helix.signer);
    expect((await verifyCapabilityAttestation(byHelix, resolve)).ok).toBe(true);
  });

  it('refuses bad inputs before signing', async () => {
    await expect(buildCapabilityAttestation({ ...input, subjectDid: 'x' }, helix.signer)).rejects.toThrow('subjectDid must be a DID');
    await expect(buildCapabilityAttestation({ ...input, capability: 'read orders' }, helix.signer)).rejects.toThrow('capability must be');
    await expect(buildCapabilityAttestation({ ...input, validUntil: undefined as never }, helix.signer)).rejects.toThrow('validUntil is required');
    expect(() => requireCapability('')).toThrow();
  });

  it('refuses on schema, subject, capability, issuer, window, proof and revocation, in that order', async () => {
    const attestation = await buildCapabilityAttestation(input, owner.signer);
    const at = (options: Parameters<typeof verifyCapabilityAttestation>[2]) => verifyCapabilityAttestation(attestation, resolve, { now: NOW, ...options });
    expect(await verifyCapabilityAttestation({ ...attestation, validUntil: undefined }, resolve)).toMatchObject({ ok: false, reason: 'schema_invalid' });
    expect(await at({ subjectDid: stranger.did })).toMatchObject({ ok: false, reason: 'subject_mismatch' });
    expect(await at({ capability: 'write:orders' })).toMatchObject({ ok: false, reason: 'capability_mismatch' });
    expect(await at({ trustedIssuers: [helix.did] })).toMatchObject({ ok: false, reason: 'issuer_untrusted' });
    expect(await at({ trustedIssuers: [helix.did, owner.did] })).toMatchObject({ ok: true });
    expect(await at({ trustedIssuers: '*' })).toMatchObject({ ok: true });
    expect(await at({ now: Date.parse('2027-06-01T00:00:00Z') })).toMatchObject({ ok: false, reason: 'credential_expired' });
    expect(await verifyCapabilityAttestation({ ...attestation, issuer: helix.did }, resolve, { now: NOW })).toMatchObject({ ok: false, reason: 'proof_issuer_mismatch' });
    const list = setBit(createStatusList(64), 3, 1);
    expect(await at({ statusList: { credentialSubject: { encodedList: list } } })).toMatchObject({ ok: false, reason: 'credential_revoked' });
    expect(await at({ statusList: { credentialSubject: { encodedList: createStatusList(64) } } })).toMatchObject({ ok: true });
  });

  it('isTrustedIssuer and isRevokedIn', () => {
    expect(isTrustedIssuer('did:web:a', '*')).toBe(true);
    expect(isTrustedIssuer('did:web:a', ['did:web:a'])).toBe(true);
    expect(isTrustedIssuer('did:web:a', [])).toBe(false);
    expect(isTrustedIssuer('did:web:a', 'did:web:a' as never)).toBe(false);
    const list = setBit(createStatusList(64), 5, 1);
    expect(isRevokedIn(entry(5), list)).toBe(true);
    expect(isRevokedIn(entry(6), list)).toBe(false);
    expect(isRevokedIn({ ...entry(6), statusListIndex: 'six' }, list)).toBe(true);
    expect(isRevokedIn(entry(9999), list)).toBe(true);
    expect(isRevokedIn(entry(1), 'not-a-list')).toBe(true);
  });
});

describe('delegation hop', () => {
  const root = { invoker: agent.did, invocationTarget: 'did:web:service.example', allowedAction: ['read:orders'], validUntil: '2027-01-01T00:00:00Z', statusEntry: entry(7) };

  it('builds the §6.10 shape with the capability id as the VC id and verifies its proof', async () => {
    const hop = await buildDelegationHop(rootHopInput({ ...root, caveats: [{ type: 'MaxAmount', limit: '10', currency: 'USD' }], validFrom: '2026-01-01T00:00:00Z', id: 'urn:zcap:root', proofCreated: '2026-01-01T00:00:00Z' }), owner.signer);
    expect(hop.id).toBe('urn:zcap:root');
    expect(hop.credentialSubject).toEqual({
      id: 'urn:zcap:root',
      invoker: agent.did,
      parentCapability: 'did:web:service.example',
      invocationTarget: 'did:web:service.example',
      allowedAction: ['read:orders'],
      caveats: [{ type: 'MaxAmount', limit: '10', currency: 'USD' }],
    });
    expect(hop.validFrom).toBe('2026-01-01T00:00:00Z');
    expect(await verifyDelegationHop(hop, resolve)).toMatchObject({ ok: true, issuer: owner.did, invoker: agent.did });
    const bare = await buildDelegationHop(rootHopInput(root), owner.signer);
    expect(bare.id).toMatch(/^urn:zcap:/);
    expect(bare.credentialSubject.caveats).toBeUndefined();
    expect(bare.validFrom).toBeUndefined();
  });

  it('refuses bad inputs before signing', async () => {
    await expect(buildDelegationHop(rootHopInput({ ...root, invoker: 'x' }), owner.signer)).rejects.toThrow('invoker must be a DID');
    await expect(buildDelegationHop({ ...root, parentCapability: '' }, owner.signer)).rejects.toThrow('parentCapability is required');
    await expect(buildDelegationHop({ ...root, parentCapability: 'p', invocationTarget: '' }, owner.signer)).rejects.toThrow('invocationTarget is required');
    await expect(buildDelegationHop(rootHopInput({ ...root, allowedAction: ['', 'x'] }), owner.signer)).rejects.toThrow('allowedAction must be');
    await expect(buildDelegationHop(rootHopInput({ ...root, validUntil: undefined as never }), owner.signer)).rejects.toThrow('validUntil is required');
  });

  it('refuses a hop with an unknown subject member (Core L3.5a) and a hop whose proof does not hold', async () => {
    const hop = await buildDelegationHop(rootHopInput(root), owner.signer);
    expect(await verifyDelegationHop({ ...hop, credentialSubject: { ...hop.credentialSubject, scopes: [] } }, resolve)).toMatchObject({ ok: false, reason: 'schema_invalid' });
    expect(await verifyDelegationHop({ ...hop, credentialSubject: { ...hop.credentialSubject, allowedAction: ['admin'] } }, resolve)).toMatchObject({ ok: false, reason: 'signature_invalid' });
    const controlled = { ...hop, credentialSubject: { ...hop.credentialSubject, controller: agent.did } };
    delete (controlled.credentialSubject as { invoker?: string }).invoker;
    expect(await verifyDelegationHop(controlled, resolve)).toMatchObject({ ok: false, reason: 'signature_invalid' });
  });
});

describe('card level (story C-B)', () => {
  it('derives L1, L2 and L3 the way SPEC-ENTITY-CARD.md §9.4 does, demoting fail-closed', () => {
    expect(deriveConformanceLevel({ verified: [], unverified: [] })).toBe('L1');
    expect(deriveConformanceLevel({ verified: ['a'], unverified: ['b'] })).toBe('L1');
    expect(deriveConformanceLevel({ verified: ['a'], unverified: [] })).toBe('L2');
    expect(deriveConformanceLevel({ verified: ['a'], unverified: [] }, true)).toBe('L3');
    expect(deriveConformanceLevel({ verified: ['a'], unverified: [] }, true, false)).toBe('L2');
    expect(deriveConformanceLevel({ verified: [], unverified: [] }, true)).toBe('L1');
  });

  it('sorts a card\'s capabilities into verified and unverified', async () => {
    const validFrom = '2026-01-01T00:00:00Z';
    const read = await buildCapabilityAttestation({ subjectDid: agent.did, capability: 'read:orders', validUntil: '2026-12-31T00:00:00Z', statusEntry: entry(11), validFrom }, helix.signer);
    const write = await buildCapabilityAttestation({ subjectDid: agent.did, capability: 'write:orders', validUntil: '2026-12-31T00:00:00Z', statusEntry: entry(12), validFrom }, owner.signer);
    const expired = await buildCapabilityAttestation({ subjectDid: agent.did, capability: 'write:orders', validUntil: '2026-02-01T00:00:00Z', statusEntry: entry(13), validFrom }, helix.signer);
    const capabilities = [attestedCapabilityEntry('read:orders', [read]), attestedCapabilityEntry('write:orders', [expired, write]), 'handshake'];
    expect(capabilities.map(capabilityName)).toEqual(['read:orders', 'write:orders', 'handshake']);
    const check = await checkCapabilities(capabilities, resolve, { subjectDid: agent.did, now: NOW });
    expect(check).toEqual({ verified: ['read:orders', 'write:orders'], unverified: ['handshake'] });
    expect(deriveConformanceLevel(check)).toBe('L1');
    const listed = await checkCapabilities(capabilities.slice(0, 2), resolve, { subjectDid: agent.did, now: NOW, trustedIssuers: [helix.did], maxClockSkewMs: 0 });
    expect(listed).toEqual({ verified: ['read:orders'], unverified: ['write:orders'] });
    const revokedList = setBit(createStatusList(64), 11, 1);
    const revoked = await checkCapabilities(capabilities.slice(0, 2), resolve, { subjectDid: agent.did, now: NOW, statusLists: { [LIST_URL]: { credentialSubject: { encodedList: revokedList } } } });
    expect(revoked).toEqual({ verified: ['write:orders'], unverified: ['read:orders'] });
    const noVc = await checkCapabilities([{ name: 'x', attestations: [{ vc: 'jwt-cap-attestation' }, { vc: null }] }], resolve, { subjectDid: agent.did });
    expect(noVc).toEqual({ verified: [], unverified: ['x'] });
  });
});
