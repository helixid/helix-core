// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: what a Helix-hosted card says is read from the DID, agent and service records.
import { describe, expect, it, vi } from 'vitest';
import { buildDIDDocument, buildDidDocument, publicKeyBytesToJwk } from '../../../src/core/index.js';
import { assertionKeyOf, attestedCardCapabilities, createEntityCardSource, credentialCardDetails } from '../../../src/services/entity-card/entity-card.source.js';

const JWK = publicKeyBytesToJwk(new Uint8Array(32).fill(8));
const AGENT = 'did:web:helix.test:acme:ledger-agent';
const SERVICE = 'did:web:helix.test:acme:orders';
const ORG = 'did:web:helix.test:acme';

const dids: Record<string, { subjectType: string; didDocument: unknown; deactivatedAt?: Date | null }> = {
  [AGENT]: { subjectType: 'agent', didDocument: buildDidDocument({ did: AGENT, publicKeyJwk: JWK, kid: 'signing' }) },
  [SERVICE]: { subjectType: 'service', didDocument: buildDIDDocument(SERVICE, 'a'.repeat(64)), deactivatedAt: new Date('2026-01-01') },
  [ORG]: { subjectType: 'user', didDocument: buildDidDocument({ did: ORG, publicKeyJwk: JWK }) },
};

describe('assertionKeyOf', () => {
  it('picks the first assertion method that carries a public Ed25519 JWK, and nothing from a legacy document', () => {
    expect(assertionKeyOf(buildDidDocument({ did: AGENT, publicKeyJwk: JWK, kid: 'signing' }))).toEqual({ kid: `${AGENT}#signing`, publicKeyJwk: JWK });
    expect(assertionKeyOf({ id: AGENT, assertionMethod: ['#k'], verificationMethod: [{ id: `${AGENT}#other`, publicKeyJwk: JWK }, { id: `${AGENT}#k`, publicKeyJwk: { ...JWK, x: 'B'.repeat(43) } }] })).toEqual({ kid: `${AGENT}#k`, publicKeyJwk: { ...JWK, x: 'B'.repeat(43) } });
    expect(assertionKeyOf({ id: AGENT, assertionMethod: [{ id: `${AGENT}#k` }], verificationMethod: [{ id: `${AGENT}#k`, publicKeyJwk: JWK }] })).toEqual({ kid: `${AGENT}#k`, publicKeyJwk: JWK });
    expect(assertionKeyOf({ id: AGENT, verificationMethod: [{ id: `${AGENT}#k`, publicKeyJwk: JWK }] })).toEqual({ kid: `${AGENT}#k`, publicKeyJwk: JWK });
    expect(assertionKeyOf(buildDIDDocument(SERVICE, 'a'.repeat(64)))).toBeUndefined();
    expect(assertionKeyOf({ id: AGENT, verificationMethod: [{ id: `${AGENT}#k`, publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'a' } }] })).toBeUndefined();
    expect(assertionKeyOf({ id: AGENT, verificationMethod: [{ publicKeyJwk: JWK }] })).toBeUndefined();
    expect(assertionKeyOf(null)).toBeUndefined();
    expect(assertionKeyOf({ id: AGENT })).toBeUndefined();
  });
});

describe('createEntityCardSource', () => {
  const didRepository = { findDidById: vi.fn(async (did: string) => dids[did] ?? null) };

  it('types agents, services and orgs, names them from their records, and carries the key', async () => {
    const source = createEntityCardSource({
      host: 'helix.test',
      didRepository,
      agentRecords: { findByDid: async (did) => (did === AGENT ? { name: 'Ledger' } : null) },
      services: { findByDid: async (did) => (did === SERVICE ? { name: 'Orders' } : null) },
    });
    expect(source.host).toBe('helix.test');
    expect(await source.find(AGENT)).toEqual({ didDocument: dids[AGENT]!.didDocument, deactivatedAt: undefined, card: { entityType: 'agent', name: 'Ledger', kid: `${AGENT}#signing`, publicKeyJwk: JWK } });
    expect(await source.find(SERVICE)).toEqual({ didDocument: dids[SERVICE]!.didDocument, deactivatedAt: dids[SERVICE]!.deactivatedAt, card: { entityType: 'mcp', name: 'Orders' } });
    expect((await source.find(ORG))!.card).toEqual({ entityType: 'verifier', name: ORG, kid: `${ORG}#key-1`, publicKeyJwk: JWK });
    expect(await source.find('did:web:helix.test:nobody')).toBeNull();
  });

  it('falls back to the DID as name without records, takes orgEntityType, and lets details override everything', async () => {
    const bare = createEntityCardSource({ host: 'helix.test', didRepository, orgEntityType: 'human' });
    expect((await bare.find(AGENT))!.card.name).toBe(AGENT);
    expect((await bare.find(ORG))!.card.entityType).toBe('human');
    const detailed = createEntityCardSource({
      host: 'helix.test',
      didRepository,
      details: async (did, subjectType) =>
        did === AGENT && subjectType === 'agent'
          ? { name: 'Named', entityType: 'client', capabilities: ['handshake'], responsibleParty: ORG, principal: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', delegationRef: 'r>d', revocation: { statusListCredential: 'https://helix.test/s', statusListIndex: '1' } }
          : undefined,
    });
    expect((await detailed.find(AGENT))!.card).toEqual({
      entityType: 'client',
      name: 'Named',
      kid: `${AGENT}#signing`,
      publicKeyJwk: JWK,
      capabilities: ['handshake'],
      responsibleParty: ORG,
      principal: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      delegationRef: 'r>d',
      revocation: { statusListCredential: 'https://helix.test/s', statusListIndex: '1' },
    });
    expect((await detailed.find(ORG))!.card.name).toBe(ORG);
  });
});

describe('credentialCardDetails (KYA-OS F-3 parity: C-B point 2, C-A point 3)', () => {
  const attestation = (subject: string, capability: unknown, id: string): Record<string, unknown> => ({
    id,
    type: ['VerifiableCredential', 'CapabilityAttestationCredential'],
    credentialSubject: { id: subject, capability },
  });
  const identity = (subject: string, id: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
    id,
    type: ['VerifiableCredential', 'AgentIdentityCredential'],
    credentialSubject: { id: subject, name: 'Ledger', responsibleParty: 'did:web:helix.test' },
    credentialStatus: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '7', statusListCredential: 'https://helix.test/v1/status-list/1' },
    ...extra,
  });
  const attestations = [
    attestation(AGENT, 'orders:read', 'att:1'),
    attestation(AGENT, 'orders:write', 'att:2'),
    attestation(AGENT, 'orders:read', 'att:3'),
    attestation('did:web:helix.test:acme:someone-else', 'orders:read', 'att:4'),
    attestation(AGENT, '', 'att:5'),
    attestation(AGENT, 7, 'att:6'),
    { id: 'att:7', type: ['VerifiableCredential', 'CapabilityAttestationCredential'] },
  ];
  const storeOf = (held: Record<string, Record<string, unknown>[]>) => ({
    listActiveBySubjectDid: vi.fn(async (_did: string, type?: string) => held[type ?? ''] ?? []),
  });

  it("puts an agent's attestations, grouped by capability in issued order, its responsible party and its identity's status entry on the card", async () => {
    const store = storeOf({
      CapabilityAttestationCredential: attestations,
      AgentIdentityCredential: [identity('did:web:other', 'id:0'), identity(AGENT, 'id:1', { credentialSubject: { id: AGENT, responsibleParty: 'did:web:older' } }), identity(AGENT, 'id:2')],
    });
    expect(await credentialCardDetails(store)(AGENT, 'agent')).toEqual({
      capabilities: [
        { name: 'orders:read', attestations: [{ vc: attestations[0] }, { vc: attestations[2] }] },
        { name: 'orders:write', attestations: [{ vc: attestations[1] }] },
      ],
      responsibleParty: 'did:web:helix.test',
      revocation: { statusListCredential: 'https://helix.test/v1/status-list/1', statusListIndex: '7' },
    });
    expect(await attestedCardCapabilities(storeOf({}), AGENT)).toBeUndefined();
  });

  it('says nothing it has no credential for, takes a numeric index, and never looks for a service or an org', async () => {
    const bare = storeOf({ AgentIdentityCredential: [identity(AGENT, 'id:1', { credentialSubject: { id: AGENT }, credentialStatus: { statusListCredential: 'https://helix.test/l', statusListIndex: 3 } })] });
    expect(await credentialCardDetails(bare)(AGENT, 'agent')).toEqual({ revocation: { statusListCredential: 'https://helix.test/l', statusListIndex: '3' } });
    const broken = storeOf({ AgentIdentityCredential: [identity(AGENT, 'id:1', { credentialSubject: { id: AGENT, responsibleParty: '' }, credentialStatus: { statusListIndex: '1' } })] });
    expect(await credentialCardDetails(broken)(AGENT, 'agent')).toBeUndefined();
    const store = storeOf({});
    expect(await credentialCardDetails(store)(SERVICE, 'service')).toBeUndefined();
    expect(await credentialCardDetails(store)(ORG, 'user')).toBeUndefined();
    expect(store.listActiveBySubjectDid).not.toHaveBeenCalled();
  });

  it('fills the hosted card where details say nothing; details still win member by member', async () => {
    const didRepository = { findDidById: async (did: string) => dids[did] ?? null };
    const store = storeOf({ CapabilityAttestationCredential: attestations.slice(0, 1), AgentIdentityCredential: [identity(AGENT, 'id:1')] });
    const source = createEntityCardSource({ host: 'helix.test', didRepository, credentials: credentialCardDetails(store) });
    expect((await source.find(AGENT))!.card).toMatchObject({
      capabilities: [{ name: 'orders:read', attestations: [{ vc: attestations[0] }] }],
      responsibleParty: 'did:web:helix.test',
      revocation: { statusListCredential: 'https://helix.test/v1/status-list/1', statusListIndex: '7' },
    });
    expect((await source.find(SERVICE))!.card).not.toHaveProperty('capabilities');
    const overridden = createEntityCardSource({
      host: 'helix.test',
      didRepository,
      details: async () => ({ capabilities: ['self-declared'], name: 'Named', responsibleParty: undefined }),
      credentials: credentialCardDetails(store),
    });
    expect((await overridden.find(AGENT))!.card).toMatchObject({ name: 'Named', capabilities: ['self-declared'], responsibleParty: 'did:web:helix.test' });
  });
});
