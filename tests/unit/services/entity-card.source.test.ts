// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: what a Helix-hosted card says is read from the DID, agent and service records.
import { describe, expect, it, vi } from 'vitest';
import { buildDIDDocument, buildDidDocument, publicKeyBytesToJwk } from '../../../src/core/index.js';
import { assertionKeyOf, createEntityCardSource } from '../../../src/services/entity-card/entity-card.source.js';

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
