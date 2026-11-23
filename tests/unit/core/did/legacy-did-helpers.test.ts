// Copyright 2026 DgVerse LLP
// The legacy DID document helpers and the Ed25519Signature2020 proof check, and the stored
// DelegationGrantCredential schema: kept for reading what older deployments stored, now that the
// service-signed consent grant is retired (story L3-H).
import { describe, expect, it } from 'vitest';
import {
  DelegationGrantVCSchema,
  addServiceEndpoint,
  buildDIDDocument,
  buildServiceEndpoints,
  createEd25519Proof,
  derivePublicKey,
  extractPublicKeyFromDIDDocument,
  removeServiceEndpoint,
  verifyEd25519Proof,
} from '../../../../src/core/index.js';

const KEY = '7'.repeat(64);
const DID = 'did:web:legacy.example:agents:1';

describe('legacy DID document helpers', () => {
  it('reads the Ed25519 key, and refuses a document without one', () => {
    const document = buildDIDDocument(DID, derivePublicKey(KEY));
    expect(extractPublicKeyFromDIDDocument(document)).toBe(derivePublicKey(KEY).toLowerCase());
    expect(() => extractPublicKeyFromDIDDocument({ ...document, verificationMethod: [] })).toThrow(/no Ed25519VerificationKey2020/);
  });

  it('adds and removes service endpoints, refusing duplicates and unknown ids', () => {
    const document = buildDIDDocument(DID, derivePublicKey(KEY));
    const [endpoint] = buildServiceEndpoints(['https://a.example']);
    const added = addServiceEndpoint(document, endpoint!);
    expect(added.service).toEqual([{ id: '#domain-1', type: 'LinkedDomains', serviceEndpoint: 'https://a.example' }]);
    expect(() => addServiceEndpoint(added, endpoint!)).toThrow(/already exists/);
    expect(removeServiceEndpoint(added, '#domain-1').service).toBeUndefined();
    const two = addServiceEndpoint(added, { id: '#domain-2', type: 'LinkedDomains', serviceEndpoint: 'https://b.example' });
    expect(removeServiceEndpoint(two, '#domain-1').service).toHaveLength(1);
    expect(() => removeServiceEndpoint(document, '#nope')).toThrow(/not found/);
  });
});

describe('verifyEd25519Proof', () => {
  it('verifies a proof value with or without its multibase prefix, and refuses anything else', async () => {
    const payload = { hello: 'world' };
    const document = buildDIDDocument(DID, derivePublicKey(KEY));
    const proof = await createEd25519Proof(payload, KEY, `${DID}#key-1`);
    expect(await verifyEd25519Proof(payload, proof, document)).toBe(true);
    expect(await verifyEd25519Proof(payload, { proofValue: `z${proof.proofValue}` }, document)).toBe(true);
    expect(await verifyEd25519Proof({ hello: 'other' }, proof, document)).toBe(false);
    expect(await verifyEd25519Proof(payload, { proofValue: 'z0OIl' }, document)).toBe(false);
    expect(await verifyEd25519Proof(payload, { proofValue: '0OIl' }, document)).toBe(false);
  });
});

describe('DelegationGrantVCSchema (stored grants)', () => {
  it('needs both credential types', () => {
    const grant = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'vc:helix:grant:1',
      type: ['VerifiableCredential', 'DelegationGrantCredential'],
      issuer: 'did:web:shop.example',
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2027-01-01T00:00:00Z',
      credentialStatus: { id: 'https://x#1', type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '1', statusListCredential: 'https://x' },
      credentialSubject: { id: 'did:web:a', type: 'DelegationGrant', userDid: 'did:web:u', scopes: ['a'], durability: 'standing' },
    };
    expect(DelegationGrantVCSchema.safeParse(grant).success).toBe(true);
    expect(DelegationGrantVCSchema.safeParse({ ...grant, type: ['VerifiableCredential'] }).success).toBe(false);
  });
});
