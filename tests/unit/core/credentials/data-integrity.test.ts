// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: DataIntegrityProof eddsa-jcs-2022 sign and verify.
import { describe, expect, it } from 'vitest';
import {
  EnvSigner,
  ProofReasons,
  buildDIDDocument,
  derivePublicKey,
  hashData,
  issuerOf,
  publicKeyToMultibase,
  signDataIntegrity,
  verifyDataIntegrity,
  type DIDDocument,
  type Signer,
} from '../../../../src/core/index.js';
import { canonicalize } from '../../../../src/core/crypto/jcs.js';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import type { DidResolver } from '../../../../src/core/credentials/index.js';

function omit<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

const KEY = '7'.repeat(64);
const OTHER_KEY = '8'.repeat(64);
const did = `did:key:${publicKeyToMultibase(derivePublicKey(KEY))}`;
const otherDid = `did:key:${publicKeyToMultibase(derivePublicKey(OTHER_KEY))}`;
const signer = new EnvSigner({ did, envVar: 'K', env: { K: KEY } });
const documents: Record<string, DIDDocument> = {
  [did]: buildDIDDocument(did, derivePublicKey(KEY)),
  [otherDid]: buildDIDDocument(otherDid, derivePublicKey(OTHER_KEY)),
};
const resolve = (async (value: string) => documents[value]) as unknown as DidResolver;

const document = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:1',
  type: ['VerifiableCredential', 'Thing'],
  issuer: did,
  credentialSubject: { id: 'did:key:z6MkSubject', n: 1 },
};

describe('signDataIntegrity', () => {
  it('writes the proof the cryptosuite describes and signs the two concatenated hashes', async () => {
    const signed = await signDataIntegrity(document, signer, { created: '2026-01-01T00:00:00Z' });
    expect(signed.proof).toEqual({
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      created: '2026-01-01T00:00:00Z',
      verificationMethod: `${did}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: expect.stringMatching(/^z[1-9A-HJ-NP-Za-km-z]+$/),
    });
    const options = omit(signed.proof, 'proofValue');
    const config = { ...options, '@context': document['@context'] };
    const data = hashData(config, document);
    expect(bytesToHex(data.slice(0, 32))).toBe(bytesToHex(sha256(utf8ToBytes(canonicalize(config)))));
    expect(bytesToHex(data.slice(32))).toBe(bytesToHex(sha256(utf8ToBytes(canonicalize(document)))));
    expect(await verifyDataIntegrity(signed, resolve)).toEqual({ ok: true, issuer: did, verificationMethod: `${did}#key-1` });
  });

  it('defaults created to now and accepts an issuer object', async () => {
    const before = Date.now();
    const signed = await signDataIntegrity({ ...document, issuer: { id: did, name: 'Helix' } }, signer);
    expect(Date.parse(signed.proof.created)).toBeGreaterThanOrEqual(before - 1000);
    expect(await verifyDataIntegrity(signed, resolve)).toMatchObject({ ok: true, issuer: did });
  });

  it('signs a document without @context', async () => {
    const bare = omit(document, '@context');
    const signed = await signDataIntegrity(bare, signer);
    expect(await verifyDataIntegrity(signed, resolve)).toMatchObject({ ok: true });
  });

  it('refuses a document that already carries a proof, a signer that is not the issuer, or a bad kid', async () => {
    const signed = await signDataIntegrity(document, signer);
    await expect(signDataIntegrity(signed, signer)).rejects.toThrow('already carries a proof');
    await expect(signDataIntegrity({ ...document, issuer: otherDid }, signer)).rejects.toThrow('is not the issuer');
    await expect(signDataIntegrity({ ...document, issuer: 7 }, signer)).rejects.toThrow('is not the issuer');
    const badKid: Signer = { did, kid: 'a#b', sign: signer.sign.bind(signer) };
    await expect(signDataIntegrity(document, badKid)).rejects.toThrow('verification-method fragment');
    const short: Signer = { did, kid: 'key-1', sign: async () => new Uint8Array(3) };
    await expect(signDataIntegrity(document, short)).rejects.toThrow('64-byte Ed25519 signature');
  });

  it('refuses a document the canonicalizer cannot write', async () => {
    await expect(signDataIntegrity({ ...document, bad: undefined }, signer)).rejects.toThrow(/canonicalize/i);
  });
});

describe('verifyDataIntegrity', () => {
  const refusal = async (value: Record<string, unknown>, resolver: DidResolver = resolve): Promise<string> => {
    const verdict = await verifyDataIntegrity(value, resolver);
    if (verdict.ok) throw new Error('expected a refusal');
    return verdict.reason;
  };

  it('refuses every malformed proof shape with its reason', async () => {
    const signed = await signDataIntegrity(document, signer);
    const proof = signed.proof as unknown as Record<string, unknown>;
    expect(await refusal(document)).toBe(ProofReasons.PROOF_MISSING);
    expect(await refusal({ ...document, proof: [proof] })).toBe(ProofReasons.PROOF_MISSING);
    expect(await refusal({ ...document, proof: { ...proof, type: 'Ed25519Signature2020' } })).toBe(ProofReasons.PROOF_UNSUPPORTED);
    expect(await refusal({ ...document, proof: { ...proof, cryptosuite: 'eddsa-rdfc-2022' } })).toBe(ProofReasons.PROOF_UNSUPPORTED);
    expect(await refusal({ ...document, proof: { ...proof, proofPurpose: 'authentication' } })).toBe(ProofReasons.PROOF_PURPOSE_MISMATCH);
    expect(await refusal({ ...document, proof: { ...proof, proofValue: 'u' + 'A'.repeat(86) } })).toBe(ProofReasons.PROOF_VALUE_MALFORMED);
    expect(await refusal({ ...document, proof: { ...proof, proofValue: 'z' } })).toBe(ProofReasons.PROOF_VALUE_MALFORMED);
    expect(await refusal({ ...document, proof: { ...proof, proofValue: 'z0OIl' } })).toBe(ProofReasons.PROOF_VALUE_MALFORMED);
    expect(await refusal({ ...document, proof: { ...proof, proofValue: 'z2' } })).toBe(ProofReasons.PROOF_VALUE_MALFORMED);
    expect(await refusal({ ...document, proof: { ...proof, verificationMethod: 7 } })).toBe(ProofReasons.PROOF_METHOD_MALFORMED);
    expect(await refusal({ ...document, proof: { ...proof, verificationMethod: did } })).toBe(ProofReasons.PROOF_METHOD_MALFORMED);
    expect(await refusal({ ...document, proof: { ...proof, verificationMethod: `${otherDid}#key-1` } })).toBe(ProofReasons.PROOF_ISSUER_MISMATCH);
    expect(await refusal({ ...signed, issuer: 'nobody' })).toBe(ProofReasons.PROOF_ISSUER_MISMATCH);
  });

  it('holds the proof @context to a prefix of the document @context', async () => {
    const signed = await signDataIntegrity(document, signer);
    const withContext = { ...signed, proof: { ...signed.proof, '@context': ['https://www.w3.org/ns/credentials/v2'] } };
    expect(await verifyDataIntegrity(withContext, resolve)).toMatchObject({ ok: true });
    const foreign = { ...signed, proof: { ...signed.proof, '@context': ['https://elsewhere'] } };
    expect(await refusal(foreign)).toBe(ProofReasons.PROOF_CONTEXT_MISMATCH);
    const longer = { ...signed, proof: { ...signed.proof, '@context': ['https://www.w3.org/ns/credentials/v2', 'https://more'] } };
    expect(await refusal(longer)).toBe(ProofReasons.PROOF_CONTEXT_MISMATCH);
    // A scalar proof @context is a prefix, but the document was signed with its array context, so the hash differs.
    const scalar = { ...signed, proof: { ...signed.proof, '@context': 'https://www.w3.org/ns/credentials/v2' } };
    expect(await refusal(scalar)).toBe(ProofReasons.SIGNATURE_INVALID);
  });

  it('refuses when the issuer DID does not resolve, the resolver throws, or the key is not an assertion method', async () => {
    const signed = await signDataIntegrity(document, signer);
    expect(await refusal(signed, async () => undefined)).toBe(ProofReasons.DID_UNRESOLVED);
    expect(await refusal(signed, async () => null)).toBe(ProofReasons.DID_UNRESOLVED);
    expect(await refusal(signed, async () => { throw new Error('offline'); })).toBe(ProofReasons.DID_UNRESOLVED);
    const authenticationOnly = { ...documents[did]!, assertionMethod: [] };
    expect(await refusal(signed, (async () => authenticationOnly) as unknown as DidResolver)).toBe(ProofReasons.KEY_REJECTED);
    const unsupported = {
      ...documents[did]!,
      verificationMethod: [{ id: `${did}#key-1`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } }],
    } as unknown as DIDDocument;
    expect(await refusal(signed, (async () => unsupported) as unknown as DidResolver)).toBe(ProofReasons.KEY_REJECTED);
  });

  it('refuses a signature that does not verify: tampered document, tampered proof, or another key', async () => {
    const signed = await signDataIntegrity(document, signer);
    expect(await refusal({ ...signed, credentialSubject: { id: 'did:key:z6MkSubject', n: 2 } })).toBe(ProofReasons.SIGNATURE_INVALID);
    const flipped = `${signed.proof.proofValue.slice(0, -1)}${signed.proof.proofValue.endsWith('1') ? '2' : '1'}`;
    expect(await refusal({ ...signed, proof: { ...signed.proof, proofValue: flipped } })).toBe(ProofReasons.SIGNATURE_INVALID);
    const otherKeyDocument = { ...documents[did]!, verificationMethod: [{ ...documents[did]!.verificationMethod[0]!, publicKeyMultibase: documents[otherDid]!.verificationMethod[0]!.publicKeyMultibase }] };
    expect(await refusal(signed, async () => otherKeyDocument)).toBe(ProofReasons.SIGNATURE_INVALID);
  });

  it('refuses a document the canonicalizer cannot write after the key is read', async () => {
    const signed = await signDataIntegrity(document, signer);
    expect(await refusal({ ...signed, extra: undefined })).toBe(ProofReasons.DOCUMENT_NOT_CANONICAL);
  });
});

describe('issuerOf', () => {
  it('reads a DID string or an { id } object and nothing else', () => {
    expect(issuerOf('did:web:a')).toBe('did:web:a');
    expect(issuerOf({ id: 'did:web:a' })).toBe('did:web:a');
    expect(issuerOf({ id: 'web:a' })).toBeUndefined();
    expect(issuerOf('https://a')).toBeUndefined();
    expect(issuerOf(null)).toBeUndefined();
    expect(issuerOf(1)).toBeUndefined();
  });
});
