// Copyright 2026 DgVerse LLP
// KYA-OS story C-E points 2 and 3: versioned DID documents, key validity by kid, the jwks.json projection.
import * as ed25519 from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import {
  DID_DOCUMENT_STALE,
  InvalidJWSError,
  JwsReasons,
  KeyValidityReasons,
  MemoryRotationSequenceStore,
  ProofReasons,
  RotationSequenceGuard,
  StaleDidDocumentError,
  buildDidDocument,
  guardedResolver,
  keyValidityProblem,
  projectJwks,
  proofTime,
  publicKeyBytesToJwk,
  readJwks,
  rotationSequenceOf,
  signDataIntegrity,
  signJws,
  verifyDataIntegrity,
  verifyJwsByKid,
  versionDidDocument,
  type AgentDidDocument,
  type JwsDidDocument,
  type Signer,
} from '../../../../src/core/index.js';
import '../../../../src/core/crypto/keys.js';

const DID = 'did:web:helix.example:agents:0a1b2c';
const OLD_SEED = new Uint8Array(32).fill(7);
const NEW_SEED = new Uint8Array(32).fill(9);
const OLD_JWK = publicKeyBytesToJwk(ed25519.getPublicKey(OLD_SEED));
const NEW_JWK = publicKeyBytesToJwk(ed25519.getPublicKey(NEW_SEED));

function signer(seed: Uint8Array, kid: string): Signer {
  return { did: DID, kid, sign: async (bytes: Uint8Array) => ed25519.signAsync(bytes, seed) };
}

/** The rotated document: key-2 current, key-1 superseded until `until`, revoked at `revoked` if given. */
function rotated(until: string, revoked?: string, sequence = 2): AgentDidDocument {
  return versionDidDocument(
    buildDidDocument({ did: DID, publicKeyJwk: NEW_JWK, kid: 'key-2' }),
    [{ kid: 'key-1', publicKeyJwk: OLD_JWK, validUntil: until, ...(revoked ? { revoked } : {}) }],
    { rotationSequence: sequence, updated: '2026-11-23T10:00:00Z' },
  );
}

const resolverOf = (document: unknown) => async (): Promise<JwsDidDocument> => document as JwsDidDocument;

describe('keyValidityProblem', () => {
  const at = Date.parse('2026-11-23T10:00:00Z');
  it('accepts a current key, and a superseded key for a proof made inside its validity', () => {
    expect(keyValidityProblem({ id: 'k' }, at)).toBeUndefined();
    expect(keyValidityProblem({ id: 'k', validUntil: '2026-11-24T00:00:00Z', validFrom: '2026-11-01T00:00:00+05:30' }, at)).toBeUndefined();
  });

  it('refuses a proof made after validUntil or before validFrom, and checks a timeless proof at now', () => {
    expect(keyValidityProblem({ id: 'k', validUntil: '2026-11-22T00:00:00Z' }, at)).toMatchObject({ reason: KeyValidityReasons.KEY_SUPERSEDED });
    expect(keyValidityProblem({ id: 'k', validFrom: '2026-11-24T00:00:00Z' }, at)).toMatchObject({ reason: 'key_superseded' });
    expect(keyValidityProblem({ id: 'k', validUntil: '2026-11-22T00:00:00Z' }, undefined, at)).toMatchObject({ reason: 'key_superseded' });
    expect(keyValidityProblem({ id: 'k', validUntil: '2026-11-24T00:00:00Z' }, undefined, at)).toBeUndefined();
  });

  it('refuses everything a revoked key signed, and a key whose validity is not an instant', () => {
    expect(keyValidityProblem({ id: 'k', validUntil: '2026-11-24T00:00:00Z', revoked: '2026-11-24T00:00:00Z' }, at)).toMatchObject({ reason: 'key_revoked' });
    expect(keyValidityProblem({ id: 'k', validUntil: 'tomorrow' }, at)).toMatchObject({ reason: 'key_validity_malformed' });
    expect(keyValidityProblem({ id: 'k', revoked: '2026-11-24' }, at)).toMatchObject({ reason: 'key_validity_malformed' });
    expect(keyValidityProblem({ validFrom: 1 }, at)).toMatchObject({ message: expect.stringContaining('the key') });
  });

  it('reads proof times as RFC 3339 instants or epoch seconds', () => {
    expect(proofTime('2026-11-23T10:00:00Z')).toBe(at);
    expect(proofTime(at / 1000)).toBe(at);
    expect(proofTime(-1)).toBeUndefined();
    expect(proofTime('23 Nov 2026')).toBeUndefined();
    expect(proofTime(undefined)).toBeUndefined();
  });
});

describe('versioned DID documents', () => {
  it('keeps the superseded key, with its validity, under every relationship, and carries the version', () => {
    const document = rotated('2026-11-24T10:00:00Z');
    expect(document).toMatchObject({ rotationSequence: 2, updated: '2026-11-23T10:00:00Z' });
    expect(document.assertionMethod).toEqual([`${DID}#key-2`, `${DID}#key-1`]);
    expect(document.authentication).toEqual([`${DID}#key-2`, `${DID}#key-1`]);
    expect(document.verificationMethod[1]).toMatchObject({ id: `${DID}#key-1`, validUntil: '2026-11-24T10:00:00Z', publicKeyJwk: OLD_JWK });
    expect(document.verificationMethod[0]).not.toHaveProperty('validUntil');
  });

  it('updates a key already listed instead of listing it twice', () => {
    const base = buildDidDocument({ did: DID, publicKeyJwk: NEW_JWK, kid: 'key-2' });
    const document = versionDidDocument(base, [{ kid: `${DID}#key-2`, publicKeyJwk: NEW_JWK, validFrom: '2026-11-23T00:00:00Z' }], { rotationSequence: 1, updated: '2026-11-23T10:00:00Z' });
    expect(document.verificationMethod).toHaveLength(1);
    expect(document.verificationMethod[0]).toMatchObject({ validFrom: '2026-11-23T00:00:00Z' });
    expect(document.assertionMethod).toEqual([`${DID}#key-2`]);
  });

  it('refuses a version that is not a whole number or an instant', () => {
    const base = buildDidDocument({ did: DID, publicKeyJwk: NEW_JWK });
    expect(() => versionDidDocument(base, [], { rotationSequence: 0, updated: '2026-11-23T10:00:00Z' })).toThrow(/rotationSequence/);
    expect(() => versionDidDocument(base, [], { rotationSequence: 1.5, updated: '2026-11-23T10:00:00Z' })).toThrow(/rotationSequence/);
    expect(() => versionDidDocument(base, [], { rotationSequence: 1, updated: 'now' })).toThrow(/updated/);
  });

  it('reads rotationSequence only as a whole number from 1', () => {
    expect(rotationSequenceOf({ rotationSequence: 3 })).toBe(3);
    for (const value of [0, -1, 1.5, '3', null]) expect(rotationSequenceOf({ rotationSequence: value })).toBeUndefined();
    expect(rotationSequenceOf(null)).toBeUndefined();
  });
});

describe('verifiers pick the key by kid and check the proof time (C-E point 3)', () => {
  it('a Data Integrity proof made before rotation verifies after it; one made later with the old key is refused', async () => {
    const before = await signDataIntegrity({ issuer: DID, claim: 'before' }, signer(OLD_SEED, 'key-1'), { created: '2026-11-23T09:00:00Z' });
    const after = await signDataIntegrity({ issuer: DID, claim: 'after' }, signer(OLD_SEED, 'key-1'), { created: '2026-11-25T09:00:00Z' });
    const current = await signDataIntegrity({ issuer: DID, claim: 'new key' }, signer(NEW_SEED, 'key-2'), { created: '2026-11-25T09:00:00Z' });
    const resolve = resolverOf(rotated('2026-11-24T10:00:00Z'));
    expect(await verifyDataIntegrity(before, resolve)).toMatchObject({ ok: true, verificationMethod: `${DID}#key-1` });
    expect(await verifyDataIntegrity(after, resolve)).toMatchObject({ ok: false, reason: ProofReasons.KEY_SUPERSEDED });
    expect(await verifyDataIntegrity(current, resolve)).toMatchObject({ ok: true, verificationMethod: `${DID}#key-2` });
  });

  it('a proof signed with a revoked key is refused whatever created it claims', async () => {
    const before = await signDataIntegrity({ issuer: DID, claim: 'before' }, signer(OLD_SEED, 'key-1'), { created: '2026-11-23T09:00:00Z' });
    const resolve = resolverOf(rotated('2026-11-23T11:00:00Z', '2026-11-23T11:00:00Z', 3));
    expect(await verifyDataIntegrity(before, resolve)).toMatchObject({ ok: false, reason: ProofReasons.KEY_REVOKED });
  });

  it('a proof without created is checked at now', async () => {
    const proof = await signDataIntegrity({ issuer: DID }, signer(OLD_SEED, 'key-1'), { created: '2026-11-23T09:00:00Z' });
    const { created: _created, ...rest } = proof.proof as unknown as Record<string, unknown>;
    // Removing `created` breaks the signature, so the validity check must refuse it first.
    expect(await verifyDataIntegrity({ ...proof, proof: rest }, resolverOf(rotated('2026-11-24T10:00:00Z')), { now: Date.parse('2026-11-25T00:00:00Z') })).toMatchObject({
      ok: false,
      reason: 'key_superseded',
    });
  });

  it('a JWS is checked at its iat, else at the time the caller gives, else now', async () => {
    const resolve = resolverOf(rotated('2026-11-24T10:00:00Z'));
    const early = await signJws({ iss: DID, iat: Date.parse('2026-11-23T09:00:00Z') / 1000 }, signer(OLD_SEED, 'key-1'));
    const late = await signJws({ iss: DID, iat: Date.parse('2026-11-25T09:00:00Z') / 1000 }, signer(OLD_SEED, 'key-1'));
    const timeless = await signJws({ iss: DID }, signer(OLD_SEED, 'key-1'));
    expect((await verifyJwsByKid(early, resolve)).kid).toBe(`${DID}#key-1`);
    await expect(verifyJwsByKid(late, resolve)).rejects.toMatchObject({ reason: JwsReasons.KEY_SUPERSEDED });
    await expect(verifyJwsByKid(timeless, resolve, { now: Date.parse('2026-11-25T00:00:00Z') })).rejects.toBeInstanceOf(InvalidJWSError);
    expect((await verifyJwsByKid(late, resolve, { at: Date.parse('2026-11-23T00:00:00Z') })).did).toBe(DID);
    await expect(verifyJwsByKid(early, resolverOf(rotated('2026-11-24T10:00:00Z', '2026-11-23T11:00:00Z')))).rejects.toMatchObject({ reason: JwsReasons.KEY_REVOKED });
    const malformed = rotated('2026-11-24T10:00:00Z');
    (malformed.verificationMethod[1] as Record<string, unknown>)['validUntil'] = 'soon';
    await expect(verifyJwsByKid(early, resolverOf(malformed))).rejects.toMatchObject({ reason: JwsReasons.KEY_VALIDITY_MALFORMED });
  });
});

describe('the last-seen sequence (C-E point 2)', () => {
  it('refuses a lower sequence, and a document that drops it, once a sequence was seen', async () => {
    const guard = new RotationSequenceGuard();
    expect(await guard.check(DID, { rotationSequence: 2 })).toBeUndefined();
    expect(await guard.check(DID, { rotationSequence: 2 })).toBeUndefined();
    const stale = await guard.check(DID, { rotationSequence: 1 });
    expect(stale).toBeInstanceOf(StaleDidDocumentError);
    expect(stale).toMatchObject({ reason: DID_DOCUMENT_STALE, did: DID, sequence: 1, lastSeen: 2 });
    expect((await guard.check(DID, {}))?.message).toMatch(/carries no rotationSequence/);
    expect(await guard.check(DID, { rotationSequence: 3 })).toBeUndefined();
    await expect(guard.assertCurrent(DID, { rotationSequence: 2 })).rejects.toThrow(/lower than 3/);
    // Another DID is unaffected, and an unversioned DID stays readable.
    expect(await guard.check('did:web:other.example', {})).toBeUndefined();
  });

  it('wraps a resolver: a stale document throws, nothing resolved passes through', async () => {
    const served: unknown[] = [{ id: DID, rotationSequence: 4 }, { id: DID, rotationSequence: 3 }, null];
    const resolve = guardedResolver(async () => served.shift() as JwsDidDocument | null);
    expect(await resolve(DID)).toMatchObject({ rotationSequence: 4 });
    await expect(resolve(DID)).rejects.toBeInstanceOf(StaleDidDocumentError);
    expect(await resolve(DID)).toBeNull();
  });

  it('the memory store keeps the highest sequence and drops the oldest DID beyond its bound', () => {
    const store = new MemoryRotationSequenceStore(2);
    store.raise('a', 2);
    store.raise('a', 1);
    expect(store.get('a')).toBe(2);
    store.raise('b', 1);
    store.raise('c', 1);
    expect(store.get('a')).toBeUndefined();
    expect(store.get('c')).toBe(1);
  });

  it('a shared store is consulted asynchronously', async () => {
    const kept = new Map<string, number>();
    const guard = new RotationSequenceGuard({ get: async (did) => kept.get(did), raise: async (did, sequence) => void kept.set(did, sequence) });
    await guard.assertCurrent(DID, { rotationSequence: 5 });
    expect(kept.get(DID)).toBe(5);
    expect(await guard.check(DID, { rotationSequence: 4 })).toBeInstanceOf(StaleDidDocumentError);
  });
});

describe('the jwks.json projection', () => {
  it('projects every Ed25519 method with its kid, validity and the document version', () => {
    const document = rotated('2026-11-24T10:00:00Z', '2026-11-23T11:00:00Z');
    const withRelative = {
      ...document,
      verificationMethod: [
        ...document.verificationMethod,
        { id: '#x25519', type: 'X25519KeyAgreementKey2020', controller: DID, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: 'AA' } },
        { id: '#key-3', type: 'Ed25519VerificationKey2020', controller: DID, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: NEW_JWK.x }, validFrom: '2026-11-23T00:00:00Z' },
      ],
    };
    const jwks = projectJwks(withRelative as never);
    expect(jwks).toEqual({
      keys: [
        { kty: 'OKP', crv: 'Ed25519', x: NEW_JWK.x, kid: `${DID}#key-2`, use: 'sig', alg: 'EdDSA' },
        { kty: 'OKP', crv: 'Ed25519', x: OLD_JWK.x, kid: `${DID}#key-1`, use: 'sig', alg: 'EdDSA', validUntil: '2026-11-24T10:00:00Z', revoked: '2026-11-23T11:00:00Z' },
        { kty: 'OKP', crv: 'Ed25519', x: NEW_JWK.x, kid: `${DID}#key-3`, use: 'sig', alg: 'EdDSA', validFrom: '2026-11-23T00:00:00Z' },
      ],
      rotationSequence: 2,
      updated: '2026-11-23T10:00:00Z',
    });
    expect(projectJwks({ id: DID })).toEqual({ keys: [] });
  });

  it('reads a JWKS through the same guard: a lower sequence than the document seen is refused', async () => {
    const guard = new RotationSequenceGuard();
    await guard.assertCurrent(DID, rotated('2026-11-24T10:00:00Z', undefined, 3));
    const older = projectJwks(rotated('2026-11-24T10:00:00Z', undefined, 2));
    await expect(readJwks(DID, older, guard)).rejects.toBeInstanceOf(StaleDidDocumentError);
    const current = projectJwks(rotated('2026-11-24T10:00:00Z', undefined, 3));
    const foreign = { ...current, keys: [...current.keys, { ...current.keys[0], kid: 'did:web:evil.example#key-1' }, 'junk'] };
    expect((await readJwks(DID, foreign, guard)).map((key) => key.kid)).toEqual([`${DID}#key-2`, `${DID}#key-1`]);
    await expect(readJwks(DID, { keys: 'none' }, guard)).rejects.toThrow(/not a JWK Set/);
    await expect(readJwks(DID, null, guard)).rejects.toThrow(/not a JWK Set/);
  });
});
