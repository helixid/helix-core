// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: the custody choice, labels, proof of possession, private-material scan, KeyStoreSigner.
import * as ed25519 from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_CUSTODY_DEFAULTS,
  CUSTODY_LABEL_HELIX,
  CUSTODY_LABEL_SELF,
  CustodyChoiceInvalidError,
  KeyStoreSigner,
  base64UrlEncode,
  custodyClaims,
  custodyLabel,
  enrollmentProofMessage,
  findPrivateKeyMaterial,
  isConformantCustody,
  isCustodySubjectType,
  isDidHostingMode,
  isKeyCustodyMode,
  parseCustodyDefaults,
  resolveCustodyChoice,
  rotationProofFresh,
  rotationProofMessage,
  verifyProofOfPossession,
  type KeyStore,
} from '../../../../src/core/index.js';

describe('custody choice (F-3 point 1)', () => {
  it('takes each member from the override, else the account preference, else the built-in default', () => {
    expect(resolveCustodyChoice(undefined)).toEqual({
      keyCustody: 'self',
      didHosting: 'helix',
      source: { keyCustody: 'built-in', didHosting: 'built-in' },
    });
    expect(resolveCustodyChoice({}, { defaultKeyCustody: 'helix', defaultDidHosting: 'own' })).toEqual({
      keyCustody: 'helix',
      didHosting: 'own',
      source: { keyCustody: 'account', didHosting: 'account' },
    });
    expect(resolveCustodyChoice({ keyCustody: 'self' }, { defaultKeyCustody: 'helix', defaultDidHosting: 'own' })).toEqual({
      keyCustody: 'self',
      didHosting: 'own',
      source: { keyCustody: 'override', didHosting: 'account' },
    });
    expect(resolveCustodyChoice({ keyCustody: 'helix', didHosting: 'helix' })).toMatchObject({ keyCustody: 'helix', didHosting: 'helix' });
  });

  it('allows any combination and refuses anything but the two modes', () => {
    for (const keyCustody of ['self', 'helix']) {
      for (const didHosting of ['own', 'helix']) {
        expect(resolveCustodyChoice({ keyCustody, didHosting })).toMatchObject({ keyCustody, didHosting });
      }
    }
    expect(() => resolveCustodyChoice({ keyCustody: 'custodial' })).toThrow(CustodyChoiceInvalidError);
    expect(() => resolveCustodyChoice({ didHosting: 'mine' })).toThrow(/didHosting/);
    expect(() => resolveCustodyChoice({ keyCustody: null })).toThrow(/keyCustody/);
  });

  it('parses the account preference strictly', () => {
    expect(parseCustodyDefaults({ defaultKeyCustody: 'helix', defaultDidHosting: 'helix' })).toEqual({ defaultKeyCustody: 'helix', defaultDidHosting: 'helix' });
    expect(() => parseCustodyDefaults(null)).toThrow(/object/);
    expect(() => parseCustodyDefaults([])).toThrow(/object/);
    expect(() => parseCustodyDefaults({ defaultKeyCustody: 'self', defaultDidHosting: 'own', extra: 1 })).toThrow(/unexpected/);
    expect(() => parseCustodyDefaults({ defaultKeyCustody: 'x', defaultDidHosting: 'own' })).toThrow(/defaultKeyCustody/);
    expect(() => parseCustodyDefaults({ defaultKeyCustody: 'self', defaultDidHosting: 'x' })).toThrow(/defaultDidHosting/);
    expect(BUILT_IN_CUSTODY_DEFAULTS).toEqual({ defaultKeyCustody: 'self', defaultDidHosting: 'helix' });
    expect(Object.isFrozen(BUILT_IN_CUSTODY_DEFAULTS)).toBe(true);
  });

  it('labels custodial subjects custody: helix and only self-custody as conformant (point 5)', () => {
    expect(custodyLabel('helix')).toBe(CUSTODY_LABEL_HELIX);
    expect(custodyLabel('self')).toBe(CUSTODY_LABEL_SELF);
    expect(CUSTODY_LABEL_HELIX).toBe('custody: helix');
    expect(isConformantCustody('self')).toBe(true);
    expect(isConformantCustody('helix')).toBe(false);
    expect(custodyClaims({ keyCustody: 'helix', didHosting: 'own', extra: 1 } as never)).toEqual({ keyCustody: 'helix', didHosting: 'own' });
    expect(isKeyCustodyMode('self')).toBe(true);
    expect(isKeyCustodyMode(1)).toBe(false);
    expect(isDidHostingMode('own')).toBe(true);
    expect(isDidHostingMode('self')).toBe(false);
    expect(isCustodySubjectType('owner')).toBe(true);
    expect(isCustodySubjectType('user')).toBe(false);
  });
});

describe('proof of possession (F-3 points 2 and 6)', () => {
  const seed = new Uint8Array(32).fill(7);
  const publicKey = ed25519.getPublicKey(seed);

  it('builds the enrollment and rotation messages and verifies signatures over them', () => {
    const message = enrollmentProofMessage({ did: 'did:web:h:o:a', kid: 'did:web:h:o:a#key-1', nonce: 'ab' });
    expect(new TextDecoder().decode(message)).toBe('helix-enroll:v1:did:web:h:o:a:did:web:h:o:a#key-1:ab');
    const signature = base64UrlEncode(ed25519.sign(message, seed));
    expect(verifyProofOfPossession(message, signature, publicKey)).toBe(true);
    expect(verifyProofOfPossession(enrollmentProofMessage({ did: 'did:web:h:o:a', kid: 'did:web:h:o:a#key-1', nonce: 'ac' }), signature, publicKey)).toBe(false);
    expect(verifyProofOfPossession(message, 123, publicKey)).toBe(false);
    expect(verifyProofOfPossession(message, 'not base64url!', publicKey)).toBe(false);
    expect(verifyProofOfPossession(message, base64UrlEncode(new Uint8Array(10)), publicKey)).toBe(false);
    expect(verifyProofOfPossession(message, signature, new Uint8Array(3))).toBe(false);
    const rotation = rotationProofMessage({ did: 'did:web:h:o:a', kid: 'did:web:h:o:a#key-2', issuedAt: '2026-11-21T00:00:00.000Z' });
    expect(new TextDecoder().decode(rotation)).toBe('helix-rotate:v1:did:web:h:o:a:did:web:h:o:a#key-2:2026-11-21T00:00:00.000Z');
    expect(() => enrollmentProofMessage({ did: 'did:web:h', kid: 'a b', nonce: 'x' })).toThrow(/whitespace/);
    expect(() => enrollmentProofMessage({ did: '', kid: 'k', nonce: 'x' })).toThrow();
  });

  it('accepts a rotation proof only within five minutes of now', () => {
    const now = Date.parse('2026-11-21T12:00:00Z');
    expect(rotationProofFresh('2026-11-21T12:04:00Z', now)).toBe(true);
    expect(rotationProofFresh('2026-11-21T11:56:00Z', now)).toBe(true);
    expect(rotationProofFresh('2026-11-21T12:06:00Z', now)).toBe(false);
    expect(rotationProofFresh('yesterday', now)).toBe(false);
    expect(rotationProofFresh(undefined, now)).toBe(false);
    expect(rotationProofFresh(new Date().toISOString())).toBe(true);
  });
});

describe('private key material scan (self-custody invariant)', () => {
  it('finds a private member anywhere in a body', () => {
    expect(findPrivateKeyMaterial({ publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'x' } })).toBeUndefined();
    expect(findPrivateKeyMaterial({ publicKeyJwk: { kty: 'OKP', d: 'secret' } })).toBe('publicKeyJwk.d');
    expect(findPrivateKeyMaterial({ privateKeyHex: 'aa' })).toBe('privateKeyHex');
    expect(findPrivateKeyMaterial({ nested: [{ seed: 'aa' }] })).toBe('nested.0.seed');
    expect(findPrivateKeyMaterial('d')).toBeUndefined();
    expect(findPrivateKeyMaterial(null)).toBeUndefined();
  });
});

describe('KeyStoreSigner', () => {
  const calls: unknown[] = [];
  const store = {
    sign: async (ref: unknown, data: Uint8Array) => {
      calls.push(ref);
      return new Uint8Array(64).fill(data[0] ?? 0);
    },
  } as unknown as KeyStore;

  it('signs through the store under the full verification-method id and never holds the key', async () => {
    const signer = new KeyStoreSigner(store, 'did:web:h:o:a', 'did:web:h:o:a#key-2');
    expect(signer.did).toBe('did:web:h:o:a');
    expect(signer.kid).toBe('key-2');
    expect(signer.verificationMethodId).toBe('did:web:h:o:a#key-2');
    expect(await signer.sign(new Uint8Array([9]))).toEqual(new Uint8Array(64).fill(9));
    expect(calls).toEqual([{ did: 'did:web:h:o:a', kid: 'did:web:h:o:a#key-2' }]);
    expect(JSON.stringify(signer)).toBe('{"did":"did:web:h:o:a","kid":"key-2"}');
    expect(new KeyStoreSigner(store, 'did:web:h:o:a', 'key-1').verificationMethodId).toBe('did:web:h:o:a#key-1');
    expect(new KeyStoreSigner(store, 'did:web:h:o:a', '#key-3').kid).toBe('key-3');
    expect(() => new KeyStoreSigner(store, 'did:web:h:o:a', 'did:web:other#key-1')).toThrow(/not a verification method/);
    expect(() => new KeyStoreSigner(store, 'did:web:h:o:a', '')).toThrow();
  });
});
