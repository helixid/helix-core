// Copyright 2026 DgVerse LLP
// KYA-OS story L1-A: the did:web document of a client-held agent key.
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_AGENT_KEY_ID,
  DID_WEB_CONTEXTS,
  ValidationError,
  buildDidDocument,
  decodeBase58btc,
  derivePublicKey,
  didKeyFromPublicKey,
  encodeBase58btc,
  isBase58btc,
  isDidWeb,
  publicKeyBytesToJwk,
  publicKeyFromDidKey,
  publicKeyJwkBytes,
  publicKeyToMultibase,
  publicKeyToMultibaseOf,
  verificationMethodId,
} from '../../../../src/core/index.js';

const SEED = '11'.repeat(32);
const PUBLIC_KEY_HEX = derivePublicKey(SEED);
const PUBLIC_KEY = new Uint8Array(Buffer.from(PUBLIC_KEY_HEX, 'hex'));
const X = Buffer.from(PUBLIC_KEY).toString('base64url');
const DID = 'did:web:agents.example.com:agents:abc';
const JWK = { kty: 'OKP', crv: 'Ed25519', x: X } as const;

describe('buildDidDocument', () => {
  it('publishes the key as one verification method, <did>#<key-id>, for authentication and assertion', () => {
    const document = buildDidDocument({ did: DID, publicKeyJwk: JWK, kid: 'key-1', alsoKnownAs: [didKeyFromPublicKey(PUBLIC_KEY)] });
    const kid = `${DID}#key-1`;
    expect(document).toEqual({
      '@context': [...DID_WEB_CONTEXTS],
      id: DID,
      alsoKnownAs: [didKeyFromPublicKey(PUBLIC_KEY)],
      verificationMethod: [
        { id: kid, type: 'Ed25519VerificationKey2020', controller: DID, publicKeyJwk: JWK, publicKeyMultibase: publicKeyToMultibase(PUBLIC_KEY_HEX) },
      ],
      authentication: [kid],
      assertionMethod: [kid],
    });
  });

  it('defaults the key id, accepts a full verification-method id, drops a self-reference from alsoKnownAs, keeps services', () => {
    expect(buildDidDocument({ did: DID, publicKeyJwk: JWK }).verificationMethod[0]!.id).toBe(`${DID}#${DEFAULT_AGENT_KEY_ID}`);
    expect(buildDidDocument({ did: DID, publicKeyJwk: JWK, kid: `${DID}#k2` }).assertionMethod).toEqual([`${DID}#k2`]);
    expect(buildDidDocument({ did: DID, publicKeyJwk: JWK, kid: '#k3' }).authentication).toEqual([`${DID}#k3`]);
    const withService = buildDidDocument({ did: DID, publicKeyJwk: JWK, alsoKnownAs: [DID], service: [{ id: '#s', type: 'LinkedDomains', serviceEndpoint: 'https://a' }] });
    expect(withService.alsoKnownAs).toBeUndefined();
    expect(withService.service).toEqual([{ id: '#s', type: 'LinkedDomains', serviceEndpoint: 'https://a' }]);
    expect(buildDidDocument({ did: DID, publicKeyJwk: JWK, service: [] }).service).toBeUndefined();
  });

  it('refuses anything but a did:web DID, a kid of another DID, an empty fragment, and non-DID alsoKnownAs', () => {
    expect(() => buildDidDocument({ did: 'did:key:z6Mk', publicKeyJwk: JWK })).toThrow(ValidationError);
    expect(() => buildDidDocument({ did: 'did:web:', publicKeyJwk: JWK })).toThrow(ValidationError);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: JWK, kid: 'did:web:other.example#key-1' })).toThrow(/does not belong/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: JWK, kid: '' })).toThrow(/fragment/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: JWK, kid: `${DID}#a#b` })).toThrow(/fragment/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: JWK, alsoKnownAs: ['not-a-did'] })).toThrow(/alsoKnownAs/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: JWK, alsoKnownAs: [42 as unknown as string] })).toThrow(/alsoKnownAs/);
  });

  it('refuses private material in the JWK: d above all, then any member a public OKP JWK does not have', () => {
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: { ...JWK, d: Buffer.from(SEED, 'hex').toString('base64url') } })).toThrow(/private material \(d\)/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: { ...JWK, seed: SEED } })).toThrow(/unexpected members \(seed\)/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: { ...JWK, kty: 'EC' } })).toThrow(/OKP/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: { ...JWK, crv: 'X25519' } })).toThrow(/Ed25519/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: { ...JWK, kid: 1 } })).toThrow(/kid must be a string/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: { ...JWK, x: `${X}=` } })).toThrow(/32-byte/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: { ...JWK, x: X.slice(2) } })).toThrow(/32-byte/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519' } })).toThrow(/32-byte/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: null })).toThrow(/JSON object/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: [] })).toThrow(/JSON object/);
    expect(() => buildDidDocument({ did: DID, publicKeyJwk: 'x' })).toThrow(/JSON object/);
  });
});

describe('key helpers', () => {
  it('publicKeyJwkBytes accepts kid and gives the 32 raw bytes', () => {
    expect(publicKeyJwkBytes({ ...JWK, kid: 'any' })).toEqual(PUBLIC_KEY);
  });

  it('publicKeyBytesToJwk writes {kty, crv, x} and only adds kid when given (L1.8)', () => {
    expect(publicKeyBytesToJwk(PUBLIC_KEY)).toEqual(JWK);
    expect(publicKeyBytesToJwk(PUBLIC_KEY, 'k')).toEqual({ ...JWK, kid: 'k' });
    expect(() => publicKeyBytesToJwk(PUBLIC_KEY.slice(1))).toThrow(/32 bytes/);
  });

  it('didKeyFromPublicKey and publicKeyFromDidKey round trip through multicodec 0xed01 and base58btc (L1.1, L1.7)', () => {
    const did = didKeyFromPublicKey(PUBLIC_KEY);
    expect(did).toBe(`did:key:${publicKeyToMultibase(PUBLIC_KEY_HEX)}`);
    expect(did.startsWith('did:key:z6Mk')).toBe(true);
    expect(publicKeyFromDidKey(did)).toEqual(PUBLIC_KEY);
    expect(publicKeyToMultibaseOf(PUBLIC_KEY)).toBe(publicKeyToMultibase(PUBLIC_KEY_HEX));
    expect(() => publicKeyToMultibaseOf(new Uint8Array(31))).toThrow(/32 bytes/);
  });

  it('publicKeyFromDidKey is undefined for anything that is not an Ed25519 did:key', () => {
    const multibase = publicKeyToMultibase(PUBLIC_KEY_HEX);
    expect(publicKeyFromDidKey('did:web:example.com')).toBeUndefined();
    expect(publicKeyFromDidKey(`did:key:${multibase.slice(1)}`)).toBeUndefined();
    expect(publicKeyFromDidKey('did:key:z6MkNOTVALIDbase58!!!!')).toBeUndefined();
    expect(publicKeyFromDidKey('did:key:z')).toBeUndefined();
    expect(publicKeyFromDidKey(`did:key:z${encodeBase58btc(new Uint8Array([0xec, 0x01, ...PUBLIC_KEY]))}`)).toBeUndefined();
    expect(publicKeyFromDidKey(`did:key:z${encodeBase58btc(new Uint8Array([0xed, 0x02, ...PUBLIC_KEY]))}`)).toBeUndefined();
    expect(publicKeyFromDidKey(`did:key:z${encodeBase58btc(new Uint8Array([0xed, 0x01, ...PUBLIC_KEY.slice(1)]))}`)).toBeUndefined();
  });

  it('verificationMethodId normalises fragment, #fragment and full id', () => {
    expect(verificationMethodId(DID)).toBe(`${DID}#key-1`);
    expect(verificationMethodId(DID, 'k')).toBe(`${DID}#k`);
    expect(verificationMethodId(DID, '#k')).toBe(`${DID}#k`);
    expect(verificationMethodId(DID, `${DID}#k`)).toBe(`${DID}#k`);
    expect(() => verificationMethodId(DID, 'did:web:x#k')).toThrow(/does not belong/);
    expect(() => verificationMethodId(DID, `${DID}#`)).toThrow(/fragment/);
  });

  it('isDidWeb', () => {
    expect(isDidWeb(DID)).toBe(true);
    expect(isDidWeb('did:web:')).toBe(false);
    expect(isDidWeb('did:key:z')).toBe(false);
    expect(isDidWeb(7)).toBe(false);
  });
});

describe('base58btc (L1.9)', () => {
  it('encodes every leading zero byte as one 1 and decodes it back', () => {
    expect(encodeBase58btc(new Uint8Array([]))).toBe('');
    expect(encodeBase58btc(new Uint8Array([0]))).toBe('1');
    expect(encodeBase58btc(new Uint8Array([0, 0, 1, 2, 3])).startsWith('11')).toBe(true);
    expect(encodeBase58btc(new Uint8Array([0, 0, 1, 2, 3]))).toBe('11Ldp');
    expect(encodeBase58btc(new TextEncoder().encode('Hello'))).toBe('9Ajdvzr');
    expect(decodeBase58btc('')).toEqual(new Uint8Array([]));
    expect(decodeBase58btc('111')).toEqual(new Uint8Array([0, 0, 0]));
    expect(decodeBase58btc('11Ldp')).toEqual(new Uint8Array([0, 0, 1, 2, 3]));
    const key = new Uint8Array([0xed, 0x01, ...new Uint8Array(32).fill(42)]);
    expect(decodeBase58btc(encodeBase58btc(key))).toEqual(key);
    expect(decodeBase58btc(encodeBase58btc(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])))).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
  });

  it('refuses characters outside the alphabet', () => {
    for (const bad of ['0invalid', 'testO', 'testI', 'testl']) {
      expect(() => decodeBase58btc(bad)).toThrow(/Invalid base58 character/);
      expect(isBase58btc(bad)).toBe(false);
    }
    expect(isBase58btc('')).toBe(true);
    expect(isBase58btc('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')).toBe(true);
  });
});
