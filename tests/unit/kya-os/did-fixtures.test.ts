// Copyright 2026 DgVerse LLP
// KYA-OS story L1-A: the cross-language agent-key fixture set (stories rule 6).
// Regenerates fixtures/kya-os-helix/did.json from source and fails on drift,
// then checks every entry against the checked-in file the way helix-sdk-js,
// helix-sdk-py and e2e-playwright read it.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  setOutboundFetch,
  EnvSigner,
  buildDidDocument,
  clearDIDCache,
  decodeBase58btc,
  derivePublicKey,
  didKeyFromPublicKey,
  encodeBase58btc,
  publicKeyBytesToJwk,
  publicKeyFromDidKey,
  resolveDid,
  signJws,
  verifyJwsByKid,
} from '../../../src/core/index.js';
import { buildDidFixtures, serializeDidFixtures, type DidFixtures } from '../../../scripts/generate-did-fixtures.js';

const FIXTURE_PATH = fileURLToPath(new URL('../../../fixtures/kya-os-helix/did.json', import.meta.url));
const checkedIn = readFileSync(FIXTURE_PATH, 'utf8');
const fixtures = JSON.parse(checkedIn) as DidFixtures;

describe('fixtures/kya-os-helix/did.json', () => {
  afterEach(() => {
    setOutboundFetch(undefined);
    clearDIDCache();
  });

  it('is exactly what the generator produces from current source (regenerate with pnpm generate:did-fixtures)', () => {
    expect(serializeDidFixtures(buildDidFixtures())).toBe(checkedIn);
  });

  for (const [name, key] of Object.entries(fixtures.keys)) {
    it(`key ${name}: public key, JWK, did:key and did:web document all derive from the seed`, () => {
      const publicKey = new Uint8Array(Buffer.from(key.public_key_hex, 'hex'));
      expect(derivePublicKey(key.private_key_hex)).toBe(key.public_key_hex);
      expect(publicKeyBytesToJwk(publicKey)).toEqual(key.public_key_jwk);
      expect(didKeyFromPublicKey(publicKey)).toBe(key.did_key);
      expect(`z${encodeBase58btc(new Uint8Array([0xed, 0x01, ...publicKey]))}`).toBe(key.public_key_multibase);
      expect(key.did_key).toBe(`did:key:${key.public_key_multibase}`);
      expect(publicKeyFromDidKey(key.did_key)).toEqual(publicKey);
      expect(key.kid).toBe(`${key.did_web}#${key.kid_fragment}`);
      expect(buildDidDocument({ did: key.did_web, publicKeyJwk: key.public_key_jwk, kid: key.kid_fragment, alsoKnownAs: [key.did_key] })).toEqual(key.did_web_document);
      expect(key.did_web_document.verificationMethod[0]!.id).toBe(key.kid);
      expect(key.did_web_document.assertionMethod).toEqual([key.kid]);
      expect(key.did_web_document.authentication).toEqual([key.kid]);
      expect(key.did_web_document.alsoKnownAs).toEqual([key.did_key]);
    });

    it(`key ${name}: did:web and did:key resolve to the same raw key and JWK, and a JWS with kid <did>#<fragment> verifies by kid`, async () => {
      setOutboundFetch(vi.fn(async () => new Response(JSON.stringify(key.did_web_document), { status: 200 })));
      const viaWeb = await resolveDid(key.did_web);
      const viaKey = await resolveDid(key.did_key);
      expect(Buffer.from(viaWeb.rawKey).toString('hex')).toBe(key.resolved.raw_key_hex);
      expect(Buffer.from(viaKey.rawKey).toString('hex')).toBe(key.resolved.raw_key_hex);
      expect({ kty: viaWeb.jwk.kty, crv: viaWeb.jwk.crv, x: viaWeb.jwk.x }).toEqual(key.resolved.jwk);
      expect({ kty: viaKey.jwk.kty, crv: viaKey.jwk.crv, x: viaKey.jwk.x }).toEqual(key.resolved.jwk);
      expect(viaWeb.kid).toBe(key.resolved.did_web_kid);
      expect(viaKey.kid).toBe(key.resolved.did_key_kid);
      expect(viaWeb.document).toEqual(key.did_web_document);
      expect(viaKey.document).toEqual(key.did_key_document);

      const signer = new EnvSigner({ did: key.did_web, kid: key.kid, envVar: 'FIXTURE_KEY', env: { FIXTURE_KEY: key.private_key_hex } });
      expect(signer.verificationMethodId).toBe(key.kid);
      const jws = await signJws({ iss: key.did_web, sub: 'fixture' }, signer);
      const verified = await verifyJwsByKid(jws, async (did) => (did === key.did_web ? key.did_web_document : null));
      expect(verified.kid).toBe(key.kid);
    });
  }

  it('base58btc vectors (L1.9) encode and decode byte for byte', () => {
    expect(fixtures.base58btc.length).toBeGreaterThan(5);
    for (const vector of fixtures.base58btc) {
      const bytes = new Uint8Array(Buffer.from(vector.bytes_hex, 'hex'));
      expect(encodeBase58btc(bytes), vector.bytes_hex).toBe(vector.base58btc);
      expect(Buffer.from(decodeBase58btc(vector.base58btc)).toString('hex'), vector.base58btc).toBe(vector.bytes_hex);
    }
  });

  it('every did:key rejection fails to decode', () => {
    for (const rejection of fixtures.did_key_rejections) {
      expect(publicKeyFromDidKey(rejection.did), rejection.name).toBeUndefined();
    }
  });
});
