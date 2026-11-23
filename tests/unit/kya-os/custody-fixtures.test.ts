// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: fixtures/kya-os-helix/custody.json is what current source makes, and its signatures verify.
import { readFileSync } from 'node:fs';
import * as ed25519 from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import {
  CUSTODY_LABEL_HELIX,
  CUSTODY_LABEL_SELF,
  PRIVATE_KEY_MATERIAL_MEMBERS,
  base64UrlDecodeStrict,
  base64UrlEncode,
  enrollmentProofMessage,
  findPrivateKeyMaterial,
  publicKeyBytesToJwk,
  rotationProofMessage,
  verifyProofOfPossession,
} from '../../../src/core/index.js';

const fixture = JSON.parse(readFileSync(new URL('../../../fixtures/kya-os-helix/custody.json', import.meta.url), 'utf8'));
const seed = Buffer.from(fixture.key.seedHex, 'hex');
const publicKey = ed25519.getPublicKey(seed);

describe('custody.json', () => {
  it('carries the test key consistently', () => {
    expect(fixture.key.publicKeyHex).toBe(Buffer.from(publicKey).toString('hex'));
    expect(fixture.key.publicKeyJwk).toEqual(publicKeyBytesToJwk(publicKey));
  });

  it('enrollment: the message and signature are what current source makes, and the request carries no private material', () => {
    const message = enrollmentProofMessage({ did: fixture.enrollment.did, kid: fixture.enrollment.kid, nonce: fixture.enrollment.nonce });
    expect(new TextDecoder().decode(message)).toBe(fixture.enrollment.message);
    expect(fixture.enrollment.signature).toBe(base64UrlEncode(ed25519.sign(message, seed)));
    expect(verifyProofOfPossession(message, fixture.enrollment.signature, publicKey)).toBe(true);
    expect(fixture.enrollment.request.signature).toBe(fixture.enrollment.signature);
    expect(findPrivateKeyMaterial(fixture.enrollment.request)).toBeUndefined();
    expect(JSON.stringify(fixture.enrollment.request)).not.toContain(fixture.key.seedHex);
  });

  it('rotation: the message and signature are what current source makes', () => {
    const message = rotationProofMessage({ did: fixture.rotation.did, kid: fixture.rotation.kid, issuedAt: fixture.rotation.issuedAt });
    expect(new TextDecoder().decode(message)).toBe(fixture.rotation.message);
    expect(verifyProofOfPossession(message, fixture.rotation.signature, publicKey)).toBe(true);
  });

  it('sign: the response signature is the key\'s signature over the decoded payload', () => {
    const payload = base64UrlDecodeStrict(fixture.sign.request.payload)!;
    expect(new TextDecoder().decode(payload)).toBe(fixture.sign.payloadUtf8);
    expect(fixture.sign.response).toMatchObject({ did: fixture.sign.did, kid: fixture.sign.kid, alg: 'EdDSA' });
    expect(ed25519.verify(base64UrlDecodeStrict(fixture.sign.response.signature)!, payload, publicKey)).toBe(true);
  });

  it('labels and refused members match the source', () => {
    expect(fixture.labels).toEqual({ helix: CUSTODY_LABEL_HELIX, self: CUSTODY_LABEL_SELF });
    expect(fixture.privateMaterialMembers).toEqual([...PRIVATE_KEY_MATERIAL_MEMBERS].sort());
  });
});
