// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_KID_FRAGMENT,
  EnvSigner,
  defaultKidFragment,
  derivePublicKey,
  didKeyDocument,
  publicKeyToMultibase,
  resolveDID,
  signJws,
  verifyJwsByKid,
  type DidResolver,
} from '../../../src/core/index.js';

const KEY = '6'.repeat(64);
const multibase = publicKeyToMultibase(derivePublicKey(KEY));
const DID_KEY = `did:key:${multibase}`;
const env = { K: KEY };

describe('the default kid of a signer (F-1 fix: a did:key signs as its own verification method)', () => {
  it('is the multibase value for a did:key and key-1 for any other DID', () => {
    expect(defaultKidFragment(DID_KEY)).toBe(multibase);
    expect(defaultKidFragment('did:web:helix.example')).toBe(DEFAULT_KID_FRAGMENT);
    expect(defaultKidFragment('did:key:')).toBe(DEFAULT_KID_FRAGMENT);
  });

  it('a did:key EnvSigner names did:key:z…#z…, which its W3C document defines, so a JWS verifies', async () => {
    const signer = new EnvSigner({ did: DID_KEY, envVar: 'K', env });
    expect(signer.kid).toBe(multibase);
    expect(signer.verificationMethodId).toBe(`${DID_KEY}#${multibase}`);
    const jws = await signJws({ sub: 'x' }, signer);
    const verified = await verifyJwsByKid(jws, (async (did: string) => didKeyDocument(did)) as unknown as DidResolver);
    expect(verified.kid).toBe(`${DID_KEY}#${multibase}`);
  });

  it('an explicit kid still wins, and a did:web keeps key-1', () => {
    expect(new EnvSigner({ did: DID_KEY, kid: '#key-1', envVar: 'K', env }).kid).toBe('key-1');
    expect(new EnvSigner({ did: DID_KEY, kid: `${DID_KEY}#${multibase}`, envVar: 'K', env }).kid).toBe(multibase);
    expect(new EnvSigner({ did: 'did:web:helix.example', envVar: 'K', env }).kid).toBe('key-1');
  });

  it("core's resolveDID lists a did:key under both #key-1 and its W3C method id, so either signer verifies", async () => {
    const document = await resolveDID(DID_KEY);
    expect(document.verificationMethod.map((method) => method.id)).toEqual([`${DID_KEY}#key-1`, `${DID_KEY}#${multibase}`]);
    expect(document.assertionMethod).toEqual([`${DID_KEY}#key-1`, `${DID_KEY}#${multibase}`]);
    const resolve = (async (did: string) => resolveDID(did)) as unknown as DidResolver;
    for (const kid of [undefined, 'key-1']) {
      const jws = await signJws({ sub: 'x' }, new EnvSigner({ did: DID_KEY, ...(kid ? { kid } : {}), envVar: 'K', env }));
      await expect(verifyJwsByKid(jws, resolve)).resolves.toMatchObject({ did: DID_KEY });
    }
  });
});
