// Copyright 2026 DgVerse LLP
// KYA-OS story L1-A: EnvSigner announces the did:web verification-method id its document publishes.
import { describe, expect, it } from 'vitest';
import { EnvSigner, readJwsHeader, signJws } from '../../../src/core/index.js';

const DID = 'did:web:agents.example.com:agents:abc';
const env = { K: '44'.repeat(32) };

describe('EnvSigner kid forms', () => {
  it('takes the fragment, #fragment, or the full <did>#fragment id, and signs with kid <did>#fragment', async () => {
    for (const kid of ['key-1', '#key-1', `${DID}#key-1`]) {
      const signer = new EnvSigner({ did: DID, kid, envVar: 'K', env });
      expect(signer.kid).toBe('key-1');
      expect(signer.verificationMethodId).toBe(`${DID}#key-1`);
      expect(readJwsHeader(await signJws({ iss: DID }, signer))).toEqual({ alg: 'EdDSA', kid: `${DID}#key-1` });
    }
  });

  it('refuses a verification-method id of another DID, and an empty fragment', () => {
    expect(() => new EnvSigner({ did: DID, kid: 'did:web:other.example.com#key-1', envVar: 'K', env })).toThrow(/fragment of this DID/);
    expect(() => new EnvSigner({ did: DID, kid: `${DID}#`, envVar: 'K', env })).toThrow(/fragment of this DID/);
    expect(() => new EnvSigner({ did: DID, kid: '', envVar: 'K', env })).toThrow(/fragment of this DID/);
  });
});
