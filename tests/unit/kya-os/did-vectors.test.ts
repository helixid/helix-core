// Copyright 2026 DgVerse LLP
// KYA-OS conformance vectors for Core L1.1 and L1.6 to L1.9 (story L1-A),
// vendored from decentralized-identity/kya-os-mcp at a4d7f61 (suite 1.10.0)
// under fixtures/kya-os/ with the upstream path layout.
//
// did-key-resolution.json: every vector's DID through resolveDidKey (L1.6,
// L1.7), and the public key it gives as a JWK (L1.8) and as base58btc (L1.9).
// did-web-resolution.json: the vector's document served under the DID's
// well-known URL by a stubbed fetch, through resolveDid; a document of
// another id, or none at all, must fail closed.
// L1.1: a fresh Ed25519 key derives a did:key that resolves back to it.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  HelixError,
  clearDIDCache,
  decodeBase58btc,
  didKeyFromPublicKey,
  encodeBase58btc,
  generateKeyPair,
  publicKeyBytesToJwk,
  publicKeyFromDidKey,
  resolveDid,
  resolveDidKey,
  verifyJws,
} from '../../../src/core/index.js';

const VENDORED = fileURLToPath(new URL('../../../fixtures/kya-os/', import.meta.url));

interface Vector<I> {
  id: string;
  expected: 'pass' | 'fail';
  reason: string;
  input: I;
}

interface VectorFile<I> {
  version: string;
  category: string;
  vectors: Vector<I>[];
}

interface DidWebInput {
  did: string;
  didDocument?: Record<string, unknown>;
}

function load<I>(name: string): VectorFile<I> {
  return JSON.parse(readFileSync(`${VENDORED}conformance/vectors/${name}`, 'utf8')) as VectorFile<I>;
}

function sha256(path: string): string {
  return createHash('sha256').update(readFileSync(`${VENDORED}conformance/vectors/${path}`)).digest('hex');
}

async function refusal(run: () => Promise<unknown> | unknown): Promise<string | undefined> {
  try {
    await run();
    return undefined;
  } catch (error) {
    if (error instanceof HelixError) return error.code;
    throw error;
  }
}

describe('vendored vector files are the pinned ones', () => {
  it('match SUITE-MANIFEST.json', () => {
    const manifest = JSON.parse(readFileSync(`${VENDORED}conformance/SUITE-MANIFEST.json`, 'utf8')) as { suiteVersion: string; files: [string, string][] };
    expect(manifest.suiteVersion).toBe('1.10.0');
    for (const name of ['did-key-resolution.json', 'did-web-resolution.json']) {
      expect(sha256(name), name).toBe(manifest.files.find(([file]) => file === name)![1]);
    }
  });
});

describe('did-key-resolution.json (L1.6, L1.7)', () => {
  const file = load<{ did: string }>('did-key-resolution.json');

  it('has the three pinned vectors', () => {
    expect(file.category).toBe('did-key-resolution');
    expect(file.vectors.map((v) => v.id)).toEqual(['did-key/valid-ed25519', 'did-key/malformed-multibase', 'did-key/wrong-method']);
  });

  for (const vector of file.vectors) {
    it(`${vector.id}: ${vector.reason}`, async () => {
      if (vector.expected === 'pass') {
        const resolved = resolveDidKey(vector.input.did);
        expect(resolved.rawKey).toHaveLength(32);
        expect(resolved.document.verificationMethod).toHaveLength(1);
        expect(resolved.kid).toBe(`${vector.input.did}#${vector.input.did.slice('did:key:'.length)}`);
        expect(publicKeyFromDidKey(vector.input.did)).toEqual(resolved.rawKey);
        expect(await resolveDid(vector.input.did)).toEqual(resolved);
      } else {
        expect(publicKeyFromDidKey(vector.input.did)).toBeUndefined();
        expect(await refusal(() => resolveDidKey(vector.input.did))).toBeDefined();
      }
    });
  }

  it('the valid key round-trips as JWK (L1.8) and base58btc (L1.9)', () => {
    const did = file.vectors[0]!.input.did;
    const rawKey = publicKeyFromDidKey(did)!;
    const jwk = publicKeyBytesToJwk(rawKey);
    expect(jwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: Buffer.from(rawKey).toString('base64url') });
    expect(resolveDidKey(did).jwk.x).toBe(jwk.x);
    const multibase = did.slice('did:key:z'.length);
    expect(decodeBase58btc(multibase)).toEqual(new Uint8Array([0xed, 0x01, ...rawKey]));
    expect(encodeBase58btc(new Uint8Array([0xed, 0x01, ...rawKey]))).toBe(multibase);
    expect(didKeyFromPublicKey(rawKey)).toBe(did);
  });
});

describe('did-web-resolution.json', () => {
  const file = load<DidWebInput>('did-web-resolution.json');
  beforeEach(() => clearDIDCache());
  afterEach(() => vi.unstubAllGlobals());

  it('has the three pinned vectors', () => {
    expect(file.vectors.map((v) => v.id)).toEqual(['did-web/valid', 'did-web/id-mismatch', 'did-web/not-found']);
  });

  for (const vector of file.vectors) {
    it(`${vector.id}: ${vector.reason}`, async () => {
      const document = vector.input.didDocument;
      const fetchSpy = vi.fn(async (url: string) => {
        expect(url).toBe('https://agent.example.com/.well-known/did.json');
        return document === undefined
          ? new Response('not found', { status: 404 })
          : new Response(JSON.stringify(document), { status: 200, headers: { 'content-type': 'application/did+json' } });
      });
      vi.stubGlobal('fetch', fetchSpy);
      if (vector.expected === 'pass') {
        const resolved = await resolveDid(vector.input.did);
        const method = (document!['verificationMethod'] as { id: string; publicKeyJwk: { x: string }; publicKeyMultibase: string }[])[0]!;
        expect(resolved.kid).toBe(method.id);
        expect(resolved.jwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: method.publicKeyJwk.x, kid: method.id });
        expect(Buffer.from(resolved.rawKey).toString('base64url')).toBe(method.publicKeyJwk.x);
        // The two key forms in the vector agree, through our base58btc (L1.9).
        expect(decodeBase58btc(method.publicKeyMultibase.slice(1))).toEqual(new Uint8Array([0xed, 0x01, ...resolved.rawKey]));
      } else {
        expect(await refusal(() => resolveDid(vector.input.did))).toBe('VALIDATION_ERROR');
      }
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });
  }
});

describe('L1.1: a generated Ed25519 key derives a did:key', () => {
  it('that resolves back to the same key, which verifies what the key signs', async () => {
    const pair = generateKeyPair();
    const publicKey = new Uint8Array(Buffer.from(pair.publicKey, 'hex'));
    const did = didKeyFromPublicKey(publicKey);
    expect(did).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
    const resolved = await resolveDid(did);
    expect(resolved.rawKey).toEqual(publicKey);

    const { EnvSigner, signJws } = await import('../../../src/core/index.js');
    const signer = new EnvSigner({ did, kid: resolved.kid, envVar: 'L1A_KEY', env: { L1A_KEY: pair.privateKey } });
    const jws = await signJws({ iss: did, n: 1 }, signer);
    const verified = verifyJws(jws, resolved.jwk);
    expect(verified.kid).toBe(resolved.kid);
    expect(verified.payload).toEqual({ iss: did, n: 1 });
  });
});
