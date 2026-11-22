// Copyright 2026 DgVerse LLP
// KYA-OS story L1-A: resolveDid gives {rawKey, jwk, kid} for did:web (HTTPS) and did:key (local).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  InvalidJWSError,
  UnsupportedDIDMethodError,
  ValidationError,
  buildDidDocument,
  clearDIDCache,
  derivePublicKey,
  didKeyDocument,
  didKeyFromPublicKey,
  keyFromDocument,
  publicKeyBytesToJwk,
  resolveDid,
  resolveDidKey,
  resolveDidWeb,
  type JwsDidDocument,
} from '../../../../src/core/index.js';

const SEED = '22'.repeat(32);
const PUBLIC_KEY = new Uint8Array(Buffer.from(derivePublicKey(SEED), 'hex'));
const JWK = publicKeyBytesToJwk(PUBLIC_KEY);
const DID_WEB = 'did:web:agents.example.com:agents:abc';
const DID_KEY = didKeyFromPublicKey(PUBLIC_KEY);
const KID = `${DID_WEB}#key-1`;
const DOCUMENT = buildDidDocument({ did: DID_WEB, publicKeyJwk: JWK, kid: 'key-1', alsoKnownAs: [DID_KEY] });

function servedJson(body: unknown, status = 200): typeof fetch {
  return vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/did+json' } })) as unknown as typeof fetch;
}

describe('resolveDid', () => {
  beforeEach(() => clearDIDCache());
  afterEach(() => vi.unstubAllGlobals());

  it('decodes did:key locally into the same raw key and JWK the did:web document publishes', async () => {
    const fromKey = await resolveDid(DID_KEY);
    expect(fromKey.rawKey).toEqual(PUBLIC_KEY);
    expect(fromKey.jwk).toEqual({ ...JWK, kid: `${DID_KEY}#${DID_KEY.slice('did:key:'.length)}` });
    expect(fromKey.kid).toBe(`${DID_KEY}#${DID_KEY.slice('did:key:'.length)}`);
    expect(fromKey.document).toEqual(didKeyDocument(DID_KEY));
    expect(resolveDidKey(DID_KEY)).toEqual(fromKey);

    vi.stubGlobal('fetch', servedJson(DOCUMENT));
    const fromWeb = await resolveDid(DID_WEB);
    expect(fromWeb.rawKey).toEqual(fromKey.rawKey);
    expect(fromWeb.jwk.x).toBe(fromKey.jwk.x);
    expect(fromWeb.jwk).toEqual({ ...JWK, kid: KID });
    expect(fromWeb.kid).toBe(KID);
    expect(fromWeb.document).toEqual(DOCUMENT);
    expect(fetch).toHaveBeenCalledWith('https://agents.example.com/agents/abc/did.json', expect.anything());
  });

  it('the did:key document has the reference shape: <did>#<multibase> with both key forms (L1.6)', () => {
    const multibase = DID_KEY.slice('did:key:'.length);
    expect(didKeyDocument(DID_KEY)).toEqual({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
      id: DID_KEY,
      verificationMethod: [{ id: `${DID_KEY}#${multibase}`, type: 'Ed25519VerificationKey2020', controller: DID_KEY, publicKeyJwk: JWK, publicKeyMultibase: multibase }],
      authentication: [`${DID_KEY}#${multibase}`],
      assertionMethod: [`${DID_KEY}#${multibase}`],
    });
  });

  it('selects the method a kid names, as fragment, #fragment or full id', async () => {
    vi.stubGlobal('fetch', servedJson(DOCUMENT));
    expect((await resolveDidWeb(DID_WEB, { kid: 'key-1' })).kid).toBe(KID);
    expect((await resolveDid(DID_WEB, { kid: '#key-1' })).kid).toBe(KID);
    expect((await resolveDid(DID_WEB, { kid: KID })).kid).toBe(KID);
    await expect(resolveDid(DID_WEB, { kid: 'key-2' })).rejects.toMatchObject({ reason: 'jws_key_not_found' });
    expect(() => resolveDidKey(DID_KEY, { kid: 'key-1' })).toThrow(InvalidJWSError);
  });

  it('reads an embedded assertion method and #relative ids too', () => {
    const embedded: JwsDidDocument = { id: DID_WEB, assertionMethod: [{ id: '#k', type: 'Ed25519VerificationKey2020', controller: DID_WEB, publicKeyJwk: JWK }] };
    expect(keyFromDocument(embedded, DID_WEB).kid).toBe(`${DID_WEB}#k`);
    const relative: JwsDidDocument = { id: DID_WEB, verificationMethod: [{ id: '#k', controller: DID_WEB, publicKeyJwk: JWK }], assertionMethod: ['#k'] };
    expect(keyFromDocument(relative, DID_WEB).rawKey).toEqual(PUBLIC_KEY);
    expect(() => keyFromDocument({ id: DID_WEB, assertionMethod: [] }, DID_WEB)).toThrow(/no assertion method/);
    expect(() => keyFromDocument({ id: DID_WEB }, DID_WEB)).toThrow(/no assertion method/);
    expect(() => keyFromDocument({ id: DID_WEB, assertionMethod: [7 as unknown as string] }, DID_WEB)).toThrow(/no assertion method/);
    expect(() => keyFromDocument({ id: DID_WEB, assertionMethod: [{ id: 3 as unknown as string }] }, DID_WEB)).toThrow(/no assertion method/);
  });

  it('refuses did:key that is malformed and DIDs of other methods', async () => {
    expect(() => resolveDidKey('did:key:z6MkNOTVALIDbase58!!!!')).toThrow(ValidationError);
    expect(() => resolveDidKey('did:key:z')).toThrow(ValidationError);
    expect(() => didKeyDocument('did:web:example.com')).toThrow(UnsupportedDIDMethodError);
    await expect(resolveDidWeb(DID_KEY)).rejects.toThrow(UnsupportedDIDMethodError);
    await expect(resolveDid('did:hedera:testnet:abc')).rejects.toThrow(UnsupportedDIDMethodError);
    await expect(resolveDid(42 as unknown as string)).rejects.toThrow(ValidationError);
  });

  it('refuses a did:web document served under another id, and fails closed when the document is not served', async () => {
    vi.stubGlobal('fetch', servedJson({ ...DOCUMENT, id: 'did:web:evil.example.com' }));
    await expect(resolveDid(DID_WEB)).rejects.toThrow(ValidationError);
    clearDIDCache();
    vi.stubGlobal('fetch', servedJson({ error: 'not found' }, 404));
    await expect(resolveDid(DID_WEB)).rejects.toThrow(/HTTP 404/);
  });

  it('cross-border rule: resolution reaches only the network; the resolver modules import no storage, repository or service', async () => {
    const source = (name: string) => readFileSync(fileURLToPath(new URL(`../../../../src/core/${name}`, import.meta.url)), 'utf8');
    for (const name of ['did/resolve.ts', 'did/document.ts', 'did-resolver.ts']) {
      const imports = [...source(name).matchAll(/from '([^']+)'/g)].map((m) => m[1]!);
      expect(imports.filter((i) => /prisma|repositor|services|storage|sqlite|\.\.\/\.\.\/src/.test(i)), name).toEqual([]);
    }
    const fetchSpy = servedJson(DOCUMENT);
    vi.stubGlobal('fetch', fetchSpy);
    await resolveDid(DID_WEB);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(resolveDidKey(DID_KEY).rawKey).toEqual(PUBLIC_KEY);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
