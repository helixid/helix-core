// Copyright 2026 DgVerse LLP
// One did:web shape (2026-11-23): the resolver reads a port only from the
// percent-encoded host; a raw `did:web:localhost:3000:x` is host localhost,
// path 3000/x, as the did:web spec reads it (no loopback special case).
import { afterEach, describe, expect, it } from 'vitest';
import { buildDIDDocument, setOutboundFetch } from '../../../../src/core/index.js';
import { clearDIDCache, resolveDID } from '../../../../src/core/did-resolver.js';

function serving(urls: string[], documentFor: (url: string) => unknown): typeof fetch {
  return (async (input: string | URL) => {
    const url = String(input);
    urls.push(url);
    const body = documentFor(url);
    return new Response(JSON.stringify(body ?? {}), { status: body === undefined ? 404 : 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
}

describe('resolveDID for did:web', () => {
  afterEach(() => {
    setOutboundFetch(undefined);
    clearDIDCache();
  });

  it('fetches /<kind>/<hex>/did.json from the encoded host with its port', async () => {
    const did = 'did:web:localhost%3A3680:agents:0a1b2c3d';
    const urls: string[] = [];
    setOutboundFetch(serving(urls, () => buildDIDDocument(did, 'a'.repeat(64))));
    expect((await resolveDID(did)).id).toBe(did);
    expect(urls).toEqual(['http://localhost:3680/agents/0a1b2c3d/did.json']);
  });

  it('reads a raw port as a path segment, so it names another URL', async () => {
    const did = 'did:web:localhost:3000:x';
    const urls: string[] = [];
    setOutboundFetch(serving(urls, () => undefined));
    await expect(resolveDID(did)).rejects.toThrow(/HTTP 404/);
    expect(urls).toEqual(['http://localhost/3000/x/did.json']);
  });
});
