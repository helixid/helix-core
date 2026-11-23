// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: SafeFetch (SPEC-ENTITY-CARD §6.6) refuses, fail-closed,
// everything resolution must never reach, and pins what it does reach.
import { createServer, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  SAFE_FETCH_MAX_BYTES,
  SafeFetchRefusedError,
  createSafeFetch,
  fetchTransport,
  getOutboundFetch,
  isPublicUnicastAddress,
  outboundDevelopmentMode,
  setOutboundFetch,
  type SafeFetchTransport,
  type TransportRequest,
} from '../../../../src/core/index.js';

const fixture = JSON.parse(readFileSync(fileURLToPath(new URL('../../../../fixtures/kya-os-helix/entity-card.json', import.meta.url)), 'utf8')) as {
  safe_fetch_refusals: { url: string; reason: string }[];
  public_addresses: string[];
  non_public_addresses: string[];
};

const PUBLIC = '93.184.216.34';

interface Served {
  status: number;
  headers?: Record<string, string>;
  body?: string;
}

function harness(routes: Record<string, Served | ((request: TransportRequest) => Served)>, addresses: Record<string, string[]> = { 'helix.test': [PUBLIC], 'other.test': [PUBLIC] }) {
  const requests: TransportRequest[] = [];
  const lookup = vi.fn(async (hostname: string) => {
    const found = addresses[hostname];
    if (!found) throw new Error(`ENOTFOUND ${hostname}`);
    return found;
  });
  const transport: SafeFetchTransport = vi.fn(async (request: TransportRequest) => {
    requests.push(request);
    const route = routes[request.url];
    if (!route) return { status: 404, headers: {}, body: new Uint8Array() };
    const served = typeof route === 'function' ? route(request) : route;
    return { status: served.status, headers: served.headers ?? {}, body: new Uint8Array(Buffer.from(served.body ?? '')) };
  });
  return { requests, lookup, transport };
}

async function refusal(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof SafeFetchRefusedError) return error.reason;
    throw error;
  }
  throw new Error('expected a refusal');
}

describe('isPublicUnicastAddress', () => {
  it('admits the fixture public addresses and refuses every non-public one', () => {
    for (const address of fixture.public_addresses) expect(isPublicUnicastAddress(address), address).toBe(true);
    for (const address of fixture.non_public_addresses) expect(isPublicUnicastAddress(address), address).toBe(false);
    expect(isPublicUnicastAddress('helix.test')).toBe(false);
    expect(isPublicUnicastAddress('')).toBe(false);
  });
});

describe('createSafeFetch: refusals decided from the URL alone', () => {
  it('refuses every fixture URL before any lookup or request (http, loopback, metadata, private, credentials)', async () => {
    const h = harness({});
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: h.transport });
    for (const { url, reason } of fixture.safe_fetch_refusals) {
      expect(await refusal(() => safeFetch(url)), url).toBe(reason);
    }
    expect(h.lookup).not.toHaveBeenCalled();
    expect(h.transport).not.toHaveBeenCalled();
  });

  it('refuses a host that resolves to a non-public address, naming the host and not the address', async () => {
    const h = harness({}, { 'internal.test': ['10.0.0.1'], 'mixed.test': [PUBLIC, '169.254.169.254'], 'gone.test': [] });
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: h.transport });
    await expect(safeFetch('https://internal.test/')).rejects.toMatchObject({ reason: 'host_refused', message: expect.not.stringContaining('10.0.0.1') });
    expect(await refusal(() => safeFetch('https://mixed.test/'))).toBe('host_refused');
    expect(await refusal(() => safeFetch('https://gone.test/'))).toBe('unresolved');
    expect(await refusal(() => safeFetch('https://unknown.test/'))).toBe('unresolved');
    expect(h.transport).not.toHaveBeenCalled();
  });
});

describe('createSafeFetch: the read', () => {
  it('resolves once, pins the first address, sends the accept header and gives back the body', async () => {
    const h = harness({ 'https://helix.test/acme/card.json': { status: 200, headers: { 'content-type': 'application/json' }, body: '{"id":"did:web:helix.test:acme"}' } }, { 'helix.test': [PUBLIC, '8.8.8.8'] });
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: h.transport });
    const response = await safeFetch('https://helix.test/acme/card.json', { headers: { accept: 'application/did+json' } });
    expect(response.ok).toBe(true);
    expect(response.status).toBe(200);
    expect(response.url).toBe('https://helix.test/acme/card.json');
    expect(response.headers.get('Content-Type')).toBe('application/json');
    expect(await response.json()).toEqual({ id: 'did:web:helix.test:acme' });
    expect(await response.text()).toBe('{"id":"did:web:helix.test:acme"}');
    expect(h.lookup).toHaveBeenCalledTimes(1);
    expect(h.requests[0]).toMatchObject({ address: PUBLIC, headers: { accept: 'application/did+json' }, maxBytes: SAFE_FETCH_MAX_BYTES });
  });

  it('gives a public IP-literal host to the transport unpinned, since the URL already names the address', async () => {
    const h = harness({ [`https://${PUBLIC}/card.json`]: { status: 200, body: '{}' } });
    const response = await createSafeFetch({ lookup: h.lookup, transport: h.transport })(`https://${PUBLIC}/card.json`);
    expect(response.ok).toBe(true);
    expect(h.lookup).not.toHaveBeenCalled();
    expect(h.requests[0]!.address).toBeUndefined();
  });

  it('follows a same-origin redirect, re-pinning the hop, and reports the final URL', async () => {
    const h = harness({
      'https://helix.test/old.json': { status: 301, headers: { location: '/new.json' } },
      'https://helix.test/new.json': { status: 200, body: '{"moved":true}' },
    });
    const response = await createSafeFetch({ lookup: h.lookup, transport: h.transport })('https://helix.test/old.json');
    expect(await response.json()).toEqual({ moved: true });
    expect(response.url).toBe('https://helix.test/new.json');
    expect(h.lookup).toHaveBeenCalledTimes(2);
  });

  it('refuses a cross-origin redirect, a redirect to http, one without a location, and more than maxRedirects', async () => {
    const h = harness({
      'https://helix.test/cross': { status: 302, headers: { location: 'https://other.test/card.json' } },
      'https://helix.test/port': { status: 302, headers: { location: 'https://helix.test:8443/card.json' } },
      'https://helix.test/downgrade': { status: 307, headers: { location: 'http://helix.test/card.json' } },
      'https://helix.test/blank': { status: 308 },
      'https://helix.test/bad': { status: 302, headers: { location: 'http://' } },
      'https://helix.test/loop': { status: 302, headers: { location: '/loop' } },
    });
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: h.transport });
    expect(await refusal(() => safeFetch('https://helix.test/cross'))).toBe('cross_origin_redirect');
    expect(await refusal(() => safeFetch('https://helix.test/port'))).toBe('cross_origin_redirect');
    expect(await refusal(() => safeFetch('https://helix.test/downgrade'))).toBe('scheme_refused');
    expect(await refusal(() => safeFetch('https://helix.test/blank'))).toBe('unavailable');
    expect(await refusal(() => safeFetch('https://helix.test/bad'))).toBe('invalid_url');
    expect(await refusal(() => safeFetch('https://helix.test/loop'))).toBe('too_many_redirects');
    expect(h.transport).toHaveBeenCalledTimes(5 + 4);
  });

  it('reports a transport failure as unavailable and a non-2xx as not ok', async () => {
    const h = harness({ 'https://helix.test/missing': { status: 404, body: 'no' } });
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: h.transport });
    const missing = await safeFetch('https://helix.test/missing');
    expect(missing.ok).toBe(false);
    expect(missing.status).toBe(404);
    const broken = createSafeFetch({ lookup: h.lookup, transport: async () => { throw new Error('ECONNRESET'); } });
    await expect(broken('https://helix.test/')).rejects.toMatchObject({ reason: 'unavailable', code: 'SAFE_FETCH_REFUSED', httpStatus: 502 });
  });

  it('ends the read at the deadline and on the caller signal', async () => {
    const h = harness({});
    const slow: SafeFetchTransport = (request) => new Promise((_resolve, reject) => request.signal.addEventListener('abort', () => reject(request.signal.reason)));
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: slow, timeoutMs: 20 });
    expect(await refusal(() => safeFetch('https://helix.test/slow'))).toBe('deadline_exceeded');
    const controller = new AbortController();
    const pending = createSafeFetch({ lookup: h.lookup, transport: slow })('https://helix.test/slow', { signal: controller.signal });
    controller.abort(new Error('caller gave up'));
    await expect(pending).rejects.toThrow('caller gave up');
    const already = new AbortController();
    already.abort(new Error('before the read'));
    await expect(createSafeFetch({ lookup: h.lookup, transport: slow })('https://helix.test/slow', { signal: already.signal })).rejects.toThrow('before the read');
  });

  it('development mode admits http and loopback, and still refuses a cross-origin redirect', async () => {
    const h = harness({ 'http://localhost:3000/agents/a/did.json': { status: 200, body: '{"id":"x"}' }, 'http://localhost:3000/cross': { status: 302, headers: { location: 'http://10.0.0.1/' } } });
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: h.transport, development: true });
    expect((await safeFetch('http://localhost:3000/agents/a/did.json')).ok).toBe(true);
    expect(h.lookup).not.toHaveBeenCalled();
    expect(h.requests[0]!.address).toBe('127.0.0.1');
    expect(await refusal(() => safeFetch('http://localhost:3000/cross'))).toBe('cross_origin_redirect');
    const internal = createSafeFetch({ lookup: async () => ['10.0.0.1'], transport: h.transport, development: true });
    expect((await internal('https://internal.test/')).status).toBe(404);
  });
});

describe('fetchTransport', () => {
  it('reads through a fetch-compatible function with redirects left to SafeFetch, and caps the body', async () => {
    const calls: [string, RequestInit][] = [];
    const fetchLike = async (url: string, init: RequestInit): Promise<Response> => {
      calls.push([url, init]);
      if (url.endsWith('/big')) return new Response('x'.repeat(2 * 1024 * 1024), { status: 200 });
      if (url.endsWith('/declared')) return new Response('small', { status: 200, headers: { 'content-length': String(2 * 1024 * 1024) } });
      return new Response('{"ok":1}', { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const h = harness({});
    const safeFetch = createSafeFetch({ lookup: h.lookup, transport: fetchTransport(fetchLike) });
    expect(await (await safeFetch('https://helix.test/card.json')).json()).toEqual({ ok: 1 });
    expect(calls[0]![1]).toMatchObject({ redirect: 'manual' });
    expect(await refusal(() => safeFetch('https://helix.test/big'))).toBe('too_large');
    expect(await refusal(() => safeFetch('https://helix.test/declared'))).toBe('too_large');
  });
});

describe('nodeTransport over a local server (development mode)', () => {
  let server: Server;
  let origin: string;
  beforeAll(async () => {
    server = createServer((req, res) => {
      if (req.url === '/big') {
        res.writeHead(200, { 'content-type': 'application/octet-stream' });
        res.end(Buffer.alloc(2 * 1024 * 1024, 0x41));
      } else if (req.url === '/declared') {
        res.writeHead(200, { 'content-length': String(2 * 1024 * 1024) });
        res.write('a');
      } else if (req.url === '/slow') {
        // never answers
      } else if (req.url === '/redirect') {
        res.writeHead(302, { location: '/card.json' });
        res.end();
      } else {
        res.writeHead(200, { 'content-type': 'application/json', 'x-served': 'yes' });
        res.end(JSON.stringify({ path: req.url, host: req.headers.host }));
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it('reads a body, follows a same-origin redirect, and refuses a 2 MiB body, a declared 2 MiB and a read past the deadline', async () => {
    const safeFetch = createSafeFetch({ development: true, timeoutMs: 500 });
    const response = await safeFetch(`${origin}/card.json`);
    expect(response.headers.get('x-served')).toBe('yes');
    expect(await response.json()).toMatchObject({ path: '/card.json' });
    expect(await (await safeFetch(`${origin}/redirect`)).json()).toMatchObject({ path: '/card.json' });
    expect(await refusal(() => safeFetch(`${origin}/big`))).toBe('too_large');
    expect(await refusal(() => safeFetch(`${origin}/declared`))).toBe('too_large');
    expect(await refusal(() => safeFetch(`${origin}/slow`))).toBe('deadline_exceeded');
  });

  it('pins the connection to the checked address while the URL keeps its host name', async () => {
    const port = (server.address() as { port: number }).port;
    const safeFetch = createSafeFetch({ development: true, lookup: async () => ['127.0.0.1'] });
    const response = await safeFetch(`http://pinned.test:${port}/card.json`);
    expect(await response.json()).toEqual({ path: '/card.json', host: `pinned.test:${port}` });
    const loud = createSafeFetch({ lookup: async () => ['127.0.0.1'] });
    expect(await refusal(() => loud(`https://pinned.test:${port}/card.json`))).toBe('host_refused');
  });
});

describe('the outbound seam', () => {
  it('is a SafeFetch by default, strict unless the environment says development, and replaceable', async () => {
    expect(outboundDevelopmentMode({ NODE_ENV: 'production' })).toBe(false);
    expect(outboundDevelopmentMode({ NODE_ENV: 'production', HELIX_OUTBOUND_DEVELOPMENT: '1' })).toBe(true);
    expect(outboundDevelopmentMode({ NODE_ENV: 'test', HELIX_OUTBOUND_DEVELOPMENT: '0' })).toBe(false);
    expect(outboundDevelopmentMode({ NODE_ENV: 'development' })).toBe(true);
    expect(outboundDevelopmentMode({})).toBe(false);
    const stub = vi.fn(async () => new Response('{}', { status: 200 }));
    setOutboundFetch(stub);
    expect(getOutboundFetch()).toBe(stub);
    setOutboundFetch(undefined);
    expect(getOutboundFetch()).not.toBe(stub);
    // Under vitest NODE_ENV is test, so the default instance admits loopback; the strict one refuses the metadata endpoint.
    expect(outboundDevelopmentMode()).toBe(true);
    const strict = createSafeFetch({ development: outboundDevelopmentMode({ NODE_ENV: 'production' }) });
    expect(await refusal(() => strict('https://169.254.169.254/'))).toBe('host_refused');
  });
});
