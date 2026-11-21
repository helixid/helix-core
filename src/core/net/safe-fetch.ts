// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * SafeFetch: the SSRF-hardened outbound read every resolver and status-list
 * fetch goes through (KYA-OS story C-A, SPEC-ENTITY-CARD §6.6, §12.9).
 *
 * Resolution follows URLs an attacker can influence (a DID document's
 * service entry, a card's `revocation` URL, a `cardRef`), so each read is
 * held, fail-closed, to:
 *
 * - https only (no http, file, data, …);
 * - public unicast addresses only: loopback (`127/8`, `::1`), RFC 1918,
 *   link-local (`169.254/16`, with the `169.254.169.254` cloud-metadata
 *   endpoint, `fe80::/10`), CGNAT `100.64/10`, IPv6 ULA `fc00::/7`,
 *   multicast, the unspecified address and the IPv4-in-IPv6 transition
 *   ranges are refused; a host is resolved once and every address it
 *   resolves to must be public;
 * - the connection pinned to the address that was checked, so a DNS answer
 *   cannot change between the check and the connect (no rebinding window);
 * - redirects followed only to the same origin, at most `maxRedirects` (3)
 *   times, each hop resolved and pinned again;
 * - a response-size cap (1 MiB) and one deadline (5 s) over the whole read.
 *
 * `development: true` admits http and non-public addresses, for a local
 * stack whose DIDs live on a loopback host (`did:web:localhost%3A3000:…`,
 * the docker demos behind `DID_WEB_LOOPBACK_RESOLVE_HOST`); the other rules
 * still hold. Production (`NODE_ENV=production`) never turns it on by itself.
 *
 * I/O is injected (`lookup`, `transport`) so the policy is tested without a
 * network. Cross-border rule (stories, rule 4): this module reads the URL it
 * is given and nothing else.
 */

import { BlockList, isIP } from 'node:net';
import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest, type RequestOptions } from 'node:https';
import { SafeFetchRefusedError } from '../errors/HelixError.js';

export const SAFE_FETCH_MAX_BYTES = 1024 * 1024;
export const SAFE_FETCH_TIMEOUT_MS = 5_000;
export const SAFE_FETCH_MAX_REDIRECTS = 3;

/** Why SafeFetch refused or failed a read; `SafeFetchRefusedError.reason`. */
export type SafeFetchReason =
  | 'invalid_url'
  | 'scheme_refused'
  | 'host_refused'
  | 'unresolved'
  | 'cross_origin_redirect'
  | 'too_many_redirects'
  | 'too_large'
  | 'deadline_exceeded'
  | 'unavailable';

export interface SafeFetchInit {
  headers?: Record<string, string>;
  /** Ends the read when it aborts, on top of SafeFetch's own deadline. */
  signal?: AbortSignal | undefined;
}

/** What SafeFetch gives back: the subset of `Response` a resolver reads. */
export interface SafeFetchResponse {
  ok: boolean;
  status: number;
  /** The URL the body came from (after same-origin redirects). */
  url: string;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export type SafeFetch = (url: string, init?: SafeFetchInit) => Promise<SafeFetchResponse>;

/** Every address a host name resolves to. */
export type DnsLookup = (hostname: string) => Promise<string[]>;

/** One hop as the transport sends it: the URL, connected to the pinned `address` when given. */
export interface TransportRequest {
  url: string;
  headers: Record<string, string>;
  /** The checked address to connect to; undefined for an IP-literal host (the URL already names it). */
  address: string | undefined;
  signal: AbortSignal;
  /** Bytes of body after which the transport must give up with `too_large`. */
  maxBytes: number;
}

export interface TransportResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

/** Sends one hop. Redirects are never followed by the transport; SafeFetch decides them. */
export type SafeFetchTransport = (request: TransportRequest) => Promise<TransportResponse>;

export interface SafeFetchOptions {
  lookup?: DnsLookup;
  transport?: SafeFetchTransport;
  /** Admits http and non-public addresses. Local stacks only. Default false. */
  development?: boolean;
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
}

// ── Address policy ──────────────────────────────────────────────────────────

const NON_PUBLIC = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8], // RFC 1918
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, incl. 169.254.169.254
  ['172.16.0.0', 12], // RFC 1918
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.168.0.0', 16], // RFC 1918
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, incl. the broadcast address
] as const) {
  NON_PUBLIC.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['64:ff9b::', 96], // NAT64
  ['64:ff9b:1::', 48], // local-use NAT64
  ['100::', 64], // discard-only
  ['2001::', 32], // Teredo
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4
  ['fc00::', 7], // ULA
  ['fe80::', 10], // link-local
  ['fec0::', 10], // deprecated site-local
  ['ff00::', 8], // multicast
] as const) {
  NON_PUBLIC.addSubnet(net, prefix, 'ipv6');
}

/**
 * True for an IPv4 or IPv6 address that is public unicast; false for any
 * other string. An IPv4-mapped IPv6 address is judged by the IPv4 it maps
 * (Node's BlockList compares IPv4 through that form, so the ranges above
 * never name `::ffff:0:0/96` itself).
 */
export function isPublicUnicastAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !NON_PUBLIC.check(address, 'ipv4');
  if (family === 6) {
    const mapped = /^(?:0*:)*ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped?.[1]) return isPublicUnicastAddress(mapped[1]);
    return !NON_PUBLIC.check(address, 'ipv6');
  }
  return false;
}

/** `localhost`, a name under it, or an IP literal (bracketed IPv6 included) as a URL hostname. */
function ipLiteral(hostname: string): string | undefined {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return isIP(bare) ? bare : undefined;
}

function isLocalName(hostname: string): boolean {
  const name = hostname.toLowerCase().replace(/\.$/, '');
  return name === 'localhost' || name.endsWith('.localhost');
}

// ── Transports ──────────────────────────────────────────────────────────────

/**
 * The default transport: `node:https` (or `node:http` in development) with
 * the connection's `lookup` pinned to the checked address, so TLS still
 * verifies the certificate against the host name while the socket goes only
 * where SafeFetch decided. Never follows a redirect.
 */
export const nodeTransport: SafeFetchTransport = (request) =>
  new Promise<TransportResponse>((resolve, reject) => {
    const url = new URL(request.url);
    const options: RequestOptions = {
      method: 'GET',
      headers: request.headers,
      signal: request.signal,
      ...(request.address === undefined
        ? {}
        : {
            lookup: ((_hostname: string, opts: unknown, callback: (...args: unknown[]) => void): void => {
              const family = isIP(request.address!);
              const all = typeof opts === 'object' && opts !== null && (opts as { all?: boolean }).all === true;
              if (all) callback(null, [{ address: request.address, family }]);
              else callback(null, request.address, family);
            }) as unknown as RequestOptions['lookup'],
          }),
    };
    const send = url.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = send(url, options, (res) => {
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(res.headers)) {
        if (typeof value === 'string') headers[name.toLowerCase()] = value;
        else if (Array.isArray(value)) headers[name.toLowerCase()] = value.join(', ');
      }
      const declared = Number(headers['content-length']);
      if (Number.isFinite(declared) && declared > request.maxBytes) {
        res.destroy();
        reject(new SafeFetchRefusedError('too_large', `SafeFetch: declared content-length ${declared} exceeds the cap of ${request.maxBytes} bytes`));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > request.maxBytes) {
          res.destroy();
          reject(new SafeFetchRefusedError('too_large', `SafeFetch: response body exceeds the cap of ${request.maxBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers, body: new Uint8Array(Buffer.concat(chunks)) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });

/**
 * A transport over a `fetch`-compatible function: for tests that serve
 * canned `Response`s, and for runtimes without `node:https`. It cannot pin
 * the connection (the pinned `address` is ignored), so it is never the
 * default.
 */
export function fetchTransport(fetchLike: (url: string, init: RequestInit) => Promise<Response>): SafeFetchTransport {
  return async (request) => {
    const response = await fetchLike(request.url, { headers: request.headers, redirect: 'manual', signal: request.signal });
    const headers: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      headers[name.toLowerCase()] = value;
    });
    const declared = Number(headers['content-length']);
    if (Number.isFinite(declared) && declared > request.maxBytes) {
      throw new SafeFetchRefusedError('too_large', `SafeFetch: declared content-length ${declared} exceeds the cap of ${request.maxBytes} bytes`);
    }
    const body = new Uint8Array(await response.arrayBuffer());
    if (body.length > request.maxBytes) {
      throw new SafeFetchRefusedError('too_large', `SafeFetch: response body exceeds the cap of ${request.maxBytes} bytes`);
    }
    return { status: response.status, headers, body };
  };
}

export const defaultLookup: DnsLookup = async (hostname) => (await dnsLookup(hostname, { all: true })).map((entry) => entry.address);

// ── The policy ──────────────────────────────────────────────────────────────

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function parseUrl(raw: string): URL {
  try {
    return new URL(raw);
  } catch {
    throw new SafeFetchRefusedError('invalid_url', `SafeFetch: not a URL: ${raw}`);
  }
}

/** Builds a SafeFetch. See the module comment for the rules it enforces. */
export function createSafeFetch(options: SafeFetchOptions = {}): SafeFetch {
  const lookup = options.lookup ?? defaultLookup;
  const transport = options.transport ?? nodeTransport;
  const development = options.development === true;
  const maxBytes = options.maxBytes ?? SAFE_FETCH_MAX_BYTES;
  const timeoutMs = options.timeoutMs ?? SAFE_FETCH_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? SAFE_FETCH_MAX_REDIRECTS;

  function admitScheme(url: URL): void {
    if (url.protocol === 'https:') return;
    if (url.protocol === 'http:' && development) return;
    throw new SafeFetchRefusedError('scheme_refused', `SafeFetch: only https is allowed (got ${url.protocol.replace(/:$/, '')}://${url.host})`, {
      url: url.href,
    });
  }

  /** The checked address to connect to, or undefined when the URL names a (checked) IP literal. */
  async function pin(url: URL): Promise<string | undefined> {
    const hostname = url.hostname;
    if (url.username || url.password) {
      throw new SafeFetchRefusedError('host_refused', 'SafeFetch: a URL with credentials is refused', { url: url.href });
    }
    const literal = ipLiteral(hostname);
    if (literal !== undefined) {
      if (!development && !isPublicUnicastAddress(literal)) {
        throw new SafeFetchRefusedError('host_refused', `SafeFetch: ${literal} is not a public unicast address`, { host: hostname });
      }
      return undefined;
    }
    if (isLocalName(hostname)) {
      if (!development) {
        throw new SafeFetchRefusedError('host_refused', `SafeFetch: ${hostname} is a local host name`, { host: hostname });
      }
      // A local stack: `localhost` is loopback by definition, no lookup needed.
      return '127.0.0.1';
    }
    let addresses: string[];
    try {
      addresses = await lookup(hostname);
    } catch (error) {
      throw new SafeFetchRefusedError('unresolved', `SafeFetch: ${hostname} did not resolve: ${(error as Error).message}`, { host: hostname });
    }
    if (addresses.length === 0) {
      throw new SafeFetchRefusedError('unresolved', `SafeFetch: ${hostname} resolved to no address`, { host: hostname });
    }
    if (!development) {
      for (const address of addresses) {
        if (!isPublicUnicastAddress(address)) {
          // The address itself stays out of the message: whoever named the host may not know it.
          throw new SafeFetchRefusedError('host_refused', `SafeFetch: ${hostname} resolves to a non-public address`, { host: hostname });
        }
      }
    }
    return addresses[0];
  }

  return async (raw, init = {}) => {
    const origin = parseUrl(raw);
    admitScheme(origin);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new SafeFetchRefusedError('deadline_exceeded', `SafeFetch: read of ${origin.href} exceeded ${timeoutMs} ms`)), timeoutMs);
    const onCallerAbort = (): void => controller.abort(init.signal?.reason);
    if (init.signal) {
      if (init.signal.aborted) onCallerAbort();
      else init.signal.addEventListener('abort', onCallerAbort, { once: true });
    }
    const headers = { accept: 'application/json', ...(init.headers ?? {}) };
    try {
      let current = origin;
      for (let hop = 0; ; hop += 1) {
        const address = await pin(current);
        if (controller.signal.aborted) throw controller.signal.reason;
        let response: TransportResponse;
        try {
          response = await transport({ url: current.href, headers, address, signal: controller.signal, maxBytes });
        } catch (error) {
          if (controller.signal.aborted) throw controller.signal.reason;
          if (error instanceof SafeFetchRefusedError) throw error;
          throw new SafeFetchRefusedError('unavailable', `SafeFetch: ${current.href} could not be read: ${(error as Error).message}`, { url: current.href });
        }
        if (REDIRECT_STATUSES.has(response.status)) {
          const location = response.headers['location'];
          if (location === undefined) {
            throw new SafeFetchRefusedError('unavailable', `SafeFetch: ${response.status} from ${current.href} without a Location header`, { url: current.href });
          }
          if (hop >= maxRedirects) {
            throw new SafeFetchRefusedError('too_many_redirects', `SafeFetch: more than ${maxRedirects} redirects from ${origin.href}`, { url: origin.href });
          }
          let target: URL;
          try {
            target = new URL(location, current);
          } catch {
            throw new SafeFetchRefusedError('invalid_url', `SafeFetch: redirect from ${current.href} to a malformed location`, { url: current.href });
          }
          if (target.protocol !== 'https:' && !(development && target.protocol === 'http:')) {
            throw new SafeFetchRefusedError('scheme_refused', `SafeFetch: redirect from ${current.href} to a non-https target refused`, { url: current.href });
          }
          if (target.origin !== origin.origin) {
            throw new SafeFetchRefusedError('cross_origin_redirect', `SafeFetch: cross-origin redirect from ${origin.origin} refused`, { url: origin.href });
          }
          current = target;
          continue;
        }
        const text = Buffer.from(response.body).toString('utf8');
        const responseHeaders = response.headers;
        return {
          ok: response.status >= 200 && response.status < 300,
          status: response.status,
          url: current.href,
          headers: { get: (name: string) => responseHeaders[name.toLowerCase()] ?? null },
          json: () => Promise.resolve(JSON.parse(text) as unknown),
          text: () => Promise.resolve(text),
        };
      }
    } finally {
      clearTimeout(timer);
      init.signal?.removeEventListener('abort', onCallerAbort);
    }
  };
}
