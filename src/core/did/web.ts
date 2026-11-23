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
 * did:web issuance and URL derivation (KYA-OS story C-A, SPEC-ENTITY-CARD
 * §5.4; W3C did:web).
 *
 * - `did:web:host:a:b` ⇄ `https://host/a/b/did.json` and `https://host/a/b/card.json`;
 * - a bare `did:web:host` ⇄ `https://host/.well-known/did.json` and
 *   `https://host/.well-known/kya-os-card.json` (no path segment to derive a
 *   card path from, so the well-known fallback);
 * - every did:web Helix builds is `did:web:<domain>[:<kind>]:<id>`
 *   (Harish, 2026-11-23): the Helix issuer is the bare `did:web:<domain>`, an
 *   account (an owner) `did:web:<domain>:accounts:<id>`, an agent
 *   `did:web:<domain>:agents:<id>` and a service
 *   `did:web:<domain>:services:<id>`, `<id>` random hex (never a slug, never
 *   derived from a key, so the DID outlives a key rotation). They are built
 *   only through `didWebFor` / `issueDidWeb`;
 * - a DID on an owner's own domain may have any path; Helix never builds one,
 *   it only checks it (`ownDidWebProblem`) and resolves it.
 *
 * `DID_DOMAIN` is the raw `host[:port]`; `didWebFor` percent-encodes it once
 * (the port's `:` becomes `%3A`). Two spellings of one DID compare equal
 * through `sameDid`.
 */

import { randomBytes } from 'node:crypto';
import { ValidationError } from '../errors/HelixError.js';

export const KYA_OS_CARD_WELL_KNOWN_PATH = '.well-known/kya-os-card.json';
export const DID_WEB_WELL_KNOWN_PATH = '.well-known/did.json';

export interface ParsedDidWeb {
  /** Decoded host, with its port when it has one (`localhost:3000`). */
  host: string;
  /** Decoded path segments; empty for a bare host DID. */
  path: string[];
}

/** The host and decoded path segments of a did:web, or undefined for anything else. */
export function parseDidWeb(did: string): ParsedDidWeb | undefined {
  if (typeof did !== 'string' || !did.startsWith('did:web:')) return undefined;
  const parts = did.slice('did:web:'.length).split(':');
  if (parts.some((part) => part.length === 0)) return undefined;
  let decoded: string[];
  try {
    decoded = parts.map(decodeURIComponent);
  } catch {
    return undefined;
  }
  const [host, ...path] = decoded;
  if (host === undefined || host.length === 0 || host.includes('/') || host.includes('#') || host.includes('?')) return undefined;
  if (path.some((segment) => segment.length === 0 || /[/#?]/.test(segment) || segment === '.' || segment === '..')) return undefined;
  return { host, path };
}

export function isBareDidWeb(did: string): boolean {
  const parsed = parseDidWeb(did);
  return parsed !== undefined && parsed.path.length === 0;
}

/** A raw `host[:port]`: a DNS name, an IPv4 address or a bracketed IPv6 address, with an optional port; nothing percent-encoded. */
const RAW_HOST = /^(?:\[[0-9a-f:.]+\]|[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?)(?::\d{1,5})?$/i;

/** Whether `host` is a raw `host[:port]` (`DID_DOMAIN`'s form): not percent-encoded, no path. */
export function isRawDidWebHost(host: string): boolean {
  return typeof host === 'string' && RAW_HOST.test(host);
}

/**
 * `did:web:<host>:<seg>…`, the host lowercased and percent-encoded once (a
 * port's `:` is `%3A`), every segment percent-encoded. `host` is the raw
 * `host[:port]` (`DID_DOMAIN`), never an already-encoded one; a segment
 * holds no `:` of its own.
 */
export function didWebFor(host: string, segments: readonly string[] = []): string {
  if (!isRawDidWebHost(host)) {
    throw new ValidationError(`did:web host must be a raw host name, optionally with a port (host or host:port, not percent-encoded): ${JSON.stringify(host)}`);
  }
  for (const segment of segments) {
    if (typeof segment !== 'string' || segment.length === 0 || /[/#?:]/.test(segment) || segment === '.' || segment === '..') {
      throw new ValidationError(`did:web path segment is not one segment: ${JSON.stringify(segment)}`);
    }
  }
  return ['did:web', encodeURIComponent(host.toLowerCase()), ...segments.map(encodeURIComponent)].join(':');
}

/** The kinds of subject Helix hosts under its domain: `did:web:<domain>:<kind>:<id>`. */
export const HELIX_DID_KINDS = ['accounts', 'agents', 'services'] as const;
export type HelixDidKind = (typeof HELIX_DID_KINDS)[number];

/** A fresh `<id>` for a Helix-hosted did:web: 128 random bits, lowercase hex. */
export function randomDidWebId(): string {
  return randomBytes(16).toString('hex');
}

const DID_WEB_ID = /^[0-9a-f]{8,64}$/;

export interface IssueDidWebOptions {
  /** `DID_DOMAIN`: the raw hosting host, with its port when it has one. */
  host: string;
  /** The kind segment; absent for the Helix issuer's own (bare) DID. */
  kind?: HelixDidKind | undefined;
  /** The `<id>` under the kind, lowercase hex; a fresh `randomDidWebId()` when absent. */
  id?: string | undefined;
}

/**
 * The did:web Helix issues under its domain: the bare `did:web:<domain>` for
 * the Helix issuer, `did:web:<domain>:<kind>:<id>` for an account, an agent
 * or a service.
 */
export function issueDidWeb(options: IssueDidWebOptions): string {
  if (options.kind === undefined) {
    if (options.id !== undefined) throw new ValidationError('a Helix did:web <id> needs its kind segment');
    return didWebFor(options.host);
  }
  if (!(HELIX_DID_KINDS as readonly string[]).includes(options.kind)) {
    throw new ValidationError(`did:web kind must be one of ${HELIX_DID_KINDS.join(', ')}`);
  }
  const id = options.id ?? randomDidWebId();
  if (!DID_WEB_ID.test(id)) throw new ValidationError('a Helix did:web <id> is lowercase hex');
  return didWebFor(options.host, [options.kind, id]);
}

/**
 * Why `did` cannot be a DID on its owner's own domain, or undefined when it
 * can. Any path is allowed, with or without a kind segment; a raw port is
 * not: `did:web:localhost:3000:x` is host `localhost` with path `3000/x` under
 * the did:web spec, so the port must be written `%3A3000`.
 */
export function ownDidWebProblem(did: unknown): string | undefined {
  if (typeof did !== 'string') return 'did must be a string';
  const parsed = parseDidWeb(did);
  if (parsed === undefined) return `${did} is not a did:web DID that names a URL`;
  const first = parsed.path[0];
  const rawFirst = did.slice('did:web:'.length).split(':')[1];
  if (first !== undefined && rawFirst === first && /^\d{1,5}$/.test(first) && !parsed.host.includes(':')) {
    return `${did} has an unencoded port: write the host as ${encodeURIComponent(`${parsed.host}:${first}`)} (did:web percent-encodes the port's colon)`;
  }
  return undefined;
}

/** A loopback host (a local stack) serves plain http; SafeFetch admits it only in development mode. */
export function isLoopbackHost(host: string): boolean {
  const hostname = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').toLowerCase();
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

function schemeFor(host: string): string {
  return isLoopbackHost(host) ? 'http' : 'https';
}

function requireDidWeb(did: string): ParsedDidWeb {
  const parsed = parseDidWeb(did);
  if (parsed === undefined) {
    throw new ValidationError(`${did} is not a did:web DID that names a URL`);
  }
  return parsed;
}

/** `https://host/a/b/did.json`, or `https://host/.well-known/did.json` for a bare host (`http` for a loopback host). */
export function didWebDocumentUrl(did: string): string {
  const { host, path } = requireDidWeb(did);
  return path.length === 0 ? `${schemeFor(host)}://${host}/${DID_WEB_WELL_KNOWN_PATH}` : `${schemeFor(host)}://${host}/${path.map(encodeURIComponent).join('/')}/did.json`;
}

/** `https://host/a/b/card.json`, or `https://host/.well-known/kya-os-card.json` for a bare host. */
export function didWebCardUrl(did: string): string {
  const { host, path } = requireDidWeb(did);
  return path.length === 0 ? `${schemeFor(host)}://${host}/${KYA_OS_CARD_WELL_KNOWN_PATH}` : `${schemeFor(host)}://${host}/${path.map(encodeURIComponent).join('/')}/card.json`;
}

/**
 * The did:web a request path under `host` names: `/a/b/did.json` and
 * `/a/b/card.json` are `did:web:host:a:b`; `/.well-known/did.json` and
 * `/.well-known/kya-os-card.json` the bare host. Undefined for any other path.
 */
export function didWebFromPath(host: string, pathname: string): { did: string; document: 'did' | 'card' } | undefined {
  if (!isRawDidWebHost(host)) return undefined;
  if (pathname === `/${DID_WEB_WELL_KNOWN_PATH}`) return { did: didWebFor(host), document: 'did' };
  if (pathname === `/${KYA_OS_CARD_WELL_KNOWN_PATH}`) return { did: didWebFor(host), document: 'card' };
  const match = /^\/(.+)\/(did|card)\.json$/.exec(pathname);
  if (!match) return undefined;
  let segments: string[];
  try {
    segments = match[1]!.split('/').map(decodeURIComponent);
  } catch {
    return undefined;
  }
  if (segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..' || segment.startsWith('.well-known'))) return undefined;
  try {
    return { did: didWebFor(host, segments), document: match[2] as 'did' | 'card' };
  } catch {
    return undefined;
  }
}

/**
 * One spelling for a did:web (host lowercased, each segment decoded and
 * re-encoded, so `%3a` and `%3A` agree and a decoded `:` never becomes a
 * separator); any other DID as written.
 */
export function normalizeDid(did: string): string {
  if (!did.startsWith('did:web:')) return did;
  const [host = '', ...path] = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
  return `did:web:${[host.toLowerCase(), ...path].map(encodeURIComponent).join(':')}`;
}

/** Whether two DIDs are one DID; never throws (a malformed percent-encoding is nobody's equal). */
export function sameDid(a: string, b: string): boolean {
  try {
    return normalizeDid(a) === normalizeDid(b);
  } catch {
    return false;
  }
}
