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
 * - under Helix hosting an agent or service is `did:web:<host>:<org>:<slug>`,
 *   an org `did:web:<host>:<org>`, and the Helix host itself the bare DID.
 *
 * Segments are percent-encoded as DID Core writes them (`:` in a host's port
 * is `%3A`), and two spellings of one DID compare equal through `sameDid`.
 */

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

/** `did:web:<host>:<seg>…` with every segment percent-encoded; the host lowercased. */
export function didWebFor(host: string, segments: readonly string[] = []): string {
  if (typeof host !== 'string' || host.length === 0 || /[/#?\s]/.test(host)) {
    throw new ValidationError('did:web host must be a host name, optionally with a port');
  }
  for (const segment of segments) {
    if (typeof segment !== 'string' || segment.length === 0 || /[/#?]/.test(segment) || segment === '.' || segment === '..') {
      throw new ValidationError(`did:web path segment is not one segment: ${JSON.stringify(segment)}`);
    }
  }
  return ['did:web', encodeURIComponent(host.toLowerCase()), ...segments.map(encodeURIComponent)].join(':');
}

export interface IssueDidWebOptions {
  /** The hosting host, with its port when it has one. */
  host: string;
  /** The org segment; absent for the host's own (bare) DID. */
  org?: string | undefined;
  /** The agent's or service's segment under the org; absent for the org's own DID. */
  slug?: string | undefined;
}

/**
 * The did:web Helix issues under its hosting: `did:web:<host>:<org>:<slug>`
 * for an agent or a service, `did:web:<host>:<org>` for an org, and the bare
 * `did:web:<host>` for the host itself.
 */
export function issueDidWeb(options: IssueDidWebOptions): string {
  if (options.slug !== undefined && options.org === undefined) {
    throw new ValidationError('an agent or service did:web needs its org segment');
  }
  return didWebFor(options.host, [options.org, options.slug].filter((segment): segment is string => segment !== undefined));
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
