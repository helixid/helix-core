// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Registry v3 (2026-11-24): the Helix agent registry.
//
// - There is one agent registry: the Helix registry, the Helix-hosted
//   deployment at HELIX_REGISTRY_ORIGIN (fixed). "Discoverable" means listed
//   there. An agent is made discoverable at onboarding ("Make discoverable",
//   on by default; `discoverable` in the API and SDK).
// - Nothing is public or private: whether an agent or a service can be
//   reached is up to the network it is hosted on. A DID that can be fetched
//   verifies as usual.
// - There is no service registry: an agent gets a service's URL from its user
//   or its configuration and trusts the DID the service publishes at its own
//   address (/.well-known/mcp).
// - Every other deployment answers GET /agent/registry/:did for its own
//   discoverable agents, so the Helix registry can check a registration with
//   the deployment the agent is onboarded on (helix-registry.inbox.ts).

import { ErrorCode, HelixError } from '../../core/index.js';

/** The Helix registry: the Helix-hosted deployment. Fixed, not configuration. */
export const HELIX_REGISTRY_ORIGIN = 'https://api.helixid.dev';

/**
 * TEST ONLY. Lets a local run stand a loopback deployment in for
 * api.helixid.dev. Not configuration: production never sets it.
 */
export const TEST_ONLY_HELIX_REGISTRY_ORIGIN_ENV = 'HELIX_TEST_ONLY_REGISTRY_ORIGIN';

export const AGENT_REGISTRY_PATH = '/agent/registry';
/** The Helix registry's MCP server; the registry tools live there. */
export const REGISTRY_MCP_PATH = '/mcp';

export const REGISTRY_DEFAULT_PAGE = 24;
export const REGISTRY_MAX_PAGE = 50;
export const REGISTRY_QUERY_MAX_LENGTH = 64;
const CURSOR_MAX_LENGTH = 64;

/** The origin of the Helix registry (see TEST_ONLY_HELIX_REGISTRY_ORIGIN_ENV). */
export function helixRegistryOrigin(env: Readonly<Record<string, string | undefined>> = process.env): string {
  const override = env[TEST_ONLY_HELIX_REGISTRY_ORIGIN_ENV];
  return override ? originOf(override) : HELIX_REGISTRY_ORIGIN;
}

/** The origin of an absolute http(s) URL. Throws on anything else. */
export function originOf(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new HelixError(ErrorCode.VALIDATION_ERROR, `Not an absolute URL: ${url}`, 400);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new HelixError(ErrorCode.VALIDATION_ERROR, `Not an http(s) URL: ${url}`, 400);
  }
  return parsed.origin;
}

export interface RegistryOwner {
  did: string | null;
  name: string | null;
}

/** One discoverable agent, as the registry lists it. This is the whole allowlist. */
export interface AgentRegistryEntry {
  agentDid: string;
  name: string | null;
  status: 'active';
  owner: RegistryOwner;
  /** When it was made discoverable. */
  publishedAt: string | null;
  /** The deployment it is onboarded on. */
  deployment: string;
}

export interface RegistrySearch {
  q?: string | undefined;
  limit: number;
  offset: number;
}

export interface Page<T> {
  items: T[];
  nextCursor: string | null;
}

/** Same 404 for "never onboarded", "not discoverable", "revoked" and "deactivated". */
export class NotListedError extends HelixError {
  constructor() {
    super(ErrorCode.DID_NOT_FOUND, 'Agent is not listed', 404);
  }
}

function badRequest(message: string): HelixError {
  return new HelixError(ErrorCode.VALIDATION_ERROR, message, 400);
}

/** Validates ?q=&limit=&cursor= (and the same MCP tool arguments). */
export function parseRegistrySearch(query: unknown): RegistrySearch {
  const raw = (query ?? {}) as Record<string, unknown>;
  let q: string | undefined;
  if (raw['q'] !== undefined) {
    if (typeof raw['q'] !== 'string') throw badRequest('q must be a single string');
    const trimmed = raw['q'].trim();
    if (trimmed.length > REGISTRY_QUERY_MAX_LENGTH) throw badRequest(`q must be at most ${REGISTRY_QUERY_MAX_LENGTH} characters`);
    q = trimmed === '' ? undefined : trimmed;
  }
  let limit = REGISTRY_DEFAULT_PAGE;
  if (raw['limit'] !== undefined) {
    const parsed = typeof raw['limit'] === 'number' ? raw['limit'] : typeof raw['limit'] === 'string' ? Number(raw['limit']) : Number.NaN;
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > REGISTRY_MAX_PAGE) {
      throw badRequest(`limit must be an integer between 1 and ${REGISTRY_MAX_PAGE}`);
    }
    limit = parsed;
  }
  let offset = 0;
  if (raw['cursor'] !== undefined) {
    const cursor = raw['cursor'];
    const decoded = typeof cursor === 'string' && cursor.length <= CURSOR_MAX_LENGTH ? Number(Buffer.from(cursor, 'base64url').toString('utf8')) : Number.NaN;
    if (!Number.isInteger(decoded) || decoded < 1) throw badRequest('Invalid cursor');
    offset = decoded;
  }
  return { q, limit, offset };
}

/** One page of an in-memory listing, with an opaque offset cursor. */
export function pageOf<T>(items: readonly T[], search: RegistrySearch): Page<T> {
  const next = search.offset + search.limit;
  return {
    items: items.slice(search.offset, next),
    nextCursor: next < items.length ? Buffer.from(String(next), 'utf8').toString('base64url') : null,
  };
}

/** Any word of `q`, case-insensitive, in `fields`; or `q` is exactly one of `exact`. */
export function matchesWords(q: string | undefined, fields: readonly (string | null | undefined)[], exact: readonly (string | null | undefined)[] = []): boolean {
  if (q === undefined) return true;
  if (exact.some((value) => value === q)) return true;
  const haystack = fields.filter((field): field is string => typeof field === 'string').join(' ').toLowerCase();
  return q
    .toLowerCase()
    .split(/\s+/)
    .some((word) => word !== '' && haystack.includes(word));
}

/** An agent entry matches its name or owner, or its exact DID. */
export function agentMatches(entry: AgentRegistryEntry, q: string | undefined): boolean {
  return matchesWords(q, [entry.name, entry.owner.name], [entry.agentDid]);
}

/** Sorted by name, then DID: the order every listing shares. */
export function byName(a: AgentRegistryEntry, b: AgentRegistryEntry): number {
  return (a.name ?? '').localeCompare(b.name ?? '') || a.agentDid.localeCompare(b.agentDid);
}

/** The "Make discoverable" choice given at onboarding: a boolean, default true. */
export function readDiscoverable(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value === 'boolean') return value;
  throw badRequest('discoverable must be true or false');
}
