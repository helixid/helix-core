// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Registry v3 (2026-11-24): the Helix registry's side of publishing. Only the
// Helix-hosted deployment runs it.
//
// publish(registration):
//   1. the registration is signed by the agent's own key: checked against its
//      DID document (verifyRegistration), aud = this registry;
//   2. the deployment it names must list the agent as discoverable
//      (GET <deployment>/agent/registry/<did>); what is listed here is that
//      entry, not the registration.
// withdraw(did): needs no key. The registry asks the deployment again and
//   drops the entry when the deployment no longer lists it (made not
//   discoverable, revoked, deactivated); while it still does, it stays.

import { ErrorCode, HelixError, getOutboundFetch, type DidResolver, type OutboundFetch } from '../../core/index.js';
import { verifyRegistration } from './registration.js';
import { AGENT_REGISTRY_PATH, originOf, type AgentRegistryEntry } from './registry.js';
import type { PublishedEntries } from './registry.service.js';

export interface PublishedEntry {
  did: string;
  deployment: string;
  entry: AgentRegistryEntry;
  registeredAt: Date;
}

/** Where the Helix registry keeps what other deployments published. */
export interface PublishedStore {
  list(): Promise<PublishedEntry[]>;
  get(did: string): Promise<PublishedEntry | null>;
  put(entry: PublishedEntry): Promise<void>;
  remove(did: string): Promise<boolean>;
}

export class MemoryPublishedStore implements PublishedStore {
  private readonly rows = new Map<string, PublishedEntry>();
  async list(): Promise<PublishedEntry[]> {
    return [...this.rows.values()].map((row) => structuredClone(row));
  }
  async get(did: string): Promise<PublishedEntry | null> {
    const row = this.rows.get(did);
    return row ? structuredClone(row) : null;
  }
  async put(entry: PublishedEntry): Promise<void> {
    this.rows.set(entry.did, structuredClone(entry));
  }
  async remove(did: string): Promise<boolean> {
    return this.rows.delete(did);
  }
}

export interface HelixRegistryInboxOptions {
  store: PublishedStore;
  /** Resolves the registering DID's document (a public resolver, not this server's database). */
  resolveDid: DidResolver;
  /** This registry's origin: a registration's aud. */
  origin: string;
  /** GETs the deployment's entry. Default: the outbound SafeFetch. */
  fetch?: OutboundFetch | undefined;
  log?: ((message: string) => void) | undefined;
  now?: (() => Date) | undefined;
}

class RegistryUpstreamError extends HelixError {
  constructor(message: string) {
    super(ErrorCode.REGISTRY_UPSTREAM_FAILED, message, 502);
  }
}

const ENTRY_KEYS = ['agentDid', 'name', 'status', 'owner', 'publishedAt', 'deployment'] as const;

export class HelixRegistryInbox implements PublishedEntries {
  private readonly log: (message: string) => void;
  private readonly now: () => Date;

  constructor(private readonly options: HelixRegistryInboxOptions) {
    this.log = options.log ?? ((message: string): void => console.info(`[registry] ${message}`));
    this.now = options.now ?? ((): Date => new Date());
  }

  async entries(): Promise<AgentRegistryEntry[]> {
    return (await this.options.store.list()).map((row) => row.entry);
  }

  /** Lists the agent a registration names. */
  async publish(registration: unknown): Promise<PublishedEntry> {
    if (typeof registration !== 'string' || registration.length > 8192) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'registration must be a compact JWS', 400);
    }
    const claims = await verifyRegistration(registration, { resolveDid: this.options.resolveDid, audience: this.options.origin, now: this.now() });
    if (claims.deployment === originOf(this.options.origin)) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'This registry lists its own deployment already', 400);
    }
    const listed = await this.listedBy(claims.deployment, claims.iss);
    if (listed === null) {
      throw new HelixError(ErrorCode.REGISTRATION_NOT_LISTED, `${claims.deployment} does not list ${claims.iss} as discoverable`, 403);
    }
    // Only the allowlisted fields, whatever else the deployment answered.
    const entry = Object.fromEntries(ENTRY_KEYS.map((key) => [key, listed[key]])) as unknown as AgentRegistryEntry;
    const row: PublishedEntry = { did: claims.iss, deployment: claims.deployment, entry: { ...entry, deployment: claims.deployment }, registeredAt: this.now() };
    await this.options.store.put(row);
    this.log(
      `listed agent ${claims.iss} from ${claims.deployment}: registration signed by ${claims.kid}, ` +
        `checked against its DID document; ${claims.deployment} lists it as discoverable`,
    );
    return row;
  }

  /** Drops the entry once its deployment no longer lists it. */
  async withdraw(did: string): Promise<{ removed: boolean }> {
    const row = await this.options.store.get(did);
    if (!row) return { removed: false };
    if ((await this.listedBy(row.deployment, did)) !== null) {
      throw new HelixError(ErrorCode.REGISTRY_STILL_LISTED, `${row.deployment} still lists ${did} as discoverable`, 409);
    }
    const removed = await this.options.store.remove(did);
    this.log(`removed agent ${did}: ${row.deployment} no longer lists it as discoverable`);
    return { removed };
  }

  /** The deployment's entry for the DID, or null when it lists none (404). */
  private async listedBy(deployment: string, did: string): Promise<AgentRegistryEntry | null> {
    const url = `${deployment}${AGENT_REGISTRY_PATH}/${encodeURIComponent(did)}`;
    const fetchLike = this.options.fetch ?? getOutboundFetch();
    let response: Awaited<ReturnType<OutboundFetch>>;
    try {
      response = await fetchLike(url, { headers: { accept: 'application/json' } });
    } catch (error) {
      throw new RegistryUpstreamError(`Could not read ${url}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (response.status === 404) return null;
    if (!response.ok) throw new RegistryUpstreamError(`${url} answered ${response.status}`);
    const entry = ((await response.json()) as { agent?: AgentRegistryEntry } | null)?.agent;
    if (!entry || entry.agentDid !== did) throw new RegistryUpstreamError(`${url} did not answer with the agent`);
    return entry;
  }
}
