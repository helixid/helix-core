// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Registry v3 (2026-11-24): search and lookup over the discoverable agents a
// deployment lists, the same for helixid and the enterprise build. On the
// Helix registry, the agents other deployments registered
// (HelixRegistryInbox) follow the deployment's own. Matching and paging are
// in memory.

import { agentMatches, byName, NotListedError, pageOf, type AgentRegistryEntry, type RegistrySearch } from './registry.js';

/** What one deployment lists: its discoverable agents. */
export interface RegistrySource {
  agents(): Promise<AgentRegistryEntry[]>;
}

/** Agents other deployments registered with the Helix registry. */
export interface PublishedEntries {
  entries(): Promise<AgentRegistryEntry[]>;
}

export class RegistryService {
  constructor(
    readonly source: RegistrySource,
    private readonly published?: PublishedEntries | undefined,
  ) {}

  async searchAgents(search: RegistrySearch): Promise<{ agents: AgentRegistryEntry[]; nextCursor: string | null }> {
    const page = pageOf((await this.allAgents()).filter((entry) => agentMatches(entry, search.q)), search);
    return { agents: page.items, nextCursor: page.nextCursor };
  }

  async getAgent(did: string): Promise<AgentRegistryEntry> {
    const found = (await this.allAgents()).find((entry) => entry.agentDid === did);
    if (!found) throw new NotListedError();
    return found;
  }

  /** This deployment's own agent, without the published ones: what another registry checks a registration against. */
  async getOwnAgent(did: string): Promise<AgentRegistryEntry> {
    const found = (await this.source.agents()).find((entry) => entry.agentDid === did);
    if (!found) throw new NotListedError();
    return found;
  }

  /** The deployment's own entries first, then published ones it doesn't list itself. */
  private async allAgents(): Promise<AgentRegistryEntry[]> {
    const own = (await this.source.agents()).sort(byName);
    const seen = new Set(own.map((entry) => entry.agentDid));
    const others = ((await this.published?.entries()) ?? []).filter((entry) => !seen.has(entry.agentDid)).sort(byName);
    return [...own, ...others];
  }
}
