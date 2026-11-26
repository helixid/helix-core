// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Registry v3 (2026-11-24): the discoverable agents of a one-account
// deployment (helixid). The "Make discoverable" choice is in registry_entries
// (default on); an agent is listed once its custody record is active, and a
// deactivated DID drops out.

import type { RegistryEntryRepository } from '../../repositories/registry-entry.repository.js';
import type { RegistrySource } from './registry.service.js';
import type { AgentRegistryEntry, RegistryOwner } from './registry.js';

export interface DeploymentRegistrySourceDeps {
  /** This deployment's origin (API_BASE_URL). */
  deployment: string;
  /** Who answers for what it lists: the deployment's issuer DID. */
  owner: RegistryOwner;
  entries: Pick<RegistryEntryRepository, 'listDiscoverable'>;
  custody: { custodyOf(dids: readonly string[]): Promise<Array<{ did: string; name: string | null; status: string }>> };
  didRepository?: { findDidById(did: string): Promise<{ deactivatedAt: Date | null } | null> } | undefined;
}

export function deploymentRegistrySource(deps: DeploymentRegistrySourceDeps): RegistrySource {
  return {
    async agents() {
      const rows = await deps.entries.listDiscoverable();
      const views = new Map((await deps.custody.custodyOf(rows.map((row) => row.did))).map((view) => [view.did, view]));
      const states = deps.didRepository ? await Promise.all(rows.map((row) => deps.didRepository!.findDidById(row.did))) : [];
      return rows.flatMap((row, index): AgentRegistryEntry[] => {
        const view = views.get(row.did);
        if (!view || view.status !== 'active' || states[index]?.deactivatedAt) return [];
        return [{ agentDid: row.did, name: view.name, status: 'active', owner: { ...deps.owner }, publishedAt: row.updatedAt.toISOString(), deployment: deps.deployment }];
      });
    },
  };
}
