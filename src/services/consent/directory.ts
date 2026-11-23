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
 * What the consent service (KYA-OS story L3-H) asks this deployment's other
 * records: whether a service is known here (enrolled, or created through the
 * custody routes and active) and its name for the page, and the scopes an
 * agent onboarded here is attested for. Shared by core's server and the
 * enterprise server.
 */

import { HelixError } from '../../core/index.js';
import type { ConsentServiceInfo } from './consent.service.js';

export interface ServiceDirectorySources {
  services?: { findByDid(did: string): Promise<{ name: string; revokedAt?: Date | null } | null> } | undefined;
  custody?: { custodyOf(dids: readonly string[]): Promise<Array<{ did: string; subjectType: string; status: string; name: string | null }>> } | undefined;
}

/** `serviceOf` for ConsentService: an unrevoked enrolled service, or an active custody service. */
export function consentServiceDirectory(sources: ServiceDirectorySources): (serviceDid: string) => Promise<ConsentServiceInfo | undefined> {
  return async (serviceDid) => {
    const enrolled = await sources.services?.findByDid(serviceDid);
    if (enrolled && !enrolled.revokedAt) return { name: enrolled.name };
    const [record] = (await sources.custody?.custodyOf([serviceDid])) ?? [];
    if (record?.did === serviceDid && record.subjectType === 'service' && record.status === 'active') {
      return record.name === null ? {} : { name: record.name };
    }
    return undefined;
  };
}

/**
 * `agentScopesOf` for ConsentService over `getAgentScopes` (story F-1: the
 * agent's active capability attestations): undefined for an agent this
 * deployment did not onboard (the verifier still intersects), none for one
 * whose identity is no longer active.
 */
export function consentAgentScopes(
  scopes: { getAgentScopes(agentDid: string): Promise<{ scopes: string[] }> },
): (agentDid: string) => Promise<readonly string[] | undefined> {
  return async (agentDid) => {
    try {
      return (await scopes.getAgentScopes(agentDid)).scopes;
    } catch (error) {
      if (error instanceof HelixError && error.code === 'DELEGATEE_NOT_AN_AGENT') return undefined;
      if (error instanceof HelixError && error.code === 'AGENT_ACTIVE_CREDENTIAL_NOT_FOUND') return [];
      throw error;
    }
  };
}
