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
 * Entity Card capability floor and level (story C-B, SPEC-ENTITY-CARD.md §9):
 * a card's `capabilities` are bare strings (L1, self-declared) or
 * `{ name, attestations: [{ vc }] }` objects, L2 when at least one attestation
 * verifies (signature, trusted issuer, subject = card id, capability name,
 * validity, not revoked). The level is recomputed, never read off the card.
 */

import type { DidResolver } from './data-integrity.js';
import { verifyCapabilityAttestation } from './attestation.js';
import type { TrustedIssuers } from './types.js';

export type ConformanceLevel = 'L1' | 'L2' | 'L3';

export interface CardCapabilityObject {
  name: string;
  attestations: { vc: unknown }[];
}

export type CardCapability = string | CardCapabilityObject;

export interface CapabilityCheck {
  verified: string[];
  unverified: string[];
}

/** `{ name, attestations: [{ vc }] }` for a capability backed by the given credentials (story C-B point 2). */
export function attestedCapabilityEntry(name: string, attestations: readonly unknown[]): CardCapabilityObject {
  return { name, attestations: attestations.map((vc) => ({ vc })) };
}

/** The name of a capability entry, whichever form it takes. */
export function capabilityName(capability: CardCapability): string {
  return typeof capability === 'string' ? capability : capability.name;
}

export interface CheckCapabilitiesOptions {
  /** The card id every attestation must name. */
  subjectDid: string;
  /** Default `'*'`. */
  trustedIssuers?: TrustedIssuers;
  now?: number;
  maxClockSkewMs?: number;
  /**
   * The status lists the attestations point at, by `statusListCredential`
   * URL, fetched over HTTPS by the caller. An attestation whose list is
   * given and marks it revoked is unverified; one whose list is not given
   * is not checked for revocation.
   */
  statusLists?: Record<string, { credentialSubject: { encodedList: string } }>;
}

/**
 * Sorts a card's capabilities into verified (every attested name with at
 * least one attestation that verifies) and unverified (bare strings, and
 * attested names none of whose attestations verify).
 */
export async function checkCapabilities(
  capabilities: readonly CardCapability[],
  resolveDid: DidResolver,
  options: CheckCapabilitiesOptions,
): Promise<CapabilityCheck> {
  const verified: string[] = [];
  const unverified: string[] = [];
  for (const capability of capabilities) {
    if (typeof capability === 'string') {
      unverified.push(capability);
      continue;
    }
    let holds = false;
    for (const attestation of capability.attestations) {
      const vc = attestation.vc as { credentialStatus?: { statusListCredential?: string } } | undefined;
      const listUrl = vc?.credentialStatus?.statusListCredential;
      const statusList = listUrl === undefined ? undefined : options.statusLists?.[listUrl];
      const verdict = await verifyCapabilityAttestation(attestation.vc, resolveDid, {
        subjectDid: options.subjectDid,
        capability: capability.name,
        trustedIssuers: options.trustedIssuers ?? '*',
        ...(options.now === undefined ? {} : { now: options.now }),
        ...(options.maxClockSkewMs === undefined ? {} : { maxClockSkewMs: options.maxClockSkewMs }),
        ...(statusList === undefined ? {} : { statusList }),
      });
      if (verdict.ok) {
        holds = true;
        break;
      }
    }
    (holds ? verified : unverified).push(capability.name);
  }
  return { verified, unverified };
}

/**
 * SPEC-ENTITY-CARD.md §9.4: L1 unless every declared capability is attested
 * and verified; L3 only with the proof floor and a fresh revocation read;
 * otherwise L2. Fail-closed: a missing artifact demotes, never errors open.
 */
export function deriveConformanceLevel(
  check: CapabilityCheck,
  proofFloorOk = false,
  revocationFresh = true,
): ConformanceLevel {
  const allAttested = check.verified.length > 0 && check.unverified.length === 0;
  if (!allAttested) return 'L1';
  if (proofFloorOk && revocationFresh) return 'L3';
  return 'L2';
}
