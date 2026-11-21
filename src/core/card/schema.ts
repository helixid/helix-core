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
 * The KYA-OS Entity Card as SPEC-ENTITY-CARD §4 and its strict schema write
 * it (story C-A). `parseEntityCard` is `parseCard`: the schema rejects, never
 * strips, so a card with an unknown top-level field is refused. A card
 * carries `conformanceLevel` only as a hint a verifier recomputes and never
 * trusts (§9.4); Helix never writes one, and never a proof (§4.3).
 */

import { EntityCardInvalidError } from '../errors/HelixError.js';
import { KYA_OS_CARD_SCHEMA } from './card-schema.js';
import { validateJsonSchema, type JsonSchema, type SchemaIssue } from './json-schema-lite.js';

export const PROOF_PROFILE_V1 = 'org.kya-os/proof.v1';

export type EntityType = 'mcp' | 'agent' | 'client' | 'verifier' | 'human';
export const ENTITY_TYPES: readonly EntityType[] = ['mcp', 'agent', 'client', 'verifier', 'human'];

export type ConformanceLevel = 'L1' | 'L2' | 'L3';

export interface CapabilityAttestationRef {
  vc: string | Record<string, unknown>;
  [member: string]: unknown;
}

export interface Level2Capability {
  name: string;
  attestations: CapabilityAttestationRef[];
}

export type Capability = string | Level2Capability;

export interface CardAttestation {
  type: 'IdentityVerification' | 'CapabilityAttestation';
  vc: string | Record<string, unknown>;
  subject?: string;
  issuer?: string;
}

export interface BitstringStatusListEntry {
  statusListCredential: string;
  statusListIndex: string;
  statusSize?: number;
  statusMessage?: { status: string; message: string }[];
}

export interface CardPublicKeyJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string;
  use?: string;
}

export interface CimdBinding {
  clientId: string;
  jwksUri: string;
}

export interface EntityCard {
  id: string;
  entityType: EntityType;
  name: string;
  kid?: string;
  publicKeyJwk?: CardPublicKeyJwk;
  createdAt?: string;
  capabilities?: Capability[];
  /** A hint only; a verifier recomputes the level and never trusts this. Helix never writes it. */
  conformanceLevel?: ConformanceLevel;
  responsibleParty?: string;
  principal?: string;
  delegationRef?: string;
  attestations?: CardAttestation[];
  didDocument?: string;
  proofProfile?: 'org.kya-os/proof.v1' | 'org.kya-os/proof@1';
  cimd?: CimdBinding;
  revocation?: BitstringStatusListEntry;
}

/** The issues `value` has against the card schema (empty: it is a card). */
export function validateEntityCard(value: unknown): SchemaIssue[] {
  return validateJsonSchema(KYA_OS_CARD_SCHEMA as unknown as JsonSchema, value);
}

/** `parseCard`: the value as an Entity Card, or `EntityCardInvalidError` with every schema issue. */
export function parseEntityCard(value: unknown): EntityCard {
  const issues = validateEntityCard(value);
  if (issues.length > 0) {
    const first = issues[0]!;
    throw new EntityCardInvalidError(`Entity Card is invalid: ${first.path || '/'} ${first.message}`, { issues });
  }
  return value as EntityCard;
}

/** The name of a capability, whether declared bare (L1) or with attestations (L2). */
export function capabilityName(capability: Capability): string {
  return typeof capability === 'string' ? capability : capability.name;
}
