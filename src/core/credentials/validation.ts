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
 * Shape and window checks shared by the three verifiers: each credential
 * must match its JSON schema (src/core/schemas/*.schema.json), and be inside
 * the validity window it states, each bound held with a clock tolerance.
 */

import {
  CAPABILITY_ATTESTATION_SCHEMA,
  DELEGATION_HOP_SCHEMA,
  IDENTITY_CREDENTIAL_SCHEMA,
} from '../schemas/credential-schemas.js';
import { parseDateTime, validateJsonSchema, type SchemaViolation } from './json-schema.js';
import {
  DEFAULT_CLOCK_SKEW_MS,
  MAX_CLOCK_SKEW_MS,
  type SignedCapabilityAttestation,
  type SignedDelegationHop,
  type SignedIdentityCredential,
} from './types.js';

export type CredentialKind = 'identity' | 'attestation' | 'hop';

const SCHEMAS = {
  identity: IDENTITY_CREDENTIAL_SCHEMA,
  attestation: CAPABILITY_ATTESTATION_SCHEMA,
  hop: DELEGATION_HOP_SCHEMA,
} as const;

/** Every way `value` fails the schema of `kind`; empty when it conforms. */
export function credentialSchemaViolations(kind: CredentialKind, value: unknown): SchemaViolation[] {
  return validateJsonSchema(SCHEMAS[kind], value);
}

export function isIdentityCredential(value: unknown): value is SignedIdentityCredential {
  return credentialSchemaViolations('identity', value).length === 0;
}

export function isCapabilityAttestation(value: unknown): value is SignedCapabilityAttestation {
  return credentialSchemaViolations('attestation', value).length === 0;
}

export function isDelegationHop(value: unknown): value is SignedDelegationHop {
  return credentialSchemaViolations('hop', value).length === 0;
}

export function describeViolations(violations: readonly SchemaViolation[]): string {
  return violations.map((violation) => `${violation.path}: ${violation.message}`).join('; ');
}

export type WindowVerdict = 'inside' | 'expired' | 'not_yet_valid' | 'malformed' | 'skew_invalid';

/** The clock tolerance in use, or undefined when `maxClockSkewMs` is not a number of ms from 0 to 600,000. */
export function clockSkewMs(maxClockSkewMs: unknown): number | undefined {
  if (maxClockSkewMs === undefined) return DEFAULT_CLOCK_SKEW_MS;
  if (typeof maxClockSkewMs !== 'number' || !Number.isFinite(maxClockSkewMs)) return undefined;
  if (maxClockSkewMs < 0 || maxClockSkewMs > MAX_CLOCK_SKEW_MS) return undefined;
  return maxClockSkewMs;
}

/**
 * Where `nowMs` stands against a window `validFrom` .. `validUntil`, either
 * bound optional, each held with `maxClockSkewMs`. A bound that is not an
 * RFC 3339 date-time with offset is `malformed` (fail-closed).
 */
export function windowVerdict(
  validFrom: unknown,
  validUntil: unknown,
  nowMs: number,
  maxClockSkewMs?: unknown,
): WindowVerdict {
  const skew = clockSkewMs(maxClockSkewMs);
  if (skew === undefined) return 'skew_invalid';
  let from: number | undefined;
  let until: number | undefined;
  if (validFrom !== undefined) {
    from = parseDateTime(validFrom);
    if (from === undefined) return 'malformed';
  }
  if (validUntil !== undefined) {
    until = parseDateTime(validUntil);
    if (until === undefined) return 'malformed';
  }
  if (until !== undefined && nowMs > until + skew) return 'expired';
  if (from !== undefined && nowMs < from - skew) return 'not_yet_valid';
  return 'inside';
}
