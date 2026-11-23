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
 * A verification method's validity (KYA-OS story C-E point 3): which
 * proofs a superseded or revoked key may still vouch for. A leaf module, so
 * the JWS and Data Integrity verifiers can import it without a cycle; see
 * `./rotation.ts` for the rest of rotation.
 */

/** Why a key was refused for a proof; the same strings the SDKs use. */
export const KeyValidityReasons = {
  /** The key carries `revoked`: compromised, so nothing it signed is accepted. */
  KEY_REVOKED: 'key_revoked',
  /** The proof's `created` is after the key's `validUntil` (or before its `validFrom`). */
  KEY_SUPERSEDED: 'key_superseded',
  /** `validFrom`, `validUntil` or `revoked` is not an RFC 3339 instant. */
  KEY_VALIDITY_MALFORMED: 'key_validity_malformed',
} as const;

export type KeyValidityReason = (typeof KeyValidityReasons)[keyof typeof KeyValidityReasons];

export interface KeyValidityProblem {
  reason: KeyValidityReason;
  message: string;
}

/** The validity members a verification method may carry. */
export interface KeyValidity {
  validFrom?: string;
  validUntil?: string;
  revoked?: string;
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i;

/** An RFC 3339 instant with an offset, as epoch ms; undefined for anything else. */
export function rfc3339Instant(value: unknown): number | undefined {
  if (typeof value !== 'string' || !RFC3339.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : ms;
}

/**
 * Whether the key `method` describes may vouch for a proof created at `at`
 * (epoch ms). With no `at` (a proof that states no time) the check is made
 * at `now`. Undefined when the key is usable.
 */
export function keyValidityProblem(
  method: Record<string, unknown>,
  at: number | undefined,
  now: number = Date.now(),
): KeyValidityProblem | undefined {
  const kid = String(method['id'] ?? 'the key');
  for (const member of ['validFrom', 'validUntil', 'revoked'] as const) {
    if (method[member] !== undefined && rfc3339Instant(method[member]) === undefined) {
      return { reason: KeyValidityReasons.KEY_VALIDITY_MALFORMED, message: `${kid}: ${member} is not an RFC 3339 instant` };
    }
  }
  if (method['revoked'] !== undefined) {
    return { reason: KeyValidityReasons.KEY_REVOKED, message: `${kid} was revoked at ${String(method['revoked'])}` };
  }
  const when = at ?? now;
  const until = rfc3339Instant(method['validUntil']);
  if (until !== undefined && when > until) {
    return { reason: KeyValidityReasons.KEY_SUPERSEDED, message: `${kid} was valid until ${String(method['validUntil'])}; the proof is from ${new Date(when).toISOString()}` };
  }
  const from = rfc3339Instant(method['validFrom']);
  if (from !== undefined && when < from) {
    return { reason: KeyValidityReasons.KEY_SUPERSEDED, message: `${kid} is valid from ${String(method['validFrom'])}; the proof is from ${new Date(when).toISOString()}` };
  }
  return undefined;
}

/** A proof time as epoch ms: an RFC 3339 string (`created`) or epoch seconds (`created`, `iat`). */
export function proofTime(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return value * 1000;
  return rfc3339Instant(value);
}

