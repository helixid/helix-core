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
 * Typed audit events of the status lists and the revocation signal (story
 * L3-C on A-1's `AuditTrail`). The event core names credentials by their
 * SPEC 7.8 reference and parties by DID only; it never carries list bits,
 * endpoints or exception text.
 */

import { delegationReference, publicDid, type AuditEventInput, type AuditTrail, type PartyRef } from '../../core/index.js';

const DID_PATTERN = /^did:[^\r\n]+$/;

/** A `public_did` reference, or nothing when the value is not a DID: the event then names no party rather than failing validation. */
export function didRef(value: string | null | undefined): PartyRef | undefined {
  return typeof value === 'string' && DID_PATTERN.test(value) ? publicDid(value) : undefined;
}

/** Records one typed event; a failure to record never breaks the revocation or the publication that caused it. */
export function recordAudit(trail: AuditTrail | undefined, input: AuditEventInput): void {
  if (trail === undefined) return;
  try {
    trail.record(input).catch(reportAuditFailure);
  } catch (error) {
    reportAuditFailure(error);
  }
}

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}

/** `configuration.changed` for a status list newly signed: `published` by Helix with the issuer's key, `submitted` by a self-custody issuer. */
export function statusListPublished(issuer: string, name: 'published' | 'submitted'): AuditEventInput {
  const party = didRef(issuer);
  return {
    eventType: 'configuration.changed',
    action: { category: 'status_list', name },
    outcome: 'succeeded',
    ...(party !== undefined ? { resource: party, ...(name === 'submitted' ? { actor: party } : {}) } : {}),
    details: { family: 'key', phase: 'configuration_changed' },
  };
}

export interface CredentialRevokedInput {
  requestId: string;
  vcId: string;
  subjectDid: string;
  /** The DID that asked (a signed revocation request's signer). */
  revoker?: string | undefined;
  /** The credential the revocation was asked for, when this one is its descendant (SPEC 6.5 cascade). */
  cascadeFrom?: string | undefined;
}

/**
 * One event per revoked credential (L3-C point 5): `delegation.revoked` for
 * the credential asked for, `delegation.cascade_revoked` with `parentRef` for
 * each descendant revoked with it.
 */
export function credentialRevoked(input: CredentialRevokedInput): AuditEventInput {
  const actor = didRef(input.revoker);
  const resource = didRef(input.subjectDid);
  const cascade = input.cascadeFrom !== undefined;
  return {
    eventType: cascade ? 'delegation.cascade_revoked' : 'delegation.revoked',
    action: { category: 'credential', name: cascade ? 'cascade_revoked' : 'revoked' },
    outcome: 'succeeded',
    correlationId: input.requestId,
    ...(actor !== undefined ? { actor } : {}),
    ...(resource !== undefined ? { resource } : {}),
    ...(cascade ? { reason: { code: 'ancestor_revoked' } } : {}),
    details: {
      family: 'delegation',
      phase: cascade ? 'cascade_revoked' : 'revoked',
      delegationRef: delegationReference(input.vcId),
      ...(cascade ? { parentRef: delegationReference(input.cascadeFrom!) } : {}),
    },
  };
}

/**
 * A revocation signal (SET) that did not go out: `delegation.revoked` with
 * outcome `failed` under the `revocation_signal` category. The credential is
 * revoked all the same (its bit is set and published); only the cache hint
 * was lost, so verifiers notice within their status cache TTL.
 */
export function revocationSignalFailed(input: { vcId: string; correlationId: string; stage: 'emit' | 'webhook_push' }): AuditEventInput {
  return {
    eventType: 'delegation.revoked',
    action: { category: 'revocation_signal', name: input.stage },
    outcome: 'failed',
    correlationId: input.correlationId,
    reason: { code: input.stage === 'emit' ? 'revocation_signal_failed' : 'webhook_push_failed' },
    details: { family: 'delegation', phase: 'revoked', delegationRef: delegationReference(input.vcId) },
  };
}
