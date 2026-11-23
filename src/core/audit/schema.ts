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
 * Strict validation of the producer event: the vendored
 * `schemas/audit-event.schema.json` as zod, every object `.strict()` so an
 * unknown member anywhere fails closed, plus the schema's rule that the
 * detail family follows the event type. The Python SDK's
 * `helix_sdk.audit` enforces the same rules by hand; the fixture
 * `fixtures/kya-os-helix/audit-events.json` carries the rejections both must agree on.
 */

import { z } from 'zod';
import { HelixError } from '../errors/HelixError.js';
import {
  AUDIT_EVENT_SCHEMA,
  AUDIT_EVENT_TYPES,
  AUDIT_EVENT_VERSION,
  auditEventFamily,
  type AuditProducerEvent,
} from './types.js';

/** Thrown when a value is not a producer event: the issue path and message name the first offending member. */
export class AuditEventInvalidError extends HelixError {
  public readonly issues: ReadonlyArray<{ path: string; message: string }>;
  constructor(issues: ReadonlyArray<{ path: string; message: string }>) {
    const first = issues[0];
    super(
      'AUDIT_EVENT_INVALID',
      first ? `Audit event is invalid at ${first.path || '$'}: ${first.message}` : 'Audit event is invalid',
      400,
      { issues: issues.map((issue) => ({ ...issue })) },
    );
    this.name = 'AuditEventInvalidError';
    this.issues = issues;
  }
}

export const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;
const BINDING_PATTERN = /^urn:kya-os:audit-binding:[a-z0-9][a-z0-9._:-]*$/;
const DID_PATTERN = /^did:[^\r\n]+$/;

const digest = z.string().regex(DIGEST_PATTERN, 'must be sha256:<64 lowercase hex>');
const decimal = z.string().max(20).regex(DECIMAL_PATTERN, 'must be a decimal integer');
const reference = z.string().min(1).max(256);
const shortReference = z.string().min(1).max(128);
const did = z.string().min(5).max(2048).regex(DID_PATTERN, 'must be a DID');

export const signerRefSchema = z
  .object({ did, kid: z.string().min(1).max(2304), alg: z.enum(['EdDSA', 'ES256']) })
  .strict();

export const evidenceRefSchema = z
  .object({
    objectId: reference,
    ciphertextDigest: digest,
    plaintextCommitment: digest.optional(),
    mediaType: reference,
    size: decimal,
    encryption: z
      .object({ suite: z.literal('A256GCM'), keyId: reference, nonce: reference, aadDigest: digest })
      .strict(),
  })
  .strict();

export const partyRefSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('public_did'), did }).strict(),
  z.object({ kind: z.literal('pairwise_did'), did }).strict(),
  z.object({ kind: z.literal('keyed_commitment'), value: digest, keyId: reference }).strict(),
  z.object({ kind: z.literal('evidence_ref'), ref: evidenceRefSchema }).strict(),
]);

const evidenceList = z.array(evidenceRefSchema).max(256);

export const auditEventDetailsSchema = z.discriminatedUnion('family', [
  z
    .object({
      family: z.literal('session'),
      phase: z.enum(['established', 'rejected', 'expired', 'replay_rejected']),
      reasonCode: shortReference.optional(),
    })
    .strict(),
  z
    .object({
      family: z.literal('tool'),
      phase: z.enum(['started', 'completed', 'failed', 'denied', 'challenged']),
      attempt: decimal,
      idempotencyRef: reference.optional(),
    })
    .strict(),
  z
    .object({
      family: z.literal('proof'),
      phase: z.enum(['generated', 'verified', 'rejected']),
      proofDigest: digest.optional(),
      verificationCode: shortReference.optional(),
    })
    .strict(),
  z
    .object({
      family: z.literal('delegation'),
      phase: z.enum(['issued', 'verified', 'rejected', 'revoked', 'cascade_revoked', 'outbound_attached']),
      delegationRef: reference,
      parentRef: reference.optional(),
      statusEvidence: evidenceList.optional(),
    })
    .strict(),
  z
    .object({
      family: z.literal('authorization'),
      phase: z.enum(['evaluated', 'approved', 'denied', 'step_up_required', 'grant_used']),
      policyDigest: digest.optional(),
      grantRef: reference.optional(),
    })
    .strict(),
  z
    .object({
      family: z.literal('consent'),
      phase: z.enum(['requested', 'approved', 'denied', 'credential_required', 'credential_verified', 'credential_failed']),
      consentRef: reference.optional(),
    })
    .strict(),
  z
    .object({
      family: z.literal('key'),
      phase: z.enum(['rotated', 'policy_changed', 'configuration_changed', 'integrity_suite_transitioned']),
      previousSigner: signerRefSchema.optional(),
      nextSigner: signerRefSchema.optional(),
      configurationDigest: digest.optional(),
    })
    .strict(),
  z
    .object({
      family: z.literal('ledger'),
      phase: z.enum([
        'epoch_started',
        'epoch_transitioned',
        'checkpoint_created',
        'checkpoint_anchored',
        'checkpoint_anchor_failed',
        'evidence_disposed',
        'projection_reconciled',
      ]),
      checkpointDigest: digest.optional(),
      previousEpochId: reference.optional(),
      previousTerminalCheckpointDigest: digest.optional(),
      successorEpochIds: z.array(reference).max(256).optional(),
      targetEvidenceRef: evidenceRefSchema.optional(),
    })
    .strict(),
  z
    .object({
      family: z.literal('administration'),
      phase: z.enum(['source_high_water', 'accessed', 'exported', 'legal_hold_applied', 'retention_executed']),
      purpose: reference.optional(),
      sourceSequence: decimal.optional(),
      selectionDigest: digest.optional(),
    })
    .strict(),
]);

export const authorizationEvidenceSchema = z
  .object({
    source: z.enum(['delegation', 'grant', 'anonymous', 'policy']),
    decision: z.enum(['allowed', 'denied', 'step_up_required', 'needs_authorization']),
    scopeId: reference.optional(),
    delegationRef: reference.optional(),
    delegationCredentialDigest: digest.optional(),
    delegationChainDigests: z.array(digest).max(256).optional(),
    statusEvidence: evidenceList.optional(),
    grantRef: reference.optional(),
    policyId: reference.optional(),
    policyVersion: reference.optional(),
    policyDigest: digest.optional(),
    verificationCode: shortReference.optional(),
  })
  .strict();

export const auditProducerEventSchema = z
  .object({
    schema: z.literal(AUDIT_EVENT_SCHEMA),
    eventId: reference,
    eventType: z.enum(AUDIT_EVENT_TYPES),
    eventVersion: z.literal(AUDIT_EVENT_VERSION),
    binding: z.string().max(256).regex(BINDING_PATTERN, 'must be urn:kya-os:audit-binding:<id>'),
    occurredAt: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    tenantRef: partyRefSchema,
    source: z
      .object({
        producer: partyRefSchema,
        sourceId: reference,
        sourceSequence: decimal.optional(),
        previousSourceEventDigest: digest.optional(),
      })
      .strict(),
    correlationId: reference.optional(),
    causationId: reference.optional(),
    trace: z
      .object({ traceId: z.string().regex(/^[a-f0-9]{32}$/).optional(), spanId: z.string().regex(/^[a-f0-9]{16}$/).optional() })
      .strict()
      .optional(),
    session: z.object({ ref: partyRefSchema, handshakeNonceCommitment: digest.optional() }).strict().optional(),
    actor: partyRefSchema.optional(),
    responsibleParty: partyRefSchema.optional(),
    resource: partyRefSchema.optional(),
    action: z.object({ category: shortReference, name: reference.optional(), detailRef: evidenceRefSchema.optional() }).strict(),
    outcome: z.enum(['succeeded', 'failed', 'denied', 'challenged', 'unknown']),
    reason: z.object({ code: shortReference, detailRef: evidenceRefSchema.optional() }).strict().optional(),
    authorization: authorizationEvidenceSchema.optional(),
    proof: evidenceRefSchema.optional(),
    evidence: evidenceList,
    details: auditEventDetailsSchema,
    privacy: z
      .object({
        classification: z.enum(['public', 'internal', 'confidential', 'restricted']),
        retentionClass: shortReference,
        legalHold: reference.optional(),
      })
      .strict(),
  })
  .strict()
  .superRefine((event, ctx) => {
    const family = auditEventFamily(event.eventType);
    if (event.details.family !== family) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['details', 'family'],
        message: `must be "${family}" for ${event.eventType}`,
      });
    }
  });

/** The event, or the issues that make the value not one. */
export function validateAuditEvent(
  value: unknown,
): { ok: true; event: AuditProducerEvent } | { ok: false; issues: Array<{ path: string; message: string }> } {
  const result = auditProducerEventSchema.safeParse(value);
  if (result.success) return { ok: true, event: result.data as AuditProducerEvent };
  return {
    ok: false,
    issues: result.error.issues.map((issue) => ({ path: issue.path.map(String).join('.'), message: issue.message })),
  };
}

/** The event, or `AuditEventInvalidError`. Fails closed: an unknown member anywhere is a refusal, never dropped. */
export function parseAuditEvent(value: unknown): AuditProducerEvent {
  const result = validateAuditEvent(value);
  if (!result.ok) throw new AuditEventInvalidError(result.issues);
  return result.event;
}
