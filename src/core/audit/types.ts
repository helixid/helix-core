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
 * KYA-OS Auditability Protocol v1 (AUDITABILITY.md, AAP-1 Recorded): the
 * producer event and the values it is made of. The wire shape is the vendored
 * schema `fixtures/kya-os/schemas/audit-event.schema.json`; `schema.ts`
 * enforces it, `trail.ts` emits it.
 */

/** `sha256:` plus 64 lowercase hex digits (SPEC section 7.3). */
export type Digest = `sha256:${string}`;
/** A non-negative integer written in decimal, as the schema carries sequences and sizes. */
export type DecimalString = string;
export type ProtocolBindingId = `urn:kya-os:audit-binding:${string}`;

/** The identity reference forms, each declaring its privacy form. */
export type PartyRef =
  | { kind: 'public_did'; did: string }
  | { kind: 'pairwise_did'; did: string }
  | { kind: 'keyed_commitment'; value: Digest; keyId: string }
  | { kind: 'evidence_ref'; ref: EvidenceRef };

export type PartyRefKind = PartyRef['kind'];

/** A cryptographically resolvable signer; never a privacy PartyRef. */
export interface SignerRef {
  did: string;
  kid: string;
  alg: 'EdDSA' | 'ES256';
}

export interface EvidenceEncryptionMetadata {
  suite: 'A256GCM';
  keyId: string;
  nonce: string;
  aadDigest: Digest;
}

/** What an event carries instead of an exact payload: the vault object's metadata, never its bytes. */
export interface EvidenceRef {
  objectId: string;
  ciphertextDigest: Digest;
  plaintextCommitment?: Digest;
  mediaType: string;
  size: DecimalString;
  encryption: EvidenceEncryptionMetadata;
}

export const AUDIT_EVENT_SCHEMA = 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0';
export const AUDIT_EVENT_VERSION = '1.0.0';

/** Digest domains (AUDITABILITY.md, Cryptographic suites): `<domain> NUL JCS(value)`. */
export const AUDIT_DIGEST_DOMAINS = {
  event: 'org.kya-os.audit.event.v1',
  entry: 'org.kya-os.audit.entry.v1',
  evidenceManifest: 'org.kya-os.audit.evidence-manifest.v1',
  idempotency: 'org.kya-os.audit.idempotency.v1',
  checkpoint: 'org.kya-os.audit.checkpoint.v1',
  observation: 'org.kya-os.audit.observation.v1',
  bundleManifest: 'org.kya-os.audit.bundle-manifest.v1',
  /** SPEC section 7.8: one credential's signed form. */
  delegationCredential: 'org.kya-os.delegation.credential.v1',
  /** SPEC section 7.8: the array of credential digests, root first. */
  delegationChain: 'org.kya-os.delegation.chain.v1',
} as const;

export const AUDIT_INTEGRITY_SUITE = 'KYA-AUDIT-JCS-SHA256-JWS-2026';

/** The MCP binding every middleware and SDK producer uses. */
export const AUDIT_BINDING_MCP: ProtocolBindingId = 'urn:kya-os:audit-binding:mcp:2025-11-25';
/** The binding of events the Helix API records about its own operations (onboarding, issuance, verification). */
export const AUDIT_BINDING_HELIX: ProtocolBindingId = 'urn:kya-os:audit-binding:helix:2026-11-20';

/** The event catalog (AUDITABILITY.md, Event and privacy model). */
export const AUDIT_EVENT_TYPES = [
  'session.established',
  'session.rejected',
  'session.expired',
  'session.replay_rejected',
  'tool.call.started',
  'tool.call.completed',
  'tool.call.failed',
  'tool.call.denied',
  'tool.call.challenged',
  'proof.generated',
  'proof.verified',
  'proof.rejected',
  'delegation.issued',
  'delegation.verified',
  'delegation.rejected',
  'delegation.revoked',
  'delegation.cascade_revoked',
  'delegation.outbound_attached',
  'authorization.evaluated',
  'authorization.approved',
  'authorization.denied',
  'authorization.step_up_required',
  'grant.used',
  'consent.requested',
  'consent.approved',
  'consent.denied',
  'credential.required',
  'credential.verified',
  'credential.failed',
  'key.rotated',
  'policy.changed',
  'configuration.changed',
  'integrity_suite.transitioned',
  'ledger.epoch.started',
  'ledger.epoch.transitioned',
  'checkpoint.created',
  'checkpoint.anchored',
  'checkpoint.anchor_failed',
  'evidence.disposed',
  'projection.reconciled',
  'audit.source_high_water',
  'audit.accessed',
  'audit.exported',
  'legal_hold.applied',
  'retention.executed',
] as const;

export type AuditEventType = (typeof AUDIT_EVENT_TYPES)[number];

export const AUDIT_EVENT_FAMILIES = [
  'session',
  'tool',
  'proof',
  'delegation',
  'authorization',
  'consent',
  'key',
  'ledger',
  'administration',
] as const;

export type AuditEventFamily = (typeof AUDIT_EVENT_FAMILIES)[number];

/** Which detail family each event type belongs to (the schema's `allOf` rules). */
export function auditEventFamily(eventType: AuditEventType): AuditEventFamily {
  const prefix = eventType.split('.')[0]!;
  switch (prefix) {
    case 'session':
    case 'tool':
    case 'proof':
    case 'delegation':
    case 'authorization':
    case 'consent':
    case 'key':
    case 'ledger':
      return prefix;
    case 'grant':
      return 'authorization';
    case 'credential':
      return 'consent';
    case 'policy':
    case 'configuration':
    case 'integrity_suite':
      return 'key';
    case 'checkpoint':
    case 'evidence':
    case 'projection':
      return 'ledger';
    default:
      // audit, legal_hold, retention
      return 'administration';
  }
}

export type SessionPhase = 'established' | 'rejected' | 'expired' | 'replay_rejected';
export type ToolPhase = 'started' | 'completed' | 'failed' | 'denied' | 'challenged';
export type ProofPhase = 'generated' | 'verified' | 'rejected';
export type DelegationPhase = 'issued' | 'verified' | 'rejected' | 'revoked' | 'cascade_revoked' | 'outbound_attached';
export type AuthorizationPhase = 'evaluated' | 'approved' | 'denied' | 'step_up_required' | 'grant_used';
export type ConsentPhase = 'requested' | 'approved' | 'denied' | 'credential_required' | 'credential_verified' | 'credential_failed';
export type KeyPhase = 'rotated' | 'policy_changed' | 'configuration_changed' | 'integrity_suite_transitioned';
export type LedgerPhase =
  | 'epoch_started'
  | 'epoch_transitioned'
  | 'checkpoint_created'
  | 'checkpoint_anchored'
  | 'checkpoint_anchor_failed'
  | 'evidence_disposed'
  | 'projection_reconciled';
export type AdministrationPhase = 'source_high_water' | 'accessed' | 'exported' | 'legal_hold_applied' | 'retention_executed';

/** Every detail payload is a closed discriminated union; an unknown member fails closed in `schema.ts`. */
export type AuditEventDetails =
  | { family: 'session'; phase: SessionPhase; reasonCode?: string }
  | { family: 'tool'; phase: ToolPhase; attempt: DecimalString; idempotencyRef?: string }
  | { family: 'proof'; phase: ProofPhase; proofDigest?: Digest; verificationCode?: string }
  | { family: 'delegation'; phase: DelegationPhase; delegationRef: string; parentRef?: string; statusEvidence?: EvidenceRef[] }
  | { family: 'authorization'; phase: AuthorizationPhase; policyDigest?: Digest; grantRef?: string }
  | { family: 'consent'; phase: ConsentPhase; consentRef?: string }
  | { family: 'key'; phase: KeyPhase; previousSigner?: SignerRef; nextSigner?: SignerRef; configurationDigest?: Digest }
  | {
      family: 'ledger';
      phase: LedgerPhase;
      checkpointDigest?: Digest;
      previousEpochId?: string;
      previousTerminalCheckpointDigest?: Digest;
      successorEpochIds?: string[];
      targetEvidenceRef?: EvidenceRef;
    }
  | { family: 'administration'; phase: AdministrationPhase; purpose?: string; sourceSequence?: DecimalString; selectionDigest?: Digest };

export type AuditOutcome = 'succeeded' | 'failed' | 'denied' | 'challenged' | 'unknown';

export interface AuthorizationEvidence {
  source: 'delegation' | 'grant' | 'anonymous' | 'policy';
  decision: 'allowed' | 'denied' | 'step_up_required' | 'needs_authorization';
  scopeId?: string;
  /** SPEC section 7.8: the presented credential's reference (`delegationRef`). */
  delegationRef?: string;
  /** SPEC section 7.8: the presented credential's digest over its signed form. */
  delegationCredentialDigest?: Digest;
  /** One digest per credential the server evaluated, root first. */
  delegationChainDigests?: Digest[];
  statusEvidence?: EvidenceRef[];
  grantRef?: string;
  policyId?: string;
  policyVersion?: string;
  policyDigest?: Digest;
  verificationCode?: string;
}

export interface AuditPrivacy {
  classification: 'public' | 'internal' | 'confidential' | 'restricted';
  retentionClass: string;
  legalHold?: string;
}

export interface AuditEventSource {
  producer: PartyRef;
  sourceId: string;
  sourceSequence?: DecimalString;
  previousSourceEventDigest?: Digest;
}

/**
 * The producer event core, exactly the vendored schema. It never holds
 * arguments, responses, tokens, prompts or exception text: an exact payload
 * that must be kept is encrypted evidence, and the event carries its
 * `EvidenceRef` (see `evidence.ts`).
 */
export interface AuditProducerEvent {
  schema: typeof AUDIT_EVENT_SCHEMA;
  eventId: string;
  eventType: AuditEventType;
  eventVersion: typeof AUDIT_EVENT_VERSION;
  binding: ProtocolBindingId;
  occurredAt: number;
  tenantRef: PartyRef;
  source: AuditEventSource;
  correlationId?: string;
  causationId?: string;
  trace?: { traceId?: string; spanId?: string };
  session?: { ref: PartyRef; handshakeNonceCommitment?: Digest };
  actor?: PartyRef;
  responsibleParty?: PartyRef;
  resource?: PartyRef;
  action: { category: string; name?: string; detailRef?: EvidenceRef };
  outcome: AuditOutcome;
  reason?: { code: string; detailRef?: EvidenceRef };
  authorization?: AuthorizationEvidence;
  proof?: EvidenceRef;
  evidence: EvidenceRef[];
  details: AuditEventDetails;
  privacy: AuditPrivacy;
}

/** What a producer hands `AuditTrail.record()`: the trail fills in the envelope (schema, version, binding, tenant, source, privacy). */
export type AuditEventInput = Omit<
  AuditProducerEvent,
  'schema' | 'eventVersion' | 'binding' | 'tenantRef' | 'source' | 'privacy' | 'eventId' | 'occurredAt' | 'evidence'
> & {
  /** A stable id lets a retry rebuild the identical event; default `audit_<uuid>`. */
  eventId?: string;
  /** Milliseconds since the epoch; default the trail's clock. */
  occurredAt?: number;
  evidence?: EvidenceRef[];
  privacy?: Partial<AuditPrivacy>;
};

/** A recorded event with its canonical text and domain-separated digest, as the sink receives it. */
export interface AuditTrailEntry {
  event: AuditProducerEvent;
  /** RFC 8785 text of `event`. */
  canonical: string;
  /** `sha256:` over `org.kya-os.audit.event.v1 NUL canonical`. */
  eventDigest: Digest;
}
