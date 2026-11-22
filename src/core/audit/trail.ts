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
 * The producer trail (AUDITABILITY.md, Delivery semantics and Event and
 * privacy model). One `AuditTrail` is one source: it fills in the envelope,
 * bounds every caller-presented reference, applies the tool-name policy,
 * validates the event before it claims a source sequence, chains consecutive
 * events by `previousSourceEventDigest`, digests the canonical event and
 * hands the entry to its sink.
 */

import { randomUUID } from 'node:crypto';
import { canonicalize } from '../crypto/jcs.js';
import { auditEventDigest } from './digest.js';
import { AuditEvidenceError, type EvidenceEncryptor, type EvidenceStore, evidenceAad } from './evidence.js';
import { sanitizeReference } from './references.js';
import { parseAuditEvent } from './schema.js';
import type { SignedAuditEntry } from './ledger.js';
import type { AuditSink } from './sink.js';
import {
  AUDIT_BINDING_HELIX,
  AUDIT_EVENT_SCHEMA,
  AUDIT_EVENT_VERSION,
  type AuditEventInput,
  type AuditPrivacy,
  type AuditProducerEvent,
  type AuditTrailEntry,
  type AuthorizationEvidence,
  type Digest,
  type EvidenceRef,
  type PartyRef,
  type ProtocolBindingId,
} from './types.js';

export interface AuditTrailEvidenceOptions {
  encryptor: EvidenceEncryptor;
  store: EvidenceStore;
}

export interface AuditTrailOptions {
  sink: AuditSink;
  /** Names this producer source; sequences and predecessor digests are per source. */
  sourceId: string;
  producer: PartyRef;
  tenantRef: PartyRef;
  binding?: ProtocolBindingId;
  privacy?: AuditPrivacy;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: () => number;
  /** Default `audit_<uuid>`. */
  newEventId?: () => string;
  /**
   * Record tool names (`action.name` on tool events). Default false: a tool
   * name is a caller-presented reference and often sensitive in itself, so
   * recording it is an explicit policy decision.
   */
  includeToolNames?: boolean;
  /** Enables `evidence()`; without it an exact payload cannot be kept and no event carries one. */
  evidence?: AuditTrailEvidenceOptions;
}

/** A recorded entry; `receipt` is the recorder's signed entry when the sink is recorder-backed (A-2). */
export type RecordedAuditEntry = AuditTrailEntry & { receipt?: SignedAuditEntry };

export const DEFAULT_AUDIT_PRIVACY: AuditPrivacy = { classification: 'internal', retentionClass: 'audit-indefinite' };

const REFERENCE_FIELDS = ['scopeId', 'delegationRef', 'grantRef', 'policyId', 'policyVersion'] as const;

function boundedAuthorization(authorization: AuthorizationEvidence): AuthorizationEvidence {
  const bounded: AuthorizationEvidence = { ...authorization };
  for (const field of REFERENCE_FIELDS) {
    const value = authorization[field];
    if (value !== undefined) bounded[field] = sanitizeReference(value);
  }
  if (authorization.verificationCode !== undefined) bounded.verificationCode = sanitizeReference(authorization.verificationCode, 128);
  return bounded;
}

function boundedDetails(details: AuditEventInput['details']): AuditEventInput['details'] {
  switch (details.family) {
    case 'delegation':
      return {
        ...details,
        delegationRef: sanitizeReference(details.delegationRef),
        ...(details.parentRef !== undefined ? { parentRef: sanitizeReference(details.parentRef) } : {}),
      };
    case 'authorization':
      return details.grantRef === undefined ? details : { ...details, grantRef: sanitizeReference(details.grantRef) };
    case 'consent':
      return details.consentRef === undefined ? details : { ...details, consentRef: sanitizeReference(details.consentRef) };
    case 'tool':
      return details.idempotencyRef === undefined ? details : { ...details, idempotencyRef: sanitizeReference(details.idempotencyRef) };
    case 'session':
      return details.reasonCode === undefined ? details : { ...details, reasonCode: sanitizeReference(details.reasonCode, 128) };
    case 'proof':
      return details.verificationCode === undefined
        ? details
        : { ...details, verificationCode: sanitizeReference(details.verificationCode, 128) };
    default:
      return details;
  }
}

export class AuditTrail {
  readonly sourceId: string;
  readonly includeToolNames: boolean;
  private readonly sink: AuditSink;
  private readonly producer: PartyRef;
  private readonly tenantRef: PartyRef;
  private readonly binding: ProtocolBindingId;
  private readonly privacy: AuditPrivacy;
  private readonly clock: () => number;
  private readonly newEventId: () => string;
  private readonly evidenceOptions: AuditTrailEvidenceOptions | undefined;
  private nextSequence = 1;
  private lastDigest: Digest | undefined;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(options: AuditTrailOptions) {
    if (options.sourceId.length === 0 || options.sourceId.length > 256) throw new TypeError('sourceId must be 1 to 256 characters');
    this.sink = options.sink;
    this.sourceId = options.sourceId;
    this.producer = options.producer;
    this.tenantRef = options.tenantRef;
    this.binding = options.binding ?? AUDIT_BINDING_HELIX;
    this.privacy = options.privacy ?? DEFAULT_AUDIT_PRIVACY;
    this.clock = options.clock ?? Date.now;
    this.newEventId = options.newEventId ?? ((): string => `audit_${randomUUID()}`);
    this.includeToolNames = options.includeToolNames ?? false;
    this.evidenceOptions = options.evidence;
  }

  /** The sequence the next recorded event claims. */
  get sequence(): number {
    return this.nextSequence;
  }

  /** The digest of the last event appended, which the next event names as its predecessor. */
  get previousSourceEventDigest(): Digest | undefined {
    return this.lastDigest;
  }

  /**
   * The event as it will be recorded, before any sequence is claimed: envelope
   * filled, references bounded, tool-name policy applied, strictly validated.
   * Throws `AuditEventInvalidError` for an input that is not a producer event.
   */
  build(input: AuditEventInput): AuditProducerEvent {
    const { eventId, occurredAt, privacy, evidence, authorization, details, action, correlationId, causationId, ...rest } = input;
    const boundedAction = { ...action };
    if (boundedAction.name !== undefined) {
      if (details.family === 'tool' && !this.includeToolNames) delete boundedAction.name;
      else boundedAction.name = sanitizeReference(boundedAction.name);
    }
    const candidate = {
      schema: AUDIT_EVENT_SCHEMA,
      eventId: eventId ?? this.newEventId(),
      eventVersion: AUDIT_EVENT_VERSION,
      binding: this.binding,
      occurredAt: occurredAt ?? this.clock(),
      tenantRef: this.tenantRef,
      source: { producer: this.producer, sourceId: this.sourceId },
      ...rest,
      ...(correlationId !== undefined ? { correlationId: sanitizeReference(correlationId) } : {}),
      ...(causationId !== undefined ? { causationId: sanitizeReference(causationId) } : {}),
      action: boundedAction,
      ...(authorization !== undefined ? { authorization: boundedAuthorization(authorization) } : {}),
      ...(rest.reason !== undefined ? { reason: { ...rest.reason, code: sanitizeReference(rest.reason.code, 128) } } : {}),
      evidence: evidence ?? [],
      details: boundedDetails(details),
      privacy: { ...this.privacy, ...(privacy ?? {}) },
    };
    return parseAuditEvent(candidate);
  }

  /**
   * Records one event: builds and validates it, then (serialized per trail)
   * claims the next source sequence, links the previous event's digest,
   * canonicalizes, digests and appends to the sink. Rejected input never
   * consumes a sequence; a sink failure consumes one and leaves the
   * predecessor link on the last appended event.
   */
  async record(input: AuditEventInput): Promise<RecordedAuditEntry> {
    const built = this.build(input);
    const run = this.queue.then(async () => {
      const sequence = this.nextSequence;
      this.nextSequence += 1;
      const event: AuditProducerEvent = {
        ...built,
        source: {
          ...built.source,
          sourceSequence: String(sequence),
          ...(this.lastDigest !== undefined ? { previousSourceEventDigest: this.lastDigest } : {}),
        },
      };
      const entry: AuditTrailEntry = { event, canonical: canonicalize(event), eventDigest: auditEventDigest(event) };
      const receipt = await this.sink.append(entry);
      this.lastDigest = entry.eventDigest;
      return receipt === undefined ? entry : { ...entry, receipt };
    });
    this.queue = run.catch(() => undefined);
    return run;
  }

  /** Resolves once every `record()` issued so far has settled (delivered or failed). */
  async settled(): Promise<void> {
    await this.queue;
  }

  /**
   * Keeps an exact payload as encrypted evidence bound to this trail's tenant
   * and `purpose`, and returns the reference an event may carry. Throws
   * `AuditEvidenceError` when the trail has no evidence vault.
   */
  async evidence(
    plaintext: Uint8Array | string,
    mediaType: string,
    purpose: string,
    options: { commitPlaintext?: boolean } = {},
  ): Promise<EvidenceRef> {
    if (this.evidenceOptions === undefined) {
      throw new AuditEvidenceError('This audit trail has no evidence vault; configure one to keep exact payloads');
    }
    const encrypted = this.evidenceOptions.encryptor.encrypt({
      plaintext,
      mediaType,
      aad: this.evidenceAad(purpose),
      ...(options.commitPlaintext !== undefined ? { commitPlaintext: options.commitPlaintext } : {}),
    });
    return this.evidenceOptions.store.putIfAbsent(encrypted);
  }

  /** The authenticated data this trail binds evidence with: its tenant and the purpose. */
  evidenceAad(purpose: string): Uint8Array {
    return evidenceAad(this.tenantRef, purpose);
  }
}

/** `{ kind: 'public_did', did }`. */
export const publicDid = (did: string): PartyRef => ({ kind: 'public_did', did });
/** `{ kind: 'pairwise_did', did }`. */
export const pairwiseDid = (did: string): PartyRef => ({ kind: 'pairwise_did', did });
/** `{ kind: 'keyed_commitment', value, keyId }`; see `keyedCommitmentValue` for the value. */
export const keyedCommitment = (value: Digest, keyId: string): PartyRef => ({ kind: 'keyed_commitment', value, keyId });
