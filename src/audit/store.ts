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
 * Where the API keeps recorded events and evidence. An `AuditEventStore` is
 * the `AuditSink` the API's own trail writes to, the sink remote producers'
 * events (`POST /v1/audit-log/events`) land in, the evidence vault, and the
 * reader behind `GET /v1/audit-log`. Append-only: there is no update or
 * delete method, and nothing in this package ever issues one. Story A-2's
 * recorder replaces the sink half (sequence, epoch, receipt) behind the same
 * `AuditSink` seam.
 */

import type { AuditProducerEvent, AuditSink, AuditTrailEntry, Digest, EvidenceStore, PartyRef } from '../core/index.js';
import { HelixError, auditEventFamily } from '../core/index.js';

export interface StoredAuditEvent {
  id: string;
  recordedAt: Date;
  eventDigest: Digest;
  event: AuditProducerEvent;
}

export interface ListAuditEventFilters {
  eventType?: string | undefined;
  family?: string | undefined;
  since?: Date | undefined;
  correlationId?: string | undefined;
  limit: number;
}

export interface AuditEventStore extends AuditSink, EvidenceStore {
  /** Newest first. */
  list(filters: ListAuditEventFilters): Promise<StoredAuditEvent[]>;
}

/** An event id reused by its source for different content (AUDITABILITY.md: same id, different content is rejected). */
export class AuditEventConflictError extends HelixError {
  constructor(sourceId: string, eventId: string) {
    super('AUDIT_EVENT_INVALID', 'An event with this id and source was already recorded with different content', 409, {
      sourceId,
      eventId,
    });
    this.name = 'AuditEventConflictError';
  }
}

/** The indexable key of a party reference: its kind and its did or commitment value. */
export function partyRefKey(ref: PartyRef | undefined): string | undefined {
  if (ref === undefined) return undefined;
  switch (ref.kind) {
    case 'public_did':
    case 'pairwise_did':
      return `${ref.kind}:${ref.did}`;
    case 'keyed_commitment':
      return `${ref.kind}:${ref.keyId}:${ref.value}`;
    default:
      return `evidence_ref:${ref.ref.objectId}`;
  }
}

/** The columns every store derives from an entry. */
export function entryColumns(entry: AuditTrailEntry): {
  eventId: string;
  eventType: string;
  family: string;
  sourceId: string;
  sourceSequence: bigint | null;
  previousSourceEventDigest: string | null;
  eventDigest: string;
  occurredAt: Date;
  correlationId: string | null;
  actorRef: string | null;
} {
  const { event } = entry;
  return {
    eventId: event.eventId,
    eventType: event.eventType,
    family: auditEventFamily(event.eventType),
    sourceId: event.source.sourceId,
    sourceSequence: event.source.sourceSequence === undefined ? null : BigInt(event.source.sourceSequence),
    previousSourceEventDigest: event.source.previousSourceEventDigest ?? null,
    eventDigest: entry.eventDigest,
    occurredAt: new Date(event.occurredAt),
    correlationId: event.correlationId ?? null,
    actorRef: partyRefKey(event.actor) ?? null,
  };
}
