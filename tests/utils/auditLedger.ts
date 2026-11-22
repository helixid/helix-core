// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

import {
  AuditTrail,
  EnvSigner,
  MemoryAuditSink,
  derivePublicKey,
  jwsAuditSigner,
  publicKeyToMultibase,
  type AuditProducerEvent,
  type AuditRecorderSubmission,
  type AuditSigner,
  type AuthenticatedAuditSubmissionContext,
  type PartyRef,
} from '../../src/core/index.js';

/** TEST-ONLY recorder keys (never used outside tests). */
export const TEST_RECORDER_KEYS = {
  primary: '1'.repeat(64),
  rotated: '2'.repeat(64),
  other: '3'.repeat(64),
} as const;

/** A recorder signer over a test key, as `did:key` with the multibase as fragment. */
export function testRecorderSigner(secretHex: string = TEST_RECORDER_KEYS.primary): AuditSigner {
  const multibase = publicKeyToMultibase(derivePublicKey(secretHex));
  return jwsAuditSigner(new EnvSigner({ did: `did:key:${multibase}`, kid: multibase, envVar: 'K', env: { K: secretHex } }));
}

export const PRODUCER: PartyRef = { kind: 'pairwise_did', did: 'did:web:orders.example.com' };
export const TENANT: PartyRef = { kind: 'pairwise_did', did: 'did:web:orders.example.com' };

/** A frozen producer event with a stable id (the trail fills the envelope; no source sequence). */
export function producerEvent(
  eventId: string,
  options: { sourceId?: string; producer?: PartyRef; tenantRef?: PartyRef; outcome?: AuditProducerEvent['outcome']; occurredAt?: number } = {},
): AuditProducerEvent {
  const trail = new AuditTrail({
    sink: new MemoryAuditSink(),
    sourceId: options.sourceId ?? 'mcp-middleware:orders',
    producer: options.producer ?? PRODUCER,
    tenantRef: options.tenantRef ?? TENANT,
  });
  return trail.build({
    eventId,
    occurredAt: options.occurredAt ?? 1_780_000_000_000,
    eventType: 'tool.call.completed',
    correlationId: `call-${eventId}`,
    action: { category: 'tool.call' },
    outcome: options.outcome ?? 'succeeded',
    details: { family: 'tool', phase: 'completed', attempt: '1' },
  });
}

export function submission(event: AuditProducerEvent, extra: Partial<AuditRecorderSubmission> = {}): AuditRecorderSubmission {
  return { producerEvent: event, encryptedEvidence: [], ...extra };
}

/** The context an operator-authenticated transport gives a producer submission. */
export function contextFor(event: AuditProducerEvent): AuthenticatedAuditSubmissionContext {
  const did = (ref: PartyRef): string => (ref.kind === 'public_did' || ref.kind === 'pairwise_did' ? ref.did : JSON.stringify(ref));
  return {
    producerAuthority: did(event.source.producer),
    tenantAuthority: did(event.tenantRef),
    producerRef: event.source.producer,
    tenantRef: event.tenantRef,
  };
}
