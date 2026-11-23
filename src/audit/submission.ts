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
 * The producer submission wire format (story A-2). One JSON object carries
 * one frozen event and the evidence it references:
 *
 *   { "ledgerId"?, "expectedLedgerEpochId"?, "producerEvent": {...},
 *     "encryptedEvidence"?: [{ "ref": EvidenceRef, "ciphertextBase64url": "..." }] }
 *
 * and the answer is `{ "entry": SignedAuditEntry }`: the recorder's entry
 * with its signed receipt. Nothing in it lets a producer choose time,
 * sequence, epoch, predecessor or signature.
 *
 * It is deliberately a self-contained member, so any request can carry it:
 * `POST /v1/audit/submissions` takes it as the whole body, and the per-call
 * nonce request can take it as an `audit` member and answer with an `audit`
 * member (`handleAuditSubmission` is the one function both call), so
 * recording costs no extra round trip. L2-A's nonce flow is not changed here.
 */

import { z } from 'zod';
import {
  AuditEvidenceError,
  HelixError,
  evidenceRefSchema,
  parseAuditEvent,
  canonicalize,
  type AuditRecorderSubmission,
  type AuthenticatedAuditSubmissionContext,
  type EvidenceRef,
  type ManagedAuditRecorder,
  type PartyRef,
  type SignedAuditEntry,
} from '../core/index.js';

export const auditSubmissionWireSchema = z
  .object({
    ledgerId: z.string().min(1).max(256).optional(),
    expectedLedgerEpochId: z.string().min(1).max(256).optional(),
    producerEvent: z.unknown(),
    encryptedEvidence: z
      .array(z.object({ ref: z.unknown(), ciphertextBase64url: z.string().min(1).regex(/^[A-Za-z0-9_-]+$/) }).strict())
      .max(256)
      .optional(),
  })
  .strict();

export type AuditSubmissionWire = z.infer<typeof auditSubmissionWireSchema>;

export interface AuditSubmissionResultWire {
  entry: SignedAuditEntry;
}

/** The authority a party reference stands for: its DID, or its canonical text for a commitment. */
export function partyAuthority(ref: PartyRef): string {
  return ref.kind === 'public_did' || ref.kind === 'pairwise_did' ? ref.did : canonicalize(ref);
}

/** Parses the wire object into a recorder submission; refuses (400) anything else. */
export function parseAuditSubmissionWire(value: unknown): AuditRecorderSubmission {
  const parsed = auditSubmissionWireSchema.safeParse(value);
  if (!parsed.success) {
    const issue = parsed.error.issues[0]!;
    throw new HelixError('VALIDATION_ERROR', `Audit submission is invalid at ${issue.path.join('.') || '$'}: ${issue.message}`, 400);
  }
  const producerEvent = parseAuditEvent(parsed.data.producerEvent);
  const encryptedEvidence = (parsed.data.encryptedEvidence ?? []).map((item) => {
    const ref = evidenceRefSchema.safeParse(item.ref);
    if (!ref.success) throw new AuditEvidenceError('encryptedEvidence[].ref is not an EvidenceRef');
    return { ref: ref.data as EvidenceRef, ciphertext: new Uint8Array(Buffer.from(item.ciphertextBase64url, 'base64url')) };
  });
  return {
    ...(parsed.data.ledgerId !== undefined ? { ledgerId: parsed.data.ledgerId } : {}),
    ...(parsed.data.expectedLedgerEpochId !== undefined ? { expectedLedgerEpochId: parsed.data.expectedLedgerEpochId } : {}),
    producerEvent,
    encryptedEvidence,
  };
}

/**
 * The submission context of an operator-authenticated caller (the admin
 * key): the caller is trusted for the producer and tenant the event names,
 * which are bound exactly. An account-scoped deployment narrows this to the
 * producers and tenants the account owns.
 */
export function operatorSubmissionContext(submission: AuditRecorderSubmission): AuthenticatedAuditSubmissionContext {
  const { producer } = submission.producerEvent.source;
  const tenant = submission.producerEvent.tenantRef;
  return { producerAuthority: partyAuthority(producer), tenantAuthority: partyAuthority(tenant), producerRef: producer, tenantRef: tenant };
}

/** Records one wire submission: what `POST /v1/audit/submissions` and a piggybacked `audit` member both call. */
export async function handleAuditSubmission(
  recorder: ManagedAuditRecorder,
  wire: unknown,
  context: (submission: AuditRecorderSubmission) => AuthenticatedAuditSubmissionContext = operatorSubmissionContext,
): Promise<AuditSubmissionResultWire> {
  const submission = parseAuditSubmissionWire(wire);
  return { entry: await recorder.submit(submission, context(submission)) };
}
