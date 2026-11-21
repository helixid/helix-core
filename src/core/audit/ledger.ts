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
 * The recorder's wire objects (story A-2, AAP-2 Chained): the entry core the
 * authoritative recorder builds around a frozen producer event, the receipt
 * it signs, and the digests that chain them. Shapes are the vendored
 * `audit-entry.schema.json` and `audit-receipt.schema.json`; the digest
 * domains and the receipt construction follow the reference implementation
 * of AUDITABILITY.md (`integrity.ts` upstream at a4d7f61).
 */

import { z } from 'zod';
import { canonicalize } from '../crypto/jcs.js';
import { HelixError } from '../errors/HelixError.js';
import { auditDigest, auditEventDigest } from './digest.js';
import { DIGEST_PATTERN, auditProducerEventSchema, signerRefSchema } from './schema.js';
import {
  AUDIT_DIGEST_DOMAINS,
  AUDIT_INTEGRITY_SUITE,
  type AuditProducerEvent,
  type DecimalString,
  type Digest,
  type EvidenceRef,
  type PartyRef,
  type SignerRef,
} from './types.js';

export const AUDIT_ENTRY_SCHEMA = 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0';
export const AUDIT_RECEIPT_SCHEMA = 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0';

/** A ledger is one tenant's history; an epoch is one recorder authority's unbroken run of it. */
export interface AuditLedgerRef {
  ledgerId: string;
  ledgerEpochId: string;
}

/** The committed head of one epoch: its last sequence and that entry's digest. */
export interface AuditHead extends AuditLedgerRef {
  sequence: DecimalString;
  entryDigest: Digest;
}

/** What the recorder adds around a frozen producer event. Producers never choose any of it. */
export interface AuditEntryCore {
  schema: typeof AUDIT_ENTRY_SCHEMA;
  ledgerId: string;
  ledgerEpochId: string;
  sequence: DecimalString;
  previousEntryDigest: Digest | null;
  /** Service time, milliseconds since the epoch, assigned by the recorder. */
  recordedAt: number;
  recorder: SignerRef;
  eventDigest: Digest;
  event: AuditProducerEvent;
  evidenceManifestDigest: Digest;
  integritySuite: typeof AUDIT_INTEGRITY_SUITE;
}

/** The receipt core: what the recorder's signature covers (RFC 8785 bytes of this object). */
export interface AuditRecorderReceiptCore {
  schema: typeof AUDIT_RECEIPT_SCHEMA;
  ledgerId: string;
  ledgerEpochId: string;
  sequence: DecimalString;
  eventId: string;
  entryDigest: Digest;
  previousEntryDigest: Digest | null;
  recordedAt: number;
  recorder: SignerRef;
  integritySuite: typeof AUDIT_INTEGRITY_SUITE;
}

/** One journal entry: the core, its digests, and the recorder's signed receipt. */
export interface SignedAuditEntry {
  core: AuditEntryCore;
  eventDigest: Digest;
  entryDigest: Digest;
  recorderReceipt: { core: AuditRecorderReceiptCore; jws: string };
}

/** A producer's request to the recorder: a frozen event and the encrypted evidence it references. */
export interface AuditRecorderSubmission {
  /** The ledger the producer expects; the managed recorder routes by the event's tenant when absent. */
  ledgerId?: string;
  /** Pins a new append to one epoch; never set on buffered redelivery (AUDITABILITY.md). */
  expectedLedgerEpochId?: string;
  producerEvent: AuditProducerEvent;
  encryptedEvidence: ReadonlyArray<{ ref: EvidenceRef; ciphertext: Uint8Array }>;
}

// ── strict schemas ────────────────────────────────────────────────────────────

const digest = z.string().regex(DIGEST_PATTERN, 'must be sha256:<64 lowercase hex>');
const decimal = z.string().max(20).regex(/^(0|[1-9][0-9]*)$/, 'must be a decimal integer');
const ledgerId = z.string().min(1).max(256);
const time = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

export const auditEntryCoreSchema = z
  .object({
    schema: z.literal(AUDIT_ENTRY_SCHEMA),
    ledgerId,
    ledgerEpochId: ledgerId,
    sequence: decimal,
    previousEntryDigest: digest.nullable(),
    recordedAt: time,
    recorder: signerRefSchema,
    eventDigest: digest,
    event: auditProducerEventSchema,
    evidenceManifestDigest: digest,
    integritySuite: z.literal(AUDIT_INTEGRITY_SUITE),
  })
  .strict();

export const auditReceiptCoreSchema = z
  .object({
    schema: z.literal(AUDIT_RECEIPT_SCHEMA),
    ledgerId,
    ledgerEpochId: ledgerId,
    sequence: decimal,
    eventId: z.string().min(1).max(256),
    entryDigest: digest,
    previousEntryDigest: digest.nullable(),
    recordedAt: time,
    recorder: signerRefSchema,
    integritySuite: z.literal(AUDIT_INTEGRITY_SUITE),
  })
  .strict();

export const signedAuditEntrySchema = z
  .object({
    core: auditEntryCoreSchema,
    eventDigest: digest,
    entryDigest: digest,
    recorderReceipt: z.object({ core: auditReceiptCoreSchema, jws: z.string().min(1).max(16_384) }).strict(),
  })
  .strict();

/** Thrown for a value that is not a signed entry (an entry read back from storage, an entry a recorder returned). */
export class AuditEntryInvalidError extends HelixError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('AUDIT_JOURNAL_FAILURE', message, 500, details);
    this.name = 'AuditEntryInvalidError';
  }
}

function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0]!;
  return `${issue.path.map(String).join('.') || '$'}: ${issue.message}`;
}

/** The entry core, strictly; unknown members anywhere fail closed. */
export function parseAuditEntryCore(value: unknown): AuditEntryCore {
  const result = auditEntryCoreSchema.safeParse(value);
  if (!result.success) throw new AuditEntryInvalidError(`Audit entry core is invalid at ${firstIssue(result.error)}`);
  return result.data as AuditEntryCore;
}

/** A signed entry, strictly. */
export function parseSignedAuditEntry(value: unknown): SignedAuditEntry {
  const result = signedAuditEntrySchema.safeParse(value);
  if (!result.success) throw new AuditEntryInvalidError(`Signed audit entry is invalid at ${firstIssue(result.error)}`);
  return result.data as SignedAuditEntry;
}

/** The issue that makes a value not a signed entry, or undefined when it is one. */
export function signedAuditEntryIssue(value: unknown): string | undefined {
  const result = signedAuditEntrySchema.safeParse(value);
  return result.success ? undefined : firstIssue(result.error);
}

// ── integrity ─────────────────────────────────────────────────────────────────

function partyEvidence(party: PartyRef | undefined): EvidenceRef[] {
  return party?.kind === 'evidence_ref' ? [party.ref] : [];
}

/** Every evidence reference a frozen event carries, in the order the reference implementation collects them. */
export function collectAuditEvidenceRefs(event: AuditProducerEvent): EvidenceRef[] {
  const details = event.details;
  const detailsEvidence =
    details.family === 'delegation'
      ? (details.statusEvidence ?? [])
      : details.family === 'ledger' && details.targetEvidenceRef !== undefined
        ? [details.targetEvidenceRef]
        : [];
  return [
    ...partyEvidence(event.tenantRef),
    ...partyEvidence(event.source.producer),
    ...partyEvidence(event.session?.ref),
    ...partyEvidence(event.actor),
    ...partyEvidence(event.responsibleParty),
    ...partyEvidence(event.resource),
    ...(event.proof === undefined ? [] : [event.proof]),
    ...event.evidence,
    ...(event.action.detailRef === undefined ? [] : [event.action.detailRef]),
    ...(event.reason?.detailRef === undefined ? [] : [event.reason.detailRef]),
    ...(event.authorization?.statusEvidence ?? []),
    ...detailsEvidence,
  ];
}

/** Domain `org.kya-os.audit.evidence-manifest.v1` over `{ refs }`. */
export function digestAuditEvidenceManifest(event: AuditProducerEvent): Digest {
  return auditDigest(AUDIT_DIGEST_DOMAINS.evidenceManifest, { refs: collectAuditEvidenceRefs(event) });
}

/** Domain `org.kya-os.audit.entry.v1` over the entry core. */
export function digestAuditEntry(core: AuditEntryCore): Digest {
  return auditDigest(AUDIT_DIGEST_DOMAINS.entry, core);
}

/**
 * The logical-ledger idempotency key: domain `org.kya-os.audit.idempotency.v1`
 * over the ledger, the authenticated producer authority, the source and the
 * event id. It spans epochs, so a retry never becomes a new event after a
 * rollover.
 */
export function auditIdempotencyKey(input: {
  ledgerId: string;
  producerAuthority: string;
  sourceId: string;
  eventId: string;
}): Digest {
  return auditDigest(AUDIT_DIGEST_DOMAINS.idempotency, {
    ledgerId: input.ledgerId,
    producerAuthority: input.producerAuthority,
    sourceId: input.sourceId,
    eventId: input.eventId,
  });
}

/** The receipt core the recorder signs for an entry. */
export function buildAuditReceiptCore(core: AuditEntryCore, entryDigest: Digest): AuditRecorderReceiptCore {
  return {
    schema: AUDIT_RECEIPT_SCHEMA,
    ledgerId: core.ledgerId,
    ledgerEpochId: core.ledgerEpochId,
    sequence: core.sequence,
    eventId: core.event.eventId,
    entryDigest,
    previousEntryDigest: core.previousEntryDigest,
    recordedAt: core.recordedAt,
    recorder: core.recorder,
    integritySuite: AUDIT_INTEGRITY_SUITE,
  };
}

/** The RFC 8785 bytes of a receipt core: the JWS payload. */
export function auditReceiptPayload(receipt: AuditRecorderReceiptCore): Uint8Array {
  return new Uint8Array(Buffer.from(canonicalize(receipt), 'utf8'));
}

/** The event digest the entry should carry, recomputed. */
export function recomputeAuditEventDigest(entry: SignedAuditEntry): Digest {
  return auditEventDigest(entry.core.event);
}

/** Same JSON, compared in RFC 8785 form. */
export function sameCanonical(left: unknown, right: unknown): boolean {
  return canonicalize(left) === canonicalize(right);
}

/** `<did>#<fragment>`, `EdDSA`: the signer reference of an L1-C `Signer`. */
export function signerRefOf(signer: { did: string; kid: string }): SignerRef {
  const fragment = signer.kid.replace(/^#/, '');
  return { did: signer.did, kid: `${signer.did}#${fragment}`, alg: 'EdDSA' };
}
