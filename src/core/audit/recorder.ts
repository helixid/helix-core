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
 * The authoritative recorder (story A-2; AUDITABILITY.md, Recorder authority
 * and topology). Exactly one logical authority assigns epoch, sequence,
 * predecessor digest and service time for a `(ledgerId, ledgerEpochId)` and
 * signs a receipt over each entry with a recorder key that is not an issuer
 * key. Producers send only a frozen event and encrypted evidence; nothing
 * they send can choose any of those fields.
 *
 * Ported from the reference `AuditRecorderService` (upstream
 * `src/audit/recorder-service.ts` at a4d7f61) onto Helix's L1-C `Signer`
 * and L1-B canonical JSON, with one addition: appends from this process are
 * serialized per recorder, so a burst of concurrent submissions costs no
 * compare-and-append retries here, while several replicas still serialize
 * through the journal's compare-and-append.
 */

import { signJws } from '../crypto/jws.js';
import type { Signer } from '../crypto/signer.js';
import { auditEventDigest } from './digest.js';
import type { EncryptedEvidence } from './evidence.js';
import { sameSignerRef, type AuditEpochTransitionReason, type AuditJournalProvider } from './journal.js';
import {
  AUDIT_ENTRY_SCHEMA,
  auditIdempotencyKey,
  auditReceiptPayload,
  buildAuditReceiptCore,
  collectAuditEvidenceRefs,
  digestAuditEntry,
  digestAuditEvidenceManifest,
  parseAuditEntryCore,
  parseSignedAuditEntry,
  sameCanonical,
  signerRefOf,
  type AuditHead,
  type AuditLedgerRef,
  type AuditRecorderSubmission,
  type SignedAuditEntry,
} from './ledger.js';
import { AUDIT_ERROR_CODES, AuditProtocolError, isAuditError } from './ledger-errors.js';
import { parseAuditEvent } from './schema.js';
import {
  AUDIT_EVENT_SCHEMA,
  AUDIT_EVENT_VERSION,
  AUDIT_INTEGRITY_SUITE,
  type AuditProducerEvent,
  type Digest,
  type PartyRef,
  type ProtocolBindingId,
  type SignerRef,
} from './types.js';

export interface AuditClock {
  now(): number;
}

/** Signs a receipt payload as a compact JWS whose header `kid` is `ref.kid`. */
export interface AuditSigner {
  readonly ref: SignerRef;
  sign(payload: Uint8Array): Promise<string>;
}

/** An L1-C `Signer` (an `EnvSigner`, later a `KeyStore` handle) as the recorder's receipt signer. */
export function jwsAuditSigner(signer: Signer): AuditSigner {
  return {
    ref: signerRefOf(signer),
    sign: (payload) => signJws(payload, signer),
  };
}

/** Who submitted, as the transport authenticated them; never taken from the event. */
export interface AuthenticatedAuditSubmissionContext {
  producerAuthority: string;
  tenantAuthority: string;
  /** Exact authenticated producer binding, for non-DID producer references. */
  producerRef?: PartyRef;
  /** Exact authenticated tenant binding, for opaque or commitment tenant references. */
  tenantRef?: PartyRef;
}

export interface AuditSubmissionAuthorizer {
  authorize(input: { submission: AuditRecorderSubmission; context: AuthenticatedAuditSubmissionContext }): Promise<boolean> | boolean;
}

/**
 * The authoritative epoch-transition port: true means the predecessor's
 * terminal digest was verified against its committed head and the
 * predecessor was sealed against new appends. Idempotent for identical input.
 */
export interface AuditEpochTransitionGuard {
  verifyAndSeal(input: {
    ledgerId: string;
    previousEpochId: string;
    nextEpochId: string;
    previousTerminalCheckpointDigest: Digest;
    reason: AuditEpochTransitionReason;
  }): Promise<boolean>;
}

/** Write-ahead evidence storage the recorder persists submitted ciphertext into. */
export interface AuditRecorderEvidenceStore {
  has(objectId: string): Promise<boolean>;
  putIfAbsent(object: EncryptedEvidence): Promise<unknown>;
  /** Best-effort compensation for ciphertext whose append failed; absent means the orphan is kept. */
  discardUncommitted?(objectId: string): Promise<void>;
}

export interface AuditRecorderServiceConfig {
  ledgerId: string;
  ledgerEpochId: string;
  tenantRef: PartyRef;
  binding: ProtocolBindingId;
  /** The recorder's own source id (its genesis and administration events). */
  sourceId: string;
  journal: AuditJournalProvider;
  signer: AuditSigner;
  clock: AuditClock;
  evidence?: AuditRecorderEvidenceStore;
  authorizer?: AuditSubmissionAuthorizer;
  previousEpochId?: string;
  previousTerminalCheckpointDigest?: Digest;
  /** Recorded as the genesis `reason.code` of a successor epoch. */
  transitionReason?: AuditEpochTransitionReason;
  epochTransitionGuard?: AuditEpochTransitionGuard;
  maxAppendConflicts?: number;
  /** Called with every head this recorder commits (the restore witness listens here). */
  onCommitted?: (head: AuditHead) => void | Promise<void>;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== 'object' || value === null || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function sameHead(left: AuditHead | null, right: AuditHead | null): boolean {
  if (left === null || right === null) return left === right;
  return left.entryDigest === right.entryDigest && left.sequence === right.sequence;
}

/** The later of two heads; at an equal sequence the first one is kept. */
function higherHead(current: AuditHead | null, candidate: AuditHead | null): AuditHead | null {
  if (candidate === null) return current;
  if (current === null) return candidate;
  return BigInt(candidate.sequence) > BigInt(current.sequence) ? candidate : current;
}

function authorityMatchesParty(authority: string, boundRef: PartyRef | undefined, claimedRef: PartyRef): boolean {
  if (boundRef !== undefined) return sameCanonical(boundRef, claimedRef);
  return (claimedRef.kind === 'public_did' || claimedRef.kind === 'pairwise_did') && claimedRef.did === authority;
}

export class AuditRecorderService {
  readonly ledger: AuditLedgerRef;
  private readonly maxAppendConflicts: number;
  private initialization: Promise<SignedAuditEntry> | undefined;
  private genesis: SignedAuditEntry | undefined;
  /** Highest head this recorder has itself appended in its epoch. */
  private committedHead: AuditHead | null = null;
  /** Highest head the journal has reported in a compare-and-append result. */
  private reportedHead: AuditHead | null = null;
  /** Write-ahead evidence objects held by submissions in flight, by object id. */
  private readonly heldEvidence = new Map<string, { holders: number; shared: boolean }>();
  /** Serializes this process's appends to the epoch. */
  private appendTail: Promise<unknown> = Promise.resolve();

  constructor(private readonly config: AuditRecorderServiceConfig) {
    if ((config.previousEpochId === undefined) !== (config.previousTerminalCheckpointDigest === undefined)) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'Previous epoch id and terminal checkpoint digest must be supplied together',
      );
    }
    if (config.previousEpochId !== undefined && config.epochTransitionGuard === undefined) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.INVALID_CONFIGURATION, 'Epoch transitions require an authoritative verify-and-seal guard');
    }
    this.maxAppendConflicts = config.maxAppendConflicts ?? 256;
    this.ledger = Object.freeze({ ledgerId: config.ledgerId, ledgerEpochId: config.ledgerEpochId });
  }

  get recorder(): SignerRef {
    return this.config.signer.ref;
  }

  get tenantRef(): PartyRef {
    return this.config.tenantRef;
  }

  /** The highest head this recorder committed, or null before its first append. */
  get head(): AuditHead | null {
    return this.committedHead;
  }

  /**
   * Opens the epoch: verifies an existing genesis against this recorder's
   * configuration, or (sealing the predecessor first, for a successor epoch)
   * appends the genesis. Called lazily by the first submission.
   */
  async open(): Promise<SignedAuditEntry> {
    return this.ensureInitialized();
  }

  async submitAuthenticated(submission: AuditRecorderSubmission, context: AuthenticatedAuditSubmissionContext): Promise<SignedAuditEntry> {
    this.validateSubmissionEnvelope(submission, context);
    const producerEvent = parseAuditEvent(submission.producerEvent);
    this.validateEventAuthority(producerEvent, context);
    if (this.config.authorizer !== undefined && (await this.config.authorizer.authorize({ submission, context })) !== true) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION, 'Audit producer is not authorized for this ledger');
    }

    const identity = this.identifyEvent(producerEvent, context);
    const duplicate = await this.config.journal.getByIdempotencyKey(this.config.ledgerId, identity.idempotencyKey);
    if (duplicate !== null) return this.resolveDuplicate(duplicate, identity.eventDigest);

    // Only a new append must target the active epoch. Logical-ledger idempotency
    // is resolved first, so a redelivered submission pinned to a retained
    // earlier epoch returns its original entry instead of wedging.
    if (submission.expectedLedgerEpochId !== undefined && submission.expectedLedgerEpochId !== this.config.ledgerEpochId) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.EPOCH_MISMATCH, 'Wrong audit ledger epoch', {
        expectedLedgerEpochId: submission.expectedLedgerEpochId,
        ledgerEpochId: this.config.ledgerEpochId,
      });
    }

    await this.ensureInitialized();
    const held = this.holdEvidence(submission.encryptedEvidence);
    try {
      const stored = await this.persistSubmittedEvidence(submission.encryptedEvidence, producerEvent);
      try {
        return await this.serialized(() => this.appendEvent(producerEvent, false, identity));
      } catch (error) {
        await this.discardUncommittedEvidence(stored, identity.idempotencyKey);
        throw error;
      }
    } finally {
      this.releaseEvidence(held);
    }
  }

  /**
   * Appends an event the recorder authors itself (administration events:
   * retention, legal hold). Its producer is the recorder's own DID.
   */
  async recordOwnEvent(event: AuditProducerEvent): Promise<SignedAuditEntry> {
    return this.submitAuthenticated(
      { ledgerId: this.config.ledgerId, producerEvent: event, encryptedEvidence: [] },
      {
        producerAuthority: this.config.signer.ref.did,
        tenantAuthority: 'audit-recorder',
        producerRef: { kind: 'public_did', did: this.config.signer.ref.did },
        tenantRef: this.config.tenantRef,
      },
    );
  }

  /** A frozen event authored by this recorder: its source, its tenant, its binding. */
  ownEvent(input: Omit<AuditProducerEvent, 'schema' | 'eventVersion' | 'binding' | 'tenantRef' | 'source' | 'evidence'> & { evidence?: AuditProducerEvent['evidence'] }): AuditProducerEvent {
    return parseAuditEvent({
      schema: AUDIT_EVENT_SCHEMA,
      eventVersion: AUDIT_EVENT_VERSION,
      binding: this.config.binding,
      tenantRef: this.config.tenantRef,
      source: { producer: { kind: 'public_did', did: this.config.signer.ref.did }, sourceId: this.config.sourceId },
      evidence: [],
      ...input,
    });
  }

  private serialized<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.appendTail.then(operation, operation);
    this.appendTail = run.catch(() => undefined);
    return run;
  }

  private holdEvidence(evidence: AuditRecorderSubmission['encryptedEvidence']): string[] {
    const objectIds = [...new Set(evidence.map((item) => item.ref.objectId))];
    for (const objectId of objectIds) {
      const hold = this.heldEvidence.get(objectId);
      if (hold === undefined) this.heldEvidence.set(objectId, { holders: 1, shared: false });
      else this.heldEvidence.set(objectId, { holders: hold.holders + 1, shared: true });
    }
    return objectIds;
  }

  private releaseEvidence(objectIds: readonly string[]): void {
    for (const objectId of objectIds) {
      const hold = this.heldEvidence.get(objectId)!;
      if (hold.holders === 1) this.heldEvidence.delete(objectId);
      else this.heldEvidence.set(objectId, { ...hold, holders: hold.holders - 1 });
    }
  }

  /**
   * Best-effort compensation for write-ahead evidence whose append failed:
   * only objects this submission newly stored, not shared with a concurrent
   * submission, and only after re-confirming no committed entry claims the
   * event identity. A failure keeps the orphan for retention tooling.
   */
  private async discardUncommittedEvidence(stored: readonly EncryptedEvidence[], idempotencyKey: Digest): Promise<void> {
    const evidence = this.config.evidence;
    if (stored.length === 0 || evidence?.discardUncommitted === undefined) return;
    try {
      if ((await this.config.journal.getByIdempotencyKey(this.config.ledgerId, idempotencyKey)) !== null) return;
      for (const item of stored) {
        if (this.heldEvidence.get(item.ref.objectId)?.shared === true) continue;
        await evidence.discardUncommitted(item.ref.objectId);
      }
    } catch {
      // Retaining an orphan is preferable to disposing racing committed evidence.
    }
  }

  private validateSubmissionEnvelope(submission: AuditRecorderSubmission, context: AuthenticatedAuditSubmissionContext): void {
    if (!context.producerAuthority || !context.tenantAuthority) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION, 'Authenticated producer and tenant authority are required');
    }
    if (submission.ledgerId !== undefined && submission.ledgerId !== this.config.ledgerId) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'Wrong audit ledger', { ledgerId: submission.ledgerId });
    }
  }

  private validateEventAuthority(event: AuditProducerEvent, context: AuthenticatedAuditSubmissionContext): void {
    if (!authorityMatchesParty(context.producerAuthority, context.producerRef, event.source.producer)) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION, 'Event producer does not match the authenticated producer authority');
    }
    if (!sameCanonical(event.tenantRef, this.config.tenantRef) || !authorityMatchesParty(context.tenantAuthority, context.tenantRef, event.tenantRef)) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION, 'Event tenant does not match the authenticated tenant authority');
    }
  }

  /** Persists write-ahead evidence and returns the objects that did not exist before. */
  private async persistSubmittedEvidence(
    evidence: AuditRecorderSubmission['encryptedEvidence'],
    event: AuditProducerEvent,
  ): Promise<EncryptedEvidence[]> {
    if (evidence.length === 0) return [];
    const store = this.config.evidence;
    if (store === undefined) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.EVIDENCE_FAILURE, 'Encrypted evidence was submitted but no evidence store is configured');
    }
    const refs = new Map(collectAuditEvidenceRefs(event).map((ref) => [ref.objectId, ref]));
    const submitted = new Set<string>();
    for (const item of evidence) {
      const referenced = refs.get(item.ref.objectId);
      if (submitted.has(item.ref.objectId) || referenced === undefined || !sameCanonical(referenced, item.ref)) {
        throw new AuditProtocolError(AUDIT_ERROR_CODES.EVIDENCE_FAILURE, 'Submitted evidence does not exactly match a unique frozen event reference', {
          objectId: item.ref.objectId,
        });
      }
      submitted.add(item.ref.objectId);
    }
    try {
      const stored: EncryptedEvidence[] = [];
      for (const item of evidence) {
        const existed = await store.has(item.ref.objectId);
        await store.putIfAbsent({ ref: item.ref, ciphertext: item.ciphertext });
        if (!existed) stored.push({ ref: item.ref, ciphertext: item.ciphertext });
      }
      return stored;
    } catch (error) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.EVIDENCE_FAILURE, 'Required evidence could not be persisted', undefined, { cause: error });
    }
  }

  private async ensureInitialized(): Promise<SignedAuditEntry> {
    if (this.genesis !== undefined) return this.genesis;
    this.genesis = await this.initialize();
    return this.genesis;
  }

  private async initialize(): Promise<SignedAuditEntry> {
    const existingHead = await this.config.journal.getHead(this.ledger);
    if (existingHead !== null) {
      for await (const entry of this.config.journal.readRange({ ...this.ledger, limit: 1 })) {
        const genesis = this.validateExistingGenesis(entry);
        this.reportedHead = higherHead(this.reportedHead, existingHead);
        return genesis;
      }
      throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'Ledger head exists without genesis');
    }

    if (this.config.previousEpochId !== undefined) {
      const verifiedAndSealed = await this.config.epochTransitionGuard!.verifyAndSeal({
        ledgerId: this.config.ledgerId,
        previousEpochId: this.config.previousEpochId,
        nextEpochId: this.config.ledgerEpochId,
        previousTerminalCheckpointDigest: this.config.previousTerminalCheckpointDigest!,
        reason: this.config.transitionReason ?? 'failover',
      });
      if (verifiedAndSealed !== true) {
        throw new AuditProtocolError(AUDIT_ERROR_CODES.INVALID_CONFIGURATION, 'Predecessor terminal digest could not be verified and sealed');
      }
    }

    this.initialization ??= this.serialized(() => this.appendEvent(this.genesisEvent(), true)).finally(() => {
      this.initialization = undefined;
    });
    return this.initialization;
  }

  private validateExistingGenesis(candidate: SignedAuditEntry): SignedAuditEntry {
    try {
      const entry = parseSignedAuditEntry(candidate);
      const details = entry.core.event.details;
      const event = entry.core.event;
      const valid =
        entry.core.sequence === '0' &&
        entry.core.previousEntryDigest === null &&
        entry.core.ledgerId === this.config.ledgerId &&
        entry.core.ledgerEpochId === this.config.ledgerEpochId &&
        sameSignerRef(entry.core.recorder, this.config.signer.ref) &&
        event.eventType === 'ledger.epoch.started' &&
        event.binding === this.config.binding &&
        event.source.sourceId === this.config.sourceId &&
        event.source.producer.kind === 'public_did' &&
        event.source.producer.did === this.config.signer.ref.did &&
        sameCanonical(event.tenantRef, this.config.tenantRef) &&
        details.family === 'ledger' &&
        details.phase === 'epoch_started' &&
        details.previousEpochId === this.config.previousEpochId &&
        details.previousTerminalCheckpointDigest === this.config.previousTerminalCheckpointDigest;
      if (!valid) throw new Error('Genesis does not match recorder epoch configuration');
      return entry;
    } catch (error) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        'Existing ledger genesis does not match the authoritative recorder configuration',
        { ledgerId: this.config.ledgerId, ledgerEpochId: this.config.ledgerEpochId },
        { cause: error },
      );
    }
  }

  private genesisEvent(): AuditProducerEvent {
    const reason = this.config.previousEpochId !== undefined ? this.config.transitionReason : undefined;
    return parseAuditEvent({
      schema: AUDIT_EVENT_SCHEMA,
      eventId: `genesis:${this.config.ledgerId}:${this.config.ledgerEpochId}`.slice(0, 256),
      eventType: 'ledger.epoch.started',
      eventVersion: AUDIT_EVENT_VERSION,
      binding: this.config.binding,
      occurredAt: this.config.clock.now(),
      tenantRef: this.config.tenantRef,
      source: {
        producer: { kind: 'public_did', did: this.config.signer.ref.did },
        sourceId: this.config.sourceId,
        sourceSequence: '0',
      },
      resource: { kind: 'public_did', did: this.config.signer.ref.did },
      action: { category: 'ledger.epoch' },
      outcome: 'succeeded',
      ...(reason !== undefined ? { reason: { code: reason } } : {}),
      evidence: [],
      details: {
        family: 'ledger',
        phase: 'epoch_started',
        ...(this.config.previousEpochId !== undefined
          ? {
              previousEpochId: this.config.previousEpochId,
              previousTerminalCheckpointDigest: this.config.previousTerminalCheckpointDigest,
            }
          : {}),
      },
      privacy: { classification: 'internal', retentionClass: 'integrity-ledger' },
    });
  }

  private async appendEvent(
    event: AuditProducerEvent,
    genesis: boolean,
    knownIdentity?: { eventDigest: Digest; idempotencyKey: Digest },
  ): Promise<SignedAuditEntry> {
    const { eventDigest, idempotencyKey } =
      knownIdentity ??
      this.identifyEvent(event, { producerAuthority: this.config.signer.ref.did, tenantAuthority: 'audit-recorder' });

    const duplicate = await this.config.journal.getByIdempotencyKey(this.config.ledgerId, idempotencyKey);
    if (duplicate !== null) {
      // A raced replica genesis differs only in recorder-authored timing, so it
      // resolves through epoch-configuration validation, not content identity.
      return genesis ? this.validateExistingGenesis(duplicate) : this.resolveDuplicate(duplicate, eventDigest);
    }

    for (let attempt = 0; attempt <= this.maxAppendConflicts; attempt += 1) {
      // A read behind this recorder's own commits (a lagging replica) is not an
      // append position: compare-and-append against the committed head, so a
      // journal that really moved backwards answers with a conflict that proves it.
      const committed = this.committedHead;
      const reported = this.reportedHead;
      const head = higherHead(committed, await this.config.journal.getHead(this.ledger));
      if (genesis && head !== null) {
        const raced = await this.config.journal.getByIdempotencyKey(this.config.ledgerId, idempotencyKey);
        if (raced !== null) return this.validateExistingGenesis(raced);
      }

      const candidate = await this.buildCandidate(event, eventDigest, head, genesis);
      let result;
      try {
        result = await this.config.journal.compareAndAppend({ ledger: this.ledger, expectedHead: head, entry: candidate, idempotencyKey });
      } catch (error) {
        if (isAuditError(error, AUDIT_ERROR_CODES.EPOCH_MISMATCH) || isAuditError(error, AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION)) throw error;
        throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'Audit journal append failed', undefined, { cause: error });
      }

      if (result.kind === 'appended') {
        const appended: AuditHead = { ...this.ledger, sequence: result.entry.core.sequence, entryDigest: result.entry.entryDigest };
        this.committedHead = higherHead(this.committedHead, appended);
        this.reportedHead = higherHead(this.reportedHead, appended);
        await this.config.onCommitted?.(appended);
        return result.entry;
      }
      if (result.kind === 'duplicate' || result.kind === 'idempotency_conflict') {
        const existing = result.kind === 'duplicate' ? result.entry : result.existing;
        return genesis ? this.validateExistingGenesis(existing) : this.resolveDuplicate(existing, eventDigest);
      }
      this.assertNoRegression(result.actualHead, committed, reported);
      this.reportedHead = higherHead(this.reportedHead, result.actualHead);
      if (sameHead(head, result.actualHead)) {
        throw new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, 'Audit journal reported a head conflict without advancing its head');
      }
    }

    throw new AuditProtocolError(AUDIT_ERROR_CODES.APPEND_CONFLICT_EXHAUSTED, 'Audit append conflict retry budget exhausted');
  }

  /**
   * The compare-and-append result is the journal's authoritative head. One
   * below a head this recorder committed before issuing the append, or a
   * different digest at a sequence the journal already reported, means a
   * failover to a lagging primary or a restore: the recorder fails closed
   * instead of signing a second entry at a receipted sequence.
   */
  private assertNoRegression(actual: AuditHead | null, committed: AuditHead | null, reported: AuditHead | null): void {
    const forks = (known: AuditHead | null): boolean =>
      known !== null && actual !== null && known.sequence === actual.sequence && known.entryDigest !== actual.entryDigest;
    if ((committed !== null && (actual === null || BigInt(actual.sequence) < BigInt(committed.sequence))) || forks(committed) || forks(reported)) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        'Audit journal head moved behind a head this recorder already committed or saw',
        { committedSequence: committed?.sequence, reportedSequence: actual?.sequence },
      );
    }
  }

  private identifyEvent(event: AuditProducerEvent, context: AuthenticatedAuditSubmissionContext): { eventDigest: Digest; idempotencyKey: Digest } {
    return {
      eventDigest: auditEventDigest(event),
      idempotencyKey: auditIdempotencyKey({
        ledgerId: this.config.ledgerId,
        producerAuthority: context.producerAuthority,
        sourceId: event.source.sourceId,
        eventId: event.eventId,
      }),
    };
  }

  private resolveDuplicate(existing: SignedAuditEntry, digest: Digest): SignedAuditEntry {
    if (existing.eventDigest !== digest) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.EVENT_ID_CONFLICT, 'Authenticated producer event identity was reused with different content', {
        eventId: existing.core.event.eventId,
      });
    }
    return existing;
  }

  private async buildCandidate(event: AuditProducerEvent, eventDigest: Digest, head: AuditHead | null, genesis: boolean): Promise<SignedAuditEntry> {
    const sequence = head === null ? '0' : (BigInt(head.sequence) + 1n).toString();
    if (genesis !== (sequence === '0')) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.JOURNAL_FAILURE,
        genesis ? 'Genesis must be the first epoch entry' : 'Producer event cannot replace genesis',
      );
    }
    const core = parseAuditEntryCore({
      schema: AUDIT_ENTRY_SCHEMA,
      ledgerId: this.config.ledgerId,
      ledgerEpochId: this.config.ledgerEpochId,
      sequence,
      previousEntryDigest: head?.entryDigest ?? null,
      recordedAt: this.config.clock.now(),
      recorder: this.config.signer.ref,
      eventDigest,
      event,
      evidenceManifestDigest: digestAuditEvidenceManifest(event),
      integritySuite: AUDIT_INTEGRITY_SUITE,
    });
    const entryDigest = digestAuditEntry(core);
    const receiptCore = buildAuditReceiptCore(core, entryDigest);
    const jws = await this.config.signer.sign(auditReceiptPayload(receiptCore));
    return deepFreeze({ core, eventDigest, entryDigest, recorderReceipt: { core: receiptCore, jws } } satisfies SignedAuditEntry);
  }
}

