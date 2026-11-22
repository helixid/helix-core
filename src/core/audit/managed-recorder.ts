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
 * The recorder as a service (story A-2 point 1). In managed mode Helix is
 * the recorder for its tenants: each tenant has its own ledger, and one
 * `AuditRecorderService` per ledger is the single authority for the active
 * epoch. In self-hosted mode an enterprise runs exactly this code against
 * its own journal, restricted to the tenants it names.
 *
 * Activation (the first time this process opens a ledger) is where epoch
 * transitions start on their own: a journal behind the restore witness opens
 * a `restore` epoch, and a configured recorder key other than the active
 * epoch's opens a `key_rotation` epoch. Failover and retention rollover are
 * operator commands (`transition`). After activation a foreign authority on
 * the active epoch is refused, never transitioned away from, so two
 * misconfigured replicas cannot ping-pong a ledger between keys.
 */

import { createHash, randomUUID } from 'node:crypto';
import { canonicalize } from '../crypto/jcs.js';
import {
  JournalEpochTransitionGuard,
  newAuditEpochId,
  terminalHeadDigest,
  witnessShowsRestore,
  type AuditRecorderWitness,
} from './epochs.js';
import {
  sameSignerRef,
  type AuditEpochRecord,
  type AuditEpochTransitionReason,
  type AuditLedgerRecord,
  type AuditLedgerStore,
} from './journal.js';
import type { AuditHead, AuditRecorderSubmission, SignedAuditEntry } from './ledger.js';
import { AUDIT_ERROR_CODES, AuditProtocolError, isAuditError } from './ledger-errors.js';
import {
  AuditRecorderService,
  type AuditClock,
  type AuditRecorderEvidenceStore,
  type AuditSigner,
  type AuditSubmissionAuthorizer,
  type AuthenticatedAuditSubmissionContext,
} from './recorder.js';
import { parseAuditEvent } from './schema.js';
import { AUDIT_BINDING_HELIX, type AuditProducerEvent, type Digest, type PartyRef, type ProtocolBindingId } from './types.js';

export type AuditRecorderMode = 'managed' | 'self-hosted';

export interface AuditEpochTransitionResult {
  ledgerId: string;
  previousEpochId: string;
  nextEpochId: string;
  terminalDigest: Digest;
  reason: AuditEpochTransitionReason;
  genesis: SignedAuditEntry;
}

export interface ManagedAuditRecorderOptions {
  store: AuditLedgerStore;
  /** The recorder key: never an issuer key. */
  signer: AuditSigner;
  clock?: AuditClock;
  /** Binding of the recorder's own events (genesis, administration). Default the Helix binding. */
  binding?: ProtocolBindingId;
  /** Source id of the recorder's own events. Default `helix-audit-recorder`. */
  sourceId?: string;
  evidence?: AuditRecorderEvidenceStore;
  witness?: AuditRecorderWitness;
  authorizer?: AuditSubmissionAuthorizer;
  mode?: AuditRecorderMode;
  /** Self-hosted mode: the tenants this recorder keeps ledgers for (others are refused). */
  tenants?: PartyRef[];
  /** The ledger id of a tenant; default `ledger_<32 hex of sha256(JCS(tenantRef))>`. */
  ledgerIdFor?: (tenantRef: PartyRef) => string;
  newEpochId?: (index: number, now: number) => string;
  maxAppendConflicts?: number;
  onEpochTransition?: (transition: AuditEpochTransitionResult) => void;
  /** A witness write failed after a commit; the commit stands. Default: logged to stderr. */
  onWitnessFailure?: (error: unknown) => void;
  /**
   * Told of every producer submission's signed entry (a redelivery's
   * original one too), in the submitter's async context, after the receipt
   * exists: the seam for an index a deployment keeps beside the journal
   * (account attribution, say). It cannot fail or delay the submission; a
   * throw is reported through `onWitnessFailure`'s logger.
   */
  onRecorded?: (entry: SignedAuditEntry, context: AuthenticatedAuditSubmissionContext) => void;
}

/** The default ledger id of a tenant: opaque, stable, derived from its reference. */
export function defaultAuditLedgerId(tenantRef: PartyRef): string {
  return `ledger_${createHash('sha256').update(canonicalize(tenantRef), 'utf8').digest('hex').slice(0, 32)}`;
}

/** What an administration event names; the recorder fills in the rest. */
export type AuditAdministrationInput = Pick<AuditProducerEvent, 'eventType' | 'action' | 'outcome' | 'details'> &
  Partial<Pick<AuditProducerEvent, 'reason' | 'resource' | 'actor' | 'correlationId' | 'evidence'>>;

export class ManagedAuditRecorder {
  readonly mode: AuditRecorderMode;
  private readonly clock: AuditClock;
  private readonly binding: ProtocolBindingId;
  private readonly sourceId: string;
  private readonly ledgerIdFor: (tenantRef: PartyRef) => string;
  private readonly newEpochId: (index: number, now: number) => string;
  private readonly guard: JournalEpochTransitionGuard;
  private readonly recorders = new Map<string, Promise<AuditRecorderService>>();
  private readonly activated = new Set<string>();
  private readonly locks = new Map<string, Promise<unknown>>();
  private readonly allowedTenants: Set<string> | undefined;
  private witnessTail: Promise<void> = Promise.resolve();

  constructor(private readonly options: ManagedAuditRecorderOptions) {
    this.mode = options.mode ?? 'managed';
    this.clock = options.clock ?? { now: (): number => Date.now() };
    this.binding = options.binding ?? AUDIT_BINDING_HELIX;
    this.sourceId = options.sourceId ?? 'helix-audit-recorder';
    this.ledgerIdFor = options.ledgerIdFor ?? defaultAuditLedgerId;
    this.newEpochId = options.newEpochId ?? newAuditEpochId;
    this.guard = new JournalEpochTransitionGuard(options.store);
    if (this.mode === 'self-hosted') {
      if (options.tenants === undefined || options.tenants.length === 0) {
        throw new AuditProtocolError(AUDIT_ERROR_CODES.INVALID_CONFIGURATION, 'A self-hosted recorder names the tenants it records for');
      }
      this.allowedTenants = new Set(options.tenants.map((tenant) => canonicalize(tenant)));
    }
  }

  get signer(): AuditSigner {
    return this.options.signer;
  }

  get store(): AuditLedgerStore {
    return this.options.store;
  }

  /** Resolves once every restore-witness write issued so far has finished (or failed and been reported). */
  async settled(): Promise<void> {
    await this.witnessTail;
  }

  /** The ledger id a tenant's events go to. */
  ledgerIdOf(tenantRef: PartyRef): string {
    return this.ledgerIdFor(tenantRef);
  }

  /** Opens every ledger the store already holds (server start), running restore and key-rotation checks. */
  async start(): Promise<void> {
    for (const ledger of await this.options.store.listLedgers()) await this.recorderFor(ledger.ledgerId);
  }

  /** The tenant's ledger, created on first use (managed mode) or when the tenant is allowed (self-hosted). */
  async ledgerFor(tenantRef: PartyRef): Promise<AuditLedgerRecord> {
    if (this.allowedTenants !== undefined && !this.allowedTenants.has(canonicalize(tenantRef))) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION, 'This self-hosted recorder does not record for this tenant');
    }
    const ledger = await this.options.store.ensureLedger({ ledgerId: this.ledgerIdFor(tenantRef), tenantRef, createdAt: this.clock.now() });
    if (canonicalize(ledger.tenantRef) !== canonicalize(tenantRef)) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'The ledger id of this tenant belongs to another tenant', { ledgerId: ledger.ledgerId });
    }
    return ledger;
  }

  /**
   * Records one producer submission and returns the signed entry (the
   * original one for a redelivery). Routed by `ledgerId`, else by the
   * event's tenant.
   */
  async submit(submission: AuditRecorderSubmission, context: AuthenticatedAuditSubmissionContext): Promise<SignedAuditEntry> {
    const event = parseAuditEvent(submission.producerEvent);
    const ledger = await this.ledgerFor(event.tenantRef);
    if (submission.ledgerId !== undefined && submission.ledgerId !== ledger.ledgerId) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'Wrong audit ledger for this tenant', { ledgerId: submission.ledgerId });
    }
    const entry = await this.withActive(ledger.ledgerId, (recorder) => recorder.submitAuthenticated({ ...submission, producerEvent: event }, context));
    try {
      this.options.onRecorded?.(entry, context);
    } catch (error) {
      console.error('audit recorder: onRecorded observer failed', error);
    }
    return entry;
  }

  /** Records an administration event the recorder itself authors (retention, legal hold). */
  async recordAdministration(ledgerId: string, input: AuditAdministrationInput): Promise<SignedAuditEntry> {
    return this.withActive(ledgerId, (recorder) =>
      recorder.recordOwnEvent(
        recorder.ownEvent({
          ...input,
          eventId: `admin_${randomUUID()}`,
          occurredAt: this.clock.now(),
          privacy: { classification: 'internal', retentionClass: 'integrity-ledger' },
        }),
      ),
    );
  }

  /** The active epoch's recorder for a ledger, activating it on first use. */
  recorderFor(ledgerId: string): Promise<AuditRecorderService> {
    let recorder = this.recorders.get(ledgerId);
    if (recorder === undefined) {
      recorder = this.locked(ledgerId, () => this.activate(ledgerId));
      this.recorders.set(ledgerId, recorder);
      recorder.catch(() => this.recorders.delete(ledgerId));
    }
    return recorder;
  }

  /**
   * Closes the active epoch at its committed head and opens a successor whose
   * genesis commits the previous epoch id and terminal digest. Failover and
   * retention rollover are started here by an operator; restore and key
   * rotation also start here on their own at activation.
   */
  async transition(ledgerId: string, reason: AuditEpochTransitionReason): Promise<AuditEpochTransitionResult> {
    await this.recorderFor(ledgerId).catch(() => undefined);
    const result = this.locked(ledgerId, async () => {
      const { recorder, transition } = await this.transitionNow(ledgerId, reason);
      this.recorders.set(ledgerId, Promise.resolve(recorder));
      return transition;
    });
    return result;
  }

  private async withActive<T>(ledgerId: string, operation: (recorder: AuditRecorderService) => Promise<T>): Promise<T> {
    const recorder = await this.recorderFor(ledgerId);
    try {
      return await operation(recorder);
    } catch (error) {
      // Another replica sealed the epoch (a transition): reopen the active one once.
      if (!isAuditError(error, AUDIT_ERROR_CODES.EPOCH_MISMATCH) || error.details?.['reason'] !== 'epoch_sealed') throw error;
      if ((await this.recorders.get(ledgerId)?.catch(() => undefined)) === recorder) this.recorders.delete(ledgerId);
      return operation(await this.recorderFor(ledgerId));
    }
  }

  private locked<T>(ledgerId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(ledgerId) ?? Promise.resolve();
    const run = previous.then(operation, operation);
    this.locks.set(
      ledgerId,
      run.catch(() => undefined),
    );
    return run;
  }

  private async activate(ledgerId: string): Promise<AuditRecorderService> {
    const initial = !this.activated.has(ledgerId);
    const recorder = await this.activateNow(ledgerId, initial);
    this.activated.add(ledgerId);
    return recorder;
  }

  private async activateNow(ledgerId: string, initial: boolean, attempt = 0): Promise<AuditRecorderService> {
    const store = this.options.store;
    const ledger = await store.getLedger(ledgerId);
    if (ledger === null) throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'No such audit ledger', { ledgerId });
    const epochs = await store.listEpochs(ledgerId);

    if (ledger.activeEpochId === null) {
      if (epochs.length > 0) throw this.inconsistent(ledgerId, 'the ledger has epochs but no active epoch');
      const epochId = this.newEpochId(1, this.clock.now());
      if (!(await store.setActiveEpoch(ledgerId, null, epochId))) {
        // Another process opened the ledger first: read it again, a bounded number of times.
        if (attempt >= 3) throw this.inconsistent(ledgerId, 'the first epoch could not be set');
        return this.activateNow(ledgerId, initial, attempt + 1);
      }
      return this.openRecorder(ledger, epochId, undefined);
    }

    const active = epochs.find((epoch) => epoch.ledgerEpochId === ledger.activeEpochId);
    if (active === undefined) {
      // The pointer names an epoch whose genesis is not written yet: a new
      // ledger, or a successor whose predecessor was sealed mid-transition.
      const predecessor = epochs.find((epoch) => epoch.successorEpochId === ledger.activeEpochId);
      if (predecessor !== undefined) {
        return this.openRecorder(ledger, ledger.activeEpochId, {
          previousEpochId: predecessor.ledgerEpochId,
          terminalDigest: predecessor.terminalDigest!,
          reason: predecessor.sealReason ?? 'failover',
        });
      }
      if (epochs.length === 0) return this.openRecorder(ledger, ledger.activeEpochId, undefined);
      throw this.inconsistent(ledgerId, 'the active epoch has no genesis and no sealed predecessor');
    }
    if (active.status === 'sealed') throw this.inconsistent(ledgerId, 'the active epoch is sealed');

    if (initial) {
      if (await this.restoreDetected(ledgerId, active, epochs)) return (await this.transitionNow(ledgerId, 'restore')).recorder;
      if (!sameSignerRef(active.recorder, this.options.signer.ref)) return (await this.transitionNow(ledgerId, 'key_rotation')).recorder;
    } else if (!sameSignerRef(active.recorder, this.options.signer.ref)) {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.UNAUTHORIZED_SUBMISSION,
        'Another recorder authority holds this ledger\'s active epoch; restart this recorder to take it over by key rotation',
        { ledgerId, ledgerEpochId: active.ledgerEpochId },
      );
    }
    return this.openRecorder(ledger, active.ledgerEpochId, await this.predecessorOf(active));
  }

  private async restoreDetected(ledgerId: string, active: AuditEpochRecord, epochs: AuditEpochRecord[]): Promise<boolean> {
    const witnessed = await this.options.witness?.read(ledgerId);
    if (witnessed === undefined || witnessed === null) return false;
    if (witnessed.ledgerEpochId !== active.ledgerEpochId) {
      // A witnessed epoch the journal no longer holds was lost with the restore.
      return !epochs.some((epoch) => epoch.ledgerEpochId === witnessed.ledgerEpochId);
    }
    const digestAtWitnessed = await this.entryDigestAt(active, witnessed.sequence);
    return witnessShowsRestore(witnessed, active.head, digestAtWitnessed);
  }

  private async entryDigestAt(epoch: AuditEpochRecord, sequence: string): Promise<Digest | null> {
    const after = BigInt(sequence) - 1n;
    const query = { ledgerId: epoch.ledgerId, ledgerEpochId: epoch.ledgerEpochId, limit: 1, ...(after >= 0n ? { afterSequence: after.toString() } : {}) };
    for await (const entry of this.options.store.readRange(query)) return entry.core.sequence === sequence ? entry.entryDigest : null;
    return null;
  }

  private async predecessorOf(epoch: AuditEpochRecord): Promise<{ previousEpochId: string; terminalDigest: Digest; reason: AuditEpochTransitionReason } | undefined> {
    for await (const genesis of this.options.store.readRange({ ledgerId: epoch.ledgerId, ledgerEpochId: epoch.ledgerEpochId, limit: 1 })) {
      const details = genesis.core.event.details;
      if (details.family !== 'ledger' || details.previousEpochId === undefined || details.previousTerminalCheckpointDigest === undefined) return undefined;
      const reason = (genesis.core.event.reason?.code ?? 'failover') as AuditEpochTransitionReason;
      return { previousEpochId: details.previousEpochId, terminalDigest: details.previousTerminalCheckpointDigest, reason };
    }
    return undefined;
  }

  private async transitionNow(ledgerId: string, reason: AuditEpochTransitionReason): Promise<{ recorder: AuditRecorderService; transition: AuditEpochTransitionResult }> {
    const store = this.options.store;
    let nextEpochId: string | undefined;
    let announced = false;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const ledger = await store.getLedger(ledgerId);
      if (ledger === null || ledger.activeEpochId === null) {
        throw new AuditProtocolError(AUDIT_ERROR_CODES.LEDGER_MISMATCH, 'No active epoch to transition from', { ledgerId });
      }
      const epochs = await store.listEpochs(ledgerId);
      const active = epochs.find((epoch) => epoch.ledgerEpochId === ledger.activeEpochId);
      if (active === undefined || active.status !== 'active') throw this.inconsistent(ledgerId, 'the active epoch has no genesis to close');
      nextEpochId ??= this.newEpochId(epochs.length + 1, this.clock.now());
      if (reason === 'retention_rollover' && !announced && sameSignerRef(active.recorder, this.options.signer.ref)) {
        // A sealed rollover by the same authority closes its epoch with an explicit
        // last word. Never for a restore or failover: the journal may be behind
        // receipts already issued, and appending there would sign a receipted sequence again.
        await this.announceTransition(ledger, active, nextEpochId, reason);
        announced = true;
        continue;
      }
      const terminalDigest = terminalHeadDigest(active.head);
      try {
        const recorder = this.makeRecorder(ledger, nextEpochId, { previousEpochId: active.ledgerEpochId, terminalDigest, reason });
        const genesis = await recorder.open();
        this.activated.add(ledgerId);
        const transition: AuditEpochTransitionResult = { ledgerId, previousEpochId: active.ledgerEpochId, nextEpochId, terminalDigest, reason, genesis };
        this.options.onEpochTransition?.(transition);
        return { recorder, transition };
      } catch (error) {
        // The predecessor moved under us (a concurrent append): read it again.
        if (isAuditError(error, AUDIT_ERROR_CODES.INVALID_CONFIGURATION)) continue;
        throw error;
      }
    }
    throw new AuditProtocolError(AUDIT_ERROR_CODES.APPEND_CONFLICT_EXHAUSTED, 'The active epoch kept moving; the transition was not made', { ledgerId });
  }

  private async announceTransition(
    ledger: AuditLedgerRecord,
    active: AuditEpochRecord,
    nextEpochId: string,
    reason: AuditEpochTransitionReason,
  ): Promise<void> {
    const cached = await this.recorders.get(ledger.ledgerId)?.catch(() => undefined);
    const current =
      cached !== undefined && cached.ledger.ledgerEpochId === active.ledgerEpochId
        ? cached
        : await this.openRecorder(ledger, active.ledgerEpochId, await this.predecessorOf(active));
    await current.recordOwnEvent(
      current.ownEvent({
        eventId: `transition:${active.ledgerEpochId}:${nextEpochId}`,
        eventType: 'ledger.epoch.transitioned',
        occurredAt: this.clock.now(),
        action: { category: 'ledger.epoch' },
        outcome: 'succeeded',
        reason: { code: reason },
        details: { family: 'ledger', phase: 'epoch_transitioned', successorEpochIds: [nextEpochId] },
        privacy: { classification: 'internal', retentionClass: 'integrity-ledger' },
      }),
    );
  }

  private async openRecorder(
    ledger: AuditLedgerRecord,
    epochId: string,
    previous: { previousEpochId: string; terminalDigest: Digest; reason: AuditEpochTransitionReason } | undefined,
  ): Promise<AuditRecorderService> {
    const recorder = this.makeRecorder(ledger, epochId, previous);
    await recorder.open();
    return recorder;
  }

  private makeRecorder(
    ledger: AuditLedgerRecord,
    epochId: string,
    previous: { previousEpochId: string; terminalDigest: Digest; reason: AuditEpochTransitionReason } | undefined,
  ): AuditRecorderService {
    const witness = this.options.witness;
    return new AuditRecorderService({
      ledgerId: ledger.ledgerId,
      ledgerEpochId: epochId,
      tenantRef: ledger.tenantRef,
      binding: this.binding,
      sourceId: this.sourceId,
      journal: this.options.store,
      signer: this.options.signer,
      clock: this.clock,
      epochTransitionGuard: this.guard,
      ...(this.options.evidence !== undefined ? { evidence: this.options.evidence } : {}),
      ...(this.options.authorizer !== undefined ? { authorizer: this.options.authorizer } : {}),
      ...(this.options.maxAppendConflicts !== undefined ? { maxAppendConflicts: this.options.maxAppendConflicts } : {}),
      ...(previous !== undefined
        ? { previousEpochId: previous.previousEpochId, previousTerminalCheckpointDigest: previous.terminalDigest, transitionReason: previous.reason }
        : {}),
      ...(witness !== undefined
        ? {
            // Not awaited: the witness coalesces its own writes, so a burst of
            // appends is not serialized behind one fsync each. It is a restore
            // detector, not part of the commit; a failure is reported, the commit stands.
            onCommitted: (head: AuditHead): void => {
              const write = witness.record(head).catch((error: unknown) => {
                (this.options.onWitnessFailure ?? ((e: unknown): void => console.error('AUDIT_WITNESS_WRITE_FAILED', e)))(error);
              });
              this.witnessTail = Promise.all([this.witnessTail, write]).then(() => undefined);
            },
          }
        : {}),
    });
  }

  private inconsistent(ledgerId: string, what: string): AuditProtocolError {
    return new AuditProtocolError(AUDIT_ERROR_CODES.JOURNAL_FAILURE, `Audit ledger state is inconsistent: ${what}`, { ledgerId });
  }
}
