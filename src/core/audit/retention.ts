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
 * Retention administration (story A-2 point 6; AUDITABILITY.md, Evidence,
 * retention, and access). The ledger is retained indefinitely by default:
 * nothing expires on a timer. The only removal is an explicit disposal
 * command, and it removes ciphertext, never the commitment: the entry and
 * its receipt stay, so history still verifies, while the evidence object
 * becomes explicitly disposed.
 *
 * Every command is itself recorded through the recorder: a legal hold as
 * `legal_hold.applied`, a release and a disposal as `retention.executed`
 * (purpose `legal_hold_released` / `disposal`), each disposed object as
 * `evidence.disposed`, and a refused disposal as `retention.executed` with
 * outcome `denied`. A disposal is refused under any active legal hold on
 * the ledger, the entry or the object, and for anything younger than the
 * retention floor: the longer of the ledger policy's minimum and the
 * longest lifetime (`validUntil` minus issuance) of any delegation; a
 * delegation without `validUntil` makes the floor unbounded.
 */

import { auditDigest } from './digest.js';
import type { AuditLedgerStore } from './journal.js';
import { collectAuditEvidenceRefs, type SignedAuditEntry } from './ledger.js';
import { AUDIT_ERROR_CODES, AuditProtocolError } from './ledger-errors.js';
import type { ManagedAuditRecorder } from './managed-recorder.js';
import { sanitizeReference } from './references.js';
import type { Digest, EvidenceRef } from './types.js';

export type AuditRetentionTarget =
  | { kind: 'ledger'; ledgerId: string }
  | { kind: 'entry'; ledgerId: string; ledgerEpochId: string; sequence: string }
  | { kind: 'evidence'; ledgerId: string; objectId: string };

export interface AuditLegalHold {
  holdId: string;
  target: AuditRetentionTarget;
  appliedAt: number;
  appliedBy: string;
  releasedAt?: number;
  releasedBy?: string;
}

export interface AuditEvidenceRetentionState {
  ref: EvidenceRef;
  storedAt: number;
  disposedAt?: number;
}

/** Where holds live and where ciphertext is disposed. No entry is ever touched. */
export interface AuditRetentionStore {
  /** Inserts a hold; `exists` when that hold id is already applied to the same target. */
  insertHold(hold: AuditLegalHold): Promise<'inserted' | 'exists'>;
  /** Marks a hold released; null when there is no active hold with that id. */
  releaseHold(holdId: string, releasedAt: number, releasedBy: string): Promise<AuditLegalHold | null>;
  getHold(holdId: string): Promise<AuditLegalHold | null>;
  activeHolds(ledgerId: string): Promise<AuditLegalHold[]>;
  evidenceState(objectId: string): Promise<AuditEvidenceRetentionState | null>;
  /**
   * Removes the ciphertext and keeps the reference; idempotent. Refuses
   * (`AUDIT_EVIDENCE_LEGAL_HOLD`) while a hold on the object or its ledger is
   * active, whatever the caller checked first.
   */
  disposeEvidence(input: { ledgerId: string; objectId: string; disposedAt: number; reason: string }): Promise<'disposed' | 'already_disposed' | 'missing'>;
}

export interface AuditRetentionPolicy {
  /** A floor below which nothing is disposed, whatever the delegations; default 0. */
  minimumRetentionMs?: number;
}

export interface AuditRetentionServiceOptions {
  recorder: ManagedAuditRecorder;
  journal: AuditLedgerStore;
  retention: AuditRetentionStore;
  /** The longest delegation lifetime in milliseconds; `Infinity` when one has no `validUntil`. */
  delegationRetentionFloorMs: () => Promise<number>;
  policy?: AuditRetentionPolicy | ((ledgerId: string) => AuditRetentionPolicy);
  clock?: () => number;
}

export interface AuditDisposalResult {
  /** The `retention.executed` entry that authorized the disposal. */
  command: SignedAuditEntry;
  /** One `evidence.disposed` entry per object whose ciphertext was removed. */
  disposals: SignedAuditEntry[];
  disposedObjectIds: string[];
  /** Objects named that were already disposed or never stored. */
  skippedObjectIds: string[];
}

const RETENTION_TARGET_DOMAIN = 'org.helix.audit.retention-target.v1';

/** Domain-separated digest of a retention selection: what an administration event names instead of the target itself. */
export function retentionSelectionDigest(selection: { target: AuditRetentionTarget; holdId?: string }): Digest {
  return auditDigest(RETENTION_TARGET_DOMAIN, selection);
}

function targetMatches(hold: AuditRetentionTarget, target: AuditRetentionTarget, objectIds: readonly string[]): boolean {
  if (hold.kind === 'ledger') return hold.ledgerId === target.ledgerId;
  if (hold.kind === 'entry') {
    return target.kind === 'entry' && hold.ledgerEpochId === target.ledgerEpochId && hold.sequence === target.sequence && hold.ledgerId === target.ledgerId;
  }
  return objectIds.includes(hold.objectId);
}

export class AuditRetentionService {
  private readonly clock: () => number;

  constructor(private readonly options: AuditRetentionServiceOptions) {
    this.clock = options.clock ?? Date.now;
  }

  /** Applies a hold and records `legal_hold.applied`. Re-applying the same hold is idempotent and recorded again. */
  async applyLegalHold(input: { holdId: string; target: AuditRetentionTarget; authorizedBy: string }): Promise<SignedAuditEntry> {
    await this.assertTargetExists(input.target);
    const existing = await this.options.retention.getHold(input.holdId);
    if (existing !== null && JSON.stringify(existing.target) !== JSON.stringify(input.target)) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.RETENTION_REFUSED, 'This hold id already holds another target', { holdId: input.holdId });
    }
    // Protect first: a hold that is applied but not yet recorded protects; the reverse would not.
    await this.options.retention.insertHold({ holdId: input.holdId, target: input.target, appliedAt: this.clock(), appliedBy: input.authorizedBy });
    return this.options.recorder.recordAdministration(input.target.ledgerId, {
      eventType: 'legal_hold.applied',
      action: { category: 'retention.legal_hold' },
      outcome: 'succeeded',
      details: {
        family: 'administration',
        phase: 'legal_hold_applied',
        purpose: sanitizeReference(input.holdId),
        selectionDigest: retentionSelectionDigest({ target: input.target, holdId: input.holdId }),
      },
    });
  }

  /** Records the release (`retention.executed`, purpose `legal_hold_released`), then releases. */
  async releaseLegalHold(input: { holdId: string; authorizedBy: string }): Promise<SignedAuditEntry> {
    const hold = await this.options.retention.getHold(input.holdId);
    if (hold === null || hold.releasedAt !== undefined) {
      throw new AuditProtocolError(AUDIT_ERROR_CODES.RETENTION_REFUSED, 'No active legal hold with this id', { holdId: input.holdId });
    }
    const entry = await this.options.recorder.recordAdministration(hold.target.ledgerId, {
      eventType: 'retention.executed',
      action: { category: 'retention.legal_hold_release' },
      outcome: 'succeeded',
      details: {
        family: 'administration',
        phase: 'retention_executed',
        purpose: 'legal_hold_released',
        selectionDigest: retentionSelectionDigest({ target: hold.target, holdId: hold.holdId }),
      },
    });
    await this.options.retention.releaseHold(input.holdId, this.clock(), input.authorizedBy);
    return entry;
  }

  /**
   * Disposes the ciphertext of an entry's evidence (or of one evidence
   * object). Refused, and the refusal recorded, under a legal hold or below
   * the retention floor. The command is recorded before anything is removed.
   */
  async dispose(input: { target: Exclude<AuditRetentionTarget, { kind: 'ledger' }>; authorizedBy: string }): Promise<AuditDisposalResult> {
    const { target } = input;
    const { refs, recordedAt } = await this.resolveDisposal(target);
    const objectIds = refs.map((ref) => ref.objectId);
    const selectionDigest = retentionSelectionDigest({ target });

    const holds = (await this.options.retention.activeHolds(target.ledgerId)).filter((hold) => targetMatches(hold.target, target, objectIds));
    if (holds.length > 0) {
      await this.recordRefusal(target.ledgerId, selectionDigest, 'legal_hold');
      throw new AuditProtocolError(AUDIT_ERROR_CODES.EVIDENCE_LEGAL_HOLD, 'Disposal refused: the target is under legal hold', {
        holdIds: holds.map((hold) => hold.holdId),
      });
    }
    const floor = await this.retentionFloorMs(target.ledgerId);
    const age = this.clock() - recordedAt;
    if (!(age >= floor)) {
      await this.recordRefusal(target.ledgerId, selectionDigest, 'retention_floor');
      throw new AuditProtocolError(AUDIT_ERROR_CODES.RETENTION_REFUSED, 'Disposal refused: the target is younger than the retention floor', {
        ageMs: age,
        floorMs: Number.isFinite(floor) ? floor : 'unbounded',
      });
    }

    const command = await this.options.recorder.recordAdministration(target.ledgerId, {
      eventType: 'retention.executed',
      action: { category: 'retention.dispose' },
      outcome: 'succeeded',
      details: { family: 'administration', phase: 'retention_executed', purpose: 'disposal', selectionDigest },
    });
    const disposals: SignedAuditEntry[] = [];
    const disposedObjectIds: string[] = [];
    const skippedObjectIds: string[] = [];
    for (const ref of refs) {
      const outcome = await this.options.retention.disposeEvidence({ ledgerId: target.ledgerId, objectId: ref.objectId, disposedAt: this.clock(), reason: 'disposal' });
      if (outcome !== 'disposed') {
        skippedObjectIds.push(ref.objectId);
        continue;
      }
      disposedObjectIds.push(ref.objectId);
      disposals.push(
        await this.options.recorder.recordAdministration(target.ledgerId, {
          eventType: 'evidence.disposed',
          action: { category: 'retention.dispose' },
          outcome: 'succeeded',
          details: { family: 'ledger', phase: 'evidence_disposed', targetEvidenceRef: ref },
        }),
      );
    }
    return { command, disposals, disposedObjectIds, skippedObjectIds };
  }

  /** The floor in milliseconds for a ledger: the longer of its policy minimum and the longest delegation lifetime. */
  async retentionFloorMs(ledgerId: string): Promise<number> {
    const policy = typeof this.options.policy === 'function' ? this.options.policy(ledgerId) : (this.options.policy ?? {});
    return Math.max(policy.minimumRetentionMs ?? 0, await this.options.delegationRetentionFloorMs());
  }

  private async recordRefusal(ledgerId: string, selectionDigest: Digest, code: string): Promise<void> {
    await this.options.recorder.recordAdministration(ledgerId, {
      eventType: 'retention.executed',
      action: { category: 'retention.dispose' },
      outcome: 'denied',
      reason: { code },
      details: { family: 'administration', phase: 'retention_executed', purpose: 'disposal', selectionDigest },
    });
  }

  private async assertTargetExists(target: AuditRetentionTarget): Promise<void> {
    if (target.kind === 'ledger') {
      if ((await this.options.journal.getLedger(target.ledgerId)) === null) throw this.noTarget(target);
      return;
    }
    await this.resolveDisposal(target);
  }

  private async resolveDisposal(target: Exclude<AuditRetentionTarget, { kind: 'ledger' }>): Promise<{ refs: EvidenceRef[]; recordedAt: number }> {
    if (target.kind === 'evidence') {
      const state = await this.options.retention.evidenceState(target.objectId);
      if (state === null) throw this.noTarget(target);
      return { refs: [state.ref], recordedAt: state.storedAt };
    }
    const entry = await this.readEntry(target);
    if (entry === null) throw this.noTarget(target);
    const unique = new Map(collectAuditEvidenceRefs(entry.core.event).map((ref) => [ref.objectId, ref]));
    return { refs: [...unique.values()], recordedAt: entry.core.recordedAt };
  }

  private async readEntry(target: { ledgerId: string; ledgerEpochId: string; sequence: string }): Promise<SignedAuditEntry | null> {
    if (!/^(0|[1-9][0-9]*)$/.test(target.sequence)) return null;
    const after = BigInt(target.sequence) - 1n;
    for await (const entry of this.options.journal.readRange({
      ledgerId: target.ledgerId,
      ledgerEpochId: target.ledgerEpochId,
      limit: 1,
      ...(after >= 0n ? { afterSequence: after.toString() } : {}),
    })) {
      return entry.core.sequence === target.sequence ? entry : null;
    }
    return null;
  }

  private noTarget(target: AuditRetentionTarget): AuditProtocolError {
    return new AuditProtocolError(AUDIT_ERROR_CODES.RETENTION_REFUSED, 'No such retention target', { target });
  }
}

/** Refuses when an active hold covers the ledger or the object (the store-side half of the hold check). */
export function assertNotHeld(holds: readonly AuditLegalHold[], ledgerId: string, objectId: string): void {
  const covering = holds.filter(
    (hold) =>
      hold.releasedAt === undefined &&
      ((hold.target.kind === 'ledger' && hold.target.ledgerId === ledgerId) || (hold.target.kind === 'evidence' && hold.target.objectId === objectId)),
  );
  if (covering.length > 0) {
    throw new AuditProtocolError(AUDIT_ERROR_CODES.EVIDENCE_LEGAL_HOLD, 'Evidence under legal hold cannot be disposed', {
      objectId,
      holdIds: covering.map((hold) => hold.holdId),
    });
  }
}

/** In-memory holds and evidence states, for tests of the retention service. */
export class MemoryAuditRetentionStore implements AuditRetentionStore {
  private readonly holds = new Map<string, AuditLegalHold>();
  private readonly evidence = new Map<string, AuditEvidenceRetentionState>();

  /** Registers an evidence object (the memory vault calls this on put). */
  trackEvidence(ref: EvidenceRef, storedAt: number): void {
    if (!this.evidence.has(ref.objectId)) this.evidence.set(ref.objectId, { ref, storedAt });
  }

  async insertHold(hold: AuditLegalHold): Promise<'inserted' | 'exists'> {
    const existing = this.holds.get(hold.holdId);
    if (existing !== undefined && existing.releasedAt === undefined) return 'exists';
    this.holds.set(hold.holdId, { ...hold });
    return 'inserted';
  }

  async releaseHold(holdId: string, releasedAt: number, releasedBy: string): Promise<AuditLegalHold | null> {
    const hold = this.holds.get(holdId);
    if (hold === undefined || hold.releasedAt !== undefined) return null;
    Object.assign(hold, { releasedAt, releasedBy });
    return { ...hold };
  }

  async getHold(holdId: string): Promise<AuditLegalHold | null> {
    const hold = this.holds.get(holdId);
    return hold === undefined ? null : { ...hold };
  }

  async activeHolds(ledgerId: string): Promise<AuditLegalHold[]> {
    return [...this.holds.values()].filter((hold) => hold.releasedAt === undefined && hold.target.ledgerId === ledgerId).map((hold) => ({ ...hold }));
  }

  async evidenceState(objectId: string): Promise<AuditEvidenceRetentionState | null> {
    const state = this.evidence.get(objectId);
    return state === undefined ? null : { ...state };
  }

  async disposeEvidence(input: { ledgerId: string; objectId: string; disposedAt: number }): Promise<'disposed' | 'already_disposed' | 'missing'> {
    const { ledgerId, objectId, disposedAt } = input;
    assertNotHeld(await this.activeHolds(ledgerId), ledgerId, objectId);
    const state = this.evidence.get(objectId);
    if (state === undefined) return 'missing';
    if (state.disposedAt !== undefined) return 'already_disposed';
    state.disposedAt = disposedAt;
    return 'disposed';
  }
}
