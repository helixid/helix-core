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

import {
  assertEvidenceMatchesRef,
  assertNotHeld,
  AuditEvidenceError,
  type AuditEvidenceRetentionState,
  type AuditLegalHold,
  type AuditRetentionTarget,
  type EncryptedEvidence,
  type EvidenceRef,
} from '../core/index.js';
import type { SqliteStore } from '../storage/sqlite.js';
import type { ApiAuditEvidenceStore } from './store.js';

interface EvidenceRow {
  ref_json: string;
  ciphertext: Uint8Array;
  ciphertext_digest: string;
  stored_at: string;
  disposed_at: string | null;
}

interface HoldRow {
  hold_id: string;
  target: string;
  applied_at: number;
  applied_by: string;
  released_at: number | null;
  released_by: string | null;
}

function holdOf(row: HoldRow): AuditLegalHold {
  return {
    holdId: row.hold_id,
    target: JSON.parse(row.target) as AuditRetentionTarget,
    appliedAt: row.applied_at,
    appliedBy: row.applied_by,
    ...(row.released_at !== null ? { releasedAt: row.released_at } : {}),
    ...(row.released_by !== null ? { releasedBy: row.released_by } : {}),
  };
}

/**
 * The evidence vault and legal holds on SQLite. A disposed object keeps its
 * row and reference with a zero-length ciphertext (A-1 files declared the
 * column NOT NULL, and SQLite cannot relax that in place).
 */
export class SqliteAuditEvidenceStore implements ApiAuditEvidenceStore {
  constructor(private readonly sqlite: SqliteStore) {}

  async putIfAbsent(object: EncryptedEvidence): Promise<EvidenceRef> {
    assertEvidenceMatchesRef(object);
    const { ref } = object;
    const inserted = this.sqlite.write(
      `INSERT OR IGNORE INTO audit_evidence (object_id, ciphertext_digest, size, media_type, key_id, ref_json, ciphertext, stored_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ref.objectId,
      ref.ciphertextDigest,
      Number(ref.size),
      ref.mediaType,
      ref.encryption.keyId,
      JSON.stringify(ref),
      Buffer.from(object.ciphertext),
      new Date().toISOString(),
    );
    if (inserted.changes === 1) return ref;
    const existing = this.row(ref.objectId);
    if (existing !== undefined && existing.ciphertext_digest === ref.ciphertextDigest) return JSON.parse(existing.ref_json) as EvidenceRef;
    throw new AuditEvidenceError('Opaque evidence object id collision', { objectId: ref.objectId });
  }

  async get(objectId: string): Promise<EncryptedEvidence | null> {
    const row = this.row(objectId);
    if (row === undefined || row.disposed_at !== null) return null;
    return { ref: JSON.parse(row.ref_json) as EvidenceRef, ciphertext: new Uint8Array(row.ciphertext) };
  }

  async has(objectId: string): Promise<boolean> {
    return this.row(objectId) !== undefined;
  }

  async discardUncommitted(objectId: string): Promise<void> {
    this.sqlite.write(
      `UPDATE audit_evidence SET ciphertext = X'', disposed_at = ?, disposal_reason = 'append_failed_uncommitted' WHERE object_id = ? AND disposed_at IS NULL`,
      new Date().toISOString(),
      objectId,
    );
  }

  async evidenceState(objectId: string): Promise<AuditEvidenceRetentionState | null> {
    const row = this.row(objectId);
    if (row === undefined) return null;
    return {
      ref: JSON.parse(row.ref_json) as EvidenceRef,
      storedAt: Date.parse(row.stored_at),
      ...(row.disposed_at !== null ? { disposedAt: Date.parse(row.disposed_at) } : {}),
    };
  }

  async disposeEvidence(input: { ledgerId: string; objectId: string; disposedAt: number; reason: string }): Promise<'disposed' | 'already_disposed' | 'missing'> {
    assertNotHeld(await this.activeHolds(input.ledgerId), input.ledgerId, input.objectId);
    const changed = this.sqlite.write(
      `UPDATE audit_evidence SET ciphertext = X'', disposed_at = ?, disposal_reason = ? WHERE object_id = ? AND disposed_at IS NULL`,
      new Date(input.disposedAt).toISOString(),
      input.reason,
      input.objectId,
    );
    if (changed.changes === 1) return 'disposed';
    return this.row(input.objectId) === undefined ? 'missing' : 'already_disposed';
  }

  async insertHold(hold: AuditLegalHold): Promise<'inserted' | 'exists'> {
    const existing = await this.getHold(hold.holdId);
    if (existing !== null) {
      if (existing.releasedAt === undefined && JSON.stringify(existing.target) === JSON.stringify(hold.target)) return 'exists';
      throw new AuditEvidenceError('This legal hold id was already used', { holdId: hold.holdId });
    }
    this.sqlite.write(
      `INSERT INTO audit_legal_holds (hold_id, ledger_id, target_kind, object_id, target, applied_at, applied_by) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      hold.holdId,
      hold.target.ledgerId,
      hold.target.kind,
      hold.target.kind === 'evidence' ? hold.target.objectId : null,
      JSON.stringify(hold.target),
      hold.appliedAt,
      hold.appliedBy,
    );
    return 'inserted';
  }

  async releaseHold(holdId: string, releasedAt: number, releasedBy: string): Promise<AuditLegalHold | null> {
    const changed = this.sqlite.write(
      `UPDATE audit_legal_holds SET released_at = ?, released_by = ? WHERE hold_id = ? AND released_at IS NULL`,
      releasedAt,
      releasedBy,
      holdId,
    );
    return changed.changes === 1 ? this.getHold(holdId) : null;
  }

  async getHold(holdId: string): Promise<AuditLegalHold | null> {
    const row = this.sqlite.select<HoldRow>(`SELECT * FROM audit_legal_holds WHERE hold_id = ?`, holdId)[0];
    return row === undefined ? null : holdOf(row);
  }

  async activeHolds(ledgerId: string): Promise<AuditLegalHold[]> {
    return this.sqlite
      .select<HoldRow>(`SELECT * FROM audit_legal_holds WHERE ledger_id = ? AND released_at IS NULL ORDER BY applied_at, hold_id`, ledgerId)
      .map(holdOf);
  }

  private row(objectId: string): EvidenceRow | undefined {
    return this.sqlite.select<EvidenceRow>(
      `SELECT ref_json, ciphertext, ciphertext_digest, stored_at, disposed_at FROM audit_evidence WHERE object_id = ?`,
      objectId,
    )[0];
  }
}
