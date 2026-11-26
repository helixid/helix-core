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

import type pg from 'pg';
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
import type { ApiAuditEvidenceStore } from './store.js';

interface EvidenceRow {
  ref: EvidenceRef;
  ciphertext: Buffer | null;
  ciphertextDigest: string;
  storedAt: Date;
  disposedAt: Date | null;
}

interface HoldRow {
  holdId: string;
  target: AuditRetentionTarget;
  appliedAt: Date;
  appliedBy: string;
  releasedAt: Date | null;
  releasedBy: string | null;
}

function holdOf(row: HoldRow): AuditLegalHold {
  return {
    holdId: row.holdId,
    target: row.target,
    appliedAt: row.appliedAt.getTime(),
    appliedBy: row.appliedBy,
    ...(row.releasedAt !== null ? { releasedAt: row.releasedAt.getTime() } : {}),
    ...(row.releasedBy !== null ? { releasedBy: row.releasedBy } : {}),
  };
}

function isUniqueViolation(error: unknown): boolean {
  return (error as { code?: unknown } | null)?.code === '23505';
}

/**
 * The evidence vault and legal holds on PostgreSQL. Ciphertext is written
 * once; disposal clears it and keeps the reference (the migration's trigger
 * allows no other change and refuses it while an object-level hold is active).
 */
export class PostgresAuditEvidenceStore implements ApiAuditEvidenceStore {
  constructor(private readonly pool: pg.Pool) {}

  async putIfAbsent(object: EncryptedEvidence): Promise<EvidenceRef> {
    assertEvidenceMatchesRef(object);
    const { ref } = object;
    const inserted = await this.pool.query(
      `INSERT INTO "audit_evidence" ("objectId", "ciphertextDigest", "size", "mediaType", "keyId", "ref", "ciphertext")
       VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT ("objectId") DO NOTHING`,
      [ref.objectId, ref.ciphertextDigest, ref.size, ref.mediaType, ref.encryption.keyId, JSON.stringify(ref), Buffer.from(object.ciphertext)],
    );
    if (inserted.rowCount === 1) return ref;
    const existing = await this.row(ref.objectId);
    if (existing !== null && existing.ciphertextDigest === ref.ciphertextDigest) return existing.ref;
    throw new AuditEvidenceError('Opaque evidence object id collision', { objectId: ref.objectId });
  }

  async get(objectId: string): Promise<EncryptedEvidence | null> {
    const row = await this.row(objectId);
    if (row === null || row.ciphertext === null) return null;
    return { ref: row.ref, ciphertext: new Uint8Array(row.ciphertext) };
  }

  async has(objectId: string): Promise<boolean> {
    return (await this.row(objectId)) !== null;
  }

  async discardUncommitted(objectId: string): Promise<void> {
    await this.pool.query(
      `UPDATE "audit_evidence" SET "ciphertext" = NULL, "disposedAt" = CURRENT_TIMESTAMP, "disposalReason" = 'append_failed_uncommitted'
        WHERE "objectId" = $1 AND "disposedAt" IS NULL`,
      [objectId],
    );
  }

  async evidenceState(objectId: string): Promise<AuditEvidenceRetentionState | null> {
    const row = await this.row(objectId);
    if (row === null) return null;
    return { ref: row.ref, storedAt: row.storedAt.getTime(), ...(row.disposedAt !== null ? { disposedAt: row.disposedAt.getTime() } : {}) };
  }

  async disposeEvidence(input: { ledgerId: string; objectId: string; disposedAt: number; reason: string }): Promise<'disposed' | 'already_disposed' | 'missing'> {
    assertNotHeld(await this.activeHolds(input.ledgerId), input.ledgerId, input.objectId);
    const result = await this.pool.query(
      `UPDATE "audit_evidence" SET "ciphertext" = NULL, "disposedAt" = $2, "disposalReason" = $3 WHERE "objectId" = $1 AND "disposedAt" IS NULL`,
      [input.objectId, new Date(input.disposedAt), input.reason],
    );
    if (result.rowCount === 1) return 'disposed';
    return (await this.row(input.objectId)) === null ? 'missing' : 'already_disposed';
  }

  async insertHold(hold: AuditLegalHold): Promise<'inserted' | 'exists'> {
    try {
      await this.pool.query(
        `INSERT INTO "audit_legal_holds" ("holdId", "ledgerId", "targetKind", "objectId", "target", "appliedAt", "appliedBy")
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          hold.holdId,
          hold.target.ledgerId,
          hold.target.kind,
          hold.target.kind === 'evidence' ? hold.target.objectId : null,
          JSON.stringify(hold.target),
          new Date(hold.appliedAt),
          hold.appliedBy,
        ],
      );
      return 'inserted';
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const existing = await this.getHold(hold.holdId);
      if (existing !== null && existing.releasedAt === undefined && JSON.stringify(existing.target) === JSON.stringify(hold.target)) return 'exists';
      throw new AuditEvidenceError('This legal hold id was already used', { holdId: hold.holdId });
    }
  }

  async releaseHold(holdId: string, releasedAt: number, releasedBy: string): Promise<AuditLegalHold | null> {
    const { rows } = await this.pool.query<HoldRow>(
      `UPDATE "audit_legal_holds" SET "releasedAt" = $2, "releasedBy" = $3 WHERE "holdId" = $1 AND "releasedAt" IS NULL RETURNING *`,
      [holdId, new Date(releasedAt), releasedBy],
    );
    return rows[0] === undefined ? null : holdOf(rows[0]);
  }

  async getHold(holdId: string): Promise<AuditLegalHold | null> {
    const { rows } = await this.pool.query<HoldRow>(`SELECT * FROM "audit_legal_holds" WHERE "holdId" = $1`, [holdId]);
    return rows[0] === undefined ? null : holdOf(rows[0]);
  }

  async activeHolds(ledgerId: string): Promise<AuditLegalHold[]> {
    const { rows } = await this.pool.query<HoldRow>(
      `SELECT * FROM "audit_legal_holds" WHERE "ledgerId" = $1 AND "releasedAt" IS NULL ORDER BY "appliedAt", "holdId"`,
      [ledgerId],
    );
    return rows.map(holdOf);
  }

  private async row(objectId: string): Promise<EvidenceRow | null> {
    const { rows } = await this.pool.query<EvidenceRow>(
      `SELECT "ref", "ciphertext", "ciphertextDigest", "storedAt", "disposedAt" FROM "audit_evidence" WHERE "objectId" = $1`,
      [objectId],
    );
    return rows[0] ?? null;
  }
}
