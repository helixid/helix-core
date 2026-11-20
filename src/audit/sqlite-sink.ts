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
  AuditEvidenceError,
  parseAuditEvent,
  type AuditTrailEntry,
  type Digest,
  type EncryptedEvidence,
  type EvidenceRef,
} from '../core/index.js';
import { sqliteLiteral, type SqliteStore } from '../storage/sqlite.js';
import { AuditEventConflictError, entryColumns, type AuditEventStore, type ListAuditEventFilters, type StoredAuditEvent } from './store.js';

interface SqliteAuditEventRow {
  id: number;
  recorded_at: string;
  event_digest: string;
  event_json: string;
}

interface SqliteAuditEvidenceRow {
  ref_json: string;
  ciphertext: Uint8Array;
}

function isUniqueViolation(error: unknown): boolean {
  return error instanceof Error && /UNIQUE constraint failed/.test(error.message);
}

/** The SQLite store, for the self-hosted single-file deployment; same contract as `PrismaAuditSink`. */
export class SqliteAuditSink implements AuditEventStore {
  constructor(private readonly sqlite: SqliteStore) {}

  async append(entry: AuditTrailEntry): Promise<void> {
    const c = entryColumns(entry);
    try {
      this.sqlite.execute(`
        INSERT INTO audit_events (
          event_id, event_type, family, source_id, source_sequence, previous_source_event_digest,
          event_digest, occurred_at, recorded_at, correlation_id, actor_ref, canonical, event_json
        ) VALUES (
          ${sqliteLiteral(c.eventId)}, ${sqliteLiteral(c.eventType)}, ${sqliteLiteral(c.family)}, ${sqliteLiteral(c.sourceId)},
          ${c.sourceSequence === null ? 'NULL' : c.sourceSequence.toString()}, ${sqliteLiteral(c.previousSourceEventDigest)},
          ${sqliteLiteral(c.eventDigest)}, ${sqliteLiteral(c.occurredAt)}, ${sqliteLiteral(new Date())},
          ${sqliteLiteral(c.correlationId)}, ${sqliteLiteral(c.actorRef)}, ${sqliteLiteral(entry.canonical)},
          ${sqliteLiteral(JSON.stringify(entry.event))}
        )
      `);
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const existing = this.sqlite.query<{ event_digest: string }>(
        `SELECT event_digest FROM audit_events WHERE source_id = ${sqliteLiteral(c.sourceId)} AND event_id = ${sqliteLiteral(c.eventId)}`,
      );
      if (existing[0]?.event_digest === entry.eventDigest) return;
      throw new AuditEventConflictError(c.sourceId, c.eventId);
    }
  }

  async list(filters: ListAuditEventFilters): Promise<StoredAuditEvent[]> {
    const conditions: string[] = [];
    if (filters.eventType !== undefined) conditions.push(`event_type = ${sqliteLiteral(filters.eventType)}`);
    if (filters.family !== undefined) conditions.push(`family = ${sqliteLiteral(filters.family)}`);
    if (filters.correlationId !== undefined) conditions.push(`correlation_id = ${sqliteLiteral(filters.correlationId)}`);
    if (filters.since !== undefined) conditions.push(`recorded_at >= ${sqliteLiteral(filters.since)}`);
    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const rows = this.sqlite.query<SqliteAuditEventRow>(`
      SELECT id, recorded_at, event_digest, event_json FROM audit_events
      ${where}
      ORDER BY recorded_at DESC, id DESC
      LIMIT ${Math.trunc(filters.limit)}
    `);
    return rows.map((row) => ({
      id: String(row.id),
      recordedAt: new Date(row.recorded_at),
      eventDigest: row.event_digest as Digest,
      event: parseAuditEvent(JSON.parse(row.event_json)),
    }));
  }

  async putIfAbsent(object: EncryptedEvidence): Promise<EvidenceRef> {
    assertEvidenceMatchesRef(object);
    const { ref } = object;
    try {
      this.sqlite.execute(`
        INSERT INTO audit_evidence (object_id, ciphertext_digest, size, media_type, key_id, ref_json, ciphertext, stored_at)
        VALUES (
          ${sqliteLiteral(ref.objectId)}, ${sqliteLiteral(ref.ciphertextDigest)}, ${Number(ref.size)}, ${sqliteLiteral(ref.mediaType)},
          ${sqliteLiteral(ref.encryption.keyId)}, ${sqliteLiteral(JSON.stringify(ref))},
          X'${Buffer.from(object.ciphertext).toString('hex')}', ${sqliteLiteral(new Date())}
        )
      `);
      return ref;
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const existing = await this.get(ref.objectId);
      if (existing !== null && existing.ref.ciphertextDigest === ref.ciphertextDigest) return existing.ref;
      throw new AuditEvidenceError('Opaque evidence object id collision', { objectId: ref.objectId });
    }
  }

  async get(objectId: string): Promise<EncryptedEvidence | null> {
    const rows = this.sqlite.query<SqliteAuditEvidenceRow>(
      `SELECT ref_json, ciphertext FROM audit_evidence WHERE object_id = ${sqliteLiteral(objectId)}`,
    );
    const row = rows[0];
    if (row === undefined) return null;
    return { ref: JSON.parse(row.ref_json) as EvidenceRef, ciphertext: new Uint8Array(row.ciphertext) };
  }
}
