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

import type { PrismaClient } from '@prisma/client';
import {
  assertEvidenceMatchesRef,
  AuditEvidenceError,
  parseAuditEvent,
  type AuditTrailEntry,
  type Digest,
  type EncryptedEvidence,
  type EvidenceRef,
} from '../core/index.js';
import { AuditEventConflictError, entryColumns, type AuditEventStore, type ListAuditEventFilters, type StoredAuditEvent } from './store.js';

interface AuditEventRow {
  id: string;
  recordedAt: Date;
  eventDigest: string;
  event: unknown;
}

interface AuditEvidenceRow {
  ref: unknown;
  ciphertext: Uint8Array;
}

/** The slice of the Prisma client this sink uses; typed loosely so tests can hand in a stub. */
type PrismaLike = {
  auditEvent: {
    create(args: { data: Record<string, unknown> }): Promise<unknown>;
    findUnique(args: { where: Record<string, unknown> }): Promise<AuditEventRow | null>;
    findMany(args: Record<string, unknown>): Promise<AuditEventRow[]>;
  };
  auditEvidence: {
    create(args: { data: Record<string, unknown> }): Promise<unknown>;
    findUnique(args: { where: { objectId: string } }): Promise<AuditEvidenceRow | null>;
  };
};

function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'P2002';
}

/**
 * The PostgreSQL store behind the API's trail (A-1). One row per event,
 * the full event as JSON beside its canonical text and digest; a replay of
 * the same event (same source, id and digest) is idempotent, the same id
 * with different content is refused.
 */
export class PrismaAuditSink implements AuditEventStore {
  private readonly db: PrismaLike;

  constructor(prisma: PrismaClient) {
    this.db = prisma as unknown as PrismaLike;
  }

  async append(entry: AuditTrailEntry): Promise<void> {
    const columns = entryColumns(entry);
    try {
      await this.db.auditEvent.create({ data: { ...columns, canonical: entry.canonical, event: entry.event } });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const existing = await this.db.auditEvent.findUnique({
        where: { sourceId_eventId: { sourceId: columns.sourceId, eventId: columns.eventId } },
      });
      if (existing !== null && existing.eventDigest === entry.eventDigest) return;
      throw new AuditEventConflictError(columns.sourceId, columns.eventId);
    }
  }

  async list(filters: ListAuditEventFilters): Promise<StoredAuditEvent[]> {
    const where: Record<string, unknown> = {};
    if (filters.eventType !== undefined) where['eventType'] = filters.eventType;
    if (filters.family !== undefined) where['family'] = filters.family;
    if (filters.correlationId !== undefined) where['correlationId'] = filters.correlationId;
    if (filters.since !== undefined) where['recordedAt'] = { gte: filters.since };
    const rows = await this.db.auditEvent.findMany({
      where,
      orderBy: [{ recordedAt: 'desc' }, { id: 'desc' }],
      take: filters.limit,
    });
    return rows.map((row) => ({
      id: row.id,
      recordedAt: row.recordedAt,
      eventDigest: row.eventDigest as Digest,
      event: parseAuditEvent(row.event),
    }));
  }

  async putIfAbsent(object: EncryptedEvidence): Promise<EvidenceRef> {
    assertEvidenceMatchesRef(object);
    const { ref } = object;
    try {
      await this.db.auditEvidence.create({
        data: {
          objectId: ref.objectId,
          ciphertextDigest: ref.ciphertextDigest,
          size: BigInt(ref.size),
          mediaType: ref.mediaType,
          keyId: ref.encryption.keyId,
          ref,
          ciphertext: Buffer.from(object.ciphertext),
        },
      });
      return ref;
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const existing = await this.get(ref.objectId);
      if (existing !== null && existing.ref.ciphertextDigest === ref.ciphertextDigest) return existing.ref;
      throw new AuditEvidenceError('Opaque evidence object id collision', { objectId: ref.objectId });
    }
  }

  async get(objectId: string): Promise<EncryptedEvidence | null> {
    const row = await this.db.auditEvidence.findUnique({ where: { objectId } });
    if (row === null) return null;
    return { ref: row.ref as EvidenceRef, ciphertext: new Uint8Array(row.ciphertext) };
  }
}
