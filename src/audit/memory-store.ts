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

import { MemoryEvidenceStore, auditEventFamily, type AuditTrailEntry } from '../core/index.js';
import { AuditEventConflictError, type AuditEventStore, type ListAuditEventFilters, type StoredAuditEvent } from './store.js';

/**
 * The in-memory store (HELIX_STORAGE_ADAPTER unset, tests, local runs). Unlike
 * the legacy in-memory audit log it retains and lists what it records.
 */
export class MemoryAuditStore extends MemoryEvidenceStore implements AuditEventStore {
  readonly entries: Array<StoredAuditEvent & { canonical: string }> = [];
  private readonly byKey = new Map<string, string>();

  async append(entry: AuditTrailEntry): Promise<void> {
    const key = `${entry.event.source.sourceId}\0${entry.event.eventId}`;
    const existing = this.byKey.get(key);
    if (existing !== undefined) {
      if (existing === entry.eventDigest) return;
      throw new AuditEventConflictError(entry.event.source.sourceId, entry.event.eventId);
    }
    this.byKey.set(key, entry.eventDigest);
    this.entries.push({
      id: String(this.entries.length + 1),
      recordedAt: new Date(),
      eventDigest: entry.eventDigest,
      event: entry.event,
      canonical: entry.canonical,
    });
  }

  async list(filters: ListAuditEventFilters): Promise<StoredAuditEvent[]> {
    return this.entries
      .filter(
        (row) =>
          (filters.eventType === undefined || row.event.eventType === filters.eventType) &&
          (filters.family === undefined || auditEventFamily(row.event.eventType) === filters.family) &&
          (filters.correlationId === undefined || row.event.correlationId === filters.correlationId) &&
          (filters.since === undefined || row.recordedAt.getTime() >= filters.since.getTime()),
      )
      .reverse()
      .slice(0, filters.limit)
      .map((row) => ({ id: row.id, recordedAt: row.recordedAt, eventDigest: row.eventDigest, event: row.event }));
  }
}
