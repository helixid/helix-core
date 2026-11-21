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
 * Where the API keeps the audit ledger (story A-2): a journal (PostgreSQL,
 * SQLite, or memory) behind the authoritative recorder, and the evidence
 * vault with its legal holds. A-1's capture sinks are replaced: every event,
 * the API's own and every producer's, now enters through the recorder.
 */

import type {
  AuditLedgerStore,
  AuditRecorderEvidenceStore,
  AuditRetentionStore,
  Digest,
  EvidenceStore,
  SignedAuditEntry,
} from '../core/index.js';

/** The vault the recorder writes submitted ciphertext to, and the retention store over it. */
export interface ApiAuditEvidenceStore extends EvidenceStore, AuditRetentionStore {
  has: AuditRecorderEvidenceStore['has'];
  discardUncommitted: NonNullable<AuditRecorderEvidenceStore['discardUncommitted']>;
}

export interface ApiAuditStorage {
  journal: AuditLedgerStore;
  evidence: ApiAuditEvidenceStore;
}

/** One `GET /v1/audit-log` row: A-1's members, plus where the recorder placed the event and its receipt. */
export interface AuditLogRow {
  id: string;
  recordedAt: string;
  eventDigest: Digest;
  event: SignedAuditEntry['core']['event'];
  ledgerId: string;
  ledgerEpochId: string;
  sequence: string;
  entryDigest: Digest;
  receipt: SignedAuditEntry['recorderReceipt'];
}

export function auditLogRow(entry: SignedAuditEntry): AuditLogRow {
  return {
    id: `${entry.core.ledgerId}:${entry.core.ledgerEpochId}:${entry.core.sequence}`,
    recordedAt: new Date(entry.core.recordedAt).toISOString(),
    eventDigest: entry.eventDigest,
    event: entry.core.event,
    ledgerId: entry.core.ledgerId,
    ledgerEpochId: entry.core.ledgerEpochId,
    sequence: entry.core.sequence,
    entryDigest: entry.entryDigest,
    receipt: entry.recorderReceipt,
  };
}
