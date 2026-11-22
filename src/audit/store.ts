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
import { ErrorCode, HelixError, type AuditListCursor } from '../core/index.js';

/** The vault the recorder writes submitted ciphertext to, and the retention store over it. */
export interface ApiAuditEvidenceStore extends EvidenceStore, AuditRetentionStore {
  has: AuditRecorderEvidenceStore['has'];
  discardUncommitted: NonNullable<AuditRecorderEvidenceStore['discardUncommitted']>;
}

export interface ApiAuditStorage {
  journal: AuditLedgerStore;
  evidence: ApiAuditEvidenceStore;
}

/**
 * The opaque cursor of a listing page: the last entry's service time and
 * position (`AuditListCursor`), as base64url JSON. Every Helix audit-log
 * listing (core's, a hosted deployment's) pages with this one cursor.
 */
export function encodeAuditCursor(cursor: AuditListCursor): string {
  return Buffer.from(JSON.stringify([cursor.recordedAt, cursor.ledgerId, cursor.ledgerEpochId, cursor.sequence]), 'utf8').toString('base64url');
}

/** The cursor a page handed out; a value it could not have handed out is a 400. Empty or absent: the first page. */
export function decodeAuditCursor(value: string | undefined): AuditListCursor | undefined {
  if (value === undefined || value === '') return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
  } catch {
    parsed = undefined;
  }
  if (
    Array.isArray(parsed) &&
    parsed.length === 4 &&
    Number.isSafeInteger(parsed[0]) &&
    typeof parsed[1] === 'string' &&
    typeof parsed[2] === 'string' &&
    typeof parsed[3] === 'string' &&
    /^(0|[1-9][0-9]*)$/.test(parsed[3])
  ) {
    return { recordedAt: parsed[0] as number, ledgerId: parsed[1], ledgerEpochId: parsed[2], sequence: parsed[3] };
  }
  throw new HelixError(ErrorCode.VALIDATION_ERROR, 'cursor is not one this API issued', 400);
}

/** One page of an audit-log listing: newest first, and the cursor of the next page (null on the last). */
export interface AuditLogPage<Item> {
  items: Item[];
  nextCursor: string | null;
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
