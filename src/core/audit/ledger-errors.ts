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

import { HelixError } from '../errors/HelixError.js';

/** The recorder's refusal codes (AUDITABILITY.md, `AUDIT_ERROR_CODES` upstream). */
export const AUDIT_ERROR_CODES = {
  LEDGER_MISMATCH: 'AUDIT_LEDGER_MISMATCH',
  EPOCH_MISMATCH: 'AUDIT_EPOCH_MISMATCH',
  EVENT_ID_CONFLICT: 'AUDIT_EVENT_ID_CONFLICT',
  APPEND_CONFLICT_EXHAUSTED: 'AUDIT_APPEND_CONFLICT_EXHAUSTED',
  JOURNAL_FAILURE: 'AUDIT_JOURNAL_FAILURE',
  EVIDENCE_FAILURE: 'AUDIT_EVIDENCE_FAILURE',
  EVIDENCE_LEGAL_HOLD: 'AUDIT_EVIDENCE_LEGAL_HOLD',
  RETENTION_REFUSED: 'AUDIT_RETENTION_REFUSED',
  UNAUTHORIZED_SUBMISSION: 'AUDIT_UNAUTHORIZED_SUBMISSION',
  INVALID_CONFIGURATION: 'AUDIT_INVALID_CONFIGURATION',
} as const;

export type AuditErrorCode = (typeof AUDIT_ERROR_CODES)[keyof typeof AUDIT_ERROR_CODES];

const STATUS: Record<AuditErrorCode, number> = {
  AUDIT_LEDGER_MISMATCH: 409,
  AUDIT_EPOCH_MISMATCH: 409,
  AUDIT_EVENT_ID_CONFLICT: 409,
  AUDIT_APPEND_CONFLICT_EXHAUSTED: 503,
  // Fail closed: the recorder refuses to sign rather than risk a second entry at a receipted sequence.
  AUDIT_JOURNAL_FAILURE: 503,
  AUDIT_EVIDENCE_FAILURE: 400,
  AUDIT_EVIDENCE_LEGAL_HOLD: 409,
  AUDIT_RETENTION_REFUSED: 409,
  AUDIT_UNAUTHORIZED_SUBMISSION: 403,
  AUDIT_INVALID_CONFIGURATION: 500,
};

/** A recorder, journal or retention refusal; `code` is one of `AUDIT_ERROR_CODES`. */
export class AuditProtocolError extends HelixError {
  declare readonly code: AuditErrorCode;

  constructor(code: AuditErrorCode, message: string, details?: Record<string, unknown>, options?: { cause?: unknown }) {
    super(code, message, STATUS[code], details);
    this.name = 'AuditProtocolError';
    if (options?.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
  }
}

/** True for an `AuditProtocolError` with the given code. */
export function isAuditError(error: unknown, code?: AuditErrorCode): error is AuditProtocolError {
  return error instanceof AuditProtocolError && (code === undefined || error.code === code);
}
