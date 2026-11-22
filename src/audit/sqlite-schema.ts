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
 * The A-2 journal on SQLite, for the self-hosted single-file deployment: the
 * same tables, constraints and append-only triggers as the PostgreSQL
 * migration `20261121120000_audit_recorder_journal`, in SQLite's dialect.
 * `SqliteStore` runs it at open; every statement is idempotent.
 */
export const AUDIT_JOURNAL_SQLITE_DDL = `
DROP TABLE IF EXISTS audit_events;

CREATE TABLE IF NOT EXISTS audit_ledgers (
  ledger_id TEXT PRIMARY KEY,
  tenant_key TEXT NOT NULL UNIQUE,
  tenant_ref TEXT NOT NULL,
  active_epoch_id TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_ledger_heads (
  position INTEGER PRIMARY KEY AUTOINCREMENT,
  ledger_id TEXT NOT NULL,
  ledger_epoch_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  entry_digest TEXT NOT NULL,
  recorder_did TEXT NOT NULL,
  recorder_kid TEXT NOT NULL,
  recorder_alg TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'sealed')),
  terminal_digest TEXT,
  seal_reason TEXT,
  successor_epoch_id TEXT,
  sealed_at INTEGER,
  UNIQUE (ledger_id, ledger_epoch_id)
);

CREATE TABLE IF NOT EXISTS audit_journal_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ledger_id TEXT NOT NULL,
  ledger_epoch_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL,
  event_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  family TEXT NOT NULL,
  event_digest TEXT NOT NULL,
  entry_digest TEXT NOT NULL,
  previous_entry_digest TEXT,
  recorded_at INTEGER NOT NULL,
  correlation_id TEXT,
  entry TEXT NOT NULL,
  UNIQUE (ledger_id, ledger_epoch_id, sequence),
  UNIQUE (ledger_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_audit_journal_type_recorded ON audit_journal_entries(event_type, recorded_at);
CREATE INDEX IF NOT EXISTS idx_audit_journal_family_recorded ON audit_journal_entries(family, recorded_at);
CREATE INDEX IF NOT EXISTS idx_audit_journal_correlation ON audit_journal_entries(correlation_id);

CREATE TABLE IF NOT EXISTS audit_legal_holds (
  hold_id TEXT PRIMARY KEY,
  ledger_id TEXT NOT NULL,
  target_kind TEXT NOT NULL,
  object_id TEXT,
  target TEXT NOT NULL,
  applied_at INTEGER NOT NULL,
  applied_by TEXT NOT NULL,
  released_at INTEGER,
  released_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_legal_holds_ledger ON audit_legal_holds(ledger_id);

CREATE TRIGGER IF NOT EXISTS audit_journal_entries_insert_guard BEFORE INSERT ON audit_journal_entries
BEGIN
  SELECT RAISE(ABORT, 'audit journal: an entry must be the genesis or the next one after an active head')
   WHERE (NOT EXISTS (SELECT 1 FROM audit_ledger_heads h WHERE h.ledger_id = NEW.ledger_id AND h.ledger_epoch_id = NEW.ledger_epoch_id)
          AND (NEW.sequence <> 0 OR NEW.previous_entry_digest IS NOT NULL))
      OR EXISTS (SELECT 1 FROM audit_ledger_heads h WHERE h.ledger_id = NEW.ledger_id AND h.ledger_epoch_id = NEW.ledger_epoch_id
          AND (h.status <> 'active' OR NEW.sequence <> h.sequence + 1 OR NEW.previous_entry_digest IS NOT h.entry_digest));
END;
CREATE TRIGGER IF NOT EXISTS audit_journal_entries_no_update BEFORE UPDATE ON audit_journal_entries
BEGIN SELECT RAISE(ABORT, 'audit storage is append-only: UPDATE on audit_journal_entries refused'); END;
CREATE TRIGGER IF NOT EXISTS audit_journal_entries_no_delete BEFORE DELETE ON audit_journal_entries
BEGIN SELECT RAISE(ABORT, 'audit storage is append-only: DELETE on audit_journal_entries refused'); END;

CREATE TRIGGER IF NOT EXISTS audit_ledger_heads_insert_guard BEFORE INSERT ON audit_ledger_heads
BEGIN
  SELECT RAISE(ABORT, 'audit head: an epoch head starts at its stored genesis')
   WHERE NEW.sequence <> 0 OR NEW.status <> 'active' OR NOT EXISTS (
     SELECT 1 FROM audit_journal_entries e WHERE e.ledger_id = NEW.ledger_id AND e.ledger_epoch_id = NEW.ledger_epoch_id
        AND e.sequence = 0 AND e.entry_digest = NEW.entry_digest);
END;
CREATE TRIGGER IF NOT EXISTS audit_ledger_heads_update_guard BEFORE UPDATE ON audit_ledger_heads
BEGIN
  SELECT RAISE(ABORT, 'audit head: a sealed epoch is final, and identity and authority never change')
   WHERE OLD.status = 'sealed' OR NEW.ledger_id <> OLD.ledger_id OR NEW.ledger_epoch_id <> OLD.ledger_epoch_id
      OR NEW.recorder_did <> OLD.recorder_did OR NEW.recorder_kid <> OLD.recorder_kid OR NEW.recorder_alg <> OLD.recorder_alg;
  SELECT RAISE(ABORT, 'audit head: a head only advances by one onto a stored entry')
   WHERE NEW.status = 'active' AND (NEW.sequence <> OLD.sequence + 1 OR NEW.terminal_digest IS NOT NULL OR NOT EXISTS (
     SELECT 1 FROM audit_journal_entries e WHERE e.ledger_id = NEW.ledger_id AND e.ledger_epoch_id = NEW.ledger_epoch_id
        AND e.sequence = NEW.sequence AND e.entry_digest = NEW.entry_digest));
  SELECT RAISE(ABORT, 'audit head: an epoch is sealed at its committed head with a terminal digest and a successor')
   WHERE NEW.status = 'sealed' AND (NEW.sequence <> OLD.sequence OR NEW.entry_digest <> OLD.entry_digest
      OR NEW.terminal_digest IS NULL OR NEW.successor_epoch_id IS NULL);
END;
CREATE TRIGGER IF NOT EXISTS audit_ledger_heads_no_delete BEFORE DELETE ON audit_ledger_heads
BEGIN SELECT RAISE(ABORT, 'audit storage is append-only: DELETE on audit_ledger_heads refused'); END;

CREATE TRIGGER IF NOT EXISTS audit_ledgers_guard BEFORE UPDATE ON audit_ledgers
BEGIN
  SELECT RAISE(ABORT, 'audit ledger: a ledger''s tenant never changes')
   WHERE NEW.ledger_id <> OLD.ledger_id OR NEW.tenant_key <> OLD.tenant_key OR NEW.created_at <> OLD.created_at;
END;
CREATE TRIGGER IF NOT EXISTS audit_ledgers_no_delete BEFORE DELETE ON audit_ledgers
BEGIN SELECT RAISE(ABORT, 'audit storage is append-only: DELETE on audit_ledgers refused'); END;

CREATE TRIGGER IF NOT EXISTS audit_legal_holds_guard BEFORE UPDATE ON audit_legal_holds
BEGIN
  SELECT RAISE(ABORT, 'audit legal hold: a hold is only ever released, once')
   WHERE OLD.released_at IS NOT NULL OR NEW.released_at IS NULL OR NEW.hold_id <> OLD.hold_id OR NEW.ledger_id <> OLD.ledger_id
      OR NEW.target <> OLD.target OR NEW.applied_at <> OLD.applied_at OR NEW.applied_by <> OLD.applied_by;
END;
CREATE TRIGGER IF NOT EXISTS audit_legal_holds_no_delete BEFORE DELETE ON audit_legal_holds
BEGIN SELECT RAISE(ABORT, 'audit storage is append-only: DELETE on audit_legal_holds refused'); END;
`;

/** Evidence disposal on SQLite: run after `audit_evidence` exists (A-1 created it with a NOT NULL ciphertext). */
export const AUDIT_EVIDENCE_SQLITE_TRIGGERS = `
CREATE TRIGGER IF NOT EXISTS audit_evidence_guard BEFORE UPDATE ON audit_evidence
BEGIN
  SELECT RAISE(ABORT, 'audit evidence: an object only ever has its ciphertext disposed, once')
   WHERE OLD.disposed_at IS NOT NULL OR NEW.disposed_at IS NULL OR length(NEW.ciphertext) <> 0
      OR NEW.object_id <> OLD.object_id OR NEW.ciphertext_digest <> OLD.ciphertext_digest OR NEW.ref_json <> OLD.ref_json;
  SELECT RAISE(ABORT, 'audit evidence: the object is under legal hold')
   WHERE EXISTS (SELECT 1 FROM audit_legal_holds h WHERE h.released_at IS NULL AND h.target_kind = 'evidence' AND h.object_id = OLD.object_id);
END;
CREATE TRIGGER IF NOT EXISTS audit_evidence_no_delete BEFORE DELETE ON audit_evidence
BEGIN SELECT RAISE(ABORT, 'audit storage is append-only: DELETE on audit_evidence refused'); END;
`;
