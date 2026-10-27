import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import { vcLookupColumns } from '../core/vc-lookup.js';

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

export function sqliteLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (value instanceof Date) return shellQuote(value.toISOString());
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  return shellQuote(String(value));
}

export class SqliteStore {
  private readonly db: Database.Database;

  /**
   * @param extraDdl Additional `CREATE TABLE IF NOT EXISTS`/index statements
   * run once, immediately after core's own schema, against the same file —
   * the extension seam a downstream product (e.g. a hosted/enterprise
   * build) uses to add its own tables to the same SQLite database without
   * forking this class. Core itself never passes this.
   */
  constructor(
    public readonly dbPath: string,
    private readonly extraDdl?: string,
  ) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.init();
  }

  private init(): void {
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');

    this.db.exec(
      `
CREATE TABLE IF NOT EXISTS dids (
  id TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL,
  controller TEXT NOT NULL,
  public_key TEXT NOT NULL,
  public_key_multibase TEXT,
  hedera_topic_id TEXT,
  hedera_sequence_number INTEGER,
  hedera_transaction_id TEXT NOT NULL,
  did_document TEXT NOT NULL,
  deactivated_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dids_public_key ON dids(public_key);
CREATE INDEX IF NOT EXISTS idx_dids_public_key_multibase ON dids(public_key_multibase);

CREATE TABLE IF NOT EXISTS did_updates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did_id TEXT NOT NULL,
  update_type TEXT NOT NULL,
  hedera_transaction_id TEXT NOT NULL,
  payload_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vcs (
  vc_id TEXT PRIMARY KEY,
  subject_did TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  vc_json TEXT NOT NULL,
  privilege_scopes TEXT,
  status_list_index INTEGER NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  renewed_by_vc_id TEXT,
  delegated_from TEXT,
  delegation_depth INTEGER,
  max_delegation_depth INTEGER,
  parent_vc_id TEXT,
  vc_type TEXT,
  issuer_did TEXT,
  user_did TEXT,
  scope_key TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vcs_subject_did ON vcs(subject_did);

CREATE TABLE IF NOT EXISTS status_list_entries (
  list_id TEXT PRIMARY KEY,
  encoded_list TEXT NOT NULL,
  next_index INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS did_keys (
  id TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  subject_type TEXT NOT NULL DEFAULT 'agent',
  encrypted_private_key TEXT NOT NULL,
  iv TEXT NOT NULL,
  auth_tag TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_did_keys_did ON did_keys(did);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  agent_name TEXT NOT NULL,
  requested_scopes TEXT NOT NULL,
  requested_domains TEXT NOT NULL,
  max_delegation_depth INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  challenge_id TEXT NOT NULL UNIQUE,
  nonce TEXT NOT NULL,
  did TEXT NOT NULL,
  purpose TEXT NOT NULL,
  pending_public_key_hex TEXT,
  pending_domains TEXT,
  pending_did_create_state_json TEXT,
  pending_did_create_payload_hex TEXT,
  expires_at TEXT NOT NULL,
  verified_at TEXT,
  created_at TEXT NOT NULL,
  enrollment_token_id TEXT
);

CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  did TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  domain TEXT NOT NULL,
  required_scope TEXT NOT NULL,
  description TEXT,
  framework TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_services_name ON services(name);

CREATE TABLE IF NOT EXISTS agents (
  did TEXT PRIMARY KEY,
  name TEXT,
  visibility TEXT NOT NULL DEFAULT 'private',
  visibility_changed_at TEXT,
  published_at TEXT,
  credential_vc_id TEXT,
  credential_expires_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agents_visibility_published_at ON agents(visibility, published_at);
CREATE INDEX IF NOT EXISTS idx_agents_credential_vc_id ON agents(credential_vc_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  event_type TEXT NOT NULL,
  request_id TEXT,
  payload_json TEXT NOT NULL
);
      `.trim(),
    );
    this.migrateAgentKeysToDidKeys();
    this.migrateVcLookupColumns();

    if (this.extraDdl) {
      this.db.exec(this.extraDdl);
    }
  }

  /**
   * A SQLite file that predates did_keys still has the old agent_keys
   * table. Copy its rows over (they are all agent keys) and drop it; no-op
   * on a fresh file or once already migrated.
   */
  private migrateAgentKeysToDidKeys(): void {
    const legacy = this.db
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'agent_keys'`)
      .all();
    if (legacy.length === 0) return;
    this.db.exec(`
      INSERT OR IGNORE INTO did_keys (id, did, subject_type, encrypted_private_key, iv, auth_tag, algorithm, created_at)
      SELECT id, did, 'agent', encrypted_private_key, iv, auth_tag, algorithm, created_at FROM agent_keys;
      DROP TABLE agent_keys;
    `);
  }

  /**
   * A SQLite file that predates the vcs lookup columns (vc_type, issuer_did,
   * user_did, scope_key) gets them added and backfilled from vc_json. No-op
   * on a fresh file or once already migrated.
   */
  private migrateVcLookupColumns(): void {
    const columns = new Set(
      (this.db.prepare(`PRAGMA table_info(vcs)`).all() as Array<{ name: string }>).map((c) => c.name),
    );
    if (columns.has('scope_key')) {
      this.db.exec(`CREATE INDEX IF NOT EXISTS idx_vcs_grant_lookup ON vcs(subject_did, vc_type, issuer_did, user_did)`);
      return;
    }
    for (const column of ['vc_type', 'issuer_did', 'user_did', 'scope_key']) {
      if (!columns.has(column)) this.db.exec(`ALTER TABLE vcs ADD COLUMN ${column} TEXT`);
    }
    const rows = this.db.prepare(`SELECT vc_id, vc_json FROM vcs`).all() as Array<{ vc_id: string; vc_json: string }>;
    const update = this.db.prepare(
      `UPDATE vcs SET vc_type = ?, issuer_did = ?, user_did = ?, scope_key = ? WHERE vc_id = ?`,
    );
    for (const row of rows) {
      const columns = vcLookupColumns(JSON.parse(row.vc_json));
      update.run(columns.vcType, columns.issuerDid, columns.userDid, columns.scopeKey, row.vc_id);
    }
    this.db.exec(`CREATE INDEX IF NOT EXISTS idx_vcs_grant_lookup ON vcs(subject_did, vc_type, issuer_did, user_did)`);
  }

  execute(sql: string): void {
    this.db.exec(sql);
  }

  /**
   * Like execute(), but for a single parameterless UPDATE/DELETE where the
   * caller needs to know how many rows were actually affected (e.g. a
   * conditional `WHERE consumed_at IS NULL` used for single-use tokens).
   * exec() doesn't expose this, and comparing timestamps instead is
   * unreliable — two calls issued within the same millisecond produce
   * identical Date.now() values, so a timestamp-equality check can't tell
   * "I just set this" apart from "someone else already set this to the same
   * value" (see the SDK-API-only design's prepare-endpoint idempotency
   * requirement — this is exactly the race it's meant to close).
   */
  run(sql: string): { changes: number } {
    return this.db.prepare(sql).run();
  }

  query<T = Record<string, unknown>>(sql: string): T[] {
    return this.db.prepare(sql).all() as T[];
  }
}
