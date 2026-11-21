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

import { join } from 'node:path';
import type pg from 'pg';
import {
  AUDIT_BINDING_HELIX,
  AUDIT_ERROR_CODES,
  AuditProtocolError,
  AuditRetentionService,
  AuditTrail,
  EnvSigner,
  EvidenceEncryptor,
  FileRecorderWitness,
  ManagedAuditRecorder,
  MemoryAuditJournal,
  MemoryRecorderWitness,
  RecorderAuditSink,
  TeeAuditSink,
  derivePublicKey,
  digestText,
  generateKeyPair,
  jwsAuditSigner,
  partyRefSchema,
  publicKeyToMultibase,
  type AuditRecorderWitness,
  type AuditSigner,
  type AuditSink,
  type Config,
  type PartyRef,
} from '../core/index.js';
import { normalizeEd25519PrivateKeyHex } from '../core/crypto/keys.js';
import type { SqliteStore } from '../storage/sqlite.js';
import { MemoryAuditEvidenceStore } from './memory-evidence.js';
import { PostgresAuditEvidenceStore } from './postgres-evidence.js';
import { PostgresAuditJournal } from './postgres-journal.js';
import { SqliteAuditEvidenceStore } from './sqlite-evidence.js';
import { SqliteAuditJournal } from './sqlite-journal.js';
import type { ApiAuditStorage } from './store.js';
import { StreamAuditSink } from './stream-sink.js';

export type ApiAuditConfig = Pick<
  Config,
  | 'NODE_ENV'
  | 'AUDIT_LOG_DESTINATION'
  | 'AUDIT_LOG_PATH'
  | 'AUDIT_SOURCE_ID'
  | 'AUDIT_INCLUDE_TOOL_NAMES'
  | 'AUDIT_EVIDENCE_KEY'
  | 'AUDIT_EVIDENCE_KEY_ID'
  | 'HELIX_ISSUER_DID'
  | 'HELIX_SIGNING_KEY'
  | 'AUDIT_RECORDER_SIGNING_KEY'
  | 'AUDIT_RECORDER_DID'
  | 'AUDIT_RECORDER_KID'
  | 'AUDIT_RECORDER_MODE'
  | 'AUDIT_RECORDER_TENANTS'
  | 'AUDIT_RECORDER_WITNESS_PATH'
  | 'AUDIT_RETENTION_MIN_DAYS'
>;

export interface ApiAuditStorageDeps {
  pool?: pg.Pool | null | undefined;
  sqlite?: SqliteStore | undefined;
}

/** The journal and vault for the configured storage adapter: PostgreSQL, SQLite, or memory when neither is given. */
export function createApiAuditStorage(deps: ApiAuditStorageDeps): ApiAuditStorage {
  if (deps.pool) return { journal: new PostgresAuditJournal(deps.pool), evidence: new PostgresAuditEvidenceStore(deps.pool) };
  if (deps.sqlite) return { journal: new SqliteAuditJournal(deps.sqlite), evidence: new SqliteAuditEvidenceStore(deps.sqlite) };
  return { journal: new MemoryAuditJournal(), evidence: new MemoryAuditEvidenceStore() };
}

/** This deployment as a party: its issuer DID when it has one, else a commitment to the fixed name `helix-api`. */
export function apiPartyRef(config: Pick<ApiAuditConfig, 'HELIX_ISSUER_DID'>): PartyRef {
  if (/^did:[^\r\n]{3,}$/.test(config.HELIX_ISSUER_DID)) return { kind: 'public_did', did: config.HELIX_ISSUER_DID };
  return { kind: 'keyed_commitment', value: digestText('helix-api'), keyId: 'helix-api-tenant-v1' };
}

/**
 * The recorder's receipt signer: an L1-C `EnvSigner` over
 * AUDIT_RECORDER_SIGNING_KEY (a `KeyStore` handle once F-3 lands), never the
 * issuer key. Its DID defaults to the `did:key` of that key, so a verifier
 * resolves it offline.
 */
export function createRecorderSigner(config: ApiAuditConfig): AuditSigner {
  let secret = config.AUDIT_RECORDER_SIGNING_KEY;
  if (secret === undefined) {
    if (config.NODE_ENV === 'production') {
      throw new AuditProtocolError(
        AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
        'AUDIT_RECORDER_SIGNING_KEY is required in production: the audit recorder signs receipts with its own key',
      );
    }
    secret = generateKeyPair().privateKey;
  }
  const normalized = normalizeEd25519PrivateKeyHex(secret)!;
  if (normalized === normalizeEd25519PrivateKeyHex(config.HELIX_SIGNING_KEY)) {
    throw new AuditProtocolError(
      AUDIT_ERROR_CODES.INVALID_CONFIGURATION,
      'AUDIT_RECORDER_SIGNING_KEY must not be the issuer key (HELIX_SIGNING_KEY): the recorder key is separate from issuer keys',
    );
  }
  const multibase = publicKeyToMultibase(derivePublicKey(normalized));
  const did = config.AUDIT_RECORDER_DID ?? `did:key:${multibase}`;
  const kid = config.AUDIT_RECORDER_KID ?? multibase;
  return jwsAuditSigner(new EnvSigner({ did, kid, envVar: 'AUDIT_RECORDER_SIGNING_KEY', env: { AUDIT_RECORDER_SIGNING_KEY: normalized } }));
}

/** The tenants a self-hosted recorder keeps ledgers for: AUDIT_RECORDER_TENANTS, else this API's own. */
function selfHostedTenants(config: ApiAuditConfig): PartyRef[] {
  if (config.AUDIT_RECORDER_TENANTS === undefined) return [apiPartyRef(config)];
  let parsed: unknown;
  try {
    parsed = JSON.parse(config.AUDIT_RECORDER_TENANTS);
  } catch {
    parsed = undefined;
  }
  const tenants = Array.isArray(parsed) ? parsed.map((tenant) => partyRefSchema.safeParse(tenant)) : [];
  if (tenants.length === 0 || tenants.some((tenant) => !tenant.success)) {
    throw new AuditProtocolError(AUDIT_ERROR_CODES.INVALID_CONFIGURATION, 'AUDIT_RECORDER_TENANTS must be a JSON array of party references');
  }
  return tenants.map((tenant) => tenant.data as PartyRef);
}

/**
 * The longest delegation lifetime in milliseconds over every credential this
 * deployment issued (`vcs`: `expiresAt` minus issuance); `Infinity` when one
 * has no expiry; 0 when there are none (memory mode keeps none durably).
 */
export function delegationRetentionFloor(deps: ApiAuditStorageDeps): () => Promise<number> {
  if (deps.pool) {
    const pool = deps.pool;
    return async () => {
      const { rows } = await pool.query<{ unbounded: string; longest: string | null }>(
        `SELECT COUNT(*) FILTER (WHERE "expiresAt" IS NULL) AS unbounded,
                MAX(EXTRACT(EPOCH FROM ("expiresAt" - "createdAt")) * 1000) AS longest
           FROM "vcs"`,
      );
      const row = rows[0]!;
      if (Number(row.unbounded) > 0) return Number.POSITIVE_INFINITY;
      return Math.max(0, Number(row.longest ?? 0));
    };
  }
  if (deps.sqlite) {
    const sqlite = deps.sqlite;
    return async () => {
      const rows = sqlite.select<{ expires_at: string | null; created_at: string }>(`SELECT expires_at, created_at FROM vcs`);
      let longest = 0;
      for (const row of rows) {
        if (row.expires_at === null) return Number.POSITIVE_INFINITY;
        longest = Math.max(longest, Date.parse(row.expires_at) - Date.parse(row.created_at));
      }
      return longest;
    };
  }
  return async () => 0;
}

export interface ApiAudit {
  trail: AuditTrail;
  recorder: ManagedAuditRecorder;
  retention: AuditRetentionService;
  storage: ApiAuditStorage;
  /** Present when AUDIT_EVIDENCE_KEY is set. */
  evidenceEncryptor?: EvidenceEncryptor;
}

export interface CreateApiAuditOptions {
  deps?: ApiAuditStorageDeps;
  signer?: AuditSigner;
  witness?: AuditRecorderWitness;
  /** Where relative witness paths resolve; default the working directory. */
  baseDir?: string;
  extraSinks?: AuditSink[];
  clock?: () => number;
}

/**
 * The managed recorder over the storage, the retention service, and the
 * API's own producer trail, whose sink submits to the recorder (plus the
 * stdout/file echo), bound to this deployment as producer and tenant.
 */
export function createApiAudit(config: ApiAuditConfig, storage: ApiAuditStorage, options: CreateApiAuditOptions = {}): ApiAudit {
  const durable = storage.journal.capabilities.durability === 'durable';
  const witness =
    options.witness ??
    (config.AUDIT_RECORDER_WITNESS_PATH !== undefined || durable
      ? new FileRecorderWitness(config.AUDIT_RECORDER_WITNESS_PATH ?? join(options.baseDir ?? process.cwd(), 'data', 'audit-recorder-witness.json'))
      : new MemoryRecorderWitness());
  const party = apiPartyRef(config);
  const clock = options.clock ?? Date.now;
  const recorder = new ManagedAuditRecorder({
    store: storage.journal,
    signer: options.signer ?? createRecorderSigner(config),
    clock: { now: clock },
    binding: AUDIT_BINDING_HELIX,
    evidence: storage.evidence,
    witness,
    mode: config.AUDIT_RECORDER_MODE,
    ...(config.AUDIT_RECORDER_MODE === 'self-hosted' ? { tenants: selfHostedTenants(config) } : {}),
  });
  const retention = new AuditRetentionService({
    recorder,
    journal: storage.journal,
    retention: storage.evidence,
    delegationRetentionFloorMs: delegationRetentionFloor(options.deps ?? {}),
    policy: { minimumRetentionMs: config.AUDIT_RETENTION_MIN_DAYS * 86_400_000 },
    clock,
  });
  const sinks: AuditSink[] = [new RecorderAuditSink(recorder)];
  if (config.AUDIT_LOG_DESTINATION !== 'none') {
    sinks.push(new StreamAuditSink({ destination: config.AUDIT_LOG_DESTINATION, path: config.AUDIT_LOG_PATH }));
  }
  sinks.push(...(options.extraSinks ?? []));
  const evidenceEncryptor =
    config.AUDIT_EVIDENCE_KEY === undefined ? undefined : new EvidenceEncryptor({ key: config.AUDIT_EVIDENCE_KEY, keyId: config.AUDIT_EVIDENCE_KEY_ID });
  const trail = new AuditTrail({
    sink: sinks.length === 1 ? sinks[0]! : new TeeAuditSink(sinks),
    sourceId: config.AUDIT_SOURCE_ID,
    producer: party,
    tenantRef: party,
    binding: AUDIT_BINDING_HELIX,
    includeToolNames: config.AUDIT_INCLUDE_TOOL_NAMES,
    clock,
    ...(evidenceEncryptor === undefined ? {} : { evidence: { encryptor: evidenceEncryptor, store: storage.evidence } }),
  });
  return { trail, recorder, retention, storage, ...(evidenceEncryptor === undefined ? {} : { evidenceEncryptor }) };
}
