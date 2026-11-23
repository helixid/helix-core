// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Storage drivers for ConsentRepository (KYA-OS story L3-H): in-memory,
// Postgres through Prisma, and SQLite.

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../../storage/sqlite.js';
import { sqliteLiteral } from '../../storage/sqlite.js';
import { UnsupportedStorageDriverError, type StorageDriverDeps, type StorageDriverKind } from '../../storage/driver-registry.js';
import type {
  ConsentRequestPatch,
  ConsentRequestRow,
  ConsentRequestStatus,
  NewConsentRequest,
  NewUserConsent,
  NewUserKey,
  UserConsentFilter,
  UserConsentPatch,
  UserConsentRow,
  UserKeyRow,
} from '../consent.repository.js';

export interface ConsentStorageDriver {
  createRequest(row: NewConsentRequest): Promise<ConsentRequestRow>;
  findRequest(id: string): Promise<ConsentRequestRow | null>;
  transitionRequest(id: string, from: ConsentRequestStatus, patch: ConsentRequestPatch): Promise<ConsentRequestRow | null>;
  hasRequestForAgent(agentDid: string): Promise<boolean>;
  createUserKey(row: NewUserKey): Promise<UserKeyRow>;
  findUserKey(did: string): Promise<UserKeyRow | null>;
  findLiveUserKey(serviceDid: string, serviceUserRef: string): Promise<UserKeyRow | null>;
  listLiveUserKeys(): Promise<UserKeyRow[]>;
  markUserKeyShredded(did: string, at: Date): Promise<boolean>;
  createConsent(row: NewUserConsent): Promise<UserConsentRow>;
  findConsent(id: string): Promise<UserConsentRow | null>;
  updateConsent(id: string, patch: UserConsentPatch): Promise<UserConsentRow>;
  listConsents(filter: UserConsentFilter): Promise<UserConsentRow[]>;
}

function notFound(what: string): Error {
  return new Error(`${what} not found`);
}

const matches = (row: UserConsentRow, filter: UserConsentFilter): boolean =>
  (filter.userDid === undefined || row.userDid === filter.userDid) &&
  (filter.serviceDid === undefined || row.serviceDid === filter.serviceDid) &&
  (filter.serviceUserRef === undefined || row.serviceUserRef === filter.serviceUserRef) &&
  (filter.agentDid === undefined || row.agentDid === filter.agentDid);

const byCreated = <T extends { createdAt: Date }>(a: T, b: T): number => a.createdAt.getTime() - b.createdAt.getTime();

// ---------------------------------------------------------------- memory

export class InMemoryConsentStorageDriver implements ConsentStorageDriver {
  private readonly requests = new Map<string, ConsentRequestRow>();
  private readonly keys = new Map<string, UserKeyRow>();
  private readonly consents = new Map<string, UserConsentRow>();
  private tick = 0;

  /** Distinct creation times, so "oldest first" is the insertion order within one millisecond too. */
  private now(): Date {
    this.tick += 1;
    return new Date(Date.now() + this.tick / 1000);
  }

  async createRequest(row: NewConsentRequest): Promise<ConsentRequestRow> {
    if (this.requests.has(row.id)) throw new Error(`consent request already exists: ${row.id}`);
    const stored: ConsentRequestRow = structuredClone({ ...row, status: 'pending', pageTokenHash: null, createdAt: this.now(), decidedAt: null, consentId: null });
    this.requests.set(row.id, stored);
    return structuredClone(stored);
  }

  async findRequest(id: string): Promise<ConsentRequestRow | null> {
    const row = this.requests.get(id);
    return row ? structuredClone(row) : null;
  }

  async transitionRequest(id: string, from: ConsentRequestStatus, patch: ConsentRequestPatch): Promise<ConsentRequestRow | null> {
    const row = this.requests.get(id);
    if (!row || row.status !== from) return null;
    const next = { ...row, ...structuredClone(patch) };
    this.requests.set(id, next);
    return structuredClone(next);
  }

  async hasRequestForAgent(agentDid: string): Promise<boolean> {
    return [...this.requests.values()].some((row) => row.agentDid === agentDid);
  }

  async createUserKey(row: NewUserKey): Promise<UserKeyRow> {
    if (this.keys.has(row.did)) throw new Error(`user key already exists: ${row.did}`);
    const stored: UserKeyRow = { ...row, createdAt: this.now(), shreddedAt: null };
    this.keys.set(row.did, stored);
    return { ...stored };
  }

  async findUserKey(did: string): Promise<UserKeyRow | null> {
    const row = this.keys.get(did);
    return row ? { ...row } : null;
  }

  async findLiveUserKey(serviceDid: string, serviceUserRef: string): Promise<UserKeyRow | null> {
    const live = [...this.keys.values()]
      .filter((row) => row.serviceDid === serviceDid && row.serviceUserRef === serviceUserRef && row.shreddedAt === null)
      .sort(byCreated);
    const newest = live.at(-1);
    return newest ? { ...newest } : null;
  }

  async listLiveUserKeys(): Promise<UserKeyRow[]> {
    return [...this.keys.values()].filter((row) => row.shreddedAt === null).sort(byCreated).map((row) => ({ ...row }));
  }

  async markUserKeyShredded(did: string, at: Date): Promise<boolean> {
    const row = this.keys.get(did);
    if (!row || row.shreddedAt !== null) return false;
    this.keys.set(did, { ...row, shreddedAt: at });
    return true;
  }

  async createConsent(row: NewUserConsent): Promise<UserConsentRow> {
    if (this.consents.has(row.id)) throw new Error(`consent already exists: ${row.id}`);
    const stored: UserConsentRow = structuredClone({ ...row, createdAt: this.now(), withdrawnAt: null });
    this.consents.set(row.id, stored);
    return structuredClone(stored);
  }

  async findConsent(id: string): Promise<UserConsentRow | null> {
    const row = this.consents.get(id);
    return row ? structuredClone(row) : null;
  }

  async updateConsent(id: string, patch: UserConsentPatch): Promise<UserConsentRow> {
    const row = this.consents.get(id);
    if (!row) throw notFound(`consent ${id}`);
    const next = { ...row, ...structuredClone(patch) };
    this.consents.set(id, next);
    return structuredClone(next);
  }

  async listConsents(filter: UserConsentFilter): Promise<UserConsentRow[]> {
    return [...this.consents.values()].filter((row) => matches(row, filter)).sort(byCreated).map((row) => structuredClone(row));
  }
}

// ---------------------------------------------------------------- prisma

interface Delegate {
  create(args: unknown): Promise<unknown>;
  findUnique(args: unknown): Promise<unknown>;
  findFirst(args: unknown): Promise<unknown>;
  findMany(args: unknown): Promise<unknown[]>;
  update(args: unknown): Promise<unknown>;
  updateMany(args: unknown): Promise<{ count: number }>;
}

interface ConsentPrisma {
  consentRequest: Delegate;
  userKey: Delegate;
  userConsent: Delegate;
}

const asArray = <T>(value: unknown): T[] => (Array.isArray(value) ? (value as T[]) : []);

function requestFromPrisma(value: unknown): ConsentRequestRow | null {
  if (!value) return null;
  const row = { ...(value as Record<string, unknown>) };
  return {
    ...(row as unknown as ConsentRequestRow),
    display: (row['display'] ?? null) as ConsentRequestRow['display'],
  };
}

function consentFromPrisma(value: unknown): UserConsentRow | null {
  if (!value) return null;
  const row = value as UserConsentRow & { allowedAction: unknown; caveats: unknown };
  return {
    ...row,
    allowedAction: asArray<string>(row.allowedAction),
    caveats: Array.isArray(row.caveats) ? (row.caveats as Array<Record<string, unknown>>) : null,
  };
}

const keyFromPrisma = (value: unknown): UserKeyRow | null => (value ? ({ ...(value as UserKeyRow) }) : null);

/** Prisma's Json columns take undefined (leave unset) rather than null for an absent value. */
const jsonOrUndefined = (value: unknown): unknown => (value === null ? undefined : value);

export class PrismaConsentStorageDriver implements ConsentStorageDriver {
  private readonly db: ConsentPrisma;

  constructor(prisma: PrismaClient) {
    this.db = prisma as unknown as ConsentPrisma;
  }

  async createRequest(row: NewConsentRequest): Promise<ConsentRequestRow> {
    return requestFromPrisma(await this.db.consentRequest.create({ data: { ...row, display: jsonOrUndefined(row.display), status: 'pending' } }))!;
  }

  async findRequest(id: string): Promise<ConsentRequestRow | null> {
    return requestFromPrisma(await this.db.consentRequest.findUnique({ where: { id } }));
  }

  async transitionRequest(id: string, from: ConsentRequestStatus, patch: ConsentRequestPatch): Promise<ConsentRequestRow | null> {
    const { count } = await this.db.consentRequest.updateMany({ where: { id, status: from }, data: patch });
    return count === 1 ? this.findRequest(id) : null;
  }

  async hasRequestForAgent(agentDid: string): Promise<boolean> {
    return (await this.db.consentRequest.findFirst({ where: { agentDid }, select: { id: true } })) !== null;
  }

  async createUserKey(row: NewUserKey): Promise<UserKeyRow> {
    return keyFromPrisma(await this.db.userKey.create({ data: row }))!;
  }

  async findUserKey(did: string): Promise<UserKeyRow | null> {
    return keyFromPrisma(await this.db.userKey.findUnique({ where: { did } }));
  }

  async findLiveUserKey(serviceDid: string, serviceUserRef: string): Promise<UserKeyRow | null> {
    return keyFromPrisma(
      await this.db.userKey.findFirst({ where: { serviceDid, serviceUserRef, shreddedAt: null }, orderBy: { createdAt: 'desc' } }),
    );
  }

  async listLiveUserKeys(): Promise<UserKeyRow[]> {
    const rows = await this.db.userKey.findMany({ where: { shreddedAt: null }, orderBy: { createdAt: 'asc' } });
    return rows.map((row) => keyFromPrisma(row)!);
  }

  async markUserKeyShredded(did: string, at: Date): Promise<boolean> {
    const { count } = await this.db.userKey.updateMany({ where: { did, shreddedAt: null }, data: { shreddedAt: at } });
    return count === 1;
  }

  async createConsent(row: NewUserConsent): Promise<UserConsentRow> {
    return consentFromPrisma(await this.db.userConsent.create({ data: { ...row, caveats: jsonOrUndefined(row.caveats) } }))!;
  }

  async findConsent(id: string): Promise<UserConsentRow | null> {
    return consentFromPrisma(await this.db.userConsent.findUnique({ where: { id } }));
  }

  async updateConsent(id: string, patch: UserConsentPatch): Promise<UserConsentRow> {
    return consentFromPrisma(await this.db.userConsent.update({ where: { id }, data: patch }))!;
  }

  async listConsents(filter: UserConsentFilter): Promise<UserConsentRow[]> {
    const where = Object.fromEntries(Object.entries(filter).filter(([, value]) => value !== undefined));
    const rows = await this.db.userConsent.findMany({ where, orderBy: { createdAt: 'asc' } });
    return rows.map((row) => consentFromPrisma(row)!);
  }
}

// ---------------------------------------------------------------- sqlite

export const CONSENT_SQLITE_DDL = `
CREATE TABLE IF NOT EXISTS consent_requests (
  id TEXT PRIMARY KEY,
  service_did TEXT NOT NULL,
  service_user_ref TEXT NOT NULL,
  agent_did TEXT NOT NULL,
  grant_json TEXT NOT NULL,
  grant_digest TEXT NOT NULL,
  window_until TEXT NOT NULL,
  hop_lifetime_seconds INTEGER,
  display TEXT,
  return_url TEXT,
  status TEXT NOT NULL,
  page_token_hash TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  consent_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_consent_requests_agent ON consent_requests(agent_did);
CREATE TABLE IF NOT EXISTS user_keys (
  did TEXT PRIMARY KEY,
  kid TEXT NOT NULL,
  service_did TEXT NOT NULL,
  service_user_ref TEXT NOT NULL,
  created_at TEXT NOT NULL,
  shredded_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_user_keys_pair ON user_keys(service_did, service_user_ref);
CREATE TABLE IF NOT EXISTS user_consents (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  user_did TEXT NOT NULL,
  service_did TEXT NOT NULL,
  service_user_ref TEXT NOT NULL,
  agent_did TEXT NOT NULL,
  invocation_target TEXT NOT NULL,
  allowed_action TEXT NOT NULL,
  caveats TEXT,
  window_until TEXT NOT NULL,
  hop_lifetime_seconds INTEGER,
  consent_type TEXT NOT NULL,
  created_at TEXT NOT NULL,
  withdrawn_at TEXT,
  latest_hop_id TEXT NOT NULL,
  last_hop_until TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_consents_user ON user_consents(user_did);
CREATE INDEX IF NOT EXISTS idx_user_consents_pair ON user_consents(service_did, service_user_ref);
`;

type SqliteRow = Record<string, string | number | null>;

const date = (value: string | number | null | undefined): Date | null => (value === null || value === undefined ? null : new Date(String(value)));
const json = <T>(value: string | number | null | undefined): T | null => (value === null || value === undefined ? null : (JSON.parse(String(value)) as T));
const int = (value: string | number | null | undefined): number | null => (value === null || value === undefined ? null : Number(value));

function requestFromSqlite(row: SqliteRow | undefined): ConsentRequestRow | null {
  if (!row) return null;
  return {
    id: row['id'] as string,
    serviceDid: row['service_did'] as string,
    serviceUserRef: row['service_user_ref'] as string,
    agentDid: row['agent_did'] as string,
    grant: json(row['grant_json'])!,
    grantDigest: row['grant_digest'] as string,
    windowUntil: date(row['window_until'])!,
    hopLifetimeSeconds: int(row['hop_lifetime_seconds']),
    display: json(row['display']),
    returnUrl: (row['return_url'] as string | null) ?? null,
    status: row['status'] as ConsentRequestStatus,
    pageTokenHash: (row['page_token_hash'] as string | null) ?? null,
    expiresAt: date(row['expires_at'])!,
    createdAt: date(row['created_at'])!,
    decidedAt: date(row['decided_at']),
    consentId: (row['consent_id'] as string | null) ?? null,
  };
}

function keyFromSqlite(row: SqliteRow | undefined): UserKeyRow | null {
  if (!row) return null;
  return {
    did: row['did'] as string,
    kid: row['kid'] as string,
    serviceDid: row['service_did'] as string,
    serviceUserRef: row['service_user_ref'] as string,
    createdAt: date(row['created_at'])!,
    shreddedAt: date(row['shredded_at']),
  };
}

function consentFromSqlite(row: SqliteRow | undefined): UserConsentRow | null {
  if (!row) return null;
  return {
    id: row['id'] as string,
    requestId: row['request_id'] as string,
    userDid: row['user_did'] as string,
    serviceDid: row['service_did'] as string,
    serviceUserRef: row['service_user_ref'] as string,
    agentDid: row['agent_did'] as string,
    invocationTarget: row['invocation_target'] as string,
    allowedAction: json<string[]>(row['allowed_action']) ?? [],
    caveats: json(row['caveats']),
    windowUntil: date(row['window_until'])!,
    hopLifetimeSeconds: int(row['hop_lifetime_seconds']),
    consentType: row['consent_type'] as UserConsentRow['consentType'],
    createdAt: date(row['created_at'])!,
    withdrawnAt: date(row['withdrawn_at']),
    latestHopId: row['latest_hop_id'] as string,
    lastHopUntil: date(row['last_hop_until'])!,
  };
}

const REQUEST_COLUMNS: Record<keyof ConsentRequestPatch, string> = {
  status: 'status',
  pageTokenHash: 'page_token_hash',
  decidedAt: 'decided_at',
  consentId: 'consent_id',
};

const CONSENT_COLUMNS: Record<keyof UserConsentPatch, string> = {
  withdrawnAt: 'withdrawn_at',
  latestHopId: 'latest_hop_id',
  lastHopUntil: 'last_hop_until',
};

const FILTER_COLUMNS: Record<keyof UserConsentFilter, string> = {
  userDid: 'user_did',
  serviceDid: 'service_did',
  serviceUserRef: 'service_user_ref',
  agentDid: 'agent_did',
};

const sets = (patch: Record<string, unknown>, columns: Record<string, string>): string =>
  Object.entries(patch)
    .filter(([, value]) => value !== undefined)
    .map(([field, value]) => `${columns[field]} = ${sqliteLiteral(value)}`)
    .join(', ');

/** An ISO time a millisecond apart from the previous one this process wrote, so creation order survives equal clocks. */
let lastSqliteCreated = 0;
function sqliteCreatedAt(): Date {
  lastSqliteCreated = Math.max(Date.now(), lastSqliteCreated + 1);
  return new Date(lastSqliteCreated);
}

export class SqliteConsentStorageDriver implements ConsentStorageDriver {
  constructor(private readonly sqlite: SqliteStore) {
    this.sqlite.execute(CONSENT_SQLITE_DDL);
  }

  async createRequest(row: NewConsentRequest): Promise<ConsentRequestRow> {
    this.sqlite.execute(`
      INSERT INTO consent_requests (id, service_did, service_user_ref, agent_did, grant_json, grant_digest, window_until,
        hop_lifetime_seconds, display, return_url, status, page_token_hash, expires_at, created_at, decided_at, consent_id)
      VALUES (${sqliteLiteral(row.id)}, ${sqliteLiteral(row.serviceDid)}, ${sqliteLiteral(row.serviceUserRef)}, ${sqliteLiteral(row.agentDid)},
        ${sqliteLiteral(JSON.stringify(row.grant))}, ${sqliteLiteral(row.grantDigest)}, ${sqliteLiteral(row.windowUntil)},
        ${sqliteLiteral(row.hopLifetimeSeconds)}, ${sqliteLiteral(row.display === null ? null : JSON.stringify(row.display))},
        ${sqliteLiteral(row.returnUrl)}, 'pending', NULL, ${sqliteLiteral(row.expiresAt)}, ${sqliteLiteral(sqliteCreatedAt())}, NULL, NULL)
    `);
    return (await this.findRequest(row.id))!;
  }

  async findRequest(id: string): Promise<ConsentRequestRow | null> {
    return requestFromSqlite(this.sqlite.query<SqliteRow>(`SELECT * FROM consent_requests WHERE id = ${sqliteLiteral(id)} LIMIT 1`)[0]);
  }

  async transitionRequest(id: string, from: ConsentRequestStatus, patch: ConsentRequestPatch): Promise<ConsentRequestRow | null> {
    const assignments = sets(patch, REQUEST_COLUMNS) || `status = ${sqliteLiteral(from)}`;
    const { changes } = this.sqlite.run(
      `UPDATE consent_requests SET ${assignments} WHERE id = ${sqliteLiteral(id)} AND status = ${sqliteLiteral(from)}`,
    );
    return changes === 1 ? this.findRequest(id) : null;
  }

  async hasRequestForAgent(agentDid: string): Promise<boolean> {
    return this.sqlite.query(`SELECT 1 FROM consent_requests WHERE agent_did = ${sqliteLiteral(agentDid)} LIMIT 1`).length > 0;
  }

  async createUserKey(row: NewUserKey): Promise<UserKeyRow> {
    this.sqlite.execute(`
      INSERT INTO user_keys (did, kid, service_did, service_user_ref, created_at, shredded_at)
      VALUES (${sqliteLiteral(row.did)}, ${sqliteLiteral(row.kid)}, ${sqliteLiteral(row.serviceDid)}, ${sqliteLiteral(row.serviceUserRef)},
        ${sqliteLiteral(sqliteCreatedAt())}, NULL)
    `);
    return (await this.findUserKey(row.did))!;
  }

  async findUserKey(did: string): Promise<UserKeyRow | null> {
    return keyFromSqlite(this.sqlite.query<SqliteRow>(`SELECT * FROM user_keys WHERE did = ${sqliteLiteral(did)} LIMIT 1`)[0]);
  }

  async findLiveUserKey(serviceDid: string, serviceUserRef: string): Promise<UserKeyRow | null> {
    return keyFromSqlite(
      this.sqlite.query<SqliteRow>(
        `SELECT * FROM user_keys WHERE service_did = ${sqliteLiteral(serviceDid)} AND service_user_ref = ${sqliteLiteral(serviceUserRef)}
         AND shredded_at IS NULL ORDER BY created_at DESC LIMIT 1`,
      )[0],
    );
  }

  async listLiveUserKeys(): Promise<UserKeyRow[]> {
    return this.sqlite
      .query<SqliteRow>('SELECT * FROM user_keys WHERE shredded_at IS NULL ORDER BY created_at ASC')
      .map((row) => keyFromSqlite(row)!);
  }

  async markUserKeyShredded(did: string, at: Date): Promise<boolean> {
    const { changes } = this.sqlite.run(
      `UPDATE user_keys SET shredded_at = ${sqliteLiteral(at)} WHERE did = ${sqliteLiteral(did)} AND shredded_at IS NULL`,
    );
    return changes === 1;
  }

  async createConsent(row: NewUserConsent): Promise<UserConsentRow> {
    this.sqlite.execute(`
      INSERT INTO user_consents (id, request_id, user_did, service_did, service_user_ref, agent_did, invocation_target, allowed_action,
        caveats, window_until, hop_lifetime_seconds, consent_type, created_at, withdrawn_at, latest_hop_id, last_hop_until)
      VALUES (${sqliteLiteral(row.id)}, ${sqliteLiteral(row.requestId)}, ${sqliteLiteral(row.userDid)}, ${sqliteLiteral(row.serviceDid)},
        ${sqliteLiteral(row.serviceUserRef)}, ${sqliteLiteral(row.agentDid)}, ${sqliteLiteral(row.invocationTarget)},
        ${sqliteLiteral(JSON.stringify(row.allowedAction))}, ${sqliteLiteral(row.caveats === null ? null : JSON.stringify(row.caveats))},
        ${sqliteLiteral(row.windowUntil)}, ${sqliteLiteral(row.hopLifetimeSeconds)}, ${sqliteLiteral(row.consentType)},
        ${sqliteLiteral(sqliteCreatedAt())}, NULL, ${sqliteLiteral(row.latestHopId)}, ${sqliteLiteral(row.lastHopUntil)})
    `);
    return (await this.findConsent(row.id))!;
  }

  async findConsent(id: string): Promise<UserConsentRow | null> {
    return consentFromSqlite(this.sqlite.query<SqliteRow>(`SELECT * FROM user_consents WHERE id = ${sqliteLiteral(id)} LIMIT 1`)[0]);
  }

  async updateConsent(id: string, patch: UserConsentPatch): Promise<UserConsentRow> {
    const assignments = sets(patch, CONSENT_COLUMNS);
    if (assignments !== '') {
      const { changes } = this.sqlite.run(`UPDATE user_consents SET ${assignments} WHERE id = ${sqliteLiteral(id)}`);
      if (changes === 0) throw notFound(`consent ${id}`);
    }
    const row = await this.findConsent(id);
    if (!row) throw notFound(`consent ${id}`);
    return row;
  }

  async listConsents(filter: UserConsentFilter): Promise<UserConsentRow[]> {
    const where = Object.entries(filter)
      .filter(([, value]) => value !== undefined)
      .map(([field, value]) => `${FILTER_COLUMNS[field as keyof UserConsentFilter]} = ${sqliteLiteral(value)}`);
    const clause = where.length === 0 ? '' : `WHERE ${where.join(' AND ')}`;
    return this.sqlite.query<SqliteRow>(`SELECT * FROM user_consents ${clause} ORDER BY created_at ASC`).map((row) => consentFromSqlite(row)!);
  }
}

// ---------------------------------------------------------------- factory

export function createConsentStorageDriver(kind: StorageDriverKind, deps: StorageDriverDeps): ConsentStorageDriver {
  switch (kind) {
    case 'postgres':
      if (!deps.prisma) throw new Error("createConsentStorageDriver('postgres') requires deps.prisma");
      return new PrismaConsentStorageDriver(deps.prisma as PrismaClient);
    case 'sqlite':
      if (!deps.sqlite) throw new Error("createConsentStorageDriver('sqlite') requires deps.sqlite");
      return new SqliteConsentStorageDriver(deps.sqlite as SqliteStore);
    case 'memory':
      return new InMemoryConsentStorageDriver();
    default: {
      const _exhaustive: never = kind;
      throw new UnsupportedStorageDriverError('ConsentRepository', _exhaustive);
    }
  }
}
