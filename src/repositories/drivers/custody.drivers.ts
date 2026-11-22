// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Storage drivers for the KYA-OS story F-3 custody tables (see
// custody.repository.ts). The SQLite driver creates its own tables on
// construction, so the shared SQLite schema in storage/sqlite.ts is left as
// it is.

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../../storage/sqlite.js';
import { sqliteLiteral } from '../../storage/sqlite.js';
import {
  UnsupportedStorageDriverError,
  type StorageDriverDeps,
  type StorageDriverKind,
} from '../../storage/driver-registry.js';
import type {
  CustodyKeyPatch,
  CustodyKeyRow,
  CustodyRecordFilter,
  CustodyRecordPatch,
  CustodyRecordRow,
  NewCustodyKey,
  NewCustodyRecord,
  NewWrappedKey,
  WrappedKeyRow,
} from '../custody.repository.js';

export interface CustodyStorageDriver {
  createRecord(row: NewCustodyRecord): Promise<CustodyRecordRow>;
  findRecord(did: string): Promise<CustodyRecordRow | null>;
  findRecordByEnrollmentToken(tokenHash: string): Promise<CustodyRecordRow | null>;
  updateRecord(did: string, patch: CustodyRecordPatch): Promise<CustodyRecordRow>;
  claimEnrollment(did: string, at: Date): Promise<boolean>;
  listRecords(filter: CustodyRecordFilter): Promise<CustodyRecordRow[]>;
  addKey(row: NewCustodyKey): Promise<CustodyKeyRow>;
  listKeys(did: string): Promise<CustodyKeyRow[]>;
  updateKey(did: string, kid: string, patch: CustodyKeyPatch): Promise<CustodyKeyRow>;
}

export interface WrappedKeyStorageDriver {
  insert(row: NewWrappedKey): Promise<WrappedKeyRow>;
  find(did: string, kid: string): Promise<WrappedKeyRow | null>;
  list(did: string): Promise<WrappedKeyRow[]>;
  shred(did: string, kid: string, at: Date): Promise<boolean>;
}

function notFound(what: string): Error {
  return new Error(`${what} not found`);
}

function filterRecords(rows: CustodyRecordRow[], filter: CustodyRecordFilter): CustodyRecordRow[] {
  const dids = filter.dids ? new Set(filter.dids) : undefined;
  return rows
    .filter((row) => (filter.subjectType ? row.subjectType === filter.subjectType : true))
    .filter((row) => (dids ? dids.has(row.did) : true))
    .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.did < b.did ? -1 : 1));
}

// ---------------------------------------------------------------- memory

export class InMemoryCustodyStorageDriver implements CustodyStorageDriver {
  private readonly records = new Map<string, CustodyRecordRow>();
  private readonly keys = new Map<string, CustodyKeyRow[]>();

  async createRecord(row: NewCustodyRecord): Promise<CustodyRecordRow> {
    if (this.records.has(row.did)) throw new Error(`custody record already exists: ${row.did}`);
    const now = new Date();
    const record: CustodyRecordRow = { ...row, createdAt: now, updatedAt: now };
    this.records.set(row.did, record);
    return { ...record };
  }

  async findRecord(did: string): Promise<CustodyRecordRow | null> {
    const row = this.records.get(did);
    return row ? { ...row } : null;
  }

  async findRecordByEnrollmentToken(tokenHash: string): Promise<CustodyRecordRow | null> {
    for (const row of this.records.values()) if (row.enrollmentTokenHash === tokenHash) return { ...row };
    return null;
  }

  async updateRecord(did: string, patch: CustodyRecordPatch): Promise<CustodyRecordRow> {
    const row = this.records.get(did);
    if (!row) throw notFound(`custody record ${did}`);
    const updated: CustodyRecordRow = { ...row, ...patch, updatedAt: new Date() };
    this.records.set(did, updated);
    return { ...updated };
  }

  async claimEnrollment(did: string, at: Date): Promise<boolean> {
    const row = this.records.get(did);
    if (!row || row.enrollmentUsedAt) return false;
    this.records.set(did, { ...row, enrollmentUsedAt: at, updatedAt: new Date() });
    return true;
  }

  async listRecords(filter: CustodyRecordFilter): Promise<CustodyRecordRow[]> {
    return filterRecords([...this.records.values()].map((row) => ({ ...row })), filter);
  }

  async addKey(row: NewCustodyKey): Promise<CustodyKeyRow> {
    const list = this.keys.get(row.did) ?? [];
    if (list.some((key) => key.kid === row.kid)) throw new Error(`custody key already exists: ${row.kid}`);
    const key: CustodyKeyRow = { ...row, createdAt: new Date() };
    this.keys.set(row.did, [...list, key]);
    return { ...key };
  }

  async listKeys(did: string): Promise<CustodyKeyRow[]> {
    return (this.keys.get(did) ?? []).map((key) => ({ ...key })).sort((a, b) => a.sequence - b.sequence);
  }

  async updateKey(did: string, kid: string, patch: CustodyKeyPatch): Promise<CustodyKeyRow> {
    const list = this.keys.get(did) ?? [];
    const index = list.findIndex((key) => key.kid === kid);
    if (index === -1) throw notFound(`custody key ${kid}`);
    const updated = { ...list[index]!, ...patch };
    list[index] = updated;
    return { ...updated };
  }
}

export class InMemoryWrappedKeyStorageDriver implements WrappedKeyStorageDriver {
  private readonly rows = new Map<string, WrappedKeyRow>();

  private static key(did: string, kid: string): string {
    return `${did}\u0000${kid}`;
  }

  async insert(row: NewWrappedKey): Promise<WrappedKeyRow> {
    const id = InMemoryWrappedKeyStorageDriver.key(row.did, row.kid);
    if (this.rows.has(id)) throw new Error(`wrapped key already exists: ${row.kid}`);
    const stored: WrappedKeyRow = { ...row, createdAt: new Date(), shreddedAt: null };
    this.rows.set(id, stored);
    return { ...stored };
  }

  async find(did: string, kid: string): Promise<WrappedKeyRow | null> {
    const row = this.rows.get(InMemoryWrappedKeyStorageDriver.key(did, kid));
    return row ? { ...row } : null;
  }

  async list(did: string): Promise<WrappedKeyRow[]> {
    return [...this.rows.values()].filter((row) => row.did === did).map((row) => ({ ...row }));
  }

  async shred(did: string, kid: string, at: Date): Promise<boolean> {
    const id = InMemoryWrappedKeyStorageDriver.key(did, kid);
    const row = this.rows.get(id);
    if (!row || row.shreddedAt) return false;
    this.rows.set(id, { ...row, ciphertext: '', nonce: '', shreddedAt: at });
    return true;
  }

  /** Test seam: every stored row as stored, to prove what the table holds. */
  dump(): WrappedKeyRow[] {
    return [...this.rows.values()].map((row) => ({ ...row }));
  }
}

// ---------------------------------------------------------------- prisma

interface Delegate {
  create(args: unknown): Promise<unknown>;
  findUnique(args: unknown): Promise<unknown>;
  findMany(args: unknown): Promise<unknown[]>;
  update(args: unknown): Promise<unknown>;
  updateMany(args: unknown): Promise<{ count: number }>;
}

interface CustodyPrisma {
  custodyRecord: Delegate;
  custodyKey: Delegate;
  wrappedKey: Delegate;
}

function recordFromPrisma(value: unknown): CustodyRecordRow | null {
  if (!value) return null;
  const row = value as CustodyRecordRow & { scopes: unknown; requestedDomains: unknown };
  return {
    ...row,
    scopes: Array.isArray(row.scopes) ? (row.scopes as string[]) : null,
    requestedDomains: Array.isArray(row.requestedDomains) ? (row.requestedDomains as string[]) : null,
  };
}

function withoutId<T>(value: unknown): T {
  const row = { ...(value as Record<string, unknown>) };
  delete row['id'];
  return row as T;
}

function keyFromPrisma(value: unknown): CustodyKeyRow {
  return withoutId<CustodyKeyRow>(value);
}

function wrappedFromPrisma(value: unknown): WrappedKeyRow | null {
  if (!value) return null;
  return withoutId<WrappedKeyRow>(value);
}

function recordData(patch: CustodyRecordPatch | NewCustodyRecord): Record<string, unknown> {
  const data: Record<string, unknown> = { ...patch };
  if ('scopes' in patch) data['scopes'] = patch.scopes ?? undefined;
  if ('requestedDomains' in patch) data['requestedDomains'] = patch.requestedDomains ?? undefined;
  return data;
}

export class PrismaCustodyStorageDriver implements CustodyStorageDriver {
  private readonly db: CustodyPrisma;

  constructor(prisma: PrismaClient) {
    this.db = prisma as unknown as CustodyPrisma;
  }

  async createRecord(row: NewCustodyRecord): Promise<CustodyRecordRow> {
    return recordFromPrisma(await this.db.custodyRecord.create({ data: recordData(row) }))!;
  }

  async findRecord(did: string): Promise<CustodyRecordRow | null> {
    return recordFromPrisma(await this.db.custodyRecord.findUnique({ where: { did } }));
  }

  async findRecordByEnrollmentToken(tokenHash: string): Promise<CustodyRecordRow | null> {
    return recordFromPrisma(await this.db.custodyRecord.findUnique({ where: { enrollmentTokenHash: tokenHash } }));
  }

  async updateRecord(did: string, patch: CustodyRecordPatch): Promise<CustodyRecordRow> {
    return recordFromPrisma(await this.db.custodyRecord.update({ where: { did }, data: recordData(patch) }))!;
  }

  async claimEnrollment(did: string, at: Date): Promise<boolean> {
    const result = await this.db.custodyRecord.updateMany({ where: { did, enrollmentUsedAt: null }, data: { enrollmentUsedAt: at } });
    return result.count === 1;
  }

  async listRecords(filter: CustodyRecordFilter): Promise<CustodyRecordRow[]> {
    const rows = await this.db.custodyRecord.findMany({
      where: {
        ...(filter.subjectType ? { subjectType: filter.subjectType } : {}),
        ...(filter.dids ? { did: { in: [...filter.dids] } } : {}),
      },
      orderBy: [{ createdAt: 'asc' }, { did: 'asc' }],
    });
    return rows.map((row) => recordFromPrisma(row)!);
  }

  async addKey(row: NewCustodyKey): Promise<CustodyKeyRow> {
    return keyFromPrisma(await this.db.custodyKey.create({ data: { ...row } }));
  }

  async listKeys(did: string): Promise<CustodyKeyRow[]> {
    const rows = await this.db.custodyKey.findMany({ where: { did }, orderBy: { sequence: 'asc' } });
    return rows.map(keyFromPrisma);
  }

  async updateKey(did: string, kid: string, patch: CustodyKeyPatch): Promise<CustodyKeyRow> {
    return keyFromPrisma(await this.db.custodyKey.update({ where: { did_kid: { did, kid } }, data: { ...patch } }));
  }
}

export class PrismaWrappedKeyStorageDriver implements WrappedKeyStorageDriver {
  private readonly db: CustodyPrisma;

  constructor(prisma: PrismaClient) {
    this.db = prisma as unknown as CustodyPrisma;
  }

  async insert(row: NewWrappedKey): Promise<WrappedKeyRow> {
    return wrappedFromPrisma(await this.db.wrappedKey.create({ data: { ...row } }))!;
  }

  async find(did: string, kid: string): Promise<WrappedKeyRow | null> {
    return wrappedFromPrisma(await this.db.wrappedKey.findUnique({ where: { did_kid: { did, kid } } }));
  }

  async list(did: string): Promise<WrappedKeyRow[]> {
    const rows = await this.db.wrappedKey.findMany({ where: { did }, orderBy: { createdAt: 'asc' } });
    return rows.map((row) => wrappedFromPrisma(row)!);
  }

  async shred(did: string, kid: string, at: Date): Promise<boolean> {
    const result = await this.db.wrappedKey.updateMany({
      where: { did, kid, shreddedAt: null },
      data: { ciphertext: '', nonce: '', shreddedAt: at },
    });
    return result.count === 1;
  }
}

// ---------------------------------------------------------------- sqlite

const SQLITE_DDL = `
CREATE TABLE IF NOT EXISTS custody_records (
  did TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL,
  key_custody TEXT NOT NULL,
  did_hosting TEXT NOT NULL,
  status TEXT NOT NULL,
  kid TEXT,
  name TEXT,
  owner_did TEXT,
  scopes TEXT,
  requested_domains TEXT,
  max_delegation_depth INTEGER NOT NULL DEFAULT 0,
  enrollment_token_hash TEXT UNIQUE,
  enrollment_expires_at TEXT,
  enrollment_nonce TEXT,
  enrollment_used_at TEXT,
  credential_vc_id TEXT,
  activated_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_custody_records_subject ON custody_records(subject_type, key_custody);
CREATE TABLE IF NOT EXISTS custody_keys (
  did TEXT NOT NULL,
  kid TEXT NOT NULL,
  location TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  status TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  retires_at TEXT,
  revoked_at TEXT,
  PRIMARY KEY (did, kid)
);
CREATE TABLE IF NOT EXISTS wrapped_keys (
  did TEXT NOT NULL,
  kid TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  kek_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,
  created_at TEXT NOT NULL,
  shredded_at TEXT,
  PRIMARY KEY (did, kid)
);
`;

const RECORD_COLUMNS: Record<keyof CustodyRecordPatch, string> = {
  keyCustody: 'key_custody',
  didHosting: 'did_hosting',
  status: 'status',
  kid: 'kid',
  name: 'name',
  ownerDid: 'owner_did',
  scopes: 'scopes',
  requestedDomains: 'requested_domains',
  maxDelegationDepth: 'max_delegation_depth',
  enrollmentTokenHash: 'enrollment_token_hash',
  enrollmentExpiresAt: 'enrollment_expires_at',
  enrollmentNonce: 'enrollment_nonce',
  enrollmentUsedAt: 'enrollment_used_at',
  credentialVcId: 'credential_vc_id',
  activatedAt: 'activated_at',
};

type SqliteRow = Record<string, string | number | null>;

function date(value: string | number | null | undefined): Date | null {
  return typeof value === 'string' ? new Date(value) : null;
}

function text(value: string | number | null | undefined): string | null {
  return typeof value === 'string' ? value : null;
}

function recordFromSqlite(row: SqliteRow | undefined): CustodyRecordRow | null {
  if (!row) return null;
  return {
    did: row['did'] as string,
    subjectType: row['subject_type'] as CustodyRecordRow['subjectType'],
    keyCustody: row['key_custody'] as CustodyRecordRow['keyCustody'],
    didHosting: row['did_hosting'] as CustodyRecordRow['didHosting'],
    status: row['status'] as CustodyRecordRow['status'],
    kid: text(row['kid']),
    name: text(row['name']),
    ownerDid: text(row['owner_did']),
    scopes: typeof row['scopes'] === 'string' ? (JSON.parse(row['scopes']) as string[]) : null,
    requestedDomains: typeof row['requested_domains'] === 'string' ? (JSON.parse(row['requested_domains']) as string[]) : null,
    maxDelegationDepth: Number(row['max_delegation_depth'] ?? 0),
    enrollmentTokenHash: text(row['enrollment_token_hash']),
    enrollmentExpiresAt: date(row['enrollment_expires_at']),
    enrollmentNonce: text(row['enrollment_nonce']),
    enrollmentUsedAt: date(row['enrollment_used_at']),
    credentialVcId: text(row['credential_vc_id']),
    activatedAt: date(row['activated_at']),
    createdAt: date(row['created_at'])!,
    updatedAt: date(row['updated_at'])!,
  };
}

function keyFromSqlite(row: SqliteRow): CustodyKeyRow {
  return {
    did: row['did'] as string,
    kid: row['kid'] as string,
    location: row['location'] as CustodyKeyRow['location'],
    publicKeyJwk: JSON.parse(row['public_key_jwk'] as string) as CustodyKeyRow['publicKeyJwk'],
    status: row['status'] as CustodyKeyRow['status'],
    sequence: Number(row['sequence']),
    createdAt: date(row['created_at'])!,
    retiresAt: date(row['retires_at']),
    revokedAt: date(row['revoked_at']),
  };
}

function wrappedFromSqlite(row: SqliteRow | undefined): WrappedKeyRow | null {
  if (!row) return null;
  return {
    did: row['did'] as string,
    kid: row['kid'] as string,
    subjectType: row['subject_type'] as WrappedKeyRow['subjectType'],
    algorithm: row['algorithm'] as string,
    kekId: row['kek_id'] as string,
    nonce: row['nonce'] as string,
    ciphertext: row['ciphertext'] as string,
    publicKeyJwk: JSON.parse(row['public_key_jwk'] as string) as WrappedKeyRow['publicKeyJwk'],
    createdAt: date(row['created_at'])!,
    shreddedAt: date(row['shredded_at']),
  };
}

function sqliteValue(column: string, value: unknown): string {
  if (column === 'scopes' || column === 'requested_domains') return value === null || value === undefined ? 'NULL' : sqliteLiteral(JSON.stringify(value));
  return sqliteLiteral(value);
}

/** Columns added to custody_records after its first release; CREATE TABLE IF NOT EXISTS does not add them to an existing file. */
const SQLITE_ADDED_RECORD_COLUMNS: [string, string][] = [
  ['requested_domains', 'TEXT'],
  ['max_delegation_depth', 'INTEGER NOT NULL DEFAULT 0'],
];

export class SqliteCustodyStorageDriver implements CustodyStorageDriver {
  constructor(private readonly sqlite: SqliteStore) {
    this.sqlite.execute(SQLITE_DDL);
    const present = new Set(this.sqlite.query<{ name: string }>('PRAGMA table_info(custody_records)').map((column) => column.name));
    for (const [column, type] of SQLITE_ADDED_RECORD_COLUMNS) {
      if (!present.has(column)) this.sqlite.execute(`ALTER TABLE custody_records ADD COLUMN ${column} ${type}`);
    }
  }

  async createRecord(row: NewCustodyRecord): Promise<CustodyRecordRow> {
    const now = new Date();
    const columns = ['did', 'subject_type', ...Object.values(RECORD_COLUMNS), 'created_at', 'updated_at'];
    const values = [
      sqliteLiteral(row.did),
      sqliteLiteral(row.subjectType),
      ...Object.entries(RECORD_COLUMNS).map(([field, column]) => sqliteValue(column, row[field as keyof NewCustodyRecord])),
      sqliteLiteral(now),
      sqliteLiteral(now),
    ];
    this.sqlite.execute(`INSERT INTO custody_records (${columns.join(', ')}) VALUES (${values.join(', ')})`);
    return (await this.findRecord(row.did))!;
  }

  async findRecord(did: string): Promise<CustodyRecordRow | null> {
    return recordFromSqlite(this.sqlite.query<SqliteRow>(`SELECT * FROM custody_records WHERE did = ${sqliteLiteral(did)} LIMIT 1`)[0]);
  }

  async findRecordByEnrollmentToken(tokenHash: string): Promise<CustodyRecordRow | null> {
    return recordFromSqlite(
      this.sqlite.query<SqliteRow>(`SELECT * FROM custody_records WHERE enrollment_token_hash = ${sqliteLiteral(tokenHash)} LIMIT 1`)[0],
    );
  }

  async updateRecord(did: string, patch: CustodyRecordPatch): Promise<CustodyRecordRow> {
    const sets = Object.entries(patch)
      .filter(([field]) => field in RECORD_COLUMNS)
      .map(([field, value]) => {
        const column = RECORD_COLUMNS[field as keyof CustodyRecordPatch];
        return `${column} = ${sqliteValue(column, value)}`;
      });
    sets.push(`updated_at = ${sqliteLiteral(new Date())}`);
    const { changes } = this.sqlite.run(`UPDATE custody_records SET ${sets.join(', ')} WHERE did = ${sqliteLiteral(did)}`);
    if (changes === 0) throw notFound(`custody record ${did}`);
    return (await this.findRecord(did))!;
  }

  async claimEnrollment(did: string, at: Date): Promise<boolean> {
    const { changes } = this.sqlite.run(
      `UPDATE custody_records SET enrollment_used_at = ${sqliteLiteral(at)} WHERE did = ${sqliteLiteral(did)} AND enrollment_used_at IS NULL`,
    );
    return changes === 1;
  }

  async listRecords(filter: CustodyRecordFilter): Promise<CustodyRecordRow[]> {
    const rows = this.sqlite.query<SqliteRow>('SELECT * FROM custody_records').map((row) => recordFromSqlite(row)!);
    return filterRecords(rows, filter);
  }

  async addKey(row: NewCustodyKey): Promise<CustodyKeyRow> {
    this.sqlite.execute(`
      INSERT INTO custody_keys (did, kid, location, public_key_jwk, status, sequence, created_at, retires_at, revoked_at)
      VALUES (${sqliteLiteral(row.did)}, ${sqliteLiteral(row.kid)}, ${sqliteLiteral(row.location)},
        ${sqliteLiteral(JSON.stringify(row.publicKeyJwk))}, ${sqliteLiteral(row.status)}, ${sqliteLiteral(row.sequence)},
        ${sqliteLiteral(new Date())}, ${sqliteLiteral(row.retiresAt)}, ${sqliteLiteral(row.revokedAt)})
    `);
    return (await this.listKeys(row.did)).find((key) => key.kid === row.kid)!;
  }

  async listKeys(did: string): Promise<CustodyKeyRow[]> {
    return this.sqlite
      .query<SqliteRow>(`SELECT * FROM custody_keys WHERE did = ${sqliteLiteral(did)} ORDER BY sequence ASC`)
      .map(keyFromSqlite);
  }

  async updateKey(did: string, kid: string, patch: CustodyKeyPatch): Promise<CustodyKeyRow> {
    const columns: Record<string, string> = { status: 'status', retiresAt: 'retires_at', revokedAt: 'revoked_at' };
    const sets = Object.entries(patch).map(([field, value]) => `${columns[field]} = ${sqliteLiteral(value)}`);
    const { changes } = this.sqlite.run(
      `UPDATE custody_keys SET ${sets.join(', ')} WHERE did = ${sqliteLiteral(did)} AND kid = ${sqliteLiteral(kid)}`,
    );
    if (changes === 0) throw notFound(`custody key ${kid}`);
    return (await this.listKeys(did)).find((key) => key.kid === kid)!;
  }
}

export class SqliteWrappedKeyStorageDriver implements WrappedKeyStorageDriver {
  constructor(private readonly sqlite: SqliteStore) {
    this.sqlite.execute(SQLITE_DDL);
  }

  async insert(row: NewWrappedKey): Promise<WrappedKeyRow> {
    this.sqlite.execute(`
      INSERT INTO wrapped_keys (did, kid, subject_type, algorithm, kek_id, nonce, ciphertext, public_key_jwk, created_at, shredded_at)
      VALUES (${sqliteLiteral(row.did)}, ${sqliteLiteral(row.kid)}, ${sqliteLiteral(row.subjectType)}, ${sqliteLiteral(row.algorithm)},
        ${sqliteLiteral(row.kekId)}, ${sqliteLiteral(row.nonce)}, ${sqliteLiteral(row.ciphertext)},
        ${sqliteLiteral(JSON.stringify(row.publicKeyJwk))}, ${sqliteLiteral(new Date())}, NULL)
    `);
    return (await this.find(row.did, row.kid))!;
  }

  async find(did: string, kid: string): Promise<WrappedKeyRow | null> {
    return wrappedFromSqlite(
      this.sqlite.query<SqliteRow>(`SELECT * FROM wrapped_keys WHERE did = ${sqliteLiteral(did)} AND kid = ${sqliteLiteral(kid)} LIMIT 1`)[0],
    );
  }

  async list(did: string): Promise<WrappedKeyRow[]> {
    return this.sqlite
      .query<SqliteRow>(`SELECT * FROM wrapped_keys WHERE did = ${sqliteLiteral(did)} ORDER BY created_at ASC`)
      .map((row) => wrappedFromSqlite(row)!);
  }

  async shred(did: string, kid: string, at: Date): Promise<boolean> {
    const { changes } = this.sqlite.run(`
      UPDATE wrapped_keys SET ciphertext = '', nonce = '', shredded_at = ${sqliteLiteral(at)}
      WHERE did = ${sqliteLiteral(did)} AND kid = ${sqliteLiteral(kid)} AND shredded_at IS NULL
    `);
    return changes === 1;
  }
}

// ---------------------------------------------------------------- factories

export function createCustodyStorageDriver(kind: StorageDriverKind, deps: StorageDriverDeps): CustodyStorageDriver {
  switch (kind) {
    case 'postgres':
      if (!deps.prisma) throw new Error("createCustodyStorageDriver('postgres') requires deps.prisma");
      return new PrismaCustodyStorageDriver(deps.prisma as PrismaClient);
    case 'sqlite':
      if (!deps.sqlite) throw new Error("createCustodyStorageDriver('sqlite') requires deps.sqlite");
      return new SqliteCustodyStorageDriver(deps.sqlite as SqliteStore);
    case 'memory':
      return new InMemoryCustodyStorageDriver();
    default: {
      const _exhaustive: never = kind;
      throw new UnsupportedStorageDriverError('CustodyRepository', _exhaustive);
    }
  }
}

export function createWrappedKeyStorageDriver(kind: StorageDriverKind, deps: StorageDriverDeps): WrappedKeyStorageDriver {
  switch (kind) {
    case 'postgres':
      if (!deps.prisma) throw new Error("createWrappedKeyStorageDriver('postgres') requires deps.prisma");
      return new PrismaWrappedKeyStorageDriver(deps.prisma as PrismaClient);
    case 'sqlite':
      if (!deps.sqlite) throw new Error("createWrappedKeyStorageDriver('sqlite') requires deps.sqlite");
      return new SqliteWrappedKeyStorageDriver(deps.sqlite as SqliteStore);
    case 'memory':
      return new InMemoryWrappedKeyStorageDriver();
    default: {
      const _exhaustive: never = kind;
      throw new UnsupportedStorageDriverError('WrappedKeyRepository', _exhaustive);
    }
  }
}
