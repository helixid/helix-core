// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Storage-driver implementations for AgentRecordRepository — same shape as
// service.drivers.ts.
//
// listPublic() is written to make a leak structurally hard: the
// `visibility = 'public'` predicate is part of the WHERE clause on every path,
// the status filter and the keyset are applied in the same query (never after
// a LIMIT), and the search term only ever travels as a bound parameter or an
// escaped literal, with LIKE wildcards in it escaped.

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../../storage/sqlite.js';
import { sqliteLiteral } from '../../storage/sqlite.js';
import {
  UnsupportedStorageDriverError,
  type StorageDriverDeps,
  type StorageDriverKind,
} from '../../storage/driver-registry.js';
import type {
  AgentCreateData,
  AgentCredentialState,
  AgentRecord,
  AgentStatus,
  AgentVisibility,
  PublicAgentQuery,
  PublicAgentRow,
} from '../agent-record.repository.js';

type PrismaRaw = PrismaClient & {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
  $executeRawUnsafe(query: string, ...values: unknown[]): Promise<number>;
};

export interface AgentRecordStorageDriver {
  create(data: AgentCreateData): Promise<AgentRecord>;
  findByDid(did: string): Promise<AgentRecord | null>;
  setVisibility(did: string, visibility: AgentVisibility, at: Date): Promise<AgentRecord | null>;
  updateCredentialState(did: string, state: AgentCredentialState): Promise<void>;
  markRevokedByCredential(vcId: string, revokedAt: Date): Promise<void>;
  listPublic(query: PublicAgentQuery): Promise<PublicAgentRow[]>;
}

/** Anything but 'public' reads as private, so a bad value can only ever hide an agent. */
function asVisibility(value: unknown): AgentVisibility {
  return value === 'public' ? 'public' : 'private';
}

/** Escapes LIKE's own wildcards (and the escape character) so a search term only ever matches literally. */
export function escapeLikePattern(term: string): string {
  return term.replace(/[\\%_]/g, (character) => `\\${character}`);
}

/**
 * An agent is active when its own credential is live: it has one
 * (credentialVcId), it isn't revoked, and it either never expires
 * (credentialExpiresAt null) or hasn't yet. "No credential" is read from
 * credentialVcId, never from a null expiry: a credential enrolled with no
 * expiry, the default, stores null there and is active.
 */
function isActive(
  record: { revokedAt: Date | null; credentialVcId: string | null; credentialExpiresAt: Date | null },
  now: Date,
): boolean {
  return (
    record.revokedAt === null &&
    record.credentialVcId !== null &&
    (record.credentialExpiresAt === null || record.credentialExpiresAt.getTime() > now.getTime())
  );
}

function newRecord(data: AgentCreateData): AgentRecord {
  return {
    did: data.did,
    name: data.name,
    visibility: data.visibility,
    visibilityChangedAt: data.publishedAt,
    publishedAt: data.publishedAt,
    credentialVcId: data.credentialVcId,
    credentialExpiresAt: data.credentialExpiresAt,
    revokedAt: data.revokedAt,
    createdAt: data.createdAt,
    updatedAt: data.createdAt,
  };
}

// ── Postgres ────────────────────────────────────────────────────────────────

type PgAgentRow = Omit<AgentRecord, 'visibility'> & { visibility: string };

function fromPgRow(row: PgAgentRow): AgentRecord {
  return { ...row, visibility: asVisibility(row.visibility) };
}

/** Postgres: isActive() as SQL. NULL-safe, so it is always TRUE or FALSE. */
const PG_ACTIVE = (nowParam: string): string =>
  `("revokedAt" IS NULL AND "credentialVcId" IS NOT NULL AND ("credentialExpiresAt" IS NULL OR "credentialExpiresAt" > ${nowParam}))`;

export class PrismaAgentRecordStorageDriver implements AgentRecordStorageDriver {
  constructor(private readonly prisma: PrismaClient) {}

  private get raw(): PrismaRaw {
    return this.prisma as PrismaRaw;
  }

  async create(data: AgentCreateData): Promise<AgentRecord> {
    const record = newRecord(data);
    await this.raw.$executeRawUnsafe(
      `INSERT INTO "agents" (
         "did", "name", "visibility", "visibilityChangedAt", "publishedAt",
         "credentialVcId", "credentialExpiresAt", "revokedAt", "createdAt", "updatedAt"
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT ("did") DO NOTHING`,
      record.did,
      record.name,
      record.visibility,
      record.visibilityChangedAt,
      record.publishedAt,
      record.credentialVcId,
      record.credentialExpiresAt,
      record.revokedAt,
      record.createdAt,
      record.updatedAt,
    );
    const stored = await this.findByDid(record.did);
    if (!stored) throw new Error('Agent insert left no row');
    return stored;
  }

  async findByDid(did: string): Promise<AgentRecord | null> {
    const rows = await this.raw.$queryRawUnsafe<PgAgentRow[]>(
      `SELECT * FROM "agents" WHERE "did" = $1 LIMIT 1`,
      did,
    );
    return rows[0] ? fromPgRow(rows[0]) : null;
  }

  async setVisibility(did: string, visibility: AgentVisibility, at: Date): Promise<AgentRecord | null> {
    const rows = await this.raw.$queryRawUnsafe<PgAgentRow[]>(
      `UPDATE "agents"
         SET "visibility" = $1, "visibilityChangedAt" = $2, "publishedAt" = $3, "updatedAt" = $2
       WHERE "did" = $4
       RETURNING *`,
      visibility,
      at,
      visibility === 'public' ? at : null,
      did,
    );
    return rows[0] ? fromPgRow(rows[0]) : null;
  }

  async updateCredentialState(did: string, state: AgentCredentialState): Promise<void> {
    await this.raw.$executeRawUnsafe(
      `UPDATE "agents"
         SET "credentialVcId" = $1, "credentialExpiresAt" = $2, "revokedAt" = $3, "updatedAt" = $4
       WHERE "did" = $5`,
      state.credentialVcId,
      state.credentialExpiresAt,
      state.revokedAt,
      new Date(),
      did,
    );
  }

  async markRevokedByCredential(vcId: string, revokedAt: Date): Promise<void> {
    await this.raw.$executeRawUnsafe(
      `UPDATE "agents" SET "revokedAt" = $1, "updatedAt" = $1
       WHERE "credentialVcId" = $2 AND "revokedAt" IS NULL`,
      revokedAt,
      vcId,
    );
  }

  async listPublic(query: PublicAgentQuery): Promise<PublicAgentRow[]> {
    const params: unknown[] = [query.now];
    const active = PG_ACTIVE('$1');
    const where = [`"visibility" = 'public'`, `"publishedAt" IS NOT NULL`];
    if (query.status === 'active') where.push(active);
    if (query.status === 'revoked') where.push(`NOT ${active}`);
    if (query.q !== undefined) {
      params.push(`%${escapeLikePattern(query.q)}%`, query.q);
      where.push(`("name" ILIKE $${params.length - 1} ESCAPE '\\' OR "did" = $${params.length})`);
    }
    if (query.after) {
      params.push(query.after.publishedAt, query.after.did);
      const p = `$${params.length - 1}`;
      const d = `$${params.length}`;
      where.push(`("publishedAt" < ${p} OR ("publishedAt" = ${p} AND "did" > ${d}))`);
    }
    params.push(query.limit);
    const rows = await this.raw.$queryRawUnsafe<
      Array<{ did: string; name: string | null; publishedAt: Date; status: AgentStatus }>
    >(
      `SELECT "did", "name", "publishedAt",
              CASE WHEN ${active} THEN 'active' ELSE 'revoked' END AS "status"
         FROM "agents"
        WHERE ${where.join(' AND ')}
        ORDER BY "publishedAt" DESC, "did" ASC
        LIMIT $${params.length}`,
      ...params,
    );
    return rows.map((row) => ({ ...row, status: row.status === 'active' ? 'active' : 'revoked' }));
  }
}

// ── SQLite ──────────────────────────────────────────────────────────────────

type SqliteAgentRow = {
  did: string;
  name: string | null;
  visibility: string;
  visibility_changed_at: string | null;
  published_at: string | null;
  credential_vc_id: string | null;
  credential_expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
};

function toDate(value: string | null): Date | null {
  return value === null ? null : new Date(value);
}

function fromSqliteRow(row: SqliteAgentRow): AgentRecord {
  return {
    did: row.did,
    name: row.name,
    visibility: asVisibility(row.visibility),
    visibilityChangedAt: toDate(row.visibility_changed_at),
    publishedAt: toDate(row.published_at),
    credentialVcId: row.credential_vc_id,
    credentialExpiresAt: toDate(row.credential_expires_at),
    revokedAt: toDate(row.revoked_at),
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
  };
}

/**
 * SQLite: same predicate as PG_ACTIVE. Timestamps are ISO-8601 UTC text
 * (sqliteLiteral writes Date#toISOString()), so they compare correctly as
 * strings.
 */
const SQLITE_ACTIVE = (now: Date): string =>
  `(revoked_at IS NULL AND credential_vc_id IS NOT NULL AND (credential_expires_at IS NULL OR credential_expires_at > ${sqliteLiteral(now)}))`;

export class SqliteAgentRecordStorageDriver implements AgentRecordStorageDriver {
  constructor(private readonly sqlite: SqliteStore) {}

  async create(data: AgentCreateData): Promise<AgentRecord> {
    const record = newRecord(data);
    this.sqlite.execute(`
      INSERT OR IGNORE INTO agents (
        did, name, visibility, visibility_changed_at, published_at,
        credential_vc_id, credential_expires_at, revoked_at, created_at, updated_at
      ) VALUES (
        ${sqliteLiteral(record.did)},
        ${sqliteLiteral(record.name)},
        ${sqliteLiteral(record.visibility)},
        ${sqliteLiteral(record.visibilityChangedAt)},
        ${sqliteLiteral(record.publishedAt)},
        ${sqliteLiteral(record.credentialVcId)},
        ${sqliteLiteral(record.credentialExpiresAt)},
        ${sqliteLiteral(record.revokedAt)},
        ${sqliteLiteral(record.createdAt)},
        ${sqliteLiteral(record.updatedAt)}
      )
    `);
    const stored = await this.findByDid(record.did);
    if (!stored) throw new Error('Agent insert left no row');
    return stored;
  }

  async findByDid(did: string): Promise<AgentRecord | null> {
    const rows = this.sqlite.query<SqliteAgentRow>(
      `SELECT * FROM agents WHERE did = ${sqliteLiteral(did)} LIMIT 1`,
    );
    return rows[0] ? fromSqliteRow(rows[0]) : null;
  }

  async setVisibility(did: string, visibility: AgentVisibility, at: Date): Promise<AgentRecord | null> {
    this.sqlite.execute(`
      UPDATE agents
         SET visibility = ${sqliteLiteral(visibility)},
             visibility_changed_at = ${sqliteLiteral(at)},
             published_at = ${sqliteLiteral(visibility === 'public' ? at : null)},
             updated_at = ${sqliteLiteral(at)}
       WHERE did = ${sqliteLiteral(did)}
    `);
    return this.findByDid(did);
  }

  async updateCredentialState(did: string, state: AgentCredentialState): Promise<void> {
    this.sqlite.execute(`
      UPDATE agents
         SET credential_vc_id = ${sqliteLiteral(state.credentialVcId)},
             credential_expires_at = ${sqliteLiteral(state.credentialExpiresAt)},
             revoked_at = ${sqliteLiteral(state.revokedAt)},
             updated_at = ${sqliteLiteral(new Date())}
       WHERE did = ${sqliteLiteral(did)}
    `);
  }

  async markRevokedByCredential(vcId: string, revokedAt: Date): Promise<void> {
    this.sqlite.execute(`
      UPDATE agents SET revoked_at = ${sqliteLiteral(revokedAt)}, updated_at = ${sqliteLiteral(revokedAt)}
       WHERE credential_vc_id = ${sqliteLiteral(vcId)} AND revoked_at IS NULL
    `);
  }

  async listPublic(query: PublicAgentQuery): Promise<PublicAgentRow[]> {
    const active = SQLITE_ACTIVE(query.now);
    const where = [`visibility = 'public'`, `published_at IS NOT NULL`];
    if (query.status === 'active') where.push(active);
    if (query.status === 'revoked') where.push(`NOT ${active}`);
    if (query.q !== undefined) {
      // SQLite's LIKE is already case-insensitive for ASCII.
      const pattern = sqliteLiteral(`%${escapeLikePattern(query.q)}%`);
      where.push(`(name LIKE ${pattern} ESCAPE '\\' OR did = ${sqliteLiteral(query.q)})`);
    }
    if (query.after) {
      const p = sqliteLiteral(query.after.publishedAt);
      where.push(`(published_at < ${p} OR (published_at = ${p} AND did > ${sqliteLiteral(query.after.did)}))`);
    }
    const rows = this.sqlite.query<{ did: string; name: string | null; published_at: string; status: string }>(`
      SELECT did, name, published_at,
             CASE WHEN ${active} THEN 'active' ELSE 'revoked' END AS status
        FROM agents
       WHERE ${where.join(' AND ')}
       ORDER BY published_at DESC, did ASC
       LIMIT ${sqliteLiteral(query.limit)}
    `);
    return rows.map((row) => ({
      did: row.did,
      name: row.name,
      publishedAt: new Date(row.published_at),
      status: row.status === 'active' ? 'active' : 'revoked',
    }));
  }
}

// ── Memory ──────────────────────────────────────────────────────────────────

export class InMemoryAgentRecordStorageDriver implements AgentRecordStorageDriver {
  private readonly rows = new Map<string, AgentRecord>();

  async create(data: AgentCreateData): Promise<AgentRecord> {
    const existing = this.rows.get(data.did);
    if (existing) return { ...existing };
    const record = newRecord(data);
    this.rows.set(record.did, record);
    return { ...record };
  }

  async findByDid(did: string): Promise<AgentRecord | null> {
    const row = this.rows.get(did);
    return row ? { ...row } : null;
  }

  async setVisibility(did: string, visibility: AgentVisibility, at: Date): Promise<AgentRecord | null> {
    const row = this.rows.get(did);
    if (!row) return null;
    row.visibility = visibility;
    row.visibilityChangedAt = at;
    row.publishedAt = visibility === 'public' ? at : null;
    row.updatedAt = at;
    return { ...row };
  }

  async updateCredentialState(did: string, state: AgentCredentialState): Promise<void> {
    const row = this.rows.get(did);
    if (!row) return;
    Object.assign(row, state, { updatedAt: new Date() });
  }

  async markRevokedByCredential(vcId: string, revokedAt: Date): Promise<void> {
    for (const row of this.rows.values()) {
      if (row.credentialVcId === vcId && row.revokedAt === null) {
        row.revokedAt = revokedAt;
        row.updatedAt = revokedAt;
      }
    }
  }

  async listPublic(query: PublicAgentQuery): Promise<PublicAgentRow[]> {
    const needle = query.q?.toLowerCase();
    return [...this.rows.values()]
      .filter((row): row is AgentRecord & { publishedAt: Date } => {
        if (row.visibility !== 'public' || row.publishedAt === null) return false;
        const active = isActive(row, query.now);
        if (query.status === 'active' && !active) return false;
        if (query.status === 'revoked' && active) return false;
        if (needle !== undefined && !(row.name?.toLowerCase().includes(needle) || row.did === query.q)) {
          return false;
        }
        if (query.after) {
          const published = row.publishedAt.getTime();
          const cursor = query.after.publishedAt.getTime();
          if (published > cursor || (published === cursor && row.did <= query.after.did)) return false;
        }
        return true;
      })
      .sort((a, b) => b.publishedAt.getTime() - a.publishedAt.getTime() || (a.did < b.did ? -1 : 1))
      .slice(0, query.limit)
      .map((row) => ({
        did: row.did,
        name: row.name,
        publishedAt: row.publishedAt,
        status: isActive(row, query.now) ? 'active' : 'revoked',
      }));
  }
}

export function createAgentRecordStorageDriver(
  kind: StorageDriverKind,
  deps: StorageDriverDeps,
): AgentRecordStorageDriver {
  switch (kind) {
    case 'postgres':
      if (!deps.prisma) throw new Error("createAgentRecordStorageDriver('postgres') requires deps.prisma");
      return new PrismaAgentRecordStorageDriver(deps.prisma as PrismaClient);
    case 'sqlite':
      if (!deps.sqlite) throw new Error("createAgentRecordStorageDriver('sqlite') requires deps.sqlite");
      return new SqliteAgentRecordStorageDriver(deps.sqlite as SqliteStore);
    case 'memory':
      return new InMemoryAgentRecordStorageDriver();
    default: {
      const _exhaustive: never = kind;
      throw new UnsupportedStorageDriverError('AgentRecordRepository', _exhaustive);
    }
  }
}
