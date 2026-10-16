// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Storage-driver implementations for DidKeyRepository — same pluggable
// pattern as did.drivers.ts. Core owns this schema, so the Prisma driver
// calls prisma.didKey.* directly, same as PrismaDidStorageDriver.

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../../storage/sqlite.js';
import { sqliteLiteral } from '../../storage/sqlite.js';
import {
  UnsupportedStorageDriverError,
  type StorageDriverDeps,
  type StorageDriverKind,
} from '../../storage/driver-registry.js';
import type {
  CreateDidKeyRecordParams,
  DidKeyRecord,
  DidKeySubjectType,
} from '../did-key.repository.js';

function makeId(prefix: string): string {
  return `${prefix}:${Math.random().toString(16).slice(2, 14)}`;
}

/** Everything DidKeyRepository needs from a storage backend. */
export interface DidKeyStorageDriver {
  create(data: CreateDidKeyRecordParams): Promise<DidKeyRecord>;
  findByDid(did: string): Promise<DidKeyRecord | null>;
}

type PrismaDidKeyRow = Omit<DidKeyRecord, 'subjectType'> & { subjectType: string };

type PrismaLike = PrismaClient & {
  didKey: {
    create(args: unknown): Promise<PrismaDidKeyRow>;
    findUnique(args: unknown): Promise<PrismaDidKeyRow | null>;
  };
};

function fromPrismaRow(row: PrismaDidKeyRow | null): DidKeyRecord | null {
  return row ? { ...row, subjectType: row.subjectType as DidKeySubjectType } : null;
}

export class PrismaDidKeyStorageDriver implements DidKeyStorageDriver {
  private readonly db: PrismaLike;

  constructor(prisma: PrismaClient) {
    this.db = prisma as PrismaLike;
  }

  async create(data: CreateDidKeyRecordParams): Promise<DidKeyRecord> {
    return fromPrismaRow(await this.db.didKey.create({ data }))!;
  }

  async findByDid(did: string): Promise<DidKeyRecord | null> {
    return fromPrismaRow(await this.db.didKey.findUnique({ where: { did } }));
  }
}

type SqliteDidKeyRow = {
  id: string;
  did: string;
  subject_type: string;
  encrypted_private_key: string;
  iv: string;
  auth_tag: string;
  algorithm: string;
  created_at: string;
};

function fromSqliteRow(row: SqliteDidKeyRow | undefined): DidKeyRecord | null {
  if (!row) return null;
  return {
    id: row.id,
    did: row.did,
    subjectType: row.subject_type as DidKeySubjectType,
    encryptedPrivateKey: row.encrypted_private_key,
    iv: row.iv,
    authTag: row.auth_tag,
    algorithm: row.algorithm,
    createdAt: new Date(row.created_at),
  };
}

export class SqliteDidKeyStorageDriver implements DidKeyStorageDriver {
  constructor(private readonly sqlite: SqliteStore) {}

  async create(data: CreateDidKeyRecordParams): Promise<DidKeyRecord> {
    const id = makeId('didkey');
    const now = new Date();
    this.sqlite.execute(`
      INSERT INTO did_keys (
        id, did, subject_type, encrypted_private_key, iv, auth_tag, algorithm, created_at
      ) VALUES (
        ${sqliteLiteral(id)},
        ${sqliteLiteral(data.did)},
        ${sqliteLiteral(data.subjectType)},
        ${sqliteLiteral(data.encryptedPrivateKey)},
        ${sqliteLiteral(data.iv)},
        ${sqliteLiteral(data.authTag)},
        ${sqliteLiteral(data.algorithm)},
        ${sqliteLiteral(now)}
      )
    `);
    return { id, ...data, createdAt: now };
  }

  async findByDid(did: string): Promise<DidKeyRecord | null> {
    const rows = this.sqlite.query<SqliteDidKeyRow>(`
      SELECT * FROM did_keys WHERE did = ${sqliteLiteral(did)} LIMIT 1
    `);
    return fromSqliteRow(rows[0]);
  }
}

export class InMemoryDidKeyStorageDriver implements DidKeyStorageDriver {
  private readonly keys = new Map<string, DidKeyRecord>();

  async create(data: CreateDidKeyRecordParams): Promise<DidKeyRecord> {
    const record: DidKeyRecord = { id: makeId('didkey'), ...data, createdAt: new Date() };
    this.keys.set(record.did, record);
    return record;
  }

  async findByDid(did: string): Promise<DidKeyRecord | null> {
    return this.keys.get(did) ?? null;
  }
}

/**
 * Selects a DidKeyStorageDriver by kind. This is the one place that
 * needs a new `case` when a new backend is added.
 */
export function createDidKeyStorageDriver(
  kind: StorageDriverKind,
  deps: StorageDriverDeps,
): DidKeyStorageDriver {
  switch (kind) {
    case 'postgres':
      if (!deps.prisma) throw new Error("createDidKeyStorageDriver('postgres') requires deps.prisma");
      return new PrismaDidKeyStorageDriver(deps.prisma as PrismaClient);
    case 'sqlite':
      if (!deps.sqlite) throw new Error("createDidKeyStorageDriver('sqlite') requires deps.sqlite");
      return new SqliteDidKeyStorageDriver(deps.sqlite as SqliteStore);
    case 'memory':
      return new InMemoryDidKeyStorageDriver();
    default: {
      // Exhaustiveness check: if StorageDriverKind gains a member without a
      // corresponding case above, this line fails to compile.
      const _exhaustive: never = kind;
      throw new UnsupportedStorageDriverError('DidKeyRepository', _exhaustive);
    }
  }
}
