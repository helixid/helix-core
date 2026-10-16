// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Storage-driver implementations for ServiceRepository — same pluggable
// pattern as did.drivers.ts.

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../../storage/sqlite.js';
import { sqliteLiteral } from '../../storage/sqlite.js';
import {
  UnsupportedStorageDriverError,
  type StorageDriverDeps,
  type StorageDriverKind,
} from '../../storage/driver-registry.js';
import type { ServiceCreateData, ServiceRecord } from '../service.repository.js';

export interface ServiceStorageDriver {
  create(data: ServiceCreateData): Promise<ServiceRecord>;
  findById(id: string): Promise<ServiceRecord | null>;
  findByDid(did: string): Promise<ServiceRecord | null>;
  findByName(name: string): Promise<ServiceRecord | null>;
  list(): Promise<ServiceRecord[]>;
  revoke(id: string): Promise<void>;
}

type PrismaLike = PrismaClient & {
  service: {
    create(args: unknown): Promise<ServiceRecord>;
    findUnique(args: unknown): Promise<ServiceRecord | null>;
    findFirst(args: unknown): Promise<ServiceRecord | null>;
    findMany(args: unknown): Promise<ServiceRecord[]>;
    updateMany(args: unknown): Promise<unknown>;
  };
};

export class PrismaServiceStorageDriver implements ServiceStorageDriver {
  private readonly db: PrismaLike;

  constructor(prisma: PrismaClient) {
    this.db = prisma as PrismaLike;
  }

  async create(data: ServiceCreateData): Promise<ServiceRecord> {
    return this.db.service.create({ data });
  }

  async findById(id: string): Promise<ServiceRecord | null> {
    return this.db.service.findUnique({ where: { id } });
  }

  async findByDid(did: string): Promise<ServiceRecord | null> {
    return this.db.service.findUnique({ where: { did } });
  }

  async findByName(name: string): Promise<ServiceRecord | null> {
    return this.db.service.findFirst({ where: { name } });
  }

  async list(): Promise<ServiceRecord[]> {
    return this.db.service.findMany({ orderBy: { createdAt: 'desc' } });
  }

  async revoke(id: string): Promise<void> {
    await this.db.service.updateMany({ where: { id, revokedAt: null }, data: { revokedAt: new Date() } });
  }
}

type SqliteServiceRow = {
  id: string;
  did: string;
  name: string;
  domain: string;
  required_scope: string;
  description: string | null;
  framework: string | null;
  created_at: string;
  revoked_at: string | null;
};

function fromSqliteRow(row: SqliteServiceRow | undefined): ServiceRecord | null {
  if (!row) return null;
  return {
    id: row.id,
    did: row.did,
    name: row.name,
    domain: row.domain,
    requiredScope: row.required_scope,
    description: row.description,
    framework: row.framework,
    createdAt: new Date(row.created_at),
    revokedAt: row.revoked_at ? new Date(row.revoked_at) : null,
  };
}

export class SqliteServiceStorageDriver implements ServiceStorageDriver {
  constructor(private readonly sqlite: SqliteStore) {}

  async create(data: ServiceCreateData): Promise<ServiceRecord> {
    const createdAt = new Date();
    this.sqlite.execute(`
      INSERT INTO services (
        id, did, name, domain, required_scope, description, framework, created_at, revoked_at
      ) VALUES (
        ${sqliteLiteral(data.id)},
        ${sqliteLiteral(data.did)},
        ${sqliteLiteral(data.name)},
        ${sqliteLiteral(data.domain)},
        ${sqliteLiteral(data.requiredScope)},
        ${sqliteLiteral(data.description)},
        ${sqliteLiteral(data.framework)},
        ${sqliteLiteral(createdAt)},
        NULL
      )
    `);
    return { ...data, createdAt, revokedAt: null };
  }

  private one(where: string): ServiceRecord | null {
    return fromSqliteRow(this.sqlite.query<SqliteServiceRow>(`SELECT * FROM services WHERE ${where} LIMIT 1`)[0]);
  }

  async findById(id: string): Promise<ServiceRecord | null> {
    return this.one(`id = ${sqliteLiteral(id)}`);
  }

  async findByDid(did: string): Promise<ServiceRecord | null> {
    return this.one(`did = ${sqliteLiteral(did)}`);
  }

  async findByName(name: string): Promise<ServiceRecord | null> {
    return this.one(`name = ${sqliteLiteral(name)}`);
  }

  async list(): Promise<ServiceRecord[]> {
    return this.sqlite
      .query<SqliteServiceRow>(`SELECT * FROM services ORDER BY created_at DESC`)
      .map((row) => fromSqliteRow(row)!);
  }

  async revoke(id: string): Promise<void> {
    this.sqlite.execute(
      `UPDATE services SET revoked_at = ${sqliteLiteral(new Date())} WHERE id = ${sqliteLiteral(id)} AND revoked_at IS NULL`,
    );
  }
}

export class InMemoryServiceStorageDriver implements ServiceStorageDriver {
  private readonly rows = new Map<string, ServiceRecord>();

  async create(data: ServiceCreateData): Promise<ServiceRecord> {
    const record: ServiceRecord = { ...data, createdAt: new Date(), revokedAt: null };
    this.rows.set(record.id, record);
    return record;
  }

  async findById(id: string): Promise<ServiceRecord | null> {
    return this.rows.get(id) ?? null;
  }

  async findByDid(did: string): Promise<ServiceRecord | null> {
    return [...this.rows.values()].find((row) => row.did === did) ?? null;
  }

  async findByName(name: string): Promise<ServiceRecord | null> {
    return [...this.rows.values()].find((row) => row.name === name) ?? null;
  }

  async list(): Promise<ServiceRecord[]> {
    return [...this.rows.values()].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async revoke(id: string): Promise<void> {
    const row = this.rows.get(id);
    if (row && !row.revokedAt) row.revokedAt = new Date();
  }
}

export function createServiceStorageDriver(
  kind: StorageDriverKind,
  deps: StorageDriverDeps,
): ServiceStorageDriver {
  switch (kind) {
    case 'postgres':
      if (!deps.prisma) throw new Error("createServiceStorageDriver('postgres') requires deps.prisma");
      return new PrismaServiceStorageDriver(deps.prisma as PrismaClient);
    case 'sqlite':
      if (!deps.sqlite) throw new Error("createServiceStorageDriver('sqlite') requires deps.sqlite");
      return new SqliteServiceStorageDriver(deps.sqlite as SqliteStore);
    case 'memory':
      return new InMemoryServiceStorageDriver();
    default: {
      const _exhaustive: never = kind;
      throw new UnsupportedStorageDriverError('ServiceRepository', _exhaustive);
    }
  }
}
