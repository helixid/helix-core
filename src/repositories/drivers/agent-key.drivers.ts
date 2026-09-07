// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Storage-driver implementations for AgentKeyRepository — same pluggable
// pattern as did.drivers.ts. Unlike helix-server-enterprise's original
// AgentKeyRecord (which has no generated Prisma model of its own and falls
// back to raw SQL), core owns its own schema, so the Prisma driver here
// calls prisma.agentKey.* directly, same as PrismaDidStorageDriver.

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../../storage/sqlite.js';
import { sqliteLiteral } from '../../storage/sqlite.js';
import {
  UnsupportedStorageDriverError,
  type StorageDriverDeps,
  type StorageDriverKind,
} from '../../storage/driver-registry.js';
import type { AgentKeyRecord, CreateAgentKeyRecordParams } from '../agent-key.repository.js';

function makeId(prefix: string): string {
  return `${prefix}:${Math.random().toString(16).slice(2, 14)}`;
}

/** Everything AgentKeyRepository needs from a storage backend. */
export interface AgentKeyStorageDriver {
  create(data: CreateAgentKeyRecordParams): Promise<AgentKeyRecord>;
  findByDid(did: string): Promise<AgentKeyRecord | null>;
}

type PrismaLike = PrismaClient & {
  agentKey: {
    create(args: unknown): Promise<AgentKeyRecord>;
    findUnique(args: unknown): Promise<AgentKeyRecord | null>;
  };
};

export class PrismaAgentKeyStorageDriver implements AgentKeyStorageDriver {
  private readonly db: PrismaLike;

  constructor(prisma: PrismaClient) {
    this.db = prisma as PrismaLike;
  }

  async create(data: CreateAgentKeyRecordParams): Promise<AgentKeyRecord> {
    return this.db.agentKey.create({ data });
  }

  async findByDid(did: string): Promise<AgentKeyRecord | null> {
    return this.db.agentKey.findUnique({ where: { did } });
  }
}

type SqliteAgentKeyRow = {
  id: string;
  did: string;
  encrypted_private_key: string;
  iv: string;
  auth_tag: string;
  algorithm: string;
  created_at: string;
};

function fromSqliteRow(row: SqliteAgentKeyRow | undefined): AgentKeyRecord | null {
  if (!row) return null;
  return {
    id: row.id,
    did: row.did,
    encryptedPrivateKey: row.encrypted_private_key,
    iv: row.iv,
    authTag: row.auth_tag,
    algorithm: row.algorithm,
    createdAt: new Date(row.created_at),
  };
}

export class SqliteAgentKeyStorageDriver implements AgentKeyStorageDriver {
  constructor(private readonly sqlite: SqliteStore) {}

  async create(data: CreateAgentKeyRecordParams): Promise<AgentKeyRecord> {
    const id = makeId('agentkey');
    const now = new Date();
    this.sqlite.execute(`
      INSERT INTO agent_keys (
        id, did, encrypted_private_key, iv, auth_tag, algorithm, created_at
      ) VALUES (
        ${sqliteLiteral(id)},
        ${sqliteLiteral(data.did)},
        ${sqliteLiteral(data.encryptedPrivateKey)},
        ${sqliteLiteral(data.iv)},
        ${sqliteLiteral(data.authTag)},
        ${sqliteLiteral(data.algorithm)},
        ${sqliteLiteral(now)}
      )
    `);
    return {
      id,
      did: data.did,
      encryptedPrivateKey: data.encryptedPrivateKey,
      iv: data.iv,
      authTag: data.authTag,
      algorithm: data.algorithm,
      createdAt: now,
    };
  }

  async findByDid(did: string): Promise<AgentKeyRecord | null> {
    const rows = this.sqlite.query<SqliteAgentKeyRow>(`
      SELECT * FROM agent_keys WHERE did = ${sqliteLiteral(did)} LIMIT 1
    `);
    return fromSqliteRow(rows[0]);
  }
}

export class InMemoryAgentKeyStorageDriver implements AgentKeyStorageDriver {
  private readonly keys = new Map<string, AgentKeyRecord>();

  async create(data: CreateAgentKeyRecordParams): Promise<AgentKeyRecord> {
    const record: AgentKeyRecord = {
      id: makeId('agentkey'),
      did: data.did,
      encryptedPrivateKey: data.encryptedPrivateKey,
      iv: data.iv,
      authTag: data.authTag,
      algorithm: data.algorithm,
      createdAt: new Date(),
    };
    this.keys.set(record.did, record);
    return record;
  }

  async findByDid(did: string): Promise<AgentKeyRecord | null> {
    return this.keys.get(did) ?? null;
  }
}

/**
 * Selects an AgentKeyStorageDriver by kind. This is the one place that
 * needs a new `case` when a new backend is added.
 */
export function createAgentKeyStorageDriver(
  kind: StorageDriverKind,
  deps: StorageDriverDeps,
): AgentKeyStorageDriver {
  switch (kind) {
    case 'postgres':
      if (!deps.prisma) throw new Error("createAgentKeyStorageDriver('postgres') requires deps.prisma");
      return new PrismaAgentKeyStorageDriver(deps.prisma as PrismaClient);
    case 'sqlite':
      if (!deps.sqlite) throw new Error("createAgentKeyStorageDriver('sqlite') requires deps.sqlite");
      return new SqliteAgentKeyStorageDriver(deps.sqlite as SqliteStore);
    case 'memory':
      return new InMemoryAgentKeyStorageDriver();
    default: {
      // Exhaustiveness check: if StorageDriverKind gains a member without a
      // corresponding case above, this line fails to compile.
      const _exhaustive: never = kind;
      throw new UnsupportedStorageDriverError('AgentKeyRepository', _exhaustive);
    }
  }
}
