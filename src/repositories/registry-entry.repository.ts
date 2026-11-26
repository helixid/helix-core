// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Registry v3 (2026-11-24): `registry_entries`, the "Make discoverable"
// choice an agent was onboarded with, keyed by DID. helixid lists its
// discoverable agents from here; the enterprise build keeps the choice here
// from creation until the agent is active (a self-custody agent only is,
// after helix init). An agent with no row is discoverable (the default).

import type { PrismaClient } from '@prisma/client';
import { sqliteLiteral, type SqliteStore } from '../storage/sqlite.js';

export interface RegistryEntryRow {
  did: string;
  discoverable: boolean;
  createdAt: Date;
  updatedAt: Date;
}

type PrismaRaw = PrismaClient & {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
  $executeRawUnsafe(query: string, ...values: unknown[]): Promise<number>;
};

function toRow(raw: { did: string; discoverable: unknown; createdAt: unknown; updatedAt: unknown }): RegistryEntryRow {
  return {
    did: raw.did,
    discoverable: raw.discoverable === true || raw.discoverable === 1,
    createdAt: new Date(raw.createdAt as string),
    updatedAt: new Date(raw.updatedAt as string),
  };
}

export class RegistryEntryRepository {
  private readonly memory = new Map<string, RegistryEntryRow>();

  constructor(
    private readonly prisma?: PrismaClient,
    private readonly sqlite?: SqliteStore,
  ) {}

  async get(did: string): Promise<RegistryEntryRow | null> {
    return (await this.select(`did = ${sqliteLiteral(did)}`, `"did" = $1`, [did], (row) => row.did === did))[0] ?? null;
  }

  /** Every discoverable agent's row, oldest first. */
  async listDiscoverable(): Promise<RegistryEntryRow[]> {
    const rows = await this.select('discoverable = 1', `"discoverable" = true`, [], (row) => row.discoverable);
    return rows.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.did.localeCompare(b.did));
  }

  /** Inserts or updates the choice. */
  async set(did: string, discoverable: boolean): Promise<RegistryEntryRow> {
    const current = await this.get(did);
    const now = new Date();
    const row: RegistryEntryRow = { did, discoverable, createdAt: current?.createdAt ?? now, updatedAt: now };
    if (this.prisma) {
      await (this.prisma as PrismaRaw).$executeRawUnsafe(
        `INSERT INTO "registry_entries" ("did", "discoverable", "createdAt", "updatedAt") VALUES ($1, $2, $3, $3)
         ON CONFLICT ("did") DO UPDATE SET "discoverable" = $2, "updatedAt" = $3`,
        did,
        discoverable,
        now,
      );
    } else if (this.sqlite) {
      this.sqlite.execute(`
        INSERT INTO registry_entries (did, discoverable, created_at, updated_at)
        VALUES (${sqliteLiteral(did)}, ${sqliteLiteral(discoverable)}, ${sqliteLiteral(row.createdAt)}, ${sqliteLiteral(now)})
        ON CONFLICT (did) DO UPDATE SET discoverable = excluded.discoverable, updated_at = excluded.updated_at
      `);
    } else {
      this.memory.set(did, { ...row });
    }
    return row;
  }

  private async select(
    sqliteWhere: string,
    pgWhere: string,
    pgValues: unknown[],
    memoryWhere: (row: RegistryEntryRow) => boolean,
  ): Promise<RegistryEntryRow[]> {
    if (this.prisma) {
      const rows = await (this.prisma as PrismaRaw).$queryRawUnsafe<Array<{ did: string; discoverable: boolean; createdAt: Date; updatedAt: Date }>>(
        `SELECT "did", "discoverable", "createdAt", "updatedAt" FROM "registry_entries" WHERE ${pgWhere}`,
        ...pgValues,
      );
      return rows.map(toRow);
    }
    if (this.sqlite) {
      return this.sqlite
        .query<{ did: string; discoverable: number; created_at: string; updated_at: string }>(
          `SELECT did, discoverable, created_at, updated_at FROM registry_entries WHERE ${sqliteWhere}`,
        )
        .map((row) => toRow({ ...row, createdAt: row.created_at, updatedAt: row.updated_at }));
    }
    return [...this.memory.values()].filter(memoryWhere).map((row) => ({ ...row }));
  }
}
