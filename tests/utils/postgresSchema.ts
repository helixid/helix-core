// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';

/**
 * The PostgreSQL the A-2 journal tests run against: AUDIT_JOURNAL_DATABASE_URL,
 * else A-1's AUDIT_STORE_DATABASE_URL. Unset, those tests are skipped.
 */
export const auditJournalDatabaseUrl = process.env['AUDIT_JOURNAL_DATABASE_URL'] ?? process.env['AUDIT_STORE_DATABASE_URL'];

const migrationsDir = join(process.cwd(), 'prisma', 'migrations');

/**
 * A fresh schema with every migration applied, and a pool whose connections
 * use it: each provider the contract creates gets an empty journal without
 * ever deleting from one (the triggers would refuse).
 */
export async function createMigratedSchema(url: string, prefix = 'a2'): Promise<{ pool: pg.Pool; schema: string; drop(): Promise<void> }> {
  const schema = `${prefix}_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: url });
  await admin.connect();
  try {
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.query(`SET search_path TO "${schema}"`);
    const migrations = readdirSync(migrationsDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
    for (const migration of migrations) {
      const sql = readFileSync(join(migrationsDir, migration, 'migration.sql'), 'utf8');
      if (sql.trim()) await admin.query(sql);
    }
  } finally {
    await admin.end();
  }
  const pool = new pg.Pool({ connectionString: url, options: `-c search_path="${schema}"`, max: 20 });
  return {
    pool,
    schema,
    async drop(): Promise<void> {
      await pool.end();
      const cleanup = new pg.Client({ connectionString: url });
      await cleanup.connect();
      try {
        await cleanup.query(`DROP SCHEMA "${schema}" CASCADE`);
      } finally {
        await cleanup.end();
      }
    },
  };
}
