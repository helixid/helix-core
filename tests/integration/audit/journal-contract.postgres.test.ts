// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { afterAll, describe, expect, it } from 'vitest';
import { assertAuditProviderContract, evaluateAuditJournalProviderContract } from '../../../src/core/index.js';
import { PostgresAuditJournal } from '../../../src/audit/postgres-journal.js';
import { auditJournalDatabaseUrl, createMigratedSchema } from '../../utils/postgresSchema.js';

const url = auditJournalDatabaseUrl;
const schemas: Array<{ drop(): Promise<void> }> = [];

describe.skipIf(!url)('PostgresAuditJournal: the journal provider contract on PostgreSQL', () => {
  afterAll(async () => {
    for (const schema of schemas) await schema.drop();
  });

  it('passes evaluateAuditJournalProviderContract', async () => {
    const report = await evaluateAuditJournalProviderContract(async () => {
      const migrated = await createMigratedSchema(url!);
      schemas.push(migrated);
      return new PostgresAuditJournal(migrated.pool);
    });
    for (const item of report.checks) if (!item.passed) console.error(item.name, item.error);
    expect(report.checks.map((item) => [item.name, item.passed])).toEqual([
      ['declares atomic ordered capabilities', true],
      ['atomically appends and rejects a stale head', true],
      ['returns exact duplicates and rejects idempotency conflicts', true],
      ['keeps logical-ledger idempotency across epoch changes', true],
      ['scopes heads and ranges by epoch within a logical ledger', true],
      ['provides ordered stable range cursors', true],
    ]);
    expect(report.passed).toBe(true);
    assertAuditProviderContract(report);
  });
});
