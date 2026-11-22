// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { AuditTrail, EvidenceEncryptor, evidenceAad, pairwiseDid, publicDid, type AuditTrailEntry } from '../../src/core/index.js';
import { AuditEventConflictError, PrismaAuditSink } from '../../src/audit/index.js';
import { createTestPrisma } from '../utils/prisma.js';
import { fixture } from '../unit/core/audit/fixture.js';

/**
 * `PrismaAuditSink` against a real PostgreSQL with the A-1 migration applied.
 * Needs AUDIT_STORE_DATABASE_URL (a database prepared with
 * `scripts/prepare-test-db.mjs`); skipped otherwise, so the rest of the suite
 * never depends on a database.
 */
const url = process.env['AUDIT_STORE_DATABASE_URL'];

describe.skipIf(!url)('PrismaAuditSink on PostgreSQL', () => {
  let prisma: PrismaClient;
  let sink: PrismaAuditSink;
  const sourceId = `pg-test-${Date.now()}`;

  beforeAll(() => {
    process.env['DATABASE_URL'] = url;
    prisma = createTestPrisma();
    sink = new PrismaAuditSink(prisma);
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('appends through the trail, lists newest first, and chains the source', async () => {
    const trail = new AuditTrail({ sink, sourceId, producer: publicDid('did:web:issuer.example'), tenantRef: publicDid('did:web:issuer.example') });
    const first = await trail.record({ eventType: 'session.established', correlationId: sourceId, action: { category: 'session' }, outcome: 'succeeded', details: { family: 'session', phase: 'established' } });
    const second = await trail.record({ eventType: 'tool.call.started', correlationId: sourceId, actor: pairwiseDid('did:key:zA'), action: { category: 'tool.call' }, outcome: 'unknown', details: { family: 'tool', phase: 'started', attempt: '1' } });
    const rows = await sink.list({ correlationId: sourceId, limit: 10 });
    expect(rows.map((row) => row.eventDigest)).toEqual([second.eventDigest, first.eventDigest]);
    expect(rows[0]!.event).toEqual(second.event);
    expect(rows[0]!.event.source.previousSourceEventDigest).toBe(first.eventDigest);
    expect((await sink.list({ correlationId: sourceId, family: 'tool', limit: 10 })).length).toBe(1);
    expect((await sink.list({ correlationId: sourceId, eventType: 'session.established', since: new Date(0), limit: 10 })).length).toBe(1);
    const stored = await prisma.auditEvent.findUnique({ where: { eventDigest: second.eventDigest } });
    expect(stored).toMatchObject({ family: 'tool', sourceId, sourceSequence: 2n, actorRef: 'pairwise_did:did:key:zA', canonical: second.canonical });
  });

  it('is idempotent on the same event and refuses the same id with other content', async () => {
    const trail = new AuditTrail({ sink, sourceId: `${sourceId}-dup`, producer: publicDid('did:web:issuer.example'), tenantRef: publicDid('did:web:issuer.example') });
    const entry = await trail.record({ eventType: 'session.expired', eventId: 'stable', occurredAt: 1, action: { category: 'session' }, outcome: 'succeeded', details: { family: 'session', phase: 'expired' } });
    await sink.append(entry);
    const changed: AuditTrailEntry = { ...entry, event: { ...entry.event, outcome: 'failed' }, canonical: '{}', eventDigest: `sha256:${'2'.repeat(64)}` };
    await expect(sink.append(changed)).rejects.toThrow(AuditEventConflictError);
  });

  it('keeps evidence bytes exactly and decrypts them under the right AAD', async () => {
    const encryptor = new EvidenceEncryptor({ key: fixture.evidence.key_hex, keyId: fixture.evidence.key_id });
    const aad = evidenceAad(fixture.evidence.tenant, `${fixture.evidence.purpose}:${sourceId}`);
    const encrypted = encryptor.encrypt({ plaintext: fixture.evidence.plaintext_utf8, mediaType: 'application/json', aad, commitPlaintext: true });
    expect(await sink.putIfAbsent(encrypted)).toEqual(encrypted.ref);
    expect(await sink.putIfAbsent(encrypted)).toEqual(encrypted.ref);
    const got = (await sink.get(encrypted.ref.objectId))!;
    expect(got.ref).toEqual(encrypted.ref);
    expect(Buffer.from(encryptor.decrypt(got, aad)).toString()).toBe(fixture.evidence.plaintext_utf8);
    expect(() => encryptor.decrypt(got, evidenceAad(fixture.evidence.wrong_tenant, fixture.evidence.purpose))).toThrow();
    expect(await sink.get('evi_missing')).toBeNull();
  });
});
