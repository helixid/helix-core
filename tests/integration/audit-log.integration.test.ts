// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { MemoryRecorderWitness, pairwiseDid, type AuditProducerEvent } from '../../src/core/index.js';
import { createApiAudit, createApiAuditStorage, decodeAuditCursor, encodeAuditCursor, type ApiAudit, type ApiAuditConfig } from '../../src/audit/index.js';
import { testRecorderSigner } from '../utils/auditLedger.js';
import { errorHandler } from '../../src/middleware/errorHandler.js';
import auditLogRoutes from '../../src/routes/audit-log/index.js';
import { fixture } from '../unit/core/audit/fixture.js';

const ADMIN = 'test-admin-key-0001';
const admin = { 'x-admin-api-key': ADMIN };

const config: ApiAuditConfig = {
  NODE_ENV: 'test',
  AUDIT_LOG_DESTINATION: 'none',
  AUDIT_LOG_PATH: undefined,
  AUDIT_SOURCE_ID: 'helix-api',
  AUDIT_INCLUDE_TOOL_NAMES: false,
  AUDIT_EVIDENCE_KEY: undefined,
  AUDIT_EVIDENCE_KEY_ID: 'evidence-key-v1',
  HELIX_ISSUER_DID: 'did:web:issuer.example',
  HELIX_SIGNING_KEY: 'a'.repeat(64),
  AUDIT_RECORDER_SIGNING_KEY: undefined,
  AUDIT_RECORDER_DID: undefined,
  AUDIT_RECORDER_KID: undefined,
  AUDIT_RECORDER_MODE: 'managed',
  AUDIT_RECORDER_TENANTS: undefined,
  AUDIT_RECORDER_WITNESS_PATH: undefined,
  AUDIT_RETENTION_MIN_DAYS: 0,
};

function makeAudit(): ApiAudit {
  return createApiAudit(config, createApiAuditStorage({}), { signer: testRecorderSigner(), witness: new MemoryRecorderWitness() });
}

async function makeApp(audit = makeAudit()) {
  const app = Fastify({ logger: false });
  app.setErrorHandler(errorHandler);
  await app.register(auditLogRoutes, { prefix: '/v1/audit-log', audit, adminApiKey: ADMIN });
  await app.ready();
  const store = { list: (filters: { limit: number }) => audit.storage.journal.listEntries(filters) };
  return { app, store, audit };
}

/** A producer event as the middleware would post it: its own source sequence and predecessor. */
function producerEvent(overrides: Partial<AuditProducerEvent> = {}): AuditProducerEvent {
  return { ...fixture.chain.entries[1]!.event, ...overrides };
}

describe('audit log routes (KYA-OS A-1)', () => {
  it('records a typed producer event as presented and lists it', async () => {
    const { app, store } = await makeApp();
    const event = producerEvent();
    const posted = await app.inject({ method: 'POST', url: '/v1/audit-log/events', headers: admin, payload: event });
    expect(posted.statusCode, posted.body).toBe(201);
    const recorded = posted.json() as { recorded: boolean; eventId: string; eventDigest: string; entry: { core: { sequence: string; ledgerEpochId: string; event: AuditProducerEvent } } };
    expect(recorded).toMatchObject({ recorded: true, eventId: event.eventId, eventDigest: fixture.chain.entries[1]!.digest });
    expect(recorded.entry.core).toMatchObject({ sequence: '1', event });
    const again = await app.inject({ method: 'POST', url: '/v1/audit-log/events', headers: admin, payload: event });
    expect(again.statusCode).toBe(201);
    // A redelivery gets the original entry back; the ledger holds its genesis and the one event.
    expect(again.json()).toEqual(recorded);
    expect(await store.list({ limit: 10 })).toHaveLength(2);

    const list = await app.inject({ method: 'GET', url: '/v1/audit-log?eventType=tool.call.completed&limit=10', headers: admin });
    expect(list.statusCode).toBe(200);
    const page = list.json() as { items: Array<{ id: string; recordedAt: string; eventDigest: string; event: AuditProducerEvent; sequence: string; ledgerId: string }>; nextCursor: string | null };
    expect(page.nextCursor).toBeNull();
    const rows = page.items;
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: `${rows[0]!.ledgerId}:${recorded.entry.core.ledgerEpochId}:1`, sequence: '1', eventDigest: fixture.chain.entries[1]!.digest, event });
    expect(new Date(rows[0]!.recordedAt).getTime()).toBeGreaterThan(0);
    expect(rows[0]!.event.source).toMatchObject({ sourceSequence: '2', previousSourceEventDigest: fixture.chain.entries[0]!.digest });
    const items = async (query: string): Promise<unknown[]> => ((await app.inject({ method: 'GET', url: `/v1/audit-log${query}`, headers: admin })).json() as { items: unknown[] }).items;
    expect(await items('?family=session')).toEqual([]);
    expect(await items('?correlationId=call-0001&since=2020-01-01T00:00:00Z')).toHaveLength(1);
    expect(await items(`?ledgerId=${rows[0]!.ledgerId}`)).toHaveLength(2);
    // The same key as a bearer token is accepted (the middleware reporter sends it that way).
    expect((await app.inject({ method: 'GET', url: '/v1/audit-log', headers: { authorization: `Bearer ${ADMIN}` } })).statusCode).toBe(200);
  });

  it('refuses an event with an unknown member, a wrong family, or a secret-shaped extra, with the path', async () => {
    const { app, store } = await makeApp();
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ ...producerEvent(), arguments: { orderId: 'ORD-1' } }, ''],
      [{ ...producerEvent(), details: { family: 'tool', phase: 'completed', attempt: '1', response: 'x' } }, 'details'],
      [{ ...producerEvent(), details: { family: 'session', phase: 'established' } }, 'details.family'],
      [{ ...producerEvent(), correlationId: 'x'.repeat(257) }, 'correlationId'],
    ];
    for (const [payload, path] of cases) {
      const res = await app.inject({ method: 'POST', url: '/v1/audit-log/events', headers: admin, payload });
      expect(res.statusCode, JSON.stringify(payload)).toBe(400);
      const body = res.json() as { error: { code: string; details: { issues: Array<{ path: string }> } } };
      expect(body.error.code).toBe('AUDIT_EVENT_INVALID');
      expect(body.error.details.issues[0]!.path).toBe(path);
    }
    for (const rejection of fixture.rejections) {
      const res = await app.inject({ method: 'POST', url: '/v1/audit-log/events', headers: admin, payload: rejection.event });
      expect(res.statusCode, rejection.name).toBe(400);
    }
    expect(await store.list({ limit: 10 })).toEqual([]);
  });

  it('refuses the same event id from one source with different content', async () => {
    const { app } = await makeApp();
    const event = producerEvent();
    expect((await app.inject({ method: 'POST', url: '/v1/audit-log/events', headers: admin, payload: event })).statusCode).toBe(201);
    const res = await app.inject({ method: 'POST', url: '/v1/audit-log/events', headers: admin, payload: { ...event, outcome: 'failed' } });
    expect(res.statusCode).toBe(409);
    expect((res.json() as { error: { code: string } }).error.code).toBe('AUDIT_EVENT_ID_CONFLICT');
  });

  it('is admin-gated on every route', async () => {
    const { app } = await makeApp();
    for (const [method, url] of [
      ['POST', '/v1/audit-log/events'],
      ['GET', '/v1/audit-log'],
      ['POST', '/v1/audit-log/evidence'],
      ['GET', '/v1/audit-log/evidence/x'],
    ] as const) {
      expect((await app.inject({ method, url, payload: method === 'POST' ? {} : undefined })).statusCode, url).toBe(403);
      expect((await app.inject({ method, url, headers: { 'x-admin-api-key': ['wrong'] }, payload: method === 'POST' ? {} : undefined })).statusCode, url).toBe(403);
    }
    const noKey = Fastify({ logger: false });
    noKey.setErrorHandler(errorHandler);
    await noKey.register(auditLogRoutes, { prefix: '/v1/audit-log', audit: makeAudit() });
    await noKey.ready();
    expect((await noKey.inject({ method: 'GET', url: '/v1/audit-log', headers: admin })).statusCode).toBe(403);
  });

  it('validates the list query', async () => {
    const { app } = await makeApp();
    for (const query of ['limit=0', 'limit=501', 'limit=abc', 'since=yesterday', 'eventType=nope', 'family=nope']) {
      const res = await app.inject({ method: 'GET', url: `/v1/audit-log?${query}`, headers: admin });
      expect(res.statusCode, query).toBe(400);
      expect((res.json() as { error: { code: string } }).error.code).toBe('VALIDATION_ERROR');
    }
    expect((await app.inject({ method: 'GET', url: '/v1/audit-log?eventType=&family=&since=&correlationId=', headers: admin })).statusCode).toBe(200);
  });

  it('stores and returns evidence by object id, only for bytes that match the reference', async () => {
    const { app } = await makeApp();
    const { ref, ciphertext_b64url } = fixture.evidence;
    const stored = await app.inject({ method: 'POST', url: '/v1/audit-log/evidence', headers: admin, payload: { ref, ciphertextBase64url: ciphertext_b64url } });
    expect(stored.statusCode, stored.body).toBe(201);
    expect(stored.json()).toEqual({ stored: true, objectId: ref.objectId, ciphertextDigest: ref.ciphertextDigest });
    const got = await app.inject({ method: 'GET', url: `/v1/audit-log/evidence/${ref.objectId}`, headers: admin });
    expect(got.statusCode).toBe(200);
    expect(got.json()).toEqual({ ref, ciphertextBase64url: ciphertext_b64url });
    expect((await app.inject({ method: 'GET', url: '/v1/audit-log/evidence/evi_missing', headers: admin })).statusCode).toBe(404);

    const bad: Array<Record<string, unknown>> = [
      { ref, ciphertextBase64url: 'AAAA' },
      { ref: { ...ref, bytes: 'x' }, ciphertextBase64url: ciphertext_b64url },
      { ref, ciphertextBase64url: 'not base64url!' },
      { ref },
      {},
    ];
    for (const payload of bad) {
      const res = await app.inject({ method: 'POST', url: '/v1/audit-log/evidence', headers: admin, payload });
      expect(res.statusCode, JSON.stringify(payload)).toBe(400);
      expect((res.json() as { error: { code: string } }).error.code).toBe('AUDIT_EVIDENCE_INVALID');
    }
  });

  it('records what the API trail produces through the same recorder', async () => {
    const audit = makeAudit();
    const { app } = await makeApp(audit);
    await audit.trail.record({
      eventType: 'proof.verified',
      actor: pairwiseDid('did:key:zAgent'),
      action: { category: 'presentation' },
      outcome: 'succeeded',
      details: { family: 'proof', phase: 'verified' },
    });
    const list = await app.inject({ method: 'GET', url: '/v1/audit-log?family=proof', headers: admin });
    expect((list.json() as { items: Array<{ event: AuditProducerEvent }> }).items[0]!.event.source).toMatchObject({ sourceId: 'helix-api', sourceSequence: '1' });
  });

  it('pages newest first with an opaque cursor that neither skips nor repeats an entry', async () => {
    const { app } = await makeApp();
    for (let i = 0; i < 5; i += 1) {
      const event = { ...producerEvent(), eventId: `page-${i}`, correlationId: `page-${i}` };
      expect((await app.inject({ method: 'POST', url: '/v1/audit-log/events', headers: admin, payload: event })).statusCode).toBe(201);
    }
    const seen: string[] = [];
    let cursor = '';
    let pages = 0;
    do {
      const res = await app.inject({ method: 'GET', url: `/v1/audit-log?limit=2&cursor=${cursor}`, headers: admin });
      const page = res.json() as { items: Array<{ sequence: string }>; nextCursor: string | null };
      seen.push(...page.items.map((item) => item.sequence));
      cursor = page.nextCursor ?? '';
      pages += 1;
    } while (cursor !== '');
    // Genesis (0) and five events, newest first, three pages.
    expect(seen).toEqual(['5', '4', '3', '2', '1', '0']);
    expect(pages).toBe(3);
    expect(decodeAuditCursor(encodeAuditCursor({ recordedAt: 1, ledgerId: 'l', ledgerEpochId: 'e', sequence: '9' }))).toEqual({ recordedAt: 1, ledgerId: 'l', ledgerEpochId: 'e', sequence: '9' });
    for (const bad of ['not-a-cursor', Buffer.from('[1,"l","e","x"]').toString('base64url'), Buffer.from('{}').toString('base64url')]) {
      const res = await app.inject({ method: 'GET', url: `/v1/audit-log?cursor=${bad}`, headers: admin });
      expect([res.statusCode, (res.json() as { error: { code: string } }).error.code], bad).toEqual([400, 'VALIDATION_ERROR']);
    }
  });
});
