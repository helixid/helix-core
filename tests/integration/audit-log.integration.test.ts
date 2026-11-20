// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { AuditTrail, pairwiseDid, publicDid, type AuditProducerEvent } from '../../src/core/index.js';
import { MemoryAuditStore } from '../../src/audit/index.js';
import { errorHandler } from '../../src/middleware/errorHandler.js';
import auditLogRoutes from '../../src/routes/audit-log/index.js';
import { fixture } from '../unit/core/audit/fixture.js';

const ADMIN = 'test-admin-key-0001';
const admin = { 'x-admin-api-key': ADMIN };

async function makeApp(store = new MemoryAuditStore()) {
  const app = Fastify({ logger: false });
  app.setErrorHandler(errorHandler);
  await app.register(auditLogRoutes, { prefix: '/v1/audit-log', auditStore: store, adminApiKey: ADMIN });
  await app.ready();
  return { app, store };
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
    expect(posted.json()).toEqual({ recorded: true, eventId: event.eventId, eventDigest: fixture.chain.entries[1]!.digest });
    const again = await app.inject({ method: 'POST', url: '/v1/audit-log/events', headers: admin, payload: event });
    expect(again.statusCode).toBe(201);
    expect(await store.list({ limit: 10 })).toHaveLength(1);

    const list = await app.inject({ method: 'GET', url: '/v1/audit-log?eventType=tool.call.completed&limit=10', headers: admin });
    expect(list.statusCode).toBe(200);
    const rows = list.json() as Array<{ id: string; recordedAt: string; eventDigest: string; event: AuditProducerEvent }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ id: '1', eventDigest: fixture.chain.entries[1]!.digest, event });
    expect(new Date(rows[0]!.recordedAt).getTime()).toBeGreaterThan(0);
    expect(rows[0]!.event.source).toMatchObject({ sourceSequence: '2', previousSourceEventDigest: fixture.chain.entries[0]!.digest });
    expect((await app.inject({ method: 'GET', url: '/v1/audit-log?family=session', headers: admin })).json()).toEqual([]);
    expect((await app.inject({ method: 'GET', url: '/v1/audit-log?correlationId=call-0001&since=2020-01-01T00:00:00Z', headers: admin })).json()).toHaveLength(1);
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
    await noKey.register(auditLogRoutes, { prefix: '/v1/audit-log', auditStore: new MemoryAuditStore() });
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

  it('records what the API trail produces through the same store', async () => {
    const store = new MemoryAuditStore();
    const { app } = await makeApp(store);
    const trail = new AuditTrail({ sink: store, sourceId: 'helix-api', producer: publicDid('did:web:issuer.example'), tenantRef: publicDid('did:web:issuer.example') });
    await trail.record({
      eventType: 'proof.verified',
      actor: pairwiseDid('did:key:zAgent'),
      action: { category: 'presentation' },
      outcome: 'succeeded',
      details: { family: 'proof', phase: 'verified' },
    });
    const list = await app.inject({ method: 'GET', url: '/v1/audit-log?family=proof', headers: admin });
    expect((list.json() as Array<{ event: AuditProducerEvent }>)[0]!.event.source).toMatchObject({ sourceId: 'helix-api', sourceSequence: '1' });
  });
});
