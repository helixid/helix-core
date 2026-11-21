// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import {
  EvidenceEncryptor,
  MemoryRecorderWitness,
  evidenceAad,
  type AuditLedgerVerification,
  type SignedAuditEntry,
  type StoredAuditEntry,
} from '../../src/core/index.js';
import {
  createApiAudit,
  createApiAuditStorage,
  handleAuditSubmission,
  operatorSubmissionContext,
  parseAuditSubmissionWire,
  partyAuthority,
  type ApiAudit,
  type ApiAuditConfig,
} from '../../src/audit/index.js';
import { errorHandler } from '../../src/middleware/errorHandler.js';
import auditRoutes from '../../src/routes/audit/index.js';
import { runAuditCli } from '../../src/cli/audit.js';
import { TENANT, producerEvent, testRecorderSigner } from '../utils/auditLedger.js';

const ADMIN = 'test-admin-key-0002';
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

async function makeApp(adminApiKey: string | null = ADMIN): Promise<{ app: ReturnType<typeof Fastify>; audit: ApiAudit }> {
  const audit = createApiAudit(config, createApiAuditStorage({}), { signer: testRecorderSigner(), witness: new MemoryRecorderWitness() });
  const app = Fastify({ logger: false });
  app.setErrorHandler(errorHandler);
  await app.register(auditRoutes, { prefix: '/v1/audit', audit, adminApiKey: adminApiKey ?? undefined });
  await app.ready();
  return { app, audit };
}

describe('recorder routes (A-2)', () => {
  it('records a submission with its evidence and answers with the signed entry, the original one on redelivery', async () => {
    const { app, audit } = await makeApp();
    const encrypted = new EvidenceEncryptor({ key: 'ab'.repeat(32), keyId: 'k1' }).encrypt({ plaintext: 'exact', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    const event = { ...producerEvent('route-1'), evidence: [encrypted.ref] };
    const wire = { producerEvent: event, encryptedEvidence: [{ ref: encrypted.ref, ciphertextBase64url: Buffer.from(encrypted.ciphertext).toString('base64url') }] };
    const posted = await app.inject({ method: 'POST', url: '/v1/audit/submissions', headers: admin, payload: wire });
    expect(posted.statusCode, posted.body).toBe(201);
    const { entry } = posted.json() as { entry: SignedAuditEntry };
    expect(entry.core).toMatchObject({ sequence: '1', event });
    expect(entry.recorderReceipt.core).toMatchObject({ sequence: '1', eventId: 'route-1', entryDigest: entry.entryDigest });
    expect(await audit.storage.evidence.get(encrypted.ref.objectId)).not.toBeNull();
    const again = await app.inject({ method: 'POST', url: '/v1/audit/submissions', headers: { authorization: `Bearer ${ADMIN}` }, payload: wire });
    expect(again.json()).toEqual({ entry });

    // Refusals: the wrong ledger, an unreferenced object, a changed event, a malformed wire.
    const wrongLedger = await app.inject({ method: 'POST', url: '/v1/audit/submissions', headers: admin, payload: { ...wire, ledgerId: 'ledger_other' } });
    expect([wrongLedger.statusCode, (wrongLedger.json() as { error: { code: string } }).error.code]).toEqual([409, 'AUDIT_LEDGER_MISMATCH']);
    const unreferenced = await app.inject({ method: 'POST', url: '/v1/audit/submissions', headers: admin, payload: { ...wire, producerEvent: producerEvent('route-2') } });
    expect((unreferenced.json() as { error: { code: string } }).error.code).toBe('AUDIT_EVIDENCE_FAILURE');
    for (const bad of [{}, { producerEvent: event, extra: 1 }, { producerEvent: event, encryptedEvidence: [{ ref: {}, ciphertextBase64url: 'AA' }] }]) {
      const res = await app.inject({ method: 'POST', url: '/v1/audit/submissions', headers: admin, payload: bad });
      expect(res.statusCode, JSON.stringify(bad)).toBe(400);
    }
  });

  it('lists ledgers and epochs, exports an epoch as stored, and verifies the ledger here and offline', async () => {
    const { app, audit } = await makeApp();
    for (const id of ['a', 'b', 'c']) await app.inject({ method: 'POST', url: '/v1/audit/submissions', headers: admin, payload: { producerEvent: producerEvent(id) } });
    const ledgers = (await app.inject({ method: 'GET', url: '/v1/audit/ledgers', headers: admin })).json() as Array<{ ledgerId: string; epochs: unknown[] }>;
    expect(ledgers).toHaveLength(1);
    const ledgerId = ledgers[0]!.ledgerId;
    expect(ledgerId).toBe(audit.recorder.ledgerIdOf(TENANT));
    const ledger = (await app.inject({ method: 'GET', url: `/v1/audit/ledgers/${ledgerId}/epochs`, headers: admin })).json() as {
      tenantRef: unknown;
      epochs: Array<{ ledgerEpochId: string; head: { sequence: string } }>;
    };
    expect(ledger.tenantRef).toEqual(TENANT);
    expect(ledger.epochs[0]!.head.sequence).toBe('3');
    expect((await app.inject({ method: 'GET', url: '/v1/audit/ledgers/nope/epochs', headers: admin })).statusCode).toBe(404);
    const exported = (await app.inject({ method: 'GET', url: `/v1/audit/ledgers/${ledgerId}/epochs/${ledger.epochs[0]!.ledgerEpochId}/entries`, headers: admin })).json() as StoredAuditEntry[];
    expect(exported.map((row) => row.sequence)).toEqual(['0', '1', '2', '3']);

    const verified = (await app.inject({ method: 'GET', url: `/v1/audit/ledgers/${ledgerId}/verify?trustedRecorder=${encodeURIComponent(testRecorderSigner().ref.did)}`, headers: admin })).json() as AuditLedgerVerification;
    expect(verified).toMatchObject({ ok: true, entriesVerified: 4, warnings: [] });
    const unpinned = (await app.inject({ method: 'GET', url: `/v1/audit/ledgers/${ledgerId}/verify`, headers: admin })).json() as AuditLedgerVerification;
    expect(unpinned.warnings).toHaveLength(1);
    expect((await app.inject({ method: 'GET', url: '/v1/audit/ledgers/nope/verify', headers: admin })).statusCode).toBe(404);

    // The CLI verifies the same ledger through the API's export endpoints, here.
    const lines: string[] = [];
    const fetchApp: typeof fetch = async (input, init) => {
      const res = await app.inject({ method: 'GET', url: String(input).replace('http://api.test', ''), headers: init?.headers as Record<string, string> });
      return new Response(res.body, { status: res.statusCode, headers: { 'content-type': 'application/json' } });
    };
    const io = { out: (line: string) => lines.push(line), err: (line: string) => lines.push(line), fetch: fetchApp };
    expect(await runAuditCli(['verify', '--ledger', ledgerId, '--api', 'http://api.test', '--admin-key', ADMIN], io)).toBe(0);
    expect(lines[0]).toBe(`ledger ${ledgerId}: OK, 1 epoch(s), 4 entries verified`);
    expect(await runAuditCli(['ledgers', '--api', 'http://api.test', '--admin-key', ADMIN, '--json'], io)).toBe(0);
    expect(lines.at(-1)).toBe(JSON.stringify([ledgerId]));
    expect(await runAuditCli(['verify', '--ledger', ledgerId, '--api', 'http://api.test', '--admin-key', 'wrong'], io)).toBe(2);
  });

  it('runs an epoch transition, legal hold, release and disposal, each recorded', async () => {
    const { app, audit } = await makeApp();
    const encrypted = new EvidenceEncryptor({ key: 'cd'.repeat(32), keyId: 'k2' }).encrypt({ plaintext: 'kept', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    const event = { ...producerEvent('held'), evidence: [encrypted.ref] };
    const { entry } = (
      await app.inject({
        method: 'POST',
        url: '/v1/audit/submissions',
        headers: admin,
        payload: { producerEvent: event, encryptedEvidence: [{ ref: encrypted.ref, ciphertextBase64url: Buffer.from(encrypted.ciphertext).toString('base64url') }] },
      })
    ).json() as { entry: SignedAuditEntry };
    const ledgerId = entry.core.ledgerId;
    const target = { kind: 'entry', ledgerEpochId: entry.core.ledgerEpochId, sequence: entry.core.sequence };

    const hold = await app.inject({ method: 'POST', url: `/v1/audit/ledgers/${ledgerId}/legal-holds`, headers: admin, payload: { holdId: 'case-1', target } });
    expect(hold.statusCode, hold.body).toBe(201);
    const refused = await app.inject({ method: 'POST', url: `/v1/audit/ledgers/${ledgerId}/disposals`, headers: admin, payload: { target } });
    expect([refused.statusCode, (refused.json() as { error: { code: string } }).error.code]).toEqual([409, 'AUDIT_EVIDENCE_LEGAL_HOLD']);
    const released = await app.inject({ method: 'POST', url: '/v1/audit/legal-holds/case-1/release', headers: admin });
    expect(released.json()).toMatchObject({ holdId: 'case-1', released: true });
    expect((await app.inject({ method: 'POST', url: '/v1/audit/legal-holds/case-1/release', headers: admin })).statusCode).toBe(409);
    const disposed = await app.inject({ method: 'POST', url: `/v1/audit/ledgers/${ledgerId}/disposals`, headers: admin, payload: { target } });
    expect(disposed.statusCode, disposed.body).toBe(201);
    expect(disposed.json()).toMatchObject({ disposedObjectIds: [encrypted.ref.objectId], skippedObjectIds: [] });
    expect(await audit.storage.evidence.get(encrypted.ref.objectId)).toBeNull();

    const transition = await app.inject({ method: 'POST', url: `/v1/audit/ledgers/${ledgerId}/epochs`, headers: admin, payload: { reason: 'retention_rollover' } });
    expect(transition.statusCode, transition.body).toBe(201);
    expect(transition.json()).toMatchObject({ ledgerId, previousEpochId: entry.core.ledgerEpochId, reason: 'retention_rollover' });
    const verified = (await app.inject({ method: 'GET', url: `/v1/audit/ledgers/${ledgerId}/verify`, headers: admin })).json() as AuditLedgerVerification;
    expect(verified.ok).toBe(true);
    expect(verified.epochs).toHaveLength(2);

    for (const [url, payload] of [
      [`/v1/audit/ledgers/${ledgerId}/epochs`, { reason: 'whim' }],
      [`/v1/audit/ledgers/${ledgerId}/legal-holds`, { holdId: 'x', target: { kind: 'entry', ledgerEpochId: 'e', sequence: '01' } }],
      [`/v1/audit/ledgers/${ledgerId}/disposals`, { target: { kind: 'ledger' } }],
    ] as const) {
      const res = await app.inject({ method: 'POST', url, headers: admin, payload });
      expect(res.statusCode, url).toBe(400);
    }
    const missing = await app.inject({ method: 'POST', url: `/v1/audit/ledgers/${ledgerId}/disposals`, headers: admin, payload: { target: { kind: 'evidence', objectId: 'evi_none' } } });
    expect((missing.json() as { error: { code: string } }).error.code).toBe('AUDIT_RETENTION_REFUSED');
  });

  it('is operator-gated on every route', async () => {
    const { app } = await makeApp();
    for (const [method, url] of [
      ['POST', '/v1/audit/submissions'],
      ['GET', '/v1/audit/ledgers'],
      ['GET', '/v1/audit/ledgers/x/verify'],
      ['POST', '/v1/audit/ledgers/x/epochs'],
      ['POST', '/v1/audit/legal-holds/x/release'],
    ] as const) {
      expect((await app.inject({ method, url, payload: method === 'POST' ? {} : undefined })).statusCode, url).toBe(403);
      expect((await app.inject({ method, url, headers: { authorization: 'Bearer wrong' }, payload: method === 'POST' ? {} : undefined })).statusCode, url).toBe(403);
    }
    const { app: noKey } = await makeApp(null);
    expect((await noKey.inject({ method: 'GET', url: '/v1/audit/ledgers', headers: admin })).statusCode).toBe(403);
  });

  it('exposes the submission wire for piggybacking on another request', async () => {
    const { audit } = await makeApp();
    const event = producerEvent('piggyback');
    const parsed = parseAuditSubmissionWire({ producerEvent: event, expectedLedgerEpochId: 'epoch-x', ledgerId: 'ledger-x' });
    expect(parsed).toMatchObject({ ledgerId: 'ledger-x', expectedLedgerEpochId: 'epoch-x', encryptedEvidence: [] });
    expect(operatorSubmissionContext(parsed)).toEqual({ producerAuthority: 'did:web:orders.example.com', tenantAuthority: 'did:web:orders.example.com', producerRef: event.source.producer, tenantRef: event.tenantRef });
    expect(partyAuthority({ kind: 'keyed_commitment', value: `sha256:${'1'.repeat(64)}`, keyId: 'k' })).toBe(`{"keyId":"k","kind":"keyed_commitment","value":"sha256:${'1'.repeat(64)}"}`);
    const { entry } = await handleAuditSubmission(audit.recorder, { producerEvent: event });
    expect(entry.core.event).toEqual(event);
  });
});
