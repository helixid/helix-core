// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import {
  AUDIT_BINDING_HELIX,
  AuditEventInvalidError,
  AuditEvidenceError,
  AuditTrail,
  DEFAULT_AUDIT_PRIVACY,
  EvidenceEncryptor,
  MemoryAuditSink,
  MemoryEvidenceStore,
  TeeAuditSink,
  digestText,
  evidenceAad,
  keyedCommitment,
  pairwiseDid,
  publicDid,
  sanitizeReference,
  type AuditEventInput,
  type AuditProducerEvent,
  type AuditSink,
  type AuditTrailOptions,
} from '../../../../src/core/audit/index.js';
import { fixture } from './fixture.js';

function fixtureTrail(sink: AuditSink, event: Pick<AuditProducerEvent, 'occurredAt' | 'eventId'>, extra: Partial<AuditTrailOptions> = {}): AuditTrail {
  return new AuditTrail({
    sink,
    sourceId: fixture.trail.sourceId,
    producer: fixture.trail.producer,
    tenantRef: fixture.trail.tenantRef,
    binding: fixture.trail.binding,
    privacy: fixture.trail.privacy,
    clock: () => event.occurredAt,
    newEventId: () => event.eventId,
    ...extra,
  });
}

const minimal: AuditEventInput = {
  eventType: 'session.established',
  action: { category: 'session' },
  outcome: 'succeeded',
  details: { family: 'session', phase: 'established' },
};

function trail(extra: Partial<AuditTrailOptions> = {}): { trail: AuditTrail; sink: MemoryAuditSink } {
  const sink = new MemoryAuditSink();
  return { sink, trail: new AuditTrail({ sink, sourceId: 'src-1', producer: pairwiseDid('did:key:zP'), tenantRef: publicDid('did:web:t.example'), ...extra }) };
}

describe('AuditTrail against the fixture', () => {
  it('re-records every sample to the same event, canonical form and digest', async () => {
    for (const sample of fixture.events) {
      const sink = new MemoryAuditSink();
      const entry = await fixtureTrail(sink, sample.event).record(sample.input);
      expect(entry.event, sample.name).toEqual(sample.event);
      expect(entry.canonical, sample.name).toBe(sample.canonical);
      expect(entry.eventDigest, sample.name).toBe(sample.digest);
      expect(sink.entries).toEqual([entry]);
    }
  });

  it('chains a source: sequences 1..n and each predecessor digest', async () => {
    const sink = new MemoryAuditSink();
    let index = 0;
    const chainTrail = new AuditTrail({
      sink,
      sourceId: fixture.chain.sourceId,
      producer: fixture.trail.producer,
      tenantRef: fixture.trail.tenantRef,
      binding: fixture.trail.binding,
      privacy: fixture.trail.privacy,
      clock: () => fixture.chain.entries[index]!.event.occurredAt,
      newEventId: () => fixture.chain.entries[index]!.event.eventId,
    });
    expect(chainTrail.sequence).toBe(1);
    expect(chainTrail.previousSourceEventDigest).toBeUndefined();
    for (const sample of fixture.events.slice(0, fixture.chain.entries.length)) {
      await chainTrail.record(sample.input);
      index += 1;
    }
    expect(sink.entries.map((entry) => ({ event: entry.event, canonical: entry.canonical, digest: entry.eventDigest }))).toEqual(fixture.chain.entries);
    expect(sink.entries.map((entry) => entry.event.source.sourceSequence)).toEqual(['1', '2', '3']);
    expect(sink.entries[1]!.event.source.previousSourceEventDigest).toBe(sink.entries[0]!.eventDigest);
    expect(sink.entries[2]!.event.source.previousSourceEventDigest).toBe(sink.entries[1]!.eventDigest);
    expect(chainTrail.previousSourceEventDigest).toBe(sink.entries[2]!.eventDigest);
    expect(chainTrail.sequence).toBe(4);
  });

  it('withholds tool names unless includeToolNames is set', async () => {
    const { input, included, withheld } = fixture.tool_names;
    const withSink = new MemoryAuditSink();
    await fixtureTrail(withSink, included, { includeToolNames: true }).record(input);
    expect(withSink.events[0]).toEqual(included);
    expect(included.action.name).toBe('lookup_order');
    const withoutSink = new MemoryAuditSink();
    await fixtureTrail(withoutSink, withheld).record(input);
    expect(withoutSink.events[0]).toEqual(withheld);
    expect(withheld.action.name).toBeUndefined();
    const defaultTrail = fixtureTrail(new MemoryAuditSink(), withheld);
    expect(defaultTrail.includeToolNames).toBe(false);
    expect(defaultTrail.build(input).action.name).toBeUndefined();
  });

  it('records the evidence event with its reference', async () => {
    const sink = new MemoryAuditSink();
    const { event } = fixture.evidence_event;
    const { eventType, action, outcome, evidence, details, actor } = event;
    const entry = await fixtureTrail(sink, event).record({ eventType, action, outcome, evidence, details, ...(actor ? { actor } : {}) });
    expect(entry.event).toEqual(event);
    expect(entry.eventDigest).toBe(fixture.evidence_event.digest);
  });
});

describe('AuditTrail envelope and policy', () => {
  it('fills the envelope with defaults and a random event id', async () => {
    const { trail: t, sink } = trail();
    const before = Date.now();
    const entry = await t.record(minimal);
    expect(entry.event).toMatchObject({
      schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
      eventVersion: '1.0.0',
      binding: AUDIT_BINDING_HELIX,
      tenantRef: publicDid('did:web:t.example'),
      source: { producer: pairwiseDid('did:key:zP'), sourceId: 'src-1', sourceSequence: '1' },
      evidence: [],
      privacy: DEFAULT_AUDIT_PRIVACY,
    });
    expect(entry.event.eventId).toMatch(/^audit_[0-9a-f-]{36}$/);
    expect(entry.event.occurredAt).toBeGreaterThanOrEqual(before);
    expect(entry.event.source.previousSourceEventDigest).toBeUndefined();
    expect(sink.eventTypes).toEqual(['session.established']);
    expect(t.sourceId).toBe('src-1');
  });

  it('honours a caller-supplied id, time and privacy override', async () => {
    const { trail: t } = trail();
    const entry = await t.record({ ...minimal, eventId: 'stable-1', occurredAt: 5, privacy: { classification: 'restricted' } });
    expect(entry.event.eventId).toBe('stable-1');
    expect(entry.event.occurredAt).toBe(5);
    expect(entry.event.privacy).toEqual({ classification: 'restricted', retentionClass: 'audit-indefinite' });
  });

  it('bounds every caller-presented reference before validating', () => {
    const { trail: t } = trail({ includeToolNames: true });
    const long = 'L'.repeat(300);
    const event = t.build({
      eventType: 'delegation.verified',
      correlationId: long,
      causationId: 'bad\u0000id',
      action: { category: 'delegation', name: long },
      outcome: 'succeeded',
      reason: { code: long },
      authorization: {
        source: 'delegation',
        decision: 'allowed',
        scopeId: long,
        delegationRef: long,
        grantRef: long,
        policyId: long,
        policyVersion: long,
        verificationCode: 'v'.repeat(200),
      },
      details: { family: 'delegation', phase: 'verified', delegationRef: long, parentRef: 'ok' },
    });
    const digest = digestText(long);
    expect(event.correlationId).toBe(digest);
    expect(event.causationId).toBe(digestText('bad\u0000id'));
    expect(event.action.name).toBe(digest);
    expect(event.reason?.code).toBe(digest);
    expect(event.authorization).toMatchObject({ scopeId: digest, delegationRef: digest, grantRef: digest, policyId: digest, policyVersion: digest, verificationCode: digestText('v'.repeat(200)) });
    expect(event.details).toEqual({ family: 'delegation', phase: 'verified', delegationRef: digest, parentRef: 'ok' });
    expect(t.build({ ...minimal, reason: { code: 'x'.repeat(129) } }).reason?.code).toBe(digestText('x'.repeat(129)));
    expect(t.build({ ...minimal, reason: { code: 'x'.repeat(128) } }).reason?.code).toBe('x'.repeat(128));
    expect(t.build({ ...minimal, authorization: { source: 'policy', decision: 'allowed' } }).authorization).toEqual({ source: 'policy', decision: 'allowed' });
  });

  it('bounds the per-family detail references and leaves the rest alone', () => {
    const { trail: t } = trail();
    const long = 'L'.repeat(300);
    const digest = digestText(long);
    const build = (eventType: AuditEventInput['eventType'], details: AuditEventInput['details'], category = 'c') =>
      t.build({ eventType, action: { category }, outcome: 'succeeded', details }).details;
    expect(build('delegation.issued', { family: 'delegation', phase: 'issued', delegationRef: long })).toEqual({ family: 'delegation', phase: 'issued', delegationRef: digest });
    expect(build('grant.used', { family: 'authorization', phase: 'grant_used', grantRef: long })).toEqual({ family: 'authorization', phase: 'grant_used', grantRef: digest });
    expect(build('authorization.approved', { family: 'authorization', phase: 'approved' })).toEqual({ family: 'authorization', phase: 'approved' });
    expect(build('consent.approved', { family: 'consent', phase: 'approved', consentRef: long })).toEqual({ family: 'consent', phase: 'approved', consentRef: digest });
    expect(build('consent.approved', { family: 'consent', phase: 'approved' })).toEqual({ family: 'consent', phase: 'approved' });
    expect(build('tool.call.started', { family: 'tool', phase: 'started', attempt: '1', idempotencyRef: long })).toEqual({ family: 'tool', phase: 'started', attempt: '1', idempotencyRef: digest });
    expect(build('tool.call.started', { family: 'tool', phase: 'started', attempt: '1' })).toEqual({ family: 'tool', phase: 'started', attempt: '1' });
    expect(build('session.rejected', { family: 'session', phase: 'rejected', reasonCode: 'r'.repeat(129) })).toEqual({ family: 'session', phase: 'rejected', reasonCode: digestText('r'.repeat(129)) });
    expect(build('session.rejected', { family: 'session', phase: 'rejected' })).toEqual({ family: 'session', phase: 'rejected' });
    expect(build('proof.verified', { family: 'proof', phase: 'verified', verificationCode: 'v'.repeat(129) })).toEqual({ family: 'proof', phase: 'verified', verificationCode: digestText('v'.repeat(129)) });
    expect(build('proof.verified', { family: 'proof', phase: 'verified' })).toEqual({ family: 'proof', phase: 'verified' });
    expect(build('key.rotated', { family: 'key', phase: 'rotated' })).toEqual({ family: 'key', phase: 'rotated' });
  });

  it('keeps a bounded reference verbatim', () => {
    const { trail: t } = trail();
    const event = t.build({ ...minimal, correlationId: 'call-1', action: { category: 'session', name: 'open' } });
    expect(event.correlationId).toBe('call-1');
    expect(event.action.name).toBe('open');
    expect(sanitizeReference('call-1')).toBe('call-1');
  });

  it('refuses an invalid input before claiming a sequence', async () => {
    const { trail: t, sink } = trail();
    await expect(t.record({ ...minimal, details: { family: 'tool', phase: 'started', attempt: '1' } })).rejects.toThrow(AuditEventInvalidError);
    expect(() => t.build({ ...minimal, extra: 1 } as AuditEventInput)).toThrow(AuditEventInvalidError);
    expect(t.sequence).toBe(1);
    expect(sink.entries).toHaveLength(0);
    await t.record(minimal);
    expect(sink.events[0]!.source.sourceSequence).toBe('1');
  });

  it('serializes concurrent records and links each to the one before', async () => {
    const { trail: t, sink } = trail();
    const entries = await Promise.all([t.record(minimal), t.record(minimal), t.record(minimal)]);
    expect(entries.map((entry) => entry.event.source.sourceSequence)).toEqual(['1', '2', '3']);
    expect(entries[1]!.event.source.previousSourceEventDigest).toBe(entries[0]!.eventDigest);
    expect(entries[2]!.event.source.previousSourceEventDigest).toBe(entries[1]!.eventDigest);
    expect(sink.entries).toEqual(entries);
  });

  it('consumes the sequence on a sink failure but keeps the predecessor on the last appended event', async () => {
    let fail = false;
    const inner = new MemoryAuditSink();
    const flaky: AuditSink = {
      append: async (entry) => {
        if (fail) throw new Error('disk full');
        await inner.append(entry);
      },
    };
    const t = new AuditTrail({ sink: flaky, sourceId: 's', producer: pairwiseDid('did:key:zP'), tenantRef: pairwiseDid('did:key:zP') });
    const first = await t.record(minimal);
    fail = true;
    await expect(t.record(minimal)).rejects.toThrow('disk full');
    fail = false;
    const third = await t.record(minimal);
    expect(third.event.source.sourceSequence).toBe('3');
    expect(third.event.source.previousSourceEventDigest).toBe(first.eventDigest);
    expect(inner.entries).toHaveLength(2);
  });

  it('validates the source id', () => {
    expect(() => trail({ sourceId: '' })).toThrow(TypeError);
    expect(() => trail({ sourceId: 'x'.repeat(257) })).toThrow(TypeError);
  });

  it('keeps evidence through the vault and refuses without one', async () => {
    const { trail: bare } = trail();
    await expect(bare.evidence('secret', 'text/plain', 'p')).rejects.toThrow(AuditEvidenceError);
    const encryptor = new EvidenceEncryptor({ key: 'a'.repeat(64), keyId: 'k1' });
    const store = new MemoryEvidenceStore();
    const { trail: vaulted, sink } = trail({ evidence: { encryptor, store } });
    const ref = await vaulted.evidence('{"orderId":"ORD-1"}', 'application/json', 'tool.call.arguments', { commitPlaintext: true });
    const plain = await vaulted.evidence('x', 'text/plain', 'p');
    expect(plain.plaintextCommitment).toBeUndefined();
    expect(ref.encryption.keyId).toBe('k1');
    expect(ref.encryption.aadDigest).toBe(digestText(Buffer.from(evidenceAad(publicDid('did:web:t.example'), 'tool.call.arguments')).toString('utf8')));
    expect(Buffer.from(vaulted.evidenceAad('tool.call.arguments')).toString('utf8')).toBe('{"purpose":"tool.call.arguments","tenant":{"did":"did:web:t.example","kind":"public_did"}}');
    const stored = (await store.get(ref.objectId))!;
    expect(Buffer.from(encryptor.decrypt(stored, vaulted.evidenceAad('tool.call.arguments'))).toString()).toBe('{"orderId":"ORD-1"}');
    expect(() => encryptor.decrypt(stored, vaulted.evidenceAad('other'))).toThrow(AuditEvidenceError);
    const entry = await vaulted.record({ ...minimal, eventType: 'tool.call.started', action: { category: 'tool.call', detailRef: ref }, evidence: [ref], details: { family: 'tool', phase: 'started', attempt: '1' } });
    expect(entry.canonical).not.toContain('ORD-1');
    expect(entry.event.evidence).toEqual([ref]);
    expect(sink.entries).toHaveLength(1);
  });

  it('exposes the party reference helpers', () => {
    expect(publicDid('did:web:a')).toEqual({ kind: 'public_did', did: 'did:web:a' });
    expect(pairwiseDid('did:key:zB')).toEqual({ kind: 'pairwise_did', did: 'did:key:zB' });
    expect(keyedCommitment(`sha256:${'1'.repeat(64)}`, 'k')).toEqual({ kind: 'keyed_commitment', value: `sha256:${'1'.repeat(64)}`, keyId: 'k' });
  });
});

describe('sinks', () => {
  it('MemoryAuditSink keeps entries in order with event and type views', async () => {
    const sink = new MemoryAuditSink();
    const t = new AuditTrail({ sink, sourceId: 's', producer: pairwiseDid('did:key:zP'), tenantRef: pairwiseDid('did:key:zP') });
    await t.record(minimal);
    await t.record({ ...minimal, eventType: 'session.expired', details: { family: 'session', phase: 'expired' } });
    expect(sink.eventTypes).toEqual(['session.established', 'session.expired']);
    expect(sink.events.map((event) => event.source.sourceSequence)).toEqual(['1', '2']);
  });

  it('TeeAuditSink delivers to every sink in turn and fails on the first failure', async () => {
    const a = new MemoryAuditSink();
    const b = new MemoryAuditSink();
    const t = new AuditTrail({ sink: new TeeAuditSink([a, b]), sourceId: 's', producer: pairwiseDid('did:key:zP'), tenantRef: pairwiseDid('did:key:zP') });
    await t.record(minimal);
    expect(a.entries).toEqual(b.entries);
    const failing: AuditSink = { append: async () => { throw new Error('no'); } };
    const c = new MemoryAuditSink();
    const t2 = new AuditTrail({ sink: new TeeAuditSink([failing, c]), sourceId: 's', producer: pairwiseDid('did:key:zP'), tenantRef: pairwiseDid('did:key:zP') });
    await expect(t2.record(minimal)).rejects.toThrow('no');
    expect(c.entries).toHaveLength(0);
  });
});
