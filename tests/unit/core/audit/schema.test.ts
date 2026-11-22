// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import {
  AUDIT_EVENT_FAMILIES,
  AUDIT_EVENT_TYPES,
  AuditEventInvalidError,
  auditEventFamily,
  parseAuditEvent,
  validateAuditEvent,
  type AuditEventType,
} from '../../../../src/core/audit/index.js';
import { fixture } from './fixture.js';

const base = fixture.events[0]!.event;

describe('audit event schema (strict)', () => {
  it('accepts every fixture event and the audit-integrity vector event', () => {
    for (const sample of fixture.events) {
      expect(validateAuditEvent(sample.event)).toEqual({ ok: true, event: sample.event });
    }
  });

  it('refuses every fixture rejection at the recorded path', () => {
    for (const rejection of fixture.rejections) {
      const result = validateAuditEvent(rejection.event);
      expect(result.ok, rejection.name).toBe(false);
      if (!result.ok) expect(result.issues[0]!.path, rejection.name).toBe(rejection.path);
    }
  });

  it('fails closed on an unknown member at any depth', () => {
    const cases: Array<[string, unknown]> = [
      ['top', { ...base, prompt: 'secret' }],
      ['action', { ...base, action: { ...base.action, arguments: {} } }],
      ['authorization', { ...base, authorization: { source: 'policy', decision: 'allowed', token: 'x' } }],
      ['privacy', { ...base, privacy: { ...base.privacy, owner: 'x' } }],
      ['trace', { ...base, trace: { traceId: 'a'.repeat(32), host: 'x' } }],
      ['session', { ...base, session: { ...base.session, ip: 'x' } }],
      ['evidence item', { ...base, evidence: [{ ...fixture.evidence.ref, bytes: 'x' }] }],
      ['encryption', { ...base, evidence: [{ ...fixture.evidence.ref, encryption: { ...fixture.evidence.ref.encryption, key: 'x' } }] }],
      ['signer', { ...base, eventType: 'key.rotated', details: { family: 'key', phase: 'rotated', nextSigner: { did: 'did:web:x', kid: 'k', alg: 'EdDSA', secret: 'x' } } }],
    ];
    for (const [name, value] of cases) expect(validateAuditEvent(value).ok, name).toBe(false);
  });

  it('parseAuditEvent throws AuditEventInvalidError with the issues and a 400 code', () => {
    expect(() => parseAuditEvent({ ...base, extra: 1 })).toThrow(AuditEventInvalidError);
    try {
      parseAuditEvent({ ...base, details: { family: 'tool', phase: 'completed', attempt: '1' } });
    } catch (error) {
      const invalid = error as AuditEventInvalidError;
      expect(invalid.code).toBe('AUDIT_EVENT_INVALID');
      expect(invalid.httpStatus).toBe(400);
      expect(invalid.issues[0]).toEqual({ path: 'details.family', message: 'must be "session" for session.established' });
      expect(invalid.message).toContain('details.family');
      expect(invalid.details).toEqual({ issues: [{ path: 'details.family', message: 'must be "session" for session.established' }] });
    }
    expect(parseAuditEvent(base)).toEqual(base);
    expect(new AuditEventInvalidError([]).message).toBe('Audit event is invalid');
    expect(new AuditEventInvalidError([{ path: '', message: 'x' }]).message).toBe('Audit event is invalid at $: x');
  });

  it('refuses a non-object and bad scalar forms', () => {
    expect(validateAuditEvent(null).ok).toBe(false);
    expect(validateAuditEvent('event').ok).toBe(false);
    expect(validateAuditEvent({ ...base, occurredAt: -1 }).ok).toBe(false);
    expect(validateAuditEvent({ ...base, outcome: 'ok' }).ok).toBe(false);
    expect(validateAuditEvent({ ...base, source: { ...base.source, sourceSequence: '01' } }).ok).toBe(false);
    expect(validateAuditEvent({ ...base, actor: { kind: 'public_did', did: 'not-a-did' } }).ok).toBe(false);
    expect(validateAuditEvent({ ...base, action: { category: '' } }).ok).toBe(false);
  });

  it('maps every event type to its family, covering all nine families', () => {
    const seen = new Set<string>();
    for (const eventType of AUDIT_EVENT_TYPES) seen.add(auditEventFamily(eventType));
    expect([...seen].sort()).toEqual([...AUDIT_EVENT_FAMILIES].sort());
    const expectations: Array<[AuditEventType, string]> = [
      ['grant.used', 'authorization'],
      ['credential.verified', 'consent'],
      ['policy.changed', 'key'],
      ['configuration.changed', 'key'],
      ['integrity_suite.transitioned', 'key'],
      ['checkpoint.created', 'ledger'],
      ['evidence.disposed', 'ledger'],
      ['projection.reconciled', 'ledger'],
      ['ledger.epoch.started', 'ledger'],
      ['audit.exported', 'administration'],
      ['legal_hold.applied', 'administration'],
      ['retention.executed', 'administration'],
      ['session.expired', 'session'],
      ['tool.call.denied', 'tool'],
      ['proof.rejected', 'proof'],
      ['delegation.revoked', 'delegation'],
      ['authorization.step_up_required', 'authorization'],
      ['consent.denied', 'consent'],
      ['key.rotated', 'key'],
    ];
    for (const [eventType, family] of expectations) expect(auditEventFamily(eventType)).toBe(family);
  });

  it('accepts every family with its full optional member set', () => {
    const ref = fixture.evidence.ref;
    const signer = { did: 'did:web:x.example', kid: 'did:web:x.example#k', alg: 'ES256' };
    const full = {
      ...base,
      causationId: 'c',
      trace: { traceId: 'a'.repeat(32), spanId: 'b'.repeat(16) },
      responsibleParty: { kind: 'evidence_ref', ref },
      proof: ref,
      reason: { code: 'x', detailRef: ref },
      action: { category: 'c', name: 'n', detailRef: ref },
      authorization: {
        source: 'grant',
        decision: 'needs_authorization',
        scopeId: 's',
        delegationRef: 'd',
        delegationCredentialDigest: `sha256:${'1'.repeat(64)}`,
        delegationChainDigests: [`sha256:${'1'.repeat(64)}`],
        statusEvidence: [ref],
        grantRef: 'g',
        policyId: 'p',
        policyVersion: 'v',
        policyDigest: `sha256:${'2'.repeat(64)}`,
        verificationCode: 'ok',
      },
      privacy: { ...base.privacy, legalHold: 'hold-1' },
    };
    const details: Array<[AuditEventType, Record<string, unknown>]> = [
      ['session.rejected', { family: 'session', phase: 'rejected', reasonCode: 'r' }],
      ['tool.call.started', { family: 'tool', phase: 'started', attempt: '1', idempotencyRef: 'i' }],
      ['proof.generated', { family: 'proof', phase: 'generated', proofDigest: `sha256:${'3'.repeat(64)}`, verificationCode: 'v' }],
      ['delegation.issued', { family: 'delegation', phase: 'issued', delegationRef: 'd', parentRef: 'p', statusEvidence: [ref] }],
      ['authorization.evaluated', { family: 'authorization', phase: 'evaluated', policyDigest: `sha256:${'4'.repeat(64)}`, grantRef: 'g' }],
      ['consent.requested', { family: 'consent', phase: 'requested', consentRef: 'c' }],
      ['key.rotated', { family: 'key', phase: 'rotated', previousSigner: signer, nextSigner: signer, configurationDigest: `sha256:${'5'.repeat(64)}` }],
      [
        'ledger.epoch.transitioned',
        {
          family: 'ledger',
          phase: 'epoch_transitioned',
          checkpointDigest: `sha256:${'6'.repeat(64)}`,
          previousEpochId: 'e1',
          previousTerminalCheckpointDigest: `sha256:${'7'.repeat(64)}`,
          successorEpochIds: ['e2'],
          targetEvidenceRef: ref,
        },
      ],
      ['audit.exported', { family: 'administration', phase: 'exported', purpose: 'p', sourceSequence: '9', selectionDigest: `sha256:${'8'.repeat(64)}` }],
    ];
    for (const [eventType, detail] of details) {
      const result = validateAuditEvent({ ...full, eventType, details: detail });
      expect(result.ok, eventType).toBe(true);
    }
  });
});
