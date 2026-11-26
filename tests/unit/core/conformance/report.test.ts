// Copyright 2026 DgVerse LLP
// KYA-OS story F-3 point 5: the conformance report lists self-custody subjects in the claim set and excludes custodial ones.
import { describe, expect, it } from 'vitest';
import {
  CONFORMANCE_REPORT_NOTE,
  CUSTODY_EXCLUSION_REASON,
  KYA_OS_SPEC_PIN,
  buildConformanceReport,
  isInClaimSet,
  type ConformanceSubject,
} from '../../../../src/core/index.js';

const subjects: ConformanceSubject[] = [
  { did: 'did:web:helix.example:acme:custodial', subjectType: 'agent', keyCustody: 'helix', didHosting: 'helix', name: 'Serverless bot' },
  { did: 'did:web:owner.example:agents:self', subjectType: 'agent', keyCustody: 'self', didHosting: 'own', name: 'Own domain bot', status: 'active' },
  { did: 'did:web:helix.example:acme:pending', subjectType: 'agent', keyCustody: 'self', didHosting: 'helix', status: 'pending_key' },
  { did: 'did:web:helix.example:acme:svc', subjectType: 'service', keyCustody: 'helix', didHosting: 'helix', status: 'active' },
  { did: 'did:web:helix.example:acme:owner', subjectType: 'owner', keyCustody: 'self', didHosting: 'helix', status: 'active' },
  { did: 'did:web:owner.example:agents:self', subjectType: 'agent', keyCustody: 'self', didHosting: 'own', status: 'active' },
];

describe('buildConformanceReport', () => {
  const report = buildConformanceReport({
    implementation: { name: 'Helix ID', version: '3.0.0', claims: [{ profile: 'core', level: 'L1' }, { profile: 'card', level: 'L1' }] },
    subjects,
    generatedAt: new Date('2026-11-21T00:00:00Z'),
  });

  it('puts active self-custody subjects in the claim set with the implementation claims', () => {
    expect(report.claimSet.map((entry) => entry.did)).toEqual(['did:web:helix.example:acme:owner', 'did:web:owner.example:agents:self']);
    expect(report.claimSet[1]).toEqual({
      did: 'did:web:owner.example:agents:self',
      subjectType: 'agent',
      name: 'Own domain bot',
      keyCustody: 'self',
      didHosting: 'own',
      label: 'custody: self',
      status: 'active',
      claims: [{ profile: 'core', level: 'L1' }, { profile: 'card', level: 'L1' }],
    });
    expect(isInClaimSet(report, 'did:web:owner.example:agents:self')).toBe(true);
  });

  it('excludes every custodial subject, labelled custody: helix, with the SPEC §4.5 reason', () => {
    expect(report.excluded.map((entry) => entry.did)).toEqual(['did:web:helix.example:acme:custodial', 'did:web:helix.example:acme:svc']);
    for (const entry of report.excluded) {
      expect(entry.label).toBe('custody: helix');
      expect(entry.reason).toBe(CUSTODY_EXCLUSION_REASON);
      expect(entry).not.toHaveProperty('claims');
      expect(isInClaimSet(report, entry.did)).toBe(false);
    }
    expect(report.excluded[0]!.status).toBe('active');
    expect(CUSTODY_EXCLUSION_REASON).toMatch(/§4\.5/);
  });

  it('lists self-custody subjects that are not active yet as pending, and summarises', () => {
    expect(report.pending).toEqual([
      { did: 'did:web:helix.example:acme:pending', subjectType: 'agent', name: null, keyCustody: 'self', didHosting: 'helix', label: 'custody: self', status: 'pending_key' },
    ]);
    expect(report.summary).toEqual({ subjects: 5, inClaimSet: 2, excluded: 2, pending: 1 });
    expect(report.generatedAt).toBe('2026-11-21T00:00:00.000Z');
    expect(report.spec).toEqual(KYA_OS_SPEC_PIN);
    expect(report.spec.commit).toBe('a4d7f61');
    expect(report.note).toBe(CONFORMANCE_REPORT_NOTE);
  });

  it('is deterministic over the same records and defaults generatedAt to now', () => {
    const again = buildConformanceReport({ implementation: { name: 'x', version: '1', claims: [] }, subjects: [...subjects].reverse() });
    expect(again.claimSet.map((entry) => entry.did)).toEqual(report.claimSet.map((entry) => entry.did));
    expect(Date.parse(again.generatedAt)).toBeGreaterThan(0);
    expect(again.claimSet[0]!.claims).toEqual([]);
  });
});
