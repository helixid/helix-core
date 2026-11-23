// Copyright 2026 DgVerse LLP
// KYA-OS story L3-C on A-1's typed trail: the events of the status lists and the revocation signal validate
// against the vendored schema, name parties by DID only, and a failure to record never breaks the caller.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { validateAuditEvent, type AuditTrail } from '../../../src/core/index.js';
import { credentialRevoked, didRef, recordAudit, revocationSignalFailed, statusListPublished } from '../../../src/services/revocation/audit.js';
import { TestAuditTrail } from '../../utils/TestAuditTrail.js';

const ISSUER = 'did:web:issuer.example';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('L3-C audit events', () => {
  it('records a list Helix signed and a list its issuer submitted as configuration.changed', async () => {
    const trail = new TestAuditTrail();
    recordAudit(trail, statusListPublished(ISSUER, 'published'));
    recordAudit(trail, statusListPublished(ISSUER, 'submitted'));
    await trail.flush();
    const [published, submitted] = trail.ofType('configuration.changed');
    expect(published).toMatchObject({
      action: { category: 'status_list', name: 'published' },
      outcome: 'succeeded',
      resource: { kind: 'public_did', did: ISSUER },
      details: { family: 'key', phase: 'configuration_changed' },
    });
    expect(published).not.toHaveProperty('actor');
    expect(submitted).toMatchObject({ action: { name: 'submitted' }, actor: { kind: 'public_did', did: ISSUER }, resource: { kind: 'public_did', did: ISSUER } });
    for (const event of trail.events) expect(validateAuditEvent(event).ok).toBe(true);
  });

  it('names no party when a value is not a DID', async () => {
    expect(didRef('not-a-did')).toBeUndefined();
    expect(didRef(null)).toBeUndefined();
    expect(didRef(undefined)).toBeUndefined();
    const trail = new TestAuditTrail();
    recordAudit(trail, statusListPublished('nope', 'submitted'));
    recordAudit(trail, credentialRevoked({ requestId: 'r', vcId: 'urn:uuid:a', subjectDid: 'nope', revoker: 'nope' }));
    await trail.flush();
    for (const event of trail.events) {
      expect(event).not.toHaveProperty('actor');
      expect(event).not.toHaveProperty('resource');
      expect(validateAuditEvent(event).ok).toBe(true);
    }
  });

  it('records revoked, cascade_revoked and a lost signal with bounded references', async () => {
    const trail = new TestAuditTrail();
    recordAudit(trail, credentialRevoked({ requestId: 'r', vcId: 'urn:uuid:root', subjectDid: 'did:key:z6MkSubject', revoker: ISSUER }));
    recordAudit(trail, credentialRevoked({ requestId: 'r', vcId: 'urn:uuid:child', subjectDid: 'did:key:z6MkChild', revoker: ISSUER, cascadeFrom: 'urn:uuid:root' }));
    recordAudit(trail, revocationSignalFailed({ vcId: 'x'.repeat(300), correlationId: 'jti-1', stage: 'webhook_push' }));
    await trail.flush();
    expect(trail.eventTypes).toEqual(['delegation.revoked', 'delegation.cascade_revoked', 'delegation.revoked']);
    expect(trail.events[0]).toMatchObject({ actor: { did: ISSUER }, resource: { did: 'did:key:z6MkSubject' }, details: { delegationRef: 'urn:uuid:root' } });
    expect(trail.events[0]).not.toHaveProperty('reason');
    expect(trail.events[1]).toMatchObject({ reason: { code: 'ancestor_revoked' }, details: { phase: 'cascade_revoked', delegationRef: 'urn:uuid:child', parentRef: 'urn:uuid:root' } });
    // A reference longer than 256 is recorded as its digest, never verbatim.
    const lost = trail.events[2]!;
    expect(lost).toMatchObject({ outcome: 'failed', reason: { code: 'webhook_push_failed' }, correlationId: 'jti-1' });
    expect((lost.details as { delegationRef: string }).delegationRef).toMatch(/^sha256:[0-9a-f]{64}$/);
    for (const event of trail.events) expect(validateAuditEvent(event).ok).toBe(true);
  });

  it('never throws when the trail is absent, rejects or throws', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(() => recordAudit(undefined, statusListPublished(ISSUER, 'published'))).not.toThrow();
    const rejecting = { record: () => Promise.reject(new Error('sink down')) } as unknown as AuditTrail;
    recordAudit(rejecting, statusListPublished(ISSUER, 'published'));
    const throwing = {
      record: () => {
        throw 'boom';
      },
    } as unknown as AuditTrail;
    recordAudit(throwing, statusListPublished(ISSUER, 'published'));
    await new Promise((resolve) => setImmediate(resolve));
    expect(errors).toHaveBeenCalledWith('AUDIT_RECORD_FAILED', 'sink down');
    expect(errors).toHaveBeenCalledWith('AUDIT_RECORD_FAILED', 'boom');
  });
});
