// Copyright 2026 DgVerse LLP
// KYA-OS story F-3 point 8 on story A-1's typed trail: what each custody fact is recorded as.
import { describe, expect, it, vi } from 'vitest';
import { jsonDigest, type AuditTrail } from '../../../../src/core/index.js';
import { CUSTODY_AUDIT_CATEGORY, CustodyAudit, payloadDigest } from '../../../../src/services/custody/custody-audit.js';
import { TestAuditTrail } from '../../../utils/TestAuditTrail.js';

const DID = 'did:web:helix.example:acme:agent1';
const KID = `${DID}#key-1`;
const base = { requestId: 'req_1', actor: 'account:acc_1', subjectType: 'agent' as const, did: DID };

async function recorded(act: (audit: CustodyAudit) => void): Promise<TestAuditTrail> {
  const trail = new TestAuditTrail();
  act(new CustodyAudit(trail));
  await trail.flush();
  return trail;
}

describe('CustodyAudit on the typed trail (F-3 point 8, A-1)', () => {
  it('records a choice as configuration.changed on the subject, committing the facts and the actor by digest', async () => {
    const facts = { keyCustody: 'helix' as const, didHosting: 'helix' as const, source: { keyCustody: 'override' as const, didHosting: 'account' as const } };
    const trail = await recorded((audit) => audit.chosen({ ...base, ...facts }));
    expect(trail.events).toHaveLength(1);
    expect(trail.events[0]).toMatchObject({
      eventType: 'configuration.changed',
      action: { category: CUSTODY_AUDIT_CATEGORY, name: 'chosen' },
      outcome: 'succeeded',
      correlationId: 'req_1',
      resource: { kind: 'public_did', did: DID },
      details: {
        family: 'key',
        phase: 'configuration_changed',
        configurationDigest: jsonDigest({ did: DID, actor: 'account:acc_1', subjectType: 'agent', ...facts }),
      },
    });
    expect(trail.events[0]!.actor).toBeUndefined();
  });

  it('records activation, key revocation and shredding the same way, each under its own action name', async () => {
    const trail = await recorded((audit) => {
      audit.activated({ ...base, keyCustody: 'self', didHosting: 'own', kid: KID, resolution: 'verified' });
      audit.keyRevoked({ ...base, kid: KID, location: 'helix' });
      audit.keyShredded({ ...base, kid: KID });
    });
    expect(trail.events.map((event) => [event.eventType, event.action.name])).toEqual([
      ['configuration.changed', 'activated'],
      ['configuration.changed', 'key_revoked'],
      ['configuration.changed', 'key_shredded'],
    ]);
    expect(trail.events[1]!.details).toEqual({
      family: 'key',
      phase: 'configuration_changed',
      configurationDigest: jsonDigest({ did: DID, actor: 'account:acc_1', subjectType: 'agent', kid: KID, location: 'helix' }),
    });
  });

  it('records a custody change as key.rotated with the previous and next signer', async () => {
    const newKid = `${DID}#key-2`;
    const hopReissue = { status: 'pending' as const, note: 'later' };
    const trail = await recorded((audit) =>
      audit.changed({ ...base, from: 'helix', to: 'self', oldKid: KID, newKid, retiresAt: '2026-11-22T00:00:00.000Z', hopReissue: hopReissue as never }),
    );
    expect(trail.events[0]).toMatchObject({
      eventType: 'key.rotated',
      action: { category: CUSTODY_AUDIT_CATEGORY, name: 'changed' },
      resource: { kind: 'public_did', did: DID },
      details: {
        family: 'key',
        phase: 'rotated',
        previousSigner: { did: DID, kid: KID, alg: 'EdDSA' },
        nextSigner: { did: DID, kid: newKid, alg: 'EdDSA' },
        configurationDigest: jsonDigest({
          did: DID,
          oldKid: KID,
          newKid,
          actor: 'account:acc_1',
          subjectType: 'agent',
          from: 'helix',
          to: 'self',
          retiresAt: '2026-11-22T00:00:00.000Z',
          hopReissue,
        }),
      },
    });
  });

  it('records a custodial signature by the digest of what was signed, the subject as the actor, never the bytes', async () => {
    const payload = new TextEncoder().encode('{"tool":"orders.list"}');
    const trail = await recorded((audit) => audit.signature({ ...base, kid: KID, payload }));
    expect(trail.events[0]).toMatchObject({
      eventType: 'proof.generated',
      action: { category: CUSTODY_AUDIT_CATEGORY, name: 'custodial_signature' },
      outcome: 'succeeded',
      actor: { kind: 'public_did', did: DID },
      details: { family: 'proof', phase: 'generated', proofDigest: payloadDigest(payload) },
    });
    expect(JSON.stringify(trail.events)).not.toContain('orders.list');
  });

  it('records a refused signing as proof.rejected with its reason code', async () => {
    const trail = await recorded((audit) => audit.signingRefused({ ...base, code: 'key_not_active' }));
    expect(trail.events[0]).toMatchObject({
      eventType: 'proof.rejected',
      outcome: 'denied',
      actor: { kind: 'public_did', did: DID },
      reason: { code: 'key_not_active' },
      details: { family: 'proof', phase: 'rejected', verificationCode: 'key_not_active' },
    });
  });

  it("records an activated agent as the agent service's onboarding event, naming the identity credential when there is one", async () => {
    const trail = await recorded((audit) => {
      audit.agentOnboarded({ requestId: 'req_1', agentDid: DID, credentialId: 'vc:1' });
      audit.agentOnboarded({ requestId: 'req_2', agentDid: DID });
    });
    expect(trail.events.map((event) => [event.eventType, event.action, event.actor, event.details])).toEqual([
      ['credential.verified', { category: 'onboarding', name: 'agent_onboarded' }, { kind: 'public_did', did: DID }, { family: 'consent', phase: 'credential_verified', consentRef: 'vc:1' }],
      ['credential.verified', { category: 'onboarding', name: 'agent_onboarded' }, { kind: 'public_did', did: DID }, { family: 'consent', phase: 'credential_verified' }],
    ]);
  });

  it('never fails the caller when recording fails, synchronously or not', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const rejecting = { record: () => Promise.reject(new Error('down')) } as unknown as AuditTrail;
    const throwing = { record: () => { throw 'bad input'; } } as unknown as AuditTrail;
    expect(() => new CustodyAudit(rejecting).keyShredded({ ...base, kid: KID })).not.toThrow();
    expect(() => new CustodyAudit(throwing).keyShredded({ ...base, kid: KID })).not.toThrow();
    await new Promise((resolve) => setImmediate(resolve));
    expect(error).toHaveBeenCalledWith('AUDIT_RECORD_FAILED', 'down');
    expect(error).toHaveBeenCalledWith('AUDIT_RECORD_FAILED', 'bad input');
    error.mockRestore();
  });
});
