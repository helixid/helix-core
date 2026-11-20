// Copyright 2026 DgVerse LLP
// Post-consolidation VPService unit tests (§4.2, §7.3, §9.4 A2/A3/A5/A6).
// The service is a thin wrapper over core verifyVP(): no DB-walk, no template
// step, single typed audit event per outcome, JWT scopes from effectiveScopes.

import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildDIDDocument,
  derivePublicKey,
  hashJson,
  readJwsHeader,
  verifyJWT,
  verifyJwsByKid,
  type JwsDidDocument,
} from '../../../src/core/index.js';
import { VPService } from '../../../src/services/vp/vp.service.js';
import { TestAuditTrail } from '../../utils/TestAuditTrail.js';
import {
  API_BASE_URL,
  OWN_LIST_ID,
  SP_LIST_URL,
  USER_DID,
  buildSignedVP,
  decodeJwtPayload,
  makeActor,
  makeAgentVC,
  makeGrant,
  makeOwnStatusList,
  makeSpStatusList,
  makeVcServiceStub,
  stubFetch,
} from '../../utils/vp-fixtures.js';

const DIGEST = /^sha256:[a-f0-9]{64}$/;

function makeService(issuer = makeActor()) {
  const auditTrail = new TestAuditTrail();
  const lists = { [OWN_LIST_ID]: makeOwnStatusList(issuer) };
  const service = new VPService(makeVcServiceStub(lists), auditTrail, API_BASE_URL, {
    signingKey: issuer.privateKeyHex,
    issuerDid: issuer.did,
    ttlSeconds: 600,
  });
  return { service, auditTrail, issuer };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('VPService (thin wrapper)', () => {
  it('verifies a valid single-credential VP and records exactly one proof.verified event (A5)', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const { service, auditTrail } = makeService(issuer);
    const vc = await makeAgentVC(issuer, holder.did);
    const vp = await buildSignedVP([vc], holder);

    const result = await service.verifyVP(vp, 'req-1');

    expect(result).toMatchObject({
      valid: true,
      agentDid: holder.did,
      targetService: 'orders',
    });
    expect('userDid' in result).toBe(false);
    await auditTrail.flush();
    expect(auditTrail.eventTypes).toEqual(['proof.verified']);
    const [verified] = auditTrail.ofType('proof.verified');
    expect(verified).toMatchObject({
      action: { category: 'presentation', name: 'vp_verified' },
      outcome: 'succeeded',
      correlationId: 'req-1',
      actor: { kind: 'public_did', did: holder.did },
      authorization: {
        source: 'delegation',
        decision: 'allowed',
        delegationRef: vc.id,
        delegationCredentialDigest: expect.stringMatching(DIGEST),
      },
      details: { family: 'proof', phase: 'verified', proofDigest: hashJson(vp), verificationCode: 'VP_VERIFIED' },
    });
    // One credential evaluated: the chain is that credential's digest alone.
    expect(verified?.authorization?.delegationChainDigests).toEqual([verified?.authorization?.delegationCredentialDigest]);
    // 'orders' is not a DID, so the event names no resource rather than an invalid one.
    expect(verified).not.toHaveProperty('resource');
  });

  it('uses the injected local-repo resolver for its own status lists — no HTTP round-trip (A3)', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const lists: Record<string, ReturnType<typeof makeOwnStatusList>> = { [OWN_LIST_ID]: makeOwnStatusList(issuer) };
    const getStatusListSpy = vi.fn(async (listId: string) => lists[listId]!);
    const service = new VPService(
      { getStatusList: getStatusListSpy } as never,
      new TestAuditTrail(),
      API_BASE_URL,
    );
    const fetchSpy = stubFetch({});
    const vc = await makeAgentVC(issuer, holder.did);
    const vp = await buildSignedVP([vc], holder);

    await expect(service.verifyVP(vp, 'req-1')).resolves.toMatchObject({ valid: true });
    expect(getStatusListSpy).toHaveBeenCalledWith(OWN_LIST_ID);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('resolves an SP-hosted grant status list over HTTP with schema validation (A4)', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const sp = makeActor();
    const { service, auditTrail } = makeService(issuer);
    const spList = makeSpStatusList(sp);
    const fetchSpy = stubFetch({ [SP_LIST_URL]: spList });
    const vc = await makeAgentVC(issuer, holder.did);
    const grant = await makeGrant(sp, holder.did, USER_DID, ['book:flights'], spList);
    const vp = await buildSignedVP([vc, grant], holder, USER_DID);

    await expect(service.verifyVP(vp, 'req-1')).resolves.toMatchObject({ valid: true });
    expect(fetchSpy).toHaveBeenCalledWith(SP_LIST_URL, expect.anything());
    await auditTrail.flush();
    // The grant's issuer is the target service; the consenting user is the responsible party.
    expect(auditTrail.ofType('proof.verified')[0]).toMatchObject({
      actor: { kind: 'public_did', did: holder.did },
      resource: { kind: 'public_did', did: sp.did },
      responsibleParty: { kind: 'public_did', did: USER_DID },
      authorization: { delegationRef: vc.id },
    });
  });

  it('rejects when the SP-hosted list fails schema validation — fail closed (A4/S2)', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const sp = makeActor();
    const { service, auditTrail } = makeService(issuer);
    stubFetch({ [SP_LIST_URL]: { not: 'a status list' } });
    const vc = await makeAgentVC(issuer, holder.did);
    const grant = await makeGrant(sp, holder.did, USER_DID, ['book:flights'], makeSpStatusList(sp));
    const vp = await buildSignedVP([vc, grant], holder, USER_DID);

    // §4.2/S2: an SP-hosted list that fails schema validation is treated the
    // same as "can't prove not-revoked" — the service surfaces the specific
    // VC_REVOKED failure (see vp.service.ts's catch: HelixError subtypes are
    // preserved for the caller, not collapsed to the generic code).
    await expect(service.verifyVP(vp, 'req-1')).rejects.toMatchObject({
      code: 'VC_REVOKED',
    });
    await auditTrail.flush();
    const rejected = auditTrail.ofType('proof.rejected');
    expect(rejected).toHaveLength(1);
    expect(rejected[0]).toMatchObject({
      outcome: 'failed',
      reason: { code: 'VC_REVOKED' },
      details: { family: 'proof', phase: 'rejected', verificationCode: 'VC_REVOKED' },
    });
  });

  it('issues a session JWT whose scopes claim is effectiveScopes, not raw VC scopes (A2)', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const sp = makeActor();
    const { service, auditTrail } = makeService(issuer);
    const spList = makeSpStatusList(sp);
    stubFetch({ [SP_LIST_URL]: spList });
    const vc = await makeAgentVC(issuer, holder.did, ['read:orders', 'book:flights']);
    const grant = await makeGrant(sp, holder.did, USER_DID, ['book:flights', 'modify:booking'], spList);
    const vp = await buildSignedVP([vc, grant], holder, USER_DID);

    const result = await service.verifyVP(vp, 'req-1', { issueSession: true });

    expect(result.session?.token).toBeTruthy();
    const payload = decodeJwtPayload(result.session!.token);
    expect(payload['scopes']).toEqual(['book:flights']);
    expect(payload['userDid']).toBe(USER_DID);

    // The session event names the session by a commitment to its jti: never
    // the jti, the token or the scopes.
    await auditTrail.flush();
    expect(auditTrail.eventTypes).toEqual(['proof.verified', 'session.established']);
    const [established] = auditTrail.ofType('session.established');
    expect(established).toMatchObject({
      action: { category: 'session', name: 'jwt_issued' },
      correlationId: 'req-1',
      actor: { kind: 'public_did', did: holder.did },
      resource: { kind: 'public_did', did: sp.did },
      responsibleParty: { kind: 'public_did', did: USER_DID },
      session: { ref: { kind: 'keyed_commitment', value: hashJson(payload['jti']), keyId: 'jwt-jti-v1' } },
      details: { family: 'session', phase: 'established' },
    });
    const recorded = JSON.stringify(established);
    expect(recorded).not.toContain(String(payload['jti']));
    expect(recorded).not.toContain(result.session!.token);
    expect(recorded).not.toContain('book:flights');
  });

  it('session JWT is a KYA-OS EdDSA JWS: header carries kid and it verifies through verifyJwsByKid (L1-C)', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const { service } = makeService(issuer);
    const vc = await makeAgentVC(issuer, holder.did);
    const vp = await buildSignedVP([vc], holder);

    const result = await service.verifyVP(vp, 'req-1', { issueSession: true });

    const token = result.session!.token;
    expect(readJwsHeader(token)).toEqual({ alg: 'EdDSA', kid: `${issuer.did}#key-1`, typ: 'JWT', crv: 'Ed25519' });
    const issuerDocument = buildDIDDocument(issuer.did, derivePublicKey(issuer.privateKeyHex));
    const verified = await verifyJwsByKid(token, async (did) =>
      did === issuer.did ? (issuerDocument as unknown as JwsDidDocument) : null,
    );
    expect(verified.payload).toMatchObject({ iss: issuer.did, sub: holder.did, vpId: expect.any(String) });
    expect(verifyJWT(token, derivePublicKey(issuer.privateKeyHex)).sub).toBe(holder.did);
  });

  it('session without a grant carries the full VC scopes (effectiveScopes === privilegeScopes)', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const { service } = makeService(issuer);
    const vc = await makeAgentVC(issuer, holder.did, ['read:orders', 'book:flights']);
    const vp = await buildSignedVP([vc], holder);

    const result = await service.verifyVP(vp, 'req-1', { issueSession: true });
    expect(decodeJwtPayload(result.session!.token)['scopes']).toEqual([
      'read:orders',
      'book:flights',
    ]);
  });

  it('records exactly one proof.rejected with the failure code as the reason on rejection (A6)', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const { service, auditTrail } = makeService(issuer);
    const vc = await makeAgentVC(issuer, holder.did, ['read:orders'], {
      validUntil: new Date(Date.now() - 1000).toISOString(),
    });
    const vp = await buildSignedVP([vc], holder);

    // Same preserve-the-specific-failure behavior as above: an expired VC
    // surfaces as VC_EXPIRED, not the generic fallback code.
    const failure = await service.verifyVP(vp, 'req-1').then(
      () => {
        throw new Error('expected verifyVP to reject');
      },
      (error: unknown) => error as Error,
    );
    expect(failure).toMatchObject({ code: 'VC_EXPIRED' });

    await auditTrail.flush();
    expect(auditTrail.eventTypes).toEqual(['proof.rejected']);
    const [rejected] = auditTrail.ofType('proof.rejected');
    expect(rejected).toMatchObject({
      action: { category: 'presentation', name: 'vp_verified' },
      outcome: 'failed',
      correlationId: 'req-1',
      reason: { code: 'VC_EXPIRED' },
      actor: { kind: 'public_did', did: holder.did },
      details: { family: 'proof', phase: 'rejected', verificationCode: 'VC_EXPIRED' },
    });
    // The exception text is evidence at most; with no vault it is dropped,
    // and it never appears in the event.
    expect(rejected?.reason?.detailRef).toBeUndefined();
    expect(JSON.stringify(rejected)).not.toContain(failure.message);
  });

  it('rejects a VP that names a user without carrying their consent grant', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const { service, auditTrail } = makeService(issuer);
    const vc = await makeAgentVC(issuer, holder.did);
    const vp = await buildSignedVP([vc], holder, USER_DID);

    await expect(service.verifyVP(vp, 'req-1')).rejects.toMatchObject({ code: 'CONSENT_GRANT_REQUIRED' });

    await auditTrail.flush();
    expect(auditTrail.eventTypes).toContain('proof.rejected');
    expect(auditTrail.eventTypes).not.toContain('proof.verified');
    expect(auditTrail.ofType('proof.rejected')[0]).toMatchObject({ reason: { code: 'CONSENT_GRANT_REQUIRED' } });
  });

  it('rejects a payload that fails signedVPSchema parsing', async () => {
    const { service } = makeService();
    // Rejected before core verification even runs, so it's VP_INVALID_STRUCTURE
    // specifically, not the generic VP_VERIFICATION_FAILED fallback.
    await expect(service.verifyVP({ nope: true } as never, 'req-1')).rejects.toMatchObject({
      code: 'VP_INVALID_STRUCTURE',
    });
  });

  // A rejection has no verified `result` to read from: the holder comes off
  // the raw, unverified VP, and nothing else off it reaches the event.
  it('names the presenting holder on proof.rejected and records nothing else off the unverified VP', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const { service, auditTrail } = makeService(issuer);
    const vc = await makeAgentVC(issuer, holder.did, ['read:orders'], {
      validUntil: new Date(Date.now() - 1000).toISOString(),
    });
    (vc.credentialSubject as Record<string, unknown>)['parentVcId'] = 'vc:helix:parent-1';
    (vc.credentialSubject as Record<string, unknown>)['delegatedFrom'] = 'did:key:zParent';
    const vp = await buildSignedVP([vc], holder);

    // A parentVcId/delegatedFrom on the credentialSubject with no matching
    // parent VC in the presentation is what actually fails here —
    // DELEGATION_CHAIN_INVALID, not the generic fallback code.
    await expect(service.verifyVP(vp, 'req-1')).rejects.toMatchObject({
      code: 'DELEGATION_CHAIN_INVALID',
    });

    await auditTrail.flush();
    const [rejected] = auditTrail.ofType('proof.rejected');
    expect(rejected).toMatchObject({
      actor: { kind: 'public_did', did: holder.did },
      reason: { code: 'DELEGATION_CHAIN_INVALID' },
    });
    const recorded = JSON.stringify(rejected);
    expect(recorded).not.toContain(vc.id);
    expect(recorded).not.toContain('vc:helix:parent-1');
    expect(recorded).not.toContain('did:key:zParent');
  });

  it('still records proof.rejected when the VP is too malformed to read a holder from', async () => {
    const { service, auditTrail } = makeService();

    // Rejected at schema parsing, before any parsed VP exists — the holder
    // read must degrade to no actor rather than throw over the audit call.
    await expect(
      service.verifyVP({ verifiableCredential: 'not-an-array' } as never, 'req-1'),
    ).rejects.toMatchObject({ code: 'VP_INVALID_STRUCTURE' });

    await auditTrail.flush();
    const [rejected] = auditTrail.ofType('proof.rejected');
    expect(rejected).toMatchObject({ reason: { code: 'VP_INVALID_STRUCTURE' } });
    expect(rejected).not.toHaveProperty('actor');
  });

  it('throws when a session is requested but JWT options are not configured', async () => {
    const issuer = makeActor();
    const holder = makeActor();
    const service = new VPService(
      makeVcServiceStub({ [OWN_LIST_ID]: makeOwnStatusList(issuer) }),
      new TestAuditTrail(),
      API_BASE_URL,
    );
    const vc = await makeAgentVC(issuer, holder.did);
    const vp = await buildSignedVP([vc], holder);

    await expect(service.verifyVP(vp, 'req-1', { issueSession: true })).rejects.toMatchObject({
      code: 'VP_VERIFICATION_FAILED',
    });
  });
});
