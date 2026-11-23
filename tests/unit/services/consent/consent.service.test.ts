// Copyright 2026 DgVerse LLP
// KYA-OS story L3-H: the root delegation signed by the user's did:key at consent. Request, page, click,
// renewal inside the window, withdrawal under the user's key, and crypto-shredding, over real keys.
import { describe, expect, it } from 'vitest';
import {
  ErrorCode,
  HelixError,
  evaluateDelegationChain,
  hashJson,
  publicKeyFromDidKey,
  verifyDelegationHop,
} from '../../../../src/core/index.js';
import type { DidResolver } from '../../../../src/core/credentials/index.js';
import { readUnsignedGrant } from '../../../../src/services/consent/consent.service.js';
import { CONSENT_REQUEST_TYP, signRequest } from '../../../../src/services/consent/signed-request.js';
import { serviceUserRefOf } from '../../../../src/services/consent/user-key.service.js';
import { AGENT, API, OTHER_AGENT, OTHER_SERVICE, STRANGER_SERVICE, SERVICE, consentWorld } from './harness.js';

/** did:key alone: no lookup, no hosting. */
const didKeyOnly = (async (did: string) => {
  if (!did.startsWith('did:key:')) return null;
  const { didKeyDocument } = await import('../../../../src/core/index.js');
  return didKeyDocument(did);
}) as unknown as DidResolver;

async function refusal(promise: Promise<unknown>): Promise<HelixError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(HelixError);
    return error as HelixError;
  }
  throw new Error('expected a refusal');
}

describe('consent request → page → click (L3-H points 1–3, 7)', () => {
  it('signs the root hop with a fresh did:key that verifies from the DID alone', async () => {
    const world = consentWorld();
    const { created, approved } = await world.consentTo();
    expect(created.authorizationUrl).toBe(`${API}/consent/${created.id}`);
    expect(created.resultUrl).toBe(`${API}/v1/consent/requests/${created.id}`);
    const { hop } = approved;
    expect(hop.issuer).toMatch(/^did:key:z6Mk/);
    expect(publicKeyFromDidKey(hop.issuer)).toBeDefined();
    expect(hop.proof.verificationMethod).toBe(`${hop.issuer}#${hop.issuer.slice('did:key:'.length)}`);
    expect(hop.credentialSubject).toMatchObject({ invoker: AGENT.did, invocationTarget: SERVICE.did, parentCapability: SERVICE.did, allowedAction: ['orders:read'] });
    expect(await verifyDelegationHop(hop, didKeyOnly)).toMatchObject({ ok: true, issuer: hop.issuer, invoker: AGENT.did });
    expect(evaluateDelegationChain([hop]).ok).toBe(true);
    // On the user's own list, signed by the user's own key.
    expect(await world.bitOf(hop)).toEqual({ issuer: hop.issuer, bit: false });
    const consent = (await world.repo.findConsent(approved.consentId))!;
    expect(consent).toMatchObject({ userDid: hop.issuer, consentType: 'user-signed', agentDid: AGENT.did, serviceDid: SERVICE.did, latestHopId: hop.id });
    expect(consent.serviceUserRef).toBe(serviceUserRefOf(SERVICE.did, 'user-1'));
    expect(JSON.stringify(await world.repo.findRequest(created.id))).not.toContain('user-1');
    // Audit: requested, the user's key generated, the hop issued by the user, approved by the user at the service.
    expect(world.audit.eventTypes).toEqual(expect.arrayContaining(['consent.requested', 'configuration.changed', 'delegation.issued', 'consent.approved']));
    const issued = world.audit.ofType('delegation.issued').at(-1)!;
    expect(issued.actor).toEqual({ kind: 'public_did', did: hop.issuer });
    expect(issued.resource).toEqual({ kind: 'public_did', did: AGENT.did });
    const approvedEvent = world.audit.ofType('consent.approved')[0]!;
    expect(approvedEvent).toMatchObject({
      actor: { did: hop.issuer },
      responsibleParty: { did: hop.issuer },
      resource: { did: SERVICE.did },
      authorization: { delegationRef: hop.id },
      details: { consentRef: approved.consentId },
    });
    const vc = await world.vcRepo.findByVcId(hop.id);
    expect(vc).toMatchObject({ issuerDid: hop.issuer, userDid: hop.issuer, subjectDid: AGENT.did });
  });

  it('reuses the key within a cycle, and keeps services and users apart', async () => {
    const world = consentWorld();
    const first = await world.consentTo();
    const again = await world.consentTo({ grant: world.grant({ agent: OTHER_AGENT.did }) });
    const otherService = await world.consentTo({ grant: world.grant({ service: OTHER_SERVICE.did }) }, OTHER_SERVICE.signer);
    const otherUser = await world.consentTo({ serviceUserId: 'user-2' });
    expect(again.approved.hop.issuer).toBe(first.approved.hop.issuer);
    expect(otherService.approved.hop.issuer).not.toBe(first.approved.hop.issuer);
    expect(otherUser.approved.hop.issuer).not.toBe(first.approved.hop.issuer);
  });

  it('caps each hop at its lifetime inside the window, and the page shows the window', async () => {
    const world = consentWorld();
    const { approved, page } = await world.consentTo({ hopLifetimeSeconds: 60 });
    expect(Date.parse(approved.hop.validUntil)).toBe(world.now() + 60_000);
    expect(page.request.windowUntil.toISOString()).toBe(page.request.grant.validUntil);
    expect(page.serviceName).toBe('Shop');
    expect(page.agentName).toBe(AGENT.did);
  });

  it('brands the page from display, else the known service name, else the DID', async () => {
    const world = consentWorld();
    const branded = await world.consent.createRequest(await world.requestJws({ display: { serviceName: 'Shop & Co', agentName: 'Travel bot', logoUrl: 'https://shop.example/logo.png' } }), 'r');
    expect(await world.consent.openPage(branded.id)).toMatchObject({ serviceName: 'Shop & Co', agentName: 'Travel bot' });
    const plain = await world.consent.createRequest(await world.requestJws({ grant: world.grant({ service: OTHER_SERVICE.did }) }, OTHER_SERVICE.signer), 'r');
    expect((await world.consent.openPage(plain.id)).serviceName).toBe(OTHER_SERVICE.did);
  });

  it('records the result: pending, then approved with the hop, or expired', async () => {
    const world = consentWorld();
    const created = await world.consent.createRequest(await world.requestJws({}), 'r');
    expect(await world.consent.result(created.id)).toEqual({ id: created.id, status: 'pending', expiresAt: created.expiresAt });
    const page = await world.consent.openPage(created.id);
    const approved = await world.consent.approve(created.id, { cookieToken: page.pageToken, formToken: page.pageToken, grantDigest: page.request.grantDigest }, 'r');
    const result = await world.consent.result(created.id);
    expect(result).toMatchObject({ status: 'approved', consentId: approved.consentId, hop: { id: approved.hop.id } });
    expect(result.windowUntil).toBeGreaterThan(Math.floor(world.now() / 1000));
    const late = await world.consent.createRequest(await world.requestJws({}), 'r');
    world.advance(601);
    expect((await world.consent.result(late.id)).status).toBe('expired');
    expect((await refusal(world.consent.openPage(late.id))).code).toBe(ErrorCode.CONSENT_REQUEST_CLOSED);
    expect((await refusal(world.consent.result('nope'))).code).toBe(ErrorCode.CONSENT_REQUEST_NOT_FOUND);
  });
});

describe('Helix never signs without the click (point 3)', () => {
  it('refuses an approval without the page session, with a mismatched or stale token', async () => {
    const world = consentWorld();
    const created = await world.consent.createRequest(await world.requestJws({}), 'r');
    const digest = hashJson((await world.repo.findRequest(created.id))!.grant);
    // Never opened: no session at all.
    expect((await refusal(world.consent.approve(created.id, { cookieToken: 'x', formToken: 'x', grantDigest: digest }, 'r'))).code).toBe(ErrorCode.CONSENT_PAGE_SESSION_INVALID);
    const page = await world.consent.openPage(created.id);
    expect((await refusal(world.consent.approve(created.id, { cookieToken: undefined, formToken: page.pageToken, grantDigest: digest }, 'r'))).code).toBe(ErrorCode.CONSENT_PAGE_SESSION_INVALID);
    expect((await refusal(world.consent.approve(created.id, { cookieToken: page.pageToken, formToken: 'other', grantDigest: digest }, 'r'))).code).toBe(ErrorCode.CONSENT_PAGE_SESSION_INVALID);
    const reopened = await world.consent.openPage(created.id);
    expect((await refusal(world.consent.approve(created.id, { cookieToken: page.pageToken, formToken: page.pageToken, grantDigest: digest }, 'r'))).code).toBe(ErrorCode.CONSENT_PAGE_SESSION_INVALID);
    await world.consent.approve(created.id, { cookieToken: reopened.pageToken, formToken: reopened.pageToken, grantDigest: digest }, 'r');
    expect(world.audit.ofType('consent.approved')).toHaveLength(1);
    // A second click on the same request signs nothing more.
    expect((await refusal(world.consent.approve(created.id, { cookieToken: reopened.pageToken, formToken: reopened.pageToken, grantDigest: digest }, 'r'))).code).toBe(ErrorCode.CONSENT_REQUEST_CLOSED);
  });

  it('refuses a grant altered between the screen and the click', async () => {
    const world = consentWorld();
    const created = await world.consent.createRequest(await world.requestJws({}), 'r');
    const page = await world.consent.openPage(created.id);
    const shown = page.request.grantDigest;
    const wider = hashJson({ ...page.request.grant, allowedAction: ['orders:read', 'orders:write'] });
    const click = { cookieToken: page.pageToken, formToken: page.pageToken };
    expect((await refusal(world.consent.approve(created.id, { ...click, grantDigest: wider }, 'r'))).code).toBe(ErrorCode.CONSENT_GRANT_ALTERED);
    // The stored grant changed under the page (anyone writing the row): its digest no longer matches.
    const repo = world.repo as unknown as { driver: { requests: Map<string, { grant: { allowedAction: string[] } }> } };
    repo.driver.requests.get(created.id)!.grant.allowedAction.push('orders:write');
    expect((await refusal(world.consent.approve(created.id, { ...click, grantDigest: shown }, 'r'))).code).toBe(ErrorCode.CONSENT_GRANT_ALTERED);
    expect(world.audit.ofType('delegation.issued')).toHaveLength(0);
  });

  it('declines without signing', async () => {
    const world = consentWorld();
    const created = await world.consent.createRequest(await world.requestJws({ returnUrl: 'https://shop.example/back' }), 'r');
    const page = await world.consent.openPage(created.id);
    expect(await world.consent.deny(created.id, { cookieToken: page.pageToken, formToken: page.pageToken }, 'r')).toEqual({ returnUrl: 'https://shop.example/back' });
    expect((await world.consent.result(created.id)).status).toBe('denied');
    expect(world.audit.ofType('consent.denied')).toHaveLength(1);
    expect(await world.repo.listLiveUserKeys()).toHaveLength(0);
    expect((await refusal(world.consent.deny(created.id, { cookieToken: page.pageToken, formToken: page.pageToken }, 'r'))).code).toBe(ErrorCode.CONSENT_REQUEST_CLOSED);
  });

  it('puts the request back when signing fails, so the user can try again', async () => {
    const world = consentWorld();
    const created = await world.consent.createRequest(await world.requestJws({}), 'r');
    const page = await world.consent.openPage(created.id);
    const issue = world.credentials.issueUserRootHop.bind(world.credentials);
    world.credentials.issueUserRootHop = async () => {
      throw new Error('store down');
    };
    await expect(world.consent.approve(created.id, { cookieToken: page.pageToken, formToken: page.pageToken, grantDigest: page.request.grantDigest }, 'r')).rejects.toThrow('store down');
    expect((await world.repo.findRequest(created.id))!.status).toBe('pending');
    world.credentials.issueUserRootHop = issue;
    const reopened = await world.consent.openPage(created.id);
    await world.consent.approve(created.id, { cookieToken: reopened.pageToken, formToken: reopened.pageToken, grantDigest: reopened.request.grantDigest }, 'r');
  });

  it('starts a new cycle when the job shredded the key between lookup and signing', async () => {
    const world = consentWorld();
    const first = await world.consentTo();
    const key = (await world.repo.findUserKey(first.approved.hop.issuer))!;
    const keyFor = world.userKeys.keyFor.bind(world.userKeys);
    let calls = 0;
    world.userKeys.keyFor = async (service, user) => {
      calls += 1;
      if (calls === 1) {
        await world.keyStore.shred({ did: key.did, kid: key.kid });
        await world.repo.markUserKeyShredded(key.did, new Date());
        return key;
      }
      return keyFor(service, user);
    };
    const again = await world.consentTo();
    expect(again.approved.hop.issuer).not.toBe(key.did);
    expect(calls).toBe(2);
  });
});

describe('the service submits an unsigned grant for itself (points 2, 3)', () => {
  it('refuses a grant the service already signed: it holds no key able to sign as a user', async () => {
    const world = consentWorld();
    for (const signedMember of [{ issuer: SERVICE.did }, { proof: { type: 'DataIntegrityProof' } }, { id: 'urn:zcap:1' }, { credentialStatus: {} }]) {
      const error = await refusal(world.consent.createRequest(await world.requestJws({ grant: { ...world.grant(), ...signedMember } }), 'r'));
      expect(error.code).toBe(ErrorCode.CONSENT_REQUEST_INVALID);
      expect(error.message).toMatch(/unsigned/);
    }
  });

  it('refuses a request for another service, from an unknown service, or for unattested scopes', async () => {
    const world = consentWorld({ agentScopes: { [AGENT.did]: ['orders:read'] } });
    expect((await refusal(world.consent.createRequest(await world.requestJws({ grant: world.grant({ service: OTHER_SERVICE.did }) }), 'r'))).httpStatus).toBe(403);
    const unknown = await refusal(world.consent.createRequest(await world.requestJws({ grant: world.grant({ service: STRANGER_SERVICE.did }) }, STRANGER_SERVICE.signer), 'r'));
    expect(unknown.code).toBe(ErrorCode.CONSENT_SERVICE_UNKNOWN);
    const wider = await refusal(world.consent.createRequest(await world.requestJws({ grant: world.grant({ scopes: ['orders:read', 'orders:write'] }) }), 'r'));
    expect(wider.code).toBe(ErrorCode.CONSENT_GRANT_SCOPE_NOT_ALLOWED);
    // An agent this deployment does not know: the verifier intersects later.
    await world.consent.createRequest(await world.requestJws({ grant: world.grant({ agent: OTHER_AGENT.did, scopes: ['anything'] }) }), 'r');
  });

  it('checks the signed request: typ, audience, time, jti, signature', async () => {
    const world = consentWorld();
    const body = { serviceUserId: 'user-1', grant: world.grant() };
    const wrongTyp = await signRequest(body, SERVICE.signer, 'kya-os-revocation+jwt', `${API}/v1/consent/requests`, world.now());
    expect((await refusal(world.consent.createRequest(wrongTyp, 'r'))).code).toBe(ErrorCode.CONSENT_REQUEST_INVALID);
    const wrongAud = await signRequest(body, SERVICE.signer, CONSENT_REQUEST_TYP, `${API}/v1/consent/renewals`, world.now());
    expect((await refusal(world.consent.createRequest(wrongAud, 'r'))).message).toMatch(/aud/);
    const old = await signRequest(body, SERVICE.signer, CONSENT_REQUEST_TYP, `${API}/v1/consent/requests`, world.now() - 600_000);
    expect((await refusal(world.consent.createRequest(old, 'r'))).message).toMatch(/iat/);
    const good = await world.requestJws({});
    await world.consent.createRequest(good, 'r');
    expect((await refusal(world.consent.createRequest(good, 'r'))).message).toMatch(/jti/);
    // Signed by another key than the DID it names.
    const forged = await signRequest(body, { ...OTHER_SERVICE.signer, did: SERVICE.did, kid: 'key-1', sign: (data: Uint8Array) => OTHER_SERVICE.signer.sign(data) }, CONSENT_REQUEST_TYP, `${API}/v1/consent/requests`, world.now());
    expect((await refusal(world.consent.createRequest(forged, 'r'))).code).toBe(ErrorCode.CONSENT_REQUEST_SIGNATURE_INVALID);
    for (const bad of [42, 'a.b', 'not-base64.e30.x', `${Buffer.from('{"alg":"EdDSA"}').toString('base64url')}.bm90IGpzb24.x`, `${Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: CONSENT_REQUEST_TYP })).toString('base64url')}.${Buffer.from('[]').toString('base64url')}.x`]) {
      expect((await refusal(world.consent.createRequest(bad, 'r'))).code).toBe(ErrorCode.CONSENT_REQUEST_INVALID);
    }
  });

  it('validates the rest of the request', async () => {
    const world = consentWorld({ consent: { maxWindowSeconds: 3600 } });
    const cases: Array<[Record<string, unknown>, RegExp]> = [
      [{ serviceUserId: '' }, /serviceUserId/],
      [{ hopLifetimeSeconds: 0 }, /hopLifetimeSeconds/],
      [{ display: 'x' }, /display/],
      [{ display: { serviceName: '' } }, /serviceName/],
      [{ display: { logoUrl: 'http://shop.example/x.png' } }, /logoUrl/],
      [{ returnUrl: 'javascript:alert(1)' }, /returnUrl/],
      [{ returnUrl: 'not a url' }, /returnUrl/],
      [{ returnUrl: 7 }, /returnUrl/],
      [{ grant: world.grant({ windowSeconds: 7200 }) }, /at most 3600/],
    ];
    const short = world.grant({ windowSeconds: 600 });
    for (const [body, message] of cases) {
      expect((await refusal(world.consent.createRequest(await world.requestJws({ grant: short, ...body }), 'r'))).message).toMatch(message);
    }
    const created = await world.consent.createRequest(await world.requestJws({ grant: short, display: {}, returnUrl: null }), 'r');
    expect((await world.repo.findRequest(created.id))!.display).toEqual({ serviceName: 'Shop' });
  });

  it('reads only the unsigned root grant shape', () => {
    const now = Date.now();
    const base = { validUntil: new Date(now + 1000).toISOString(), credentialSubject: { invoker: AGENT.did, invocationTarget: SERVICE.did, parentCapability: SERVICE.did, allowedAction: ['a'] } };
    const subject = base.credentialSubject;
    expect(readUnsignedGrant({ ...base, '@context': ['x'], type: ['y'], credentialSubject: { ...subject, caveats: [{ type: 'Expiry' }] } }, now, 10)).toEqual({
      invoker: AGENT.did,
      invocationTarget: SERVICE.did,
      parentCapability: SERVICE.did,
      allowedAction: ['a'],
      caveats: [{ type: 'Expiry' }],
      validUntil: base.validUntil,
    });
    const bad: Array<[unknown, RegExp]> = [
      [null, /unsigned root/],
      [{ ...base, extra: 1 }, /unknown members/],
      [{ ...base, credentialSubject: 'x' }, /credentialSubject/],
      [{ ...base, credentialSubject: { ...subject, id: 'urn:zcap:x' } }, /credentialSubject.id/],
      [{ ...base, credentialSubject: { ...subject, controller: 'did:x:y' } }, /unknown members/],
      [{ ...base, credentialSubject: { ...subject, invoker: 'agent' } }, /invoker/],
      [{ ...base, credentialSubject: { ...subject, invocationTarget: 'svc' } }, /invocationTarget/],
      [{ ...base, credentialSubject: { ...subject, parentCapability: 'urn:zcap:parent' } }, /parentCapability/],
      [{ ...base, credentialSubject: { ...subject, invoker: SERVICE.did } }, /itself/],
      [{ ...base, credentialSubject: { ...subject, allowedAction: [] } }, /allowedAction/],
      [{ ...base, credentialSubject: { ...subject, allowedAction: ['a', 'a'] } }, /allowedAction/],
      [{ ...base, credentialSubject: { ...subject, allowedAction: [''] } }, /allowedAction/],
      [{ ...base, credentialSubject: { ...subject, caveats: [{}] } }, /caveats/],
      [{ ...base, credentialSubject: { ...subject, caveats: {} } }, /caveats/],
      [{ ...base, validUntil: 'soon' }, /date-time/],
      [{ ...base, validUntil: new Date(now - 1).toISOString() }, /past/],
    ];
    for (const [value, message] of bad) expect(() => readUnsignedGrant(value, now, 10)).toThrow(message);
  });
});

describe('renewal inside the consented window, without a click (point 8, added points)', () => {
  it('renews with the same key, never past the window, and refuses after it', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo({ hopLifetimeSeconds: 60, grant: world.grant({ windowSeconds: 100 }) });
    world.advance(50);
    const renewed = await world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r');
    expect(renewed.hop.issuer).toBe(approved.hop.issuer);
    expect(renewed.hop.id).not.toBe(approved.hop.id);
    // now + 60 s would pass the window's end (start + 100 s): the hop stops at the window.
    expect(renewed.hop.validUntil).toBe((await world.repo.findConsent(approved.consentId))!.windowUntil.toISOString());
    expect(await verifyDelegationHop(renewed.hop, didKeyOnly)).toMatchObject({ ok: true });
    const consent = (await world.repo.findConsent(approved.consentId))!;
    expect(consent.latestHopId).toBe(renewed.hop.id);
    expect(world.audit.ofType('delegation.issued').at(-1)!.details).toMatchObject({ parentRef: approved.hop.id });
    expect(world.audit.ofType('delegation.issued').at(-1)!.action.name).toBe('renewed');
    // A late renewal of an earlier hop does not move lastHopUntil back.
    await world.repo.updateConsent(approved.consentId, { lastHopUntil: new Date(world.now() + 10_000_000) });
    await world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r');
    expect((await world.repo.findConsent(approved.consentId))!.lastHopUntil.getTime()).toBe(world.now() + 10_000_000);
    world.advance(60);
    const ended = await refusal(world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r'));
    expect(ended.code).toBe(ErrorCode.CONSENT_WINDOW_ENDED);
  });

  it('narrows on request; wider scopes are step_up_required', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo({ grant: world.grant({ scopes: ['orders:read', 'orders:write'] }) });
    const narrower = await world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId, allowedAction: ['orders:read'] }), 'r');
    expect(narrower.hop.credentialSubject.allowedAction).toEqual(['orders:read']);
    const wider = await refusal(world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId, allowedAction: ['orders:read', 'payments:write'] }), 'r'));
    expect(wider.code).toBe(ErrorCode.CONSENT_STEP_UP_REQUIRED);
    expect(wider.message).toMatch(/^step_up_required/);
    expect(wider.details).toEqual({ error: 'step_up_required', scopes: ['payments:write'] });
    expect((await refusal(world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId, allowedAction: [] }), 'r'))).code).toBe(ErrorCode.CONSENT_REQUEST_INVALID);
  });

  it('only the agent the consent names may renew', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo();
    expect((await refusal(world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }, OTHER_AGENT.signer), 'r'))).httpStatus).toBe(403);
    expect((await refusal(world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }, SERVICE.signer), 'r'))).httpStatus).toBe(403);
    expect((await refusal(world.consent.renewHop(await world.renewalJws({ consentId: 'urn:uuid:none' }), 'r'))).code).toBe(ErrorCode.CONSENT_NOT_FOUND);
    expect((await refusal(world.consent.renewHop(await world.renewalJws({}), 'r'))).code).toBe(ErrorCode.CONSENT_REQUEST_INVALID);
  });

  it('refuses renewal once the key is gone or the request record is missing', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo();
    const repo = world.repo as unknown as { driver: { requests: Map<string, unknown> } };
    const [requestId] = [...repo.driver.requests.keys()];
    const request = repo.driver.requests.get(requestId!);
    repo.driver.requests.delete(requestId!);
    expect((await refusal(world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r'))).code).toBe(ErrorCode.CONSENT_NOT_FOUND);
    repo.driver.requests.set(requestId!, request);
    await world.repo.markUserKeyShredded(approved.hop.issuer, new Date());
    expect((await refusal(world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r'))).code).toBe(ErrorCode.USER_KEY_NOT_SIGNABLE);
  });
});

describe('withdrawal (point 5, added points)', () => {
  it('revokes every live hop with a revocation signed under the user key, and stops renewal', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo({ hopLifetimeSeconds: 600 });
    const renewed = await world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r');
    const sibling = await world.consentTo({ grant: world.grant({ scopes: ['orders:write'] }) });
    const elsewhere = await world.consentTo({ grant: world.grant({ agent: OTHER_AGENT.did }) });
    const withdrawn = await world.consent.withdrawConsent(await world.withdrawalJws({ consentId: approved.consentId }), 'r');
    expect(withdrawn.userDid).toBe(approved.hop.issuer);
    expect(withdrawn.withdrawn.sort()).toEqual([approved.consentId, sibling.approved.consentId].sort());
    expect(withdrawn.revoked.sort()).toEqual([approved.hop.id, renewed.hop.id, sibling.approved.hop.id].sort());
    for (const hop of [approved.hop, renewed.hop]) expect(await world.bitOf(hop)).toEqual({ issuer: approved.hop.issuer, bit: true });
    expect(await world.bitOf(elsewhere.approved.hop)).toEqual({ issuer: approved.hop.issuer, bit: false });
    const revokedEvents = world.audit.ofType('delegation.revoked');
    expect(revokedEvents.length).toBeGreaterThanOrEqual(3);
    expect(revokedEvents.every((event) => event.actor?.kind === 'public_did' && (event.actor as { did: string }).did === approved.hop.issuer)).toBe(true);
    expect((await refusal(world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r'))).code).toBe(ErrorCode.CONSENT_WITHDRAWN);
    expect((await refusal(world.consent.withdrawConsent(await world.withdrawalJws({ consentId: approved.consentId }), 'r'))).code).toBe(ErrorCode.CONSENT_WITHDRAWN);
    // The other agent's consent keeps renewing.
    await world.consent.renewHop(await world.renewalJws({ consentId: elsewhere.approved.consentId }, OTHER_AGENT.signer), 'r');
  });

  it('only the service the consent was given at may withdraw; expired hops need no revocation', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo({ hopLifetimeSeconds: 1 });
    expect((await refusal(world.consent.withdrawConsent(await world.withdrawalJws({ consentId: approved.consentId }, OTHER_SERVICE.signer), 'r'))).httpStatus).toBe(403);
    expect((await refusal(world.consent.withdrawConsent(await world.withdrawalJws({ consentId: approved.consentId }, AGENT.signer), 'r'))).httpStatus).toBe(403);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const withdrawn = await world.consent.withdrawConsent(await world.withdrawalJws({ consentId: approved.consentId }), 'r');
    expect(withdrawn.revoked).toEqual([]);
  });

  it('cannot revoke once the key is gone', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo();
    await world.repo.markUserKeyShredded(approved.hop.issuer, new Date());
    expect((await refusal(world.consent.withdrawConsent(await world.withdrawalJws({ consentId: approved.consentId }), 'r'))).code).toBe(ErrorCode.USER_KEY_NOT_SIGNABLE);
  });
});
