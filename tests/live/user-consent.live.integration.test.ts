import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  CONSENT_RENEWAL_TYP,
  CONSENT_REQUEST_TYP,
  CONSENT_WITHDRAWAL_TYP,
  EnvSigner,
  derivePublicKey,
  didKeyDocument,
  generateKeyPair,
  publicKeyBytesToJwk,
  signRequest,
  verifyDelegationHop,
  type DidResolver,
} from '../../src/index.js';
import { HelixCustodialSigner } from '@helixid/sdk-js';
import { LIVE_HEDERA_TIMEOUT_MS, resetLiveTestDatabase, startLiveApi, type LiveApi } from '../utils/liveApi.js';

// KYA-OS story L3-H end to end on a live server: a service known to Helix asks consent for its user, the
// user approves on the consent page (its session cookie and form), the root hop is signed by the user's
// pairwise did:key, the agent renews it, the service withdraws it. The service and the agent keep their keys
// and Helix hosts their did:web, so this runs with LIVE_DID_METHOD=web (the e2e suite covers Postgres).
describe.skipIf(process.env['LIVE_DID_METHOD'] !== 'web')('User consent (L3-H) live integration', () => {
  let api: LiveApi;

  beforeAll(async () => {
    await resetLiveTestDatabase();
    api = await startLiveApi();
  });

  afterAll(async () => {
    await api?.stop();
  });

  const admin = async (method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> => {
    const res = await fetch(`${api.baseUrl}${path}`, {
      method,
      headers: { 'content-type': 'application/json', 'x-admin-api-key': api.adminApiKey },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: res.status, body: await res.json() };
  };

  /** A subject whose key stays with the caller, its did:web hosted by Helix. */
  async function selfSubject(kind: 'services', body: Record<string, unknown>): Promise<{ did: string; signer: EnvSigner }> {
    const keys = generateKeyPair();
    const publicKeyJwk = publicKeyBytesToJwk(Buffer.from(derivePublicKey(keys.privateKey), 'hex'));
    const res = await admin('POST', `/v1/${kind}`, { keyCustody: 'self', didHosting: 'helix', publicKeyJwk, ...body });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    const did = (res.body.did ?? res.body.service?.did) as string;
    return { did, signer: new EnvSigner({ did, envVar: 'K', env: { K: keys.privateKey } }) };
  }

  const post = async (path: string, request: string): Promise<{ status: number; body: any }> => {
    const res = await fetch(`${api.baseUrl}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request }) });
    return { status: res.status, body: await res.json() };
  };

  it('a consent approved on the page is signed by the user did:key, renews, and is withdrawn under that key', async () => {
    const service = await selfSubject('services', { name: 'live-consent-shop', domain: 'shop.example', requiredScopes: ['read:orders'] });
    // A custodial agent: it signs its renewal through the generic /sign route (F-3).
    const created_agent = await admin('POST', '/v1/agents', { name: 'Live Consent Agent', scopes: ['read:orders'], keyCustody: 'helix' });
    expect(created_agent.status, JSON.stringify(created_agent.body)).toBe(201);
    const agent = { did: created_agent.body.did as string, signer: new HelixCustodialSigner({ apiUrl: api.baseUrl, did: created_agent.body.did, subject: 'agent', adminApiKey: api.adminApiKey }) };
    const grant = {
      validUntil: new Date(Date.now() + 3_600_000).toISOString(),
      credentialSubject: { invoker: agent.did, invocationTarget: service.did, parentCapability: service.did, allowedAction: ['read:orders'] },
    };
    const created = await post('/v1/consent/requests', await signRequest({ serviceUserId: 'live-user', grant, hopLifetimeSeconds: 600 }, service.signer, CONSENT_REQUEST_TYP, `${api.baseUrl}/v1/consent/requests`));
    expect(created.status, JSON.stringify(created.body)).toBe(201);

    // The page: its session cookie and form; the click.
    const page = await fetch(created.body.authorizationUrl.replace(/^https?:\/\/[^/]+/, api.baseUrl));
    expect(page.status).toBe(200);
    const cookie = String(page.headers.get('set-cookie')).split(';')[0]!;
    const html = await page.text();
    const field = (name: string): string => new RegExp(`name="${name}" value="([^"]+)"`).exec(html)![1]!;
    const approve = await fetch(`${api.baseUrl}/consent/${created.body.id}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ pageToken: field('pageToken'), grantDigest: field('grantDigest') }).toString(),
    });
    expect(approve.status, await approve.clone().text()).toBe(200);

    const result = (await (await fetch(`${api.baseUrl}/v1/consent/requests/${created.body.id}`)).json()) as { status: string; consentId: string; hop: Record<string, any> };
    expect(result.status).toBe('approved');
    expect(result.hop.issuer).toMatch(/^did:key:z6Mk/);
    const didKeyOnly = (async (did: string) => didKeyDocument(did)) as unknown as DidResolver;
    expect(await verifyDelegationHop(result.hop, didKeyOnly)).toMatchObject({ ok: true, issuer: result.hop.issuer, invoker: agent.did });
    // Helix never signs as the user outside the click.
    expect((await admin('POST', '/v1/grants', { issuer: result.hop.issuer, invoker: agent.did, invocationTarget: service.did, allowedAction: ['read:orders'] })).status).toBeGreaterThanOrEqual(400);

    const renewed = await post('/v1/consent/renewals', await signRequest({ consentId: result.consentId }, agent.signer, CONSENT_RENEWAL_TYP, `${api.baseUrl}/v1/consent/renewals`));
    expect(renewed.status, JSON.stringify(renewed.body)).toBe(200);
    expect(renewed.body.hop.issuer).toBe(result.hop.issuer);

    const withdrawn = await post('/v1/consent/withdrawals', await signRequest({ consentId: result.consentId }, service.signer, CONSENT_WITHDRAWAL_TYP, `${api.baseUrl}/v1/consent/withdrawals`));
    expect(withdrawn.status, JSON.stringify(withdrawn.body)).toBe(200);
    expect([...withdrawn.body.revoked].sort()).toEqual([result.hop.id, renewed.body.hop.id].sort());
    const list = (await (await fetch(result.hop.credentialStatus.statusListCredential.replace(/^https?:\/\/[^/]+/, api.baseUrl))).json()) as { issuer: string };
    expect(list.issuer).toBe(result.hop.issuer);

    const again = await post('/v1/consent/renewals', await signRequest({ consentId: result.consentId }, agent.signer, CONSENT_RENEWAL_TYP, `${api.baseUrl}/v1/consent/renewals`));
    expect(again.status).toBe(403);
    expect(again.body.error.code).toBe('CONSENT_WITHDRAWN');
    // Its revoked hops have not expired yet: the key stays to keep their list signed.
    expect((await admin('POST', '/v1/consent/keys/shred', {})).body.shredded).toEqual([]);
  }, LIVE_HEDERA_TIMEOUT_MS);
});
