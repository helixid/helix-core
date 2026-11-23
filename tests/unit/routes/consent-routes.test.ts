// Copyright 2026 DgVerse LLP
// KYA-OS story L3-H: the consent API and the consent page at authorizationUrl, over HTTP. The page sets
// its session (cookie + form token); only a form post carrying both makes Helix sign as the user.
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';
import { errorHandler } from '../../../src/middleware/errorHandler.js';
import consentRoutes, { readCookie } from '../../../src/routes/consent/index.js';
import { escapeHtml, renderConsentPage } from '../../../src/routes/consent/page.js';
import { CONSENT_PAGE_COOKIE } from '../../../src/services/consent/consent.service.js';
import { AGENT, API, SERVICE, consentWorld, type ConsentWorld } from '../services/consent/harness.js';

const ADMIN = 'admin-key';
let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

async function serve(world: ConsentWorld, secureCookie?: boolean): Promise<FastifyInstance> {
  app = Fastify();
  app.setErrorHandler(errorHandler);
  await app.register(consentRoutes, { consent: world.consent, userKeys: world.userKeys, adminApiKey: ADMIN, ...(secureCookie === undefined ? {} : { secureCookie }) });
  return app;
}

const form = (fields: Record<string, string>): string => new URLSearchParams(fields).toString();
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

async function openPage(server: FastifyInstance, id: string) {
  const page = await server.inject({ method: 'GET', url: `/consent/${id}` });
  const cookie = String(page.headers['set-cookie']).split(';')[0]!;
  const token = /name="pageToken" value="([^"]+)"/.exec(page.body)![1]!;
  const digest = /name="grantDigest" value="([^"]+)"/.exec(page.body)![1]!;
  return { page, cookie, token, digest };
}

describe('consent routes', () => {
  it('runs request → page → click → result over HTTP', async () => {
    const world = consentWorld();
    const server = await serve(world);
    const created = await server.inject({ method: 'POST', url: '/v1/consent/requests', payload: { request: await world.requestJws({ display: { serviceName: 'Shop <b>&</b>' } }) } });
    expect(created.statusCode).toBe(201);
    const { id, authorizationUrl } = created.json() as { id: string; authorizationUrl: string };
    expect(authorizationUrl).toBe(`${API}/consent/${id}`);
    const { page, cookie, token, digest } = await openPage(server, id);
    expect(page.statusCode).toBe(200);
    expect(page.headers['content-type']).toMatch(/text\/html/);
    expect(page.headers['content-security-policy']).toMatch(/frame-ancestors 'none'/);
    expect(page.headers['x-frame-options']).toBe('DENY');
    expect(page.headers['cache-control']).toBe('no-store');
    expect(page.headers['set-cookie']).toMatch(new RegExp(`^${CONSENT_PAGE_COOKIE}=.+; Path=/consent/${id}; HttpOnly; SameSite=Strict$`));
    expect(page.body).toContain('Shop &lt;b&gt;&amp;&lt;/b&gt;');
    expect(page.body).toContain('<code>orders:read</code>');
    expect(page.body).toContain(escapeHtml(AGENT.did));
    expect(page.body).not.toContain('<script');
    const pending = await server.inject({ method: 'GET', url: `/v1/consent/requests/${id}` });
    expect(pending.json()).toMatchObject({ status: 'pending' });
    const approved = await server.inject({ method: 'POST', url: `/consent/${id}/approve`, headers: { ...FORM, cookie }, payload: form({ pageToken: token, grantDigest: digest }) });
    expect(approved.statusCode).toBe(200);
    expect(approved.body).toContain('data-testid="consent-approved"');
    const result = await server.inject({ method: 'GET', url: `/v1/consent/requests/${id}` });
    expect(result.headers['cache-control']).toBe('no-store');
    const body = result.json() as { status: string; consentId: string; hop: { issuer: string } };
    expect(body.status).toBe('approved');
    expect(body.hop.issuer).toMatch(/^did:key:/);
    const renewal = await server.inject({ method: 'POST', url: '/v1/consent/renewals', payload: { request: await world.renewalJws({ consentId: body.consentId }) } });
    expect(renewal.statusCode).toBe(200);
    expect(renewal.json().hop.issuer).toBe(body.hop.issuer);
    const withdrawal = await server.inject({ method: 'POST', url: '/v1/consent/withdrawals', payload: { request: await world.withdrawalJws({ consentId: body.consentId }) } });
    expect(withdrawal.statusCode).toBe(200);
    expect(withdrawal.json().revoked).toHaveLength(2);
    const stepUp = await server.inject({ method: 'POST', url: '/v1/consent/renewals', payload: { request: await world.renewalJws({ consentId: body.consentId }) } });
    expect(stepUp.statusCode).toBe(403);
    expect(stepUp.json().error.code).toBe('CONSENT_WITHDRAWN');
  });

  it('signs nothing without the page session', async () => {
    const world = consentWorld();
    const server = await serve(world, true);
    const { id } = (await server.inject({ method: 'POST', url: '/v1/consent/requests', payload: { request: await world.requestJws({}) } })).json() as { id: string };
    const { page, cookie, token, digest } = await openPage(server, id);
    expect(page.headers['set-cookie']).toMatch(/; Secure$/);
    // An API call with no cookie (what a service or script could send).
    const noCookie = await server.inject({ method: 'POST', url: `/consent/${id}/approve`, headers: FORM, payload: form({ pageToken: token, grantDigest: digest }) });
    expect(noCookie.statusCode).toBe(403);
    expect(noCookie.body).toContain('consent-error-CONSENT_PAGE_SESSION_INVALID');
    const json = await server.inject({ method: 'POST', url: `/consent/${id}/approve`, headers: { cookie }, payload: { pageToken: token, grantDigest: digest } });
    expect(json.statusCode).toBe(403);
    const altered = await server.inject({ method: 'POST', url: `/consent/${id}/approve`, headers: { ...FORM, cookie }, payload: form({ pageToken: token, grantDigest: 'sha256:00' }) });
    expect(altered.statusCode).toBe(409);
    expect(altered.body).toContain('consent-error-CONSENT_GRANT_ALTERED');
    expect((await server.inject({ method: 'GET', url: `/v1/consent/requests/${id}` })).json().status).toBe('pending');
    expect(world.audit.ofType('delegation.issued')).toHaveLength(0);
  });

  it('redirects back to the service when it gave a return URL, and declines', async () => {
    const world = consentWorld();
    const server = await serve(world);
    const make = async (): Promise<string> =>
      ((await server.inject({ method: 'POST', url: '/v1/consent/requests', payload: { request: await world.requestJws({ returnUrl: 'https://shop.example/back?x=1' }) } })).json() as { id: string }).id;
    const one = await make();
    const first = await openPage(server, one);
    const approved = await server.inject({ method: 'POST', url: `/consent/${one}/approve`, headers: { ...FORM, cookie: first.cookie }, payload: form({ pageToken: first.token, grantDigest: first.digest }) });
    expect(approved.statusCode).toBe(303);
    expect(approved.headers.location).toBe(`https://shop.example/back?x=1&consent=approved&request=${one}`);
    const two = await make();
    const second = await openPage(server, two);
    const denied = await server.inject({ method: 'POST', url: `/consent/${two}/deny`, headers: { ...FORM, cookie: second.cookie }, payload: form({ pageToken: second.token }) });
    expect(denied.headers.location).toBe(`https://shop.example/back?x=1&consent=denied&request=${two}`);
    const plain = (await server.inject({ method: 'POST', url: '/v1/consent/requests', payload: { request: await world.requestJws({}) } })).json() as { id: string };
    const third = await openPage(server, plain.id);
    const declined = await server.inject({ method: 'POST', url: `/consent/${plain.id}/deny`, headers: { ...FORM, cookie: third.cookie }, payload: form({ pageToken: third.token }) });
    expect(declined.body).toContain('consent-denied');
    const again = await server.inject({ method: 'POST', url: `/consent/${plain.id}/deny`, headers: { ...FORM, cookie: third.cookie }, payload: form({ pageToken: third.token }) });
    expect(again.statusCode).toBe(410);
  });

  it('answers errors as HTML on the page and JSON on the API', async () => {
    const world = consentWorld();
    const server = await serve(world);
    const missing = await server.inject({ method: 'GET', url: '/consent/nope' });
    expect(missing.statusCode).toBe(404);
    expect(missing.body).toContain('consent-error-CONSENT_REQUEST_NOT_FOUND');
    expect((await server.inject({ method: 'POST', url: '/consent/nope/approve', headers: FORM, payload: '' })).statusCode).toBe(404);
    expect((await server.inject({ method: 'POST', url: '/consent/nope/deny' })).statusCode).toBe(404);
    expect((await server.inject({ method: 'GET', url: '/v1/consent/requests/nope' })).json().error.code).toBe('CONSENT_REQUEST_NOT_FOUND');
    expect((await server.inject({ method: 'POST', url: '/v1/consent/requests', payload: {} })).statusCode).toBe(400);
    expect((await server.inject({ method: 'POST', url: '/v1/consent/requests', payload: { request: 'x', extra: 1 } })).statusCode).toBe(400);
    const unsigned = await server.inject({ method: 'POST', url: '/v1/consent/requests', payload: { request: 'a.b.c' } });
    expect(unsigned.json().error.code).toBe('CONSENT_REQUEST_INVALID');
    // An unexpected failure still reaches the error handler.
    world.consent.openPage = async () => {
      throw new Error('boom');
    };
    expect((await server.inject({ method: 'GET', url: '/consent/any' })).statusCode).toBe(500);
  });

  it('runs the shred job on the admin route only', async () => {
    const world = consentWorld();
    const server = await serve(world);
    expect((await server.inject({ method: 'POST', url: '/v1/consent/keys/shred' })).statusCode).toBe(403);
    expect((await server.inject({ method: 'POST', url: '/v1/consent/keys/shred', headers: { 'x-admin-api-key': 'wrong' } })).statusCode).toBe(403);
    const ran = await server.inject({ method: 'POST', url: '/v1/consent/keys/shred', headers: { 'x-admin-api-key': ADMIN } });
    expect(ran.json()).toEqual({ shredded: [] });
    await app?.close();
    app = Fastify();
    app.setErrorHandler(errorHandler);
    await app.register(consentRoutes, { consent: world.consent, userKeys: world.userKeys });
    expect((await app.inject({ method: 'POST', url: '/v1/consent/keys/shred', headers: { 'x-admin-api-key': ADMIN } })).statusCode).toBe(403);
  });

  it('reads one cookie from a Cookie header', () => {
    expect(readCookie(undefined, 'a')).toBeUndefined();
    expect(readCookie('x=1; a=two%20words; b=3', 'a')).toBe('two words');
    expect(readCookie(['x=1', 'a=2'], 'a')).toBe('2');
    expect(readCookie('novalue; a', 'a')).toBeUndefined();
    expect(readCookie('a=%E0%A4%A', 'a')).toBeUndefined();
  });

  it('renders a logo only when the service gave one', async () => {
    const world = consentWorld();
    const created = await world.consent.createRequest(await world.requestJws({ display: { logoUrl: 'https://shop.example/l.png?a=1&b="2"' } }), 'r');
    const page = await world.consent.openPage(created.id);
    expect(renderConsentPage(page, '/consent/x')).toContain('<img src="https://shop.example/l.png?a=1&amp;b=&quot;2&quot;"');
    expect(escapeHtml(`'`)).toBe('&#39;');
    expect(SERVICE.did).toContain('did:web');
  });
});
