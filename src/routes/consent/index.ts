// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * The consent routes of KYA-OS story L3-H. Registered at the root:
 *
 * - `POST /v1/consent/requests` `{request}`: a service's signed consent
 *   request (typ `helix-consent-request+jwt`); 201 `{id, authorizationUrl,
 *   resultUrl, expiresAt, status}`.
 * - `GET /v1/consent/requests/:id`: `{id, status, expiresAt, consentId?,
 *   hop?, windowUntil?}`; the signed root hop once the user approved.
 * - `POST /v1/consent/renewals` `{request}`: the agent's signed renewal
 *   (typ `helix-consent-renewal+jwt`); 200 `{consentId, hop, windowUntil}`.
 * - `POST /v1/consent/withdrawals` `{request}`: the service's signed
 *   withdrawal (typ `helix-consent-withdrawal+jwt`); 200 `{consentId,
 *   withdrawn, userDid, revoked}`.
 * - `POST /v1/consent/keys/shred` (admin key): runs the
 *   `shredExpiredUserKeys` job now; 200 `{shredded}`.
 * - `GET /consent/:id`: the consent page (HTML), which sets the page session.
 * - `POST /consent/:id/approve` and `/deny` (form posts from that page only:
 *   the page-session cookie and form token must match). Nothing else can
 *   make Helix sign as a user.
 */

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { AdminAuthRequiredError, HelixError } from '../../core/index.js';
import { CONSENT_PAGE_COOKIE, type ConsentService } from '../../services/consent/consent.service.js';
import type { UserKeyService } from '../../services/consent/user-key.service.js';
import { CONSENT_PAGE_CSP, renderConsentOutcome, renderConsentPage } from './page.js';

export interface ConsentRouteOptions {
  consent: ConsentService;
  userKeys: Pick<UserKeyService, 'shredExpiredUserKeys'>;
  adminApiKey?: string | undefined;
  /** Mark the page-session cookie `Secure` (default: when the API base URL is https). */
  secureCookie?: boolean | undefined;
}

const SIGNED_BODY = {
  type: 'object',
  required: ['request'],
  properties: { request: { type: 'string', minLength: 1, maxLength: 32768 } },
  additionalProperties: false,
} as const;

/** One cookie value from a Cookie header. */
export function readCookie(header: string | string[] | undefined, name: string): string | undefined {
  const raw = Array.isArray(header) ? header.join(';') : header;
  if (raw === undefined) return undefined;
  for (const part of raw.split(';')) {
    const at = part.indexOf('=');
    if (at === -1) continue;
    if (part.slice(0, at).trim() === name) {
      try {
        return decodeURIComponent(part.slice(at + 1).trim());
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

function pageHeaders(reply: FastifyReply): FastifyReply {
  return reply
    .header('content-type', 'text/html; charset=utf-8')
    .header('content-security-policy', CONSENT_PAGE_CSP)
    .header('x-frame-options', 'DENY')
    .header('referrer-policy', 'no-referrer')
    .header('cache-control', 'no-store');
}

const consentRoutes: FastifyPluginAsync<ConsentRouteOptions> = async (fastify, options) => {
  const { consent } = options;

  // The page posts application/x-www-form-urlencoded; parsed here only (this plugin's scope).
  fastify.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string', bodyLimit: 8192 }, (_request, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(String(body))));
  });

  fastify.post('/v1/consent/requests', { schema: { body: SIGNED_BODY } }, async (request, reply) => {
    const body = request.body as { request: string };
    return reply.code(201).send(await consent.createRequest(body.request, request.id));
  });

  fastify.get('/v1/consent/requests/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    return reply.header('cache-control', 'no-store').send(await consent.result(id));
  });

  fastify.post('/v1/consent/renewals', { schema: { body: SIGNED_BODY } }, async (request, reply) => {
    const body = request.body as { request: string };
    return reply.send(await consent.renewHop(body.request, request.id));
  });

  fastify.post('/v1/consent/withdrawals', { schema: { body: SIGNED_BODY } }, async (request, reply) => {
    const body = request.body as { request: string };
    return reply.send(await consent.withdrawConsent(body.request, request.id));
  });

  fastify.post('/v1/consent/keys/shred', async (request, reply) => {
    const submitted = request.headers['x-admin-api-key'];
    const key = Array.isArray(submitted) ? submitted[0] : submitted;
    if (!options.adminApiKey || key !== options.adminApiKey) throw new AdminAuthRequiredError();
    return reply.send({ shredded: await options.userKeys.shredExpiredUserKeys() });
  });

  const secure = options.secureCookie ?? false;
  const outcome = (reply: FastifyReply, status: number, title: string, message: string, testId: string): FastifyReply =>
    pageHeaders(reply).code(status).send(renderConsentOutcome(title, message, testId));
  const failed = (reply: FastifyReply, error: unknown): FastifyReply => {
    if (error instanceof HelixError) return outcome(reply, error.httpStatus, 'Consent not given', error.message, `consent-error-${error.code}`);
    throw error;
  };
  const sessionOf = (request: FastifyRequest): { cookieToken: unknown; formToken: unknown; grantDigest: unknown } => {
    // Only the page's own form post carries a click; any other body carries no form token.
    const isForm = String(request.headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded');
    const form = (isForm ? (request.body ?? {}) : {}) as Record<string, unknown>;
    return { cookieToken: readCookie(request.headers.cookie, CONSENT_PAGE_COOKIE), formToken: form['pageToken'], grantDigest: form['grantDigest'] };
  };
  const back = (reply: FastifyReply, returnUrl: string | null, id: string, result: 'approved' | 'denied'): FastifyReply | undefined => {
    if (returnUrl === null) return undefined;
    const url = new URL(returnUrl);
    url.searchParams.set('consent', result);
    url.searchParams.set('request', id);
    return reply.redirect(url.toString(), 303);
  };

  fastify.get('/consent/:id', async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      const page = await consent.openPage(id);
      const cookie = `${CONSENT_PAGE_COOKIE}=${encodeURIComponent(page.pageToken)}; Path=/consent/${encodeURIComponent(id)}; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`;
      return pageHeaders(reply).header('set-cookie', cookie).send(renderConsentPage(page, `/consent/${encodeURIComponent(id)}`));
    } catch (error) {
      return failed(reply, error);
    }
  });

  fastify.post('/consent/:id/approve', async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      const approved = await consent.approve(id, sessionOf(request), request.id);
      return (
        back(reply, approved.returnUrl, id, 'approved') ??
        outcome(reply, 200, 'Access allowed', 'You can return to the agent; it continues on its own.', 'consent-approved')
      );
    } catch (error) {
      return failed(reply, error);
    }
  });

  fastify.post('/consent/:id/deny', async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      const denied = await consent.deny(id, sessionOf(request), request.id);
      return back(reply, denied.returnUrl, id, 'denied') ?? outcome(reply, 200, 'Access declined', 'Nothing was signed.', 'consent-denied');
    } catch (error) {
      return failed(reply, error);
    }
  });
};

export default consentRoutes;
