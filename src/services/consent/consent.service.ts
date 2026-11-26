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
 * The consent flow of KYA-OS story L3-H: the root of an agent's delegation
 * chain is signed by the user's own did:key, on the user's click.
 *
 * 1. `createRequest` (`POST /v1/consent/requests`): the service submits the
 *    unsigned root DelegationCredential it knows how to fill (`invoker` the
 *    agent, `invocationTarget` and `parentCapability` itself, `allowedAction`
 *    from its catalog, `validUntil` the end of the consented window) in a
 *    request it signs, naming its user. A grant that already carries an
 *    issuer or a proof is refused: a service never signs a root for a user.
 *    The answer is the `authorizationUrl` (the consent page), which the
 *    middleware puts in its signed `needs_authorization` challenge (L3-E).
 * 2. `openPage` (`GET /consent/:id`): Helix shows exactly that grant, branded
 *    as the service, with a fresh page-session token (cookie and form).
 * 3. `approve` (`POST /consent/:id/approve`): only with that page session and
 *    the digest of the grant the page showed. Helix signs the root hop with
 *    the user's pairwise key (UserKeyService), `issuer` the user's did:key,
 *    records the consent (`user-signed`) and audits it. Helix never signs
 *    without the click: no other route can reach a user key.
 * 4. `result` (`GET /v1/consent/requests/:id`): the signed hop, for the agent
 *    to carry as the root of its chain (C-C) when it retries (L3-E). The hop
 *    is useless without the agent's own key, so its unguessable request id is
 *    enough to read it.
 * 5. `renewHop` (`POST /v1/consent/renewals`): the agent, in a request it
 *    signs, asks for a fresh hop before the one it holds expires. Signed by
 *    the same user key, without a click, never past the consented window;
 *    asking for more scopes than consented is `step_up_required`.
 * 6. `withdrawConsent` (`POST /v1/consent/withdrawals`): the service, in a
 *    request it signs, withdraws on its user's behalf; Helix revokes every
 *    live hop of the consent with a revocation signed under the user's key
 *    (SPEC.md §6.5.1: the root Responsible Party), and renewal stops.
 */

import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  ErrorCode,
  HelixError,
  hashJson,
  publicDid,
  type AuditEventInput,
  type AuditTrail,
  type Caveat,
  type DidResolver,
  type SignedDelegationHop,
} from '../../core/index.js';
import type { ConsentDisplay, ConsentRepository, ConsentRequestRow, UnsignedRootGrant, UserConsentRow } from '../../repositories/consent.repository.js';
import type { CredentialService } from '../credentials/credential.service.js';
import type { RevocationService } from '../revocation/revocation.service.js';
import {
  CONSENT_RENEWAL_TYP,
  CONSENT_REQUEST_TYP,
  CONSENT_WITHDRAWAL_TYP,
  MemoryJtiStore,
  verifySignedRequest,
  type JtiStore,
} from './signed-request.js';
import { isShreddedKeyError, serviceUserRefOf, type UserKeyService } from './user-key.service.js';

export const DEFAULT_CONSENT_REQUEST_TTL_SECONDS = 600;
export const DEFAULT_MAX_CONSENT_WINDOW_SECONDS = 365 * 24 * 60 * 60;
/** The page-session cookie, one per request id. */
export const CONSENT_PAGE_COOKIE = 'helix_consent_session';

/** What a service is, for the page and the check that it is known here. */
export interface ConsentServiceInfo {
  name?: string | undefined;
}

export interface ConsentServiceOptions {
  repo: ConsentRepository;
  userKeys: UserKeyService;
  credentials: Pick<CredentialService, 'issueUserRootHop' | 'chainOf' | 'listAgentCredentials'>;
  revocations: Pick<RevocationService, 'revoke'>;
  resolveDid: DidResolver;
  /** `<API>`: requests name `<API>/v1/consent/...` as their audience, and the page is `<API>/consent/<id>`. */
  apiBaseUrl: string;
  /** The service when it is known to this deployment, else undefined (its consent requests are refused). */
  serviceOf: (serviceDid: string) => Promise<ConsentServiceInfo | undefined>;
  /**
   * A deployment's own rule on who may ask whose consent for which agent
   * (the hosted build: an account's service may not ask for another
   * account's private agent). Throws to refuse; runs after the service is
   * known and before anything is stored.
   */
  authorizeRequest?: ((input: { serviceDid: string; agentDid: string }) => Promise<void> | void) | undefined;
  /** The scopes the agent is attested for, when this deployment knows it; undefined skips the check (the verifier still intersects). */
  agentScopesOf?: ((agentDid: string) => Promise<readonly string[] | undefined>) | undefined;
  audit?: AuditTrail | undefined;
  jtis?: JtiStore | undefined;
  requestTtlSeconds?: number | undefined;
  maxWindowSeconds?: number | undefined;
  clock?: (() => number) | undefined;
}

export interface CreatedConsentRequest {
  id: string;
  authorizationUrl: string;
  resultUrl: string;
  /** Unix seconds. */
  expiresAt: number;
  status: 'pending';
}

export type ConsentRequestState = 'pending' | 'approved' | 'denied' | 'expired';

export interface ConsentRequestResult {
  id: string;
  status: ConsentRequestState;
  expiresAt: number;
  consentId?: string;
  /** The newest hop of the consent, once approved. */
  hop?: SignedDelegationHop;
  /** The end of the consented window, once approved (Unix seconds). */
  windowUntil?: number;
}

export interface ConsentPage {
  request: ConsentRequestRow;
  pageToken: string;
  serviceName: string;
  agentName: string;
}

export interface ApprovedConsent {
  consentId: string;
  hop: SignedDelegationHop;
  returnUrl: string | null;
}

export interface RenewedHop {
  consentId: string;
  hop: SignedDelegationHop;
  windowUntil: number;
}

export interface WithdrawnConsent {
  consentId: string;
  /** Every consent withdrawn: this one and any other the user gave the same agent at this service in the cycle. */
  withdrawn: string[];
  userDid: string;
  revoked: string[];
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');
const seconds = (date: Date): number => Math.floor(date.getTime() / 1000);

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}

function invalid(message: string): never {
  throw new HelixError(ErrorCode.CONSENT_REQUEST_INVALID, message, 400);
}

const GRANT_MEMBERS = new Set(['@context', 'type', 'validUntil', 'validFrom', 'credentialSubject']);
const SUBJECT_MEMBERS = new Set(['invoker', 'parentCapability', 'invocationTarget', 'allowedAction', 'caveats']);

/**
 * The unsigned root DelegationCredential a service submits, read and
 * checked. Helix sets `id`, `issuer`, `credentialStatus` and the proof: a
 * grant carrying any of them, or any other member, is refused.
 */
export function readUnsignedGrant(value: unknown, now: number, maxWindowSeconds: number): UnsignedRootGrant {
  if (!isRecord(value)) invalid('grant must be the unsigned root DelegationCredential');
  for (const signed of ['issuer', 'proof', 'id', 'credentialStatus']) {
    if (Object.hasOwn(value, signed)) invalid(`grant must be unsigned: Helix sets ${signed} when the user approves (a service never signs a root for a user)`);
  }
  const foreign = Object.keys(value).filter((member) => !GRANT_MEMBERS.has(member));
  if (foreign.length > 0) invalid(`grant carries unknown members: ${foreign.join(', ')}`);
  const subject = value['credentialSubject'];
  if (!isRecord(subject)) invalid('grant.credentialSubject is required');
  if (Object.hasOwn(subject, 'id')) invalid('grant must be unsigned: Helix sets credentialSubject.id');
  const foreignSubject = Object.keys(subject).filter((member) => !SUBJECT_MEMBERS.has(member));
  if (foreignSubject.length > 0) invalid(`grant.credentialSubject carries unknown members: ${foreignSubject.join(', ')}`);
  const { invoker, invocationTarget, parentCapability, allowedAction, caveats } = subject;
  if (typeof invoker !== 'string' || !invoker.startsWith('did:')) invalid('grant.credentialSubject.invoker must be the agent DID');
  if (typeof invocationTarget !== 'string' || !invocationTarget.startsWith('did:')) invalid('grant.credentialSubject.invocationTarget must be the service DID');
  if (parentCapability !== invocationTarget) invalid('a root grant names the resource as its own parentCapability');
  if (invoker === invocationTarget) invalid('a service cannot be granted to itself');
  if (
    !Array.isArray(allowedAction) ||
    allowedAction.length === 0 ||
    allowedAction.some((action) => typeof action !== 'string' || action === '' || action.length > 200) ||
    new Set(allowedAction).size !== allowedAction.length
  ) {
    invalid('grant.credentialSubject.allowedAction must be a non-empty array of distinct scopes');
  }
  if (caveats !== undefined && (!Array.isArray(caveats) || caveats.some((caveat) => !isRecord(caveat) || typeof caveat['type'] !== 'string'))) {
    invalid('grant.credentialSubject.caveats must be an array of typed caveats');
  }
  const validUntil = typeof value['validUntil'] === 'string' ? Date.parse(value['validUntil']) : Number.NaN;
  if (Number.isNaN(validUntil)) invalid('grant.validUntil (the end of the consented window) must be a date-time');
  if (validUntil <= now) invalid('grant.validUntil is in the past');
  if (validUntil - now > maxWindowSeconds * 1000) invalid(`the consented window may last at most ${maxWindowSeconds} s`);
  return {
    invoker,
    invocationTarget,
    parentCapability: invocationTarget,
    allowedAction: [...(allowedAction as string[])],
    ...(caveats === undefined ? {} : { caveats: (caveats as Array<Record<string, unknown>>).map((caveat) => ({ ...caveat })) }),
    validUntil: new Date(validUntil).toISOString(),
  };
}

function readDisplay(value: unknown): ConsentDisplay | null {
  if (value === undefined || value === null) return null;
  if (!isRecord(value)) invalid('display must be an object');
  const display: ConsentDisplay = {};
  for (const member of ['serviceName', 'agentName'] as const) {
    const text = value[member];
    if (text === undefined) continue;
    if (typeof text !== 'string' || text.length === 0 || text.length > 120) invalid(`display.${member} must be a short string`);
    display[member] = text;
  }
  if (value['logoUrl'] !== undefined) {
    const logo = value['logoUrl'];
    if (typeof logo !== 'string' || !/^https:\/\//.test(logo) || logo.length > 2048) invalid('display.logoUrl must be an https URL');
    display.logoUrl = logo;
  }
  return Object.keys(display).length === 0 ? null : display;
}

function readReturnUrl(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length > 2048) invalid('returnUrl must be a URL');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return invalid('returnUrl must be a URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') invalid('returnUrl must be http(s)');
  return url.toString();
}

export class ConsentService {
  readonly #options: ConsentServiceOptions;
  readonly #clock: () => number;
  readonly #jtis: JtiStore;
  readonly #requestTtlSeconds: number;
  readonly #maxWindowSeconds: number;

  constructor(options: ConsentServiceOptions) {
    this.#options = options;
    this.#clock = options.clock ?? Date.now;
    this.#jtis = options.jtis ?? new MemoryJtiStore(this.#clock);
    this.#requestTtlSeconds = options.requestTtlSeconds ?? DEFAULT_CONSENT_REQUEST_TTL_SECONDS;
    this.#maxWindowSeconds = options.maxWindowSeconds ?? DEFAULT_MAX_CONSENT_WINDOW_SECONDS;
  }

  get audiences(): { requests: string; renewals: string; withdrawals: string } {
    const base = this.#options.apiBaseUrl;
    return { requests: `${base}/v1/consent/requests`, renewals: `${base}/v1/consent/renewals`, withdrawals: `${base}/v1/consent/withdrawals` };
  }

  pageUrl(id: string): string {
    return `${this.#options.apiBaseUrl}/consent/${encodeURIComponent(id)}`;
  }

  #audit(input: AuditEventInput): void {
    if (this.#options.audit === undefined) return;
    try {
      this.#options.audit.record(input).catch(reportAuditFailure);
    } catch (error) {
      reportAuditFailure(error);
    }
  }

  #verify(jws: unknown, typ: string, audience: string): ReturnType<typeof verifySignedRequest> {
    return verifySignedRequest(jws, { typ, audience, resolveDid: this.#options.resolveDid, jtis: this.#jtis, clock: this.#clock });
  }

  /** `POST /v1/consent/requests`: a service's signed request carrying the unsigned root grant for one of its users. */
  async createRequest(jws: unknown, requestId: string): Promise<CreatedConsentRequest> {
    const claims = await this.#verify(jws, CONSENT_REQUEST_TYP, this.audiences.requests);
    const now = this.#clock();
    const grant = readUnsignedGrant(claims['grant'], now, this.#maxWindowSeconds);
    if (grant.invocationTarget !== claims.iss) {
      throw new HelixError(ErrorCode.CONSENT_REQUEST_INVALID, 'a service asks consent for itself: invocationTarget must be the signing service', 403);
    }
    const userId = claims['serviceUserId'];
    if (typeof userId !== 'string' || userId.length === 0 || userId.length > 256) invalid('serviceUserId must name the service user (1 to 256 characters)');
    const lifetime = claims['hopLifetimeSeconds'];
    if (lifetime !== undefined && (typeof lifetime !== 'number' || !Number.isInteger(lifetime) || lifetime < 1)) {
      invalid('hopLifetimeSeconds must be a positive integer');
    }
    const display = readDisplay(claims['display']);
    const returnUrl = readReturnUrl(claims['returnUrl']);
    const service = await this.#options.serviceOf(claims.iss);
    if (service === undefined) {
      throw new HelixError(ErrorCode.CONSENT_SERVICE_UNKNOWN, `${claims.iss} is not a service known to this deployment`, 403);
    }
    await this.#options.authorizeRequest?.({ serviceDid: claims.iss, agentDid: grant.invoker });
    const attested = await this.#options.agentScopesOf?.(grant.invoker);
    if (attested !== undefined) {
      const held = new Set(attested);
      const notHeld = grant.allowedAction.filter((scope) => !held.has(scope));
      if (notHeld.length > 0) {
        throw new HelixError(ErrorCode.CONSENT_GRANT_SCOPE_NOT_ALLOWED, `the agent is not attested for: ${notHeld.join(', ')}`, 403);
      }
    }
    const id = randomBytes(16).toString('base64url');
    const expiresAt = new Date(now + this.#requestTtlSeconds * 1000);
    await this.#options.repo.createRequest({
      id,
      serviceDid: claims.iss,
      serviceUserRef: serviceUserRefOf(claims.iss, userId as string),
      agentDid: grant.invoker,
      grant,
      grantDigest: hashJson(grant),
      windowUntil: new Date(grant.validUntil),
      hopLifetimeSeconds: (lifetime as number | undefined) ?? null,
      display: display ?? (service.name === undefined ? null : { serviceName: service.name }),
      returnUrl,
      expiresAt,
    });
    this.#audit({
      eventType: 'consent.requested',
      action: { category: 'consent', name: 'requested' },
      outcome: 'succeeded',
      correlationId: requestId,
      actor: publicDid(claims.iss),
      resource: publicDid(grant.invoker),
      details: { family: 'consent', phase: 'requested', consentRef: id },
    });
    return { id, authorizationUrl: this.pageUrl(id), resultUrl: `${this.audiences.requests}/${id}`, expiresAt: seconds(expiresAt), status: 'pending' };
  }

  async #pending(id: string): Promise<ConsentRequestRow> {
    const request = await this.#options.repo.findRequest(id);
    if (!request) throw new HelixError(ErrorCode.CONSENT_REQUEST_NOT_FOUND, 'Consent request not found', 404);
    if (request.status !== 'pending' || request.expiresAt.getTime() <= this.#clock()) {
      throw new HelixError(ErrorCode.CONSENT_REQUEST_CLOSED, `This consent request is ${request.status === 'pending' ? 'expired' : request.status}`, 410);
    }
    return request;
  }

  /** `GET /consent/:id`: the grant as the page shows it, with a fresh page-session token (the previous one stops working). */
  async openPage(id: string): Promise<ConsentPage> {
    const request = await this.#pending(id);
    const pageToken = randomBytes(32).toString('base64url');
    const opened = await this.#options.repo.transitionRequest(id, 'pending', { pageTokenHash: sha256(pageToken) });
    if (!opened) throw new HelixError(ErrorCode.CONSENT_REQUEST_CLOSED, 'This consent request is closed', 410);
    return {
      request: opened,
      pageToken,
      serviceName: request.display?.serviceName ?? (await this.#options.serviceOf(request.serviceDid))?.name ?? request.serviceDid,
      agentName: request.display?.agentName ?? request.agentDid,
    };
  }

  /** The request, checked against the page session the click carries: the cookie and the form both hold its token. */
  async #clicked(id: string, session: { cookieToken: unknown; formToken: unknown }): Promise<ConsentRequestRow> {
    const request = await this.#pending(id);
    const { cookieToken, formToken } = session;
    if (
      typeof cookieToken !== 'string' ||
      cookieToken !== formToken ||
      request.pageTokenHash === null ||
      sha256(cookieToken) !== request.pageTokenHash
    ) {
      throw new HelixError(ErrorCode.CONSENT_PAGE_SESSION_INVALID, 'Approval needs the consent page session: open the page and click there', 403);
    }
    return request;
  }

  /** Signs the root hop of `grant` with the user's key of this cycle, starting a new cycle if the job shredded the key meanwhile. */
  async #signRootHop(request: ConsentRequestRow, grant: UnsignedRootGrant, allowedAction: readonly string[], requestId: string, renews?: string, userDid?: string): Promise<SignedDelegationHop> {
    const now = this.#clock();
    const window = new Date(grant.validUntil).getTime();
    const until = request.hopLifetimeSeconds === null ? window : Math.min(window, now + request.hopLifetimeSeconds * 1000);
    const input = {
      invoker: grant.invoker,
      invocationTarget: grant.invocationTarget,
      allowedAction,
      ...(grant.caveats === undefined ? {} : { caveats: grant.caveats as Caveat[] }),
      validUntil: new Date(until).toISOString(),
    };
    if (userDid !== undefined) {
      // A renewal: the same key, or none (a shredded key never comes back).
      const key = await this.#options.repo.findUserKey(userDid);
      if (!key || key.shreddedAt !== null) throw new HelixError(ErrorCode.USER_KEY_NOT_SIGNABLE, 'The user key of this consent is gone', 409);
      return this.#options.credentials.issueUserRootHop(this.#options.userKeys.signerOf(key), input, requestId, renews);
    }
    for (let attempt = 0; ; attempt += 1) {
      const key = await this.#options.userKeys.keyFor(request.serviceDid, request.serviceUserRef);
      try {
        return await this.#options.credentials.issueUserRootHop(this.#options.userKeys.signerOf(key), input, requestId);
      } catch (error) {
        if (attempt > 0 || !isShreddedKeyError(error)) throw error;
      }
    }
  }

  /**
   * `POST /consent/:id/approve`, the click: the page session and the digest
   * of the grant the page showed must match the request as stored (and the
   * stored grant must still hash to it). Then, and only then, the user's
   * key signs.
   */
  async approve(
    id: string,
    click: { cookieToken: unknown; formToken: unknown; grantDigest: unknown },
    requestId: string,
  ): Promise<ApprovedConsent> {
    const request = await this.#clicked(id, click);
    if (click.grantDigest !== request.grantDigest || hashJson(request.grant) !== request.grantDigest) {
      throw new HelixError(ErrorCode.CONSENT_GRANT_ALTERED, 'The grant changed after the consent page showed it; nothing was signed', 409);
    }
    const claimed = await this.#options.repo.transitionRequest(id, 'pending', { status: 'approved', decidedAt: new Date(this.#clock()), pageTokenHash: null });
    if (!claimed) throw new HelixError(ErrorCode.CONSENT_REQUEST_CLOSED, 'This consent request is closed', 410);
    let hop: SignedDelegationHop;
    try {
      hop = await this.#signRootHop(request, request.grant, request.grant.allowedAction, requestId);
    } catch (error) {
      await this.#options.repo.transitionRequest(id, 'approved', { status: 'pending', decidedAt: null });
      throw error;
    }
    const consentId = `urn:uuid:${randomUUID()}`;
    await this.#options.repo.createConsent({
      id: consentId,
      requestId: id,
      userDid: hop.issuer,
      serviceDid: request.serviceDid,
      serviceUserRef: request.serviceUserRef,
      agentDid: request.agentDid,
      invocationTarget: request.grant.invocationTarget,
      allowedAction: [...request.grant.allowedAction],
      caveats: request.grant.caveats ?? null,
      windowUntil: request.windowUntil,
      hopLifetimeSeconds: request.hopLifetimeSeconds,
      consentType: 'user-signed',
      latestHopId: hop.id,
      lastHopUntil: new Date(hop.validUntil),
    });
    await this.#options.repo.transitionRequest(id, 'approved', { consentId });
    this.#audit({
      eventType: 'consent.approved',
      action: { category: 'consent', name: 'user-signed' },
      outcome: 'succeeded',
      correlationId: requestId,
      actor: publicDid(hop.issuer),
      responsibleParty: publicDid(hop.issuer),
      resource: publicDid(request.serviceDid),
      authorization: { source: 'delegation', decision: 'allowed', delegationRef: hop.id },
      details: { family: 'consent', phase: 'approved', consentRef: consentId },
    });
    return { consentId, hop, returnUrl: request.returnUrl };
  }

  /** `POST /consent/:id/deny`: the user declined on the page; nothing is signed. */
  async deny(id: string, click: { cookieToken: unknown; formToken: unknown }, requestId: string): Promise<{ returnUrl: string | null }> {
    const request = await this.#clicked(id, click);
    const denied = await this.#options.repo.transitionRequest(id, 'pending', { status: 'denied', decidedAt: new Date(this.#clock()), pageTokenHash: null });
    if (!denied) throw new HelixError(ErrorCode.CONSENT_REQUEST_CLOSED, 'This consent request is closed', 410);
    this.#audit({
      eventType: 'consent.denied',
      action: { category: 'consent', name: 'denied' },
      outcome: 'denied',
      correlationId: requestId,
      resource: publicDid(request.serviceDid),
      details: { family: 'consent', phase: 'denied', consentRef: id },
    });
    return { returnUrl: request.returnUrl };
  }

  /** `GET /v1/consent/requests/:id`: where the request stands, and once approved the newest hop of its consent. */
  async result(id: string): Promise<ConsentRequestResult> {
    const request = await this.#options.repo.findRequest(id);
    if (!request) throw new HelixError(ErrorCode.CONSENT_REQUEST_NOT_FOUND, 'Consent request not found', 404);
    const expired = request.status === 'pending' && request.expiresAt.getTime() <= this.#clock();
    const base: ConsentRequestResult = { id, status: expired ? 'expired' : request.status, expiresAt: seconds(request.expiresAt) };
    if (request.status !== 'approved' || request.consentId === null) return base.status === 'approved' ? { ...base, status: 'pending' } : base;
    const consent = await this.#options.repo.findConsent(request.consentId);
    if (!consent) return base;
    const [hop] = await this.#options.credentials.chainOf(consent.latestHopId);
    return { ...base, consentId: consent.id, windowUntil: seconds(consent.windowUntil), ...(hop === undefined ? {} : { hop }) };
  }

  async #consent(id: unknown): Promise<UserConsentRow> {
    if (typeof id !== 'string' || id.length === 0) invalid('consentId is required');
    const consent = await this.#options.repo.findConsent(id);
    if (!consent) throw new HelixError(ErrorCode.CONSENT_NOT_FOUND, 'Consent not found', 404);
    return consent;
  }

  /**
   * `POST /v1/consent/renewals`: the agent (the hop's invoker, in a request
   * it signs) asks for a fresh hop. Same user key, no click, never past the
   * consented window; `allowedAction` may narrow, never widen
   * (`step_up_required`: a new consent).
   */
  async renewHop(jws: unknown, requestId: string): Promise<RenewedHop> {
    const claims = await this.#verify(jws, CONSENT_RENEWAL_TYP, this.audiences.renewals);
    const consent = await this.#consent(claims['consentId']);
    if (claims.iss !== consent.agentDid) {
      throw new HelixError(ErrorCode.CONSENT_REQUEST_INVALID, 'Only the agent the consent names may renew its hop', 403);
    }
    if (consent.withdrawnAt !== null) throw new HelixError(ErrorCode.CONSENT_WITHDRAWN, 'The user withdrew this consent', 403);
    const now = this.#clock();
    if (consent.windowUntil.getTime() <= now) {
      throw new HelixError(ErrorCode.CONSENT_WINDOW_ENDED, 'The consented window has ended: the user must consent again', 403);
    }
    const asked = claims['allowedAction'];
    let allowedAction = consent.allowedAction;
    if (asked !== undefined) {
      if (!Array.isArray(asked) || asked.length === 0 || asked.some((scope) => typeof scope !== 'string')) invalid('allowedAction must be a non-empty array of scopes');
      const consented = new Set(consent.allowedAction);
      const wider = (asked as string[]).filter((scope) => !consented.has(scope));
      if (wider.length > 0) {
        throw new HelixError(ErrorCode.CONSENT_STEP_UP_REQUIRED, `step_up_required: ${wider.join(', ')} was not consented; ask the user again`, 403, { error: 'step_up_required', scopes: wider });
      }
      allowedAction = [...new Set(asked as string[])];
    }
    const request = await this.#options.repo.findRequest(consent.requestId);
    if (!request) throw new HelixError(ErrorCode.CONSENT_NOT_FOUND, 'Consent request not found', 404);
    const grant: UnsignedRootGrant = {
      invoker: consent.agentDid,
      invocationTarget: consent.invocationTarget,
      parentCapability: consent.invocationTarget,
      allowedAction,
      ...(consent.caveats === null ? {} : { caveats: consent.caveats }),
      validUntil: consent.windowUntil.toISOString(),
    };
    const hop = await this.#signRootHop(request, grant, allowedAction, requestId, consent.latestHopId, consent.userDid);
    const until = new Date(hop.validUntil);
    await this.#options.repo.updateConsent(consent.id, {
      latestHopId: hop.id,
      lastHopUntil: until.getTime() > consent.lastHopUntil.getTime() ? until : consent.lastHopUntil,
    });
    return { consentId: consent.id, hop, windowUntil: seconds(consent.windowUntil) };
  }

  /**
   * `POST /v1/consent/withdrawals`: the service withdraws its user's consent
   * (the user withdrew in the service's settings). Every live hop of the
   * consent is revoked by a request signed under the user's key, cascading;
   * renewal stops. The service cannot revoke in the user's name any other way.
   */
  async withdrawConsent(jws: unknown, requestId: string): Promise<WithdrawnConsent> {
    const claims = await this.#verify(jws, CONSENT_WITHDRAWAL_TYP, this.audiences.withdrawals);
    const consent = await this.#consent(claims['consentId']);
    if (claims.iss !== consent.serviceDid) {
      throw new HelixError(ErrorCode.CONSENT_REQUEST_INVALID, 'Only the service the consent was given at may withdraw it', 403);
    }
    if (consent.withdrawnAt !== null) throw new HelixError(ErrorCode.CONSENT_WITHDRAWN, 'This consent is already withdrawn', 409);
    return this.#withdraw(consent, requestId);
  }

  /** The consents naming `agentDid` that are not withdrawn. */
  async openConsentsForAgent(agentDid: string): Promise<UserConsentRow[]> {
    return (await this.#options.repo.listConsents({ agentDid })).filter((consent) => consent.withdrawnAt === null);
  }

  /**
   * A withdrawal the host decided, with no request from the service: e.g. an
   * agent made private again loses what other accounts' services consented
   * to (L3-H follow-up). Same effect as the service's withdrawal: the hops
   * are revoked under the user's key and renewals stop. Null when it is
   * already withdrawn.
   */
  async withdrawConsentById(consentId: string, requestId: string): Promise<WithdrawnConsent | null> {
    const consent = await this.#consent(consentId);
    if (consent.withdrawnAt !== null) return null;
    return this.#withdraw(consent, requestId);
  }

  async #withdraw(consent: UserConsentRow, requestId: string): Promise<WithdrawnConsent> {
    // Every consent this user gave this agent at this service in the cycle: the hops cannot tell them apart.
    const siblings = (await this.#options.repo.listConsents({ userDid: consent.userDid, agentDid: consent.agentDid })).filter(
      (other) => other.invocationTarget === consent.invocationTarget && other.withdrawnAt === null,
    );
    const at = new Date(this.#clock());
    for (const other of siblings) await this.#options.repo.updateConsent(other.id, { withdrawnAt: at });
    const revoked: string[] = [];
    const key = await this.#options.repo.findUserKey(consent.userDid);
    const { hops } = await this.#options.credentials.listAgentCredentials(consent.agentDid);
    const live = hops.filter(
      (hop) =>
        hop.status === 'active' &&
        hop.credential.issuer === consent.userDid &&
        hop.credential.credentialSubject.invocationTarget === consent.invocationTarget,
    );
    if (live.length > 0) {
      if (!key || key.shreddedAt !== null) throw new HelixError(ErrorCode.USER_KEY_NOT_SIGNABLE, 'The user key of this consent is gone', 409);
      const signer = this.#options.userKeys.signerOf(key);
      for (const hop of live) {
        const outcome = await this.#options.revocations.revoke(hop.vcId, signer, requestId);
        revoked.push(...outcome.revoked);
      }
    }
    return { consentId: consent.id, withdrawn: siblings.map((other) => other.id), userDid: consent.userDid, revoked };
  }
}
