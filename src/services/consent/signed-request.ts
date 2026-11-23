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
 * Signed requests of the consent API (KYA-OS story L3-H), the same shape as
 * L3-C's signed revocation requests: a compact EdDSA JWS whose header `typ`
 * names the request kind and whose `kid` is a key of the signer's DID, over
 * `{iss: <signer DID>, aud: <the route's URL>, iat, jti, ...body}`. The
 * signature is checked against the signer's public DID document, so a
 * self-custody service or agent and one whose key Helix holds sign the same
 * way, and no API key is involved. A `jti` is accepted once within the
 * clock skew window.
 */

import { HelixError, ErrorCode, InvalidJWSError, readJwsHeader, signJws, verifyJwsByKid, type DidResolver, type Signer } from '../../core/index.js';
import { randomUUID } from 'node:crypto';

/** A service creating a consent request. */
export const CONSENT_REQUEST_TYP = 'helix-consent-request+jwt';
/** An agent renewing the hop it holds. */
export const CONSENT_RENEWAL_TYP = 'helix-consent-renewal+jwt';
/** A service withdrawing a user's consent on the user's behalf. */
export const CONSENT_WITHDRAWAL_TYP = 'helix-consent-withdrawal+jwt';

/** How far a request's `iat` may be from now. */
export const SIGNED_REQUEST_SKEW_SECONDS = 300;

export interface SignedRequestClaims {
  iss: string;
  aud: string;
  iat: number;
  jti: string;
  [member: string]: unknown;
}

/** Where seen `jti`s are kept until they could no longer pass the `iat` check. */
export interface JtiStore {
  /** True when `jti` was not seen before (and is now recorded until `expiresAtMs`). */
  claim(jti: string, expiresAtMs: number): Promise<boolean> | boolean;
}

/** One process's `jti`s. A multi-instance deployment passes a shared store. */
export class MemoryJtiStore implements JtiStore {
  readonly #seen = new Map<string, number>();
  readonly #clock: () => number;

  constructor(clock: () => number = Date.now) {
    this.#clock = clock;
  }

  claim(jti: string, expiresAtMs: number): boolean {
    const now = this.#clock();
    for (const [seen, until] of this.#seen) if (until <= now) this.#seen.delete(seen);
    if (this.#seen.has(jti)) return false;
    this.#seen.set(jti, expiresAtMs);
    return true;
  }
}

export interface SignedRequestOptions {
  typ: string;
  audience: string;
  resolveDid: DidResolver;
  jtis: JtiStore;
  clock?: (() => number) | undefined;
}

/** Signs `body` as a request of kind `typ` to `audience` (what the SDKs do; the API uses it in its tests and its own calls). */
export async function signRequest(body: Record<string, unknown>, signer: Signer, typ: string, audience: string, now: number = Date.now()): Promise<string> {
  const claims: SignedRequestClaims = { ...body, iss: signer.did, aud: audience, iat: Math.floor(now / 1000), jti: `urn:uuid:${randomUUID()}` };
  return signJws(claims, signer, { header: { typ } });
}

/** The claims of a request whose signature verified under its signer's key; throws HelixError for anything else. */
export async function verifySignedRequest(jws: unknown, options: SignedRequestOptions): Promise<SignedRequestClaims> {
  const invalid = (message: string): never => {
    throw new HelixError(ErrorCode.CONSENT_REQUEST_INVALID, `signed request refused: ${message}`, 400);
  };
  if (typeof jws !== 'string' || jws.split('.').length !== 3) return invalid('it is not a compact JWS');
  let typ: unknown;
  try {
    typ = readJwsHeader(jws).typ;
  } catch (error) {
    return invalid((error as Error).message);
  }
  if (typ !== options.typ) invalid(`typ must be ${options.typ}`);
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8'));
  } catch {
    return invalid('the payload is not JSON');
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return invalid('the payload is not a JSON object');
  const claims = payload as Partial<SignedRequestClaims>;
  if (typeof claims.iss !== 'string' || !claims.iss.startsWith('did:')) invalid('iss must be the signer DID');
  if (typeof claims.jti !== 'string' || claims.jti.length === 0 || claims.jti.length > 200) invalid('jti is required');
  if (claims.aud !== options.audience) invalid(`aud must be ${options.audience}`);
  const now = (options.clock ?? Date.now)();
  const nowSeconds = Math.floor(now / 1000);
  if (typeof claims.iat !== 'number' || !Number.isInteger(claims.iat) || Math.abs(nowSeconds - claims.iat) > SIGNED_REQUEST_SKEW_SECONDS) {
    invalid(`iat must be within ${SIGNED_REQUEST_SKEW_SECONDS} s of now`);
  }
  try {
    await verifyJwsByKid(jws, options.resolveDid, { expectedDid: claims.iss! });
  } catch (error) {
    const reason = error instanceof InvalidJWSError ? `${error.reason}: ` : '';
    throw new HelixError(ErrorCode.CONSENT_REQUEST_SIGNATURE_INVALID, `signed request signature refused: ${reason}${(error as Error).message}`, 401);
  }
  // Only a request whose signature verified spends its jti, so nobody can burn another party's.
  if (!(await options.jtis.claim(`${claims.iss}\u0000${claims.jti}`, now + 2 * SIGNED_REQUEST_SKEW_SECONDS * 1000))) {
    invalid('jti was already used');
  }
  return claims as SignedRequestClaims;
}
