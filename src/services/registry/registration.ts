// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Registry v3 (2026-11-24): a registration asks the Helix registry to list a
// discoverable agent. It is a compact JWS signed by the agent's own key (a
// custodial key: the deployment signs with the key it holds; a self-custody
// key: the holder signs with the SDK), so nobody can register a DID they
// don't control. The Helix registry checks it against the DID document, then
// asks the named deployment for the entry: what is listed is what that
// deployment says (GET /agent/registry/:did), never the registration.
//
//   header  { alg: EdDSA, kid: <did>#<fragment>, typ: helix-registration+jwt }
//   payload { iss: <did>, sub: <did>, aud: <Helix registry origin>,
//             deployment: <origin>, iat, exp, jti }

import { randomUUID } from 'node:crypto';
import { ErrorCode, HelixError, signJws, verifyJwsByKid, type DidResolver, type Signer } from '../../core/index.js';
import { originOf } from './registry.js';

export const REGISTRATION_TYP = 'helix-registration+jwt';
/** How long a registration is good for. Short: it is made just before it is sent. */
export const REGISTRATION_TTL_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 60;

export interface RegistrationClaims {
  iss: string;
  sub: string;
  aud: string;
  deployment: string;
  iat: number;
  exp: number;
  jti: string;
}

export class RegistrationInvalidError extends HelixError {
  constructor(message: string) {
    super(ErrorCode.VALIDATION_ERROR, `Registration refused: ${message}`, 400);
  }
}

/** Signs a registration for `signer.did` (an agent DID). */
export async function signRegistration(
  signer: Signer,
  input: { deployment: string; audience: string; now?: Date; ttlSeconds?: number },
): Promise<string> {
  const iat = Math.floor((input.now ?? new Date()).getTime() / 1000);
  const claims: RegistrationClaims = {
    iss: signer.did,
    sub: signer.did,
    aud: originOf(input.audience),
    deployment: originOf(input.deployment),
    iat,
    exp: iat + (input.ttlSeconds ?? REGISTRATION_TTL_SECONDS),
    jti: randomUUID(),
  };
  return signJws(claims as unknown as Parameters<typeof signJws>[0], signer, { header: { typ: REGISTRATION_TYP } });
}

/**
 * Verifies a registration: the signature against the DID document the kid
 * names (resolved with `resolveDid`), then the claims. Throws
 * RegistrationInvalidError on any refusal.
 */
export async function verifyRegistration(
  jws: string,
  options: { resolveDid: DidResolver; audience: string; now?: Date },
): Promise<RegistrationClaims & { kid: string }> {
  let verified: Awaited<ReturnType<typeof verifyJwsByKid>>;
  try {
    verified = await verifyJwsByKid(jws, options.resolveDid, { ...(options.now ? { now: options.now.getTime() } : {}) });
  } catch (error) {
    throw new RegistrationInvalidError(error instanceof Error ? error.message : 'signature did not verify');
  }
  if ((verified.header as unknown as Record<string, unknown>)['typ'] !== REGISTRATION_TYP) throw new RegistrationInvalidError(`typ must be ${REGISTRATION_TYP}`);
  const claims = (verified.payload ?? {}) as Partial<RegistrationClaims>;
  if (claims.iss !== verified.did || claims.sub !== verified.did) throw new RegistrationInvalidError('iss and sub must be the signing DID');
  if (typeof claims.aud !== 'string' || claims.aud !== originOf(options.audience)) throw new RegistrationInvalidError('aud is not this registry');
  if (typeof claims.deployment !== 'string') throw new RegistrationInvalidError('deployment is missing');
  const deployment = originOf(claims.deployment);
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000);
  if (typeof claims.iat !== 'number' || typeof claims.exp !== 'number' || claims.iat > now + CLOCK_SKEW_SECONDS || claims.exp < now - CLOCK_SKEW_SECONDS) {
    throw new RegistrationInvalidError('expired or not yet valid');
  }
  if (claims.exp - claims.iat > 3600) throw new RegistrationInvalidError('valid for more than an hour');
  if (typeof claims.jti !== 'string') throw new RegistrationInvalidError('jti is missing');
  return { ...(claims as RegistrationClaims), deployment, kid: verified.kid };
}
