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
 * The revocation API's service (KYA-OS story L3-C point 5; SPEC.md §6.5,
 * §6.5.1): `revoke(credentialId, revokerSigner)`.
 *
 * A revocation is asked for by a request the revoker signs: a compact EdDSA
 * JWS (header `typ: "kya-os-revocation+jwt"`, `kid` the revoker's key) over
 * `{iss: <revoker DID>, credentialId, iat, jti, aud: <API>/v1/revocations}`.
 * The signature is verified against the revoker's public DID document; the
 * request is then checked against the chain:
 *
 * - allowed: the credential's direct issuer, any ancestor issuer of its
 *   delegation chain, the root Responsible Party (the root hop's issuer),
 *   and, for an identity credential, its `responsibleParty`;
 * - never the subject (a hop's invoker, an identity's or attestation's
 *   `credentialSubject.id`), whoever else it is.
 *
 * Then the target and, recursively, every descendant hop are revoked in one
 * transaction (each bit on its issuer's list), each affected list is
 * republished, one audit event and one revocation signal are emitted per
 * credential (`StatusListService.revokeMany`).
 *
 * Story C-E point 5: a compromised key may be revoked by any ancestor issuer
 * of the subject's delegations, with the same kind of request
 * (`typ: "kya-os-key-revocation+jwt"`, `{iss, did, kid, iat, jti, aud}`):
 * `verifyKeyRevocation` accepts the issuer of any active hop delegated to
 * the subject, or of any hop above one; the subject itself never.
 */

import { randomUUID } from 'node:crypto';
import {
  DELEGATION_CREDENTIAL_TYPE,
  ErrorCode,
  HelixError,
  IDENTITY_CREDENTIAL_TYPE,
  InvalidJWSError,
  readJwsHeader,
  signJws,
  verifyJwsByKid,
  type DidResolver,
  type Signer,
} from '../../core/index.js';
import type { VcRepository, VCRecord } from '../../repositories/vc.repository.js';
import type { StatusListService } from '../status-lists/status-list.service.js';

export const REVOCATION_REQUEST_TYP = 'kya-os-revocation+jwt';
/** Story C-E: a request to revoke a compromised key, signed by an ancestor issuer. */
export const KEY_REVOCATION_REQUEST_TYP = 'kya-os-key-revocation+jwt';
/** How far a request's `iat` may be from now. */
export const REVOCATION_REQUEST_SKEW_SECONDS = 300;
/** The deepest chain walked up for the revoker check, and down for the cascade. */
const MAX_WALK = 64;

export interface RevocationRequestClaims {
  iss: string;
  credentialId: string;
  iat: number;
  jti: string;
  aud: string;
}

export interface KeyRevocationRequestClaims {
  iss: string;
  /** The subject whose key is revoked. */
  did: string;
  /** The key, as fragment or `<did>#<fragment>`. */
  kid: string;
  iat: number;
  jti: string;
  aud: string;
}

export interface RevocationOutcome {
  credentialId: string;
  revoker: string;
  /** Every credential revoked: the target first, then its descendants. */
  revoked: string[];
}

export interface RevocationServiceOptions {
  repo: Pick<VcRepository, 'findByVcId' | 'findActiveChildren'> & Partial<Pick<VcRepository, 'findActiveBySubjectDid'>>;
  statusLists: Pick<StatusListService, 'revokeMany'>;
  /** Public DID resolution, for the revoker's key. */
  resolveDid: DidResolver;
  /** `<API>/v1/revocations`: the audience every request must name. */
  audience: string;
  clock?: (() => number) | undefined;
}

type Json = Record<string, unknown>;
const asJson = (record: VCRecord): Json => (typeof record.vcJson === 'string' ? JSON.parse(record.vcJson) : record.vcJson) as Json;
const subjectOf = (vc: Json): Json => (vc['credentialSubject'] !== null && typeof vc['credentialSubject'] === 'object' ? (vc['credentialSubject'] as Json) : {});
const issuerOf = (vc: Json): string | undefined => {
  const issuer = vc['issuer'];
  if (typeof issuer === 'string') return issuer;
  return issuer !== null && typeof issuer === 'object' && typeof (issuer as Json)['id'] === 'string' ? ((issuer as Json)['id'] as string) : undefined;
};
const typesOf = (vc: Json): string[] => (Array.isArray(vc['type']) ? (vc['type'] as string[]) : []);

export class RevocationService {
  readonly #options: RevocationServiceOptions;
  readonly #clock: () => number;

  constructor(options: RevocationServiceOptions) {
    this.#options = options;
    this.#clock = options.clock ?? Date.now;
  }

  /** A revocation request for `credentialId`, signed by `revokerSigner`. */
  async signRequest(credentialId: string, revokerSigner: Signer): Promise<string> {
    const claims: RevocationRequestClaims = {
      iss: revokerSigner.did,
      credentialId,
      iat: Math.floor(this.#clock() / 1000),
      jti: `urn:uuid:${randomUUID()}`,
      aud: this.#options.audience,
    };
    return signJws(claims as unknown as Record<string, unknown>, revokerSigner, { header: { typ: REVOCATION_REQUEST_TYP } });
  }

  /** `revoke(credentialId, revokerSigner)`: signs the request with the revoker's Signer, then judges it as any other. */
  async revoke(credentialId: string, revokerSigner: Signer, requestId: string): Promise<RevocationOutcome> {
    return this.revokeSigned(await this.signRequest(credentialId, revokerSigner), requestId);
  }

  /** The claims of a request whose signature verified under its revoker's key; throws for anything else. */
  async verifyRequest(jws: unknown): Promise<RevocationRequestClaims> {
    return this.#verifySigned(jws, REVOCATION_REQUEST_TYP, (claims, invalid) => {
      if (typeof claims['credentialId'] !== 'string' || claims['credentialId'].length === 0) invalid('credentialId is required');
    }) as unknown as Promise<RevocationRequestClaims>;
  }

  /** Story C-E: a key-revocation request for `did`'s key `kid`, signed by `revokerSigner`. */
  async signKeyRevocation(did: string, kid: string, revokerSigner: Signer): Promise<string> {
    const claims: KeyRevocationRequestClaims = {
      iss: revokerSigner.did,
      did,
      kid,
      iat: Math.floor(this.#clock() / 1000),
      jti: `urn:uuid:${randomUUID()}`,
      aud: this.#options.audience,
    };
    return signJws(claims as unknown as Record<string, unknown>, revokerSigner, { header: { typ: KEY_REVOCATION_REQUEST_TYP } });
  }

  /**
   * Story C-E point 5: judges a signed request to revoke `did`'s key `kid`.
   * Resolves to the revoker DID when it issued an active hop delegated to
   * `did`, or a hop above one; throws otherwise (the subject never may).
   */
  async verifyKeyRevocation(jws: unknown, did: string, kid: string): Promise<string> {
    const claims = await this.#verifySigned(jws, KEY_REVOCATION_REQUEST_TYP, (fields, invalid) => {
      if (fields['did'] !== did) invalid(`did must be ${did}`);
      const fragment = (value: unknown): string => (typeof value === 'string' ? value.slice(value.indexOf('#') + 1) : '');
      if (fragment(fields['kid']).length === 0 || fragment(fields['kid']) !== fragment(kid)) invalid(`kid must be ${kid}`);
    });
    const revoker = claims['iss'] as string;
    if (revoker === did) throw new HelixError(ErrorCode.REVOCATION_FORBIDDEN, 'A subject may not revoke its own key through an issuer request; use its account', 403);
    const hops = (await this.#options.repo.findActiveBySubjectDid?.(did, DELEGATION_CREDENTIAL_TYPE)) ?? [];
    for (const hop of hops) {
      const { allowed } = await this.revokersOf(hop);
      if (allowed.has(revoker)) return revoker;
    }
    throw new HelixError(ErrorCode.REVOCATION_FORBIDDEN, `${revoker} issued no delegation to ${did}, directly or above one`, 403);
  }

  /** Verifies a revoker-signed request of type `typ`: header, common claims, `check` for the rest, then the signature. */
  async #verifySigned(
    jws: unknown,
    expectedTyp: string,
    check: (claims: Record<string, unknown>, invalid: (message: string) => never) => void,
  ): Promise<Record<string, unknown>> {
    const invalid = (message: string): never => {
      throw new HelixError(ErrorCode.REVOCATION_REQUEST_INVALID, `revocation request refused: ${message}`, 400);
    };
    if (typeof jws !== 'string' || jws.split('.').length !== 3) return invalid('it is not a compact JWS');
    let typ: unknown;
    try {
      typ = readJwsHeader(jws).typ;
    } catch (error) {
      return invalid((error as Error).message);
    }
    if (typ !== expectedTyp) invalid(`typ must be ${expectedTyp}`);
    let payload: unknown;
    try {
      payload = JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8'));
    } catch {
      return invalid('the payload is not JSON');
    }
    const claims = payload as Partial<RevocationRequestClaims>;
    if (payload === null || typeof payload !== 'object' || typeof claims.iss !== 'string' || !claims.iss.startsWith('did:')) invalid('iss must be the revoker DID');
    check(payload as Record<string, unknown>, invalid);
    if (typeof claims.jti !== 'string' || claims.jti.length === 0) invalid('jti is required');
    if (claims.aud !== this.#options.audience) invalid(`aud must be ${this.#options.audience}`);
    const now = Math.floor(this.#clock() / 1000);
    if (typeof claims.iat !== 'number' || !Number.isInteger(claims.iat) || Math.abs(now - claims.iat) > REVOCATION_REQUEST_SKEW_SECONDS) {
      invalid(`iat must be within ${REVOCATION_REQUEST_SKEW_SECONDS} s of now`);
    }
    try {
      await verifyJwsByKid(jws, this.#options.resolveDid, { expectedDid: claims.iss! });
    } catch (error) {
      const reason = error instanceof InvalidJWSError ? `${error.reason}: ` : '';
      throw new HelixError(ErrorCode.REVOCATION_SIGNATURE_INVALID, `revocation request signature refused: ${reason}${(error as Error).message}`, 401);
    }
    return claims as Record<string, unknown>;
  }

  /** The DIDs that may revoke `record`, and the DIDs that are its subject (who never may). */
  async revokersOf(record: VCRecord): Promise<{ allowed: Set<string>; subjects: Set<string> }> {
    const vc = asJson(record);
    const subject = subjectOf(vc);
    const allowed = new Set<string>();
    const subjects = new Set<string>();
    const issuer = issuerOf(vc);
    if (issuer !== undefined) allowed.add(issuer);
    if (typesOf(vc).includes(DELEGATION_CREDENTIAL_TYPE)) {
      for (const member of ['invoker', 'controller'] as const) if (typeof subject[member] === 'string') subjects.add(subject[member] as string);
      // Every ancestor's issuer, up to the root: the root's issuer is the Responsible Party.
      let parentId = record.parentVcId ?? null;
      for (let depth = 0; parentId !== null && depth < MAX_WALK; depth += 1) {
        const parent = await this.#options.repo.findByVcId(parentId);
        if (!parent) break;
        const parentIssuer = issuerOf(asJson(parent));
        if (parentIssuer !== undefined) allowed.add(parentIssuer);
        parentId = parent.parentVcId ?? null;
      }
    } else {
      if (typeof subject['id'] === 'string') subjects.add(subject['id']);
      if (typesOf(vc).includes(IDENTITY_CREDENTIAL_TYPE) && typeof subject['responsibleParty'] === 'string') allowed.add(subject['responsibleParty']);
    }
    return { allowed, subjects };
  }

  /** Every active descendant hop of `vcId`, parents before children. */
  async descendantsOf(vcId: string): Promise<string[]> {
    const found: string[] = [];
    const seen = new Set<string>([vcId]);
    let frontier = [vcId];
    for (let depth = 0; frontier.length > 0 && depth < MAX_WALK; depth += 1) {
      const next: string[] = [];
      for (const id of frontier) {
        for (const child of await this.#options.repo.findActiveChildren(id)) {
          if (seen.has(child.vcId)) continue;
          seen.add(child.vcId);
          found.push(child.vcId);
          next.push(child.vcId);
        }
      }
      frontier = next;
    }
    return found;
  }

  /** Judges a signed request against the chain, then revokes the target and every descendant. */
  async revokeSigned(jws: unknown, requestId: string): Promise<RevocationOutcome> {
    const claims = await this.verifyRequest(jws);
    const record = await this.#options.repo.findByVcId(claims.credentialId);
    if (!record) throw new HelixError(ErrorCode.VC_NOT_FOUND, 'Credential not found', 404);
    if (record.revokedAt) throw new HelixError(ErrorCode.VC_ALREADY_REVOKED, 'Credential already revoked', 409);
    const { allowed, subjects } = await this.revokersOf(record);
    if (subjects.has(claims.iss)) {
      throw new HelixError(ErrorCode.REVOCATION_FORBIDDEN, 'The subject of a credential may not revoke it (SPEC.md §6.5.1)', 403);
    }
    if (!allowed.has(claims.iss)) {
      throw new HelixError(
        ErrorCode.REVOCATION_FORBIDDEN,
        `${claims.iss} is neither the issuer, an ancestor issuer nor the root Responsible Party of this credential`,
        403,
      );
    }
    const descendants = await this.descendantsOf(record.vcId);
    const revoked = await this.#options.statusLists.revokeMany([record.vcId, ...descendants], { requestId, revoker: claims.iss });
    return { credentialId: record.vcId, revoker: claims.iss, revoked: revoked.map((entry) => entry.vcId) };
  }
}
