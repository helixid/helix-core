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
 * Key rotation in a DID document (KYA-OS story C-E points 2 and 3).
 *
 * - Every version of a document Helix publishes carries a monotonic
 *   `rotationSequence` (a whole number, 1 for the first key) and the
 *   `updated` instant of that version. A resolver remembers the highest
 *   sequence it has seen per DID and refuses a document with a lower one,
 *   so a cached old document cannot be replayed as current
 *   (`RotationSequenceGuard`). A document without a sequence is refused once
 *   a sequence was seen for its DID: dropping the member is a downgrade.
 * - A superseded key stays in the document with `validUntil` (the end of
 *   the overlap window), never deleted, so a proof it made while it was
 *   current still verifies. A compromised key also carries `revoked`, the
 *   instant it was revoked: every proof it signed is refused, whatever
 *   `created` the proof claims, since a holder of a stolen key can write any
 *   `created` it likes.
 * - Verifiers pick the key by `kid` and then ask `keyValidityProblem` whether
 *   the proof's `created` (a Data Integrity `created`, a request proof's
 *   `created`, a JWT's `iat`) falls inside that key's validity.
 * - The `jwks.json` a did:web subject may publish (the CIMD binding of
 *   SPEC-ENTITY-CARD, "a mechanical projection of the DID document's
 *   verificationMethod[]") is `projectJwks`; `readJwks` refuses a lower
 *   sequence through the same guard.
 *
 * Cross-border rule (stories rule 4): everything here reads the presented
 * document and a process-local (or injected shared) last-seen store. No
 * Helix database is asked anything.
 */

import { buildDidDocument, verificationMethodId, type AgentDidDocument } from './document.js';
import { rfc3339Instant, type KeyValidity } from './key-validity.js';

export * from './key-validity.js';

/** Why a document was refused as a version older than one already seen. */
export const DID_DOCUMENT_STALE = 'did_document_stale';

/** The document's `rotationSequence`, or undefined when it carries none (or one that is not a whole number ≥ 1). */
export function rotationSequenceOf(document: unknown): number | undefined {
  const value = (document as { rotationSequence?: unknown } | null | undefined)?.rotationSequence;
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 ? value : undefined;
}

/** Where a guard keeps the highest sequence seen per DID. A shared store (Redis) lets every instance refuse the same replay. */
export interface RotationSequenceStore {
  get(did: string): Promise<number | undefined> | number | undefined;
  /** Records `sequence` when it is higher than the one kept. */
  raise(did: string, sequence: number): Promise<void> | void;
}

/** The in-process store: a bounded map, oldest DID dropped first. */
export class MemoryRotationSequenceStore implements RotationSequenceStore {
  readonly #seen = new Map<string, number>();

  constructor(private readonly maxEntries = 10_000) {}

  get(did: string): number | undefined {
    return this.#seen.get(did);
  }

  raise(did: string, sequence: number): void {
    const kept = this.#seen.get(did);
    if (kept !== undefined && kept >= sequence) return;
    this.#seen.delete(did);
    this.#seen.set(did, sequence);
    if (this.#seen.size > this.maxEntries) this.#seen.delete(this.#seen.keys().next().value as string);
  }
}

export class StaleDidDocumentError extends Error {
  readonly reason = DID_DOCUMENT_STALE;

  constructor(
    readonly did: string,
    readonly sequence: number | undefined,
    readonly lastSeen: number,
  ) {
    super(
      sequence === undefined
        ? `DID document of ${did} carries no rotationSequence, but sequence ${lastSeen} was already seen`
        : `DID document of ${did} has rotationSequence ${sequence}, lower than ${lastSeen} already seen`,
    );
    this.name = 'StaleDidDocumentError';
  }
}

/** Refuses a document version older than one already seen for the same DID. */
export class RotationSequenceGuard {
  constructor(readonly store: RotationSequenceStore = new MemoryRotationSequenceStore()) {}

  /** Undefined when `document` is current; the error (not thrown) otherwise. Records a higher sequence. */
  async check(did: string, document: unknown): Promise<StaleDidDocumentError | undefined> {
    const sequence = rotationSequenceOf(document);
    const lastSeen = await this.store.get(did);
    if (lastSeen !== undefined && (sequence === undefined || sequence < lastSeen)) {
      return new StaleDidDocumentError(did, sequence, lastSeen);
    }
    if (sequence !== undefined) await this.store.raise(did, sequence);
    return undefined;
  }

  /** As `check`, throwing the error. */
  async assertCurrent(did: string, document: unknown): Promise<void> {
    const stale = await this.check(did, document);
    if (stale) throw stale;
  }
}

/** A resolver whose documents pass `guard` first: a stale version throws `StaleDidDocumentError`. */
export function guardedResolver<D>(
  resolve: (did: string) => Promise<D | null | undefined>,
  guard: RotationSequenceGuard = new RotationSequenceGuard(),
): (did: string) => Promise<D | null | undefined> {
  return async (did: string) => {
    const document = await resolve(did);
    if (document !== null && document !== undefined) await guard.assertCurrent(did, document);
    return document;
  };
}

/** One key of a projected JWKS: the method's public JWK, its `kid`, and its validity members. */
export interface ProjectedJwk extends KeyValidity {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid: string;
  use: 'sig';
  alg: 'EdDSA';
}

export interface ProjectedJwks {
  keys: ProjectedJwk[];
  rotationSequence?: number;
  updated?: string;
}

/**
 * The `jwks.json` projection of a DID document: every Ed25519
 * verification method as an OKP JWK, kid preserved (the full
 * `<did>#<fragment>` id), with its validity and the document's sequence.
 */
export function projectJwks(document: {
  id: string;
  verificationMethod?: readonly Record<string, unknown>[];
  rotationSequence?: number;
  updated?: string;
}): ProjectedJwks {
  const keys: ProjectedJwk[] = [];
  for (const method of document.verificationMethod ?? []) {
    const jwk = method['publicKeyJwk'] as { kty?: unknown; crv?: unknown; x?: unknown } | undefined;
    if (jwk?.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string' || typeof method['id'] !== 'string') continue;
    const id = method['id'].startsWith('#') ? `${document.id}${method['id']}` : method['id'];
    keys.push({
      kty: 'OKP',
      crv: 'Ed25519',
      x: jwk.x,
      kid: id,
      use: 'sig',
      alg: 'EdDSA',
      ...(typeof method['validFrom'] === 'string' ? { validFrom: method['validFrom'] } : {}),
      ...(typeof method['validUntil'] === 'string' ? { validUntil: method['validUntil'] } : {}),
      ...(typeof method['revoked'] === 'string' ? { revoked: method['revoked'] } : {}),
    });
  }
  const sequence = rotationSequenceOf(document);
  return {
    keys,
    ...(sequence === undefined ? {} : { rotationSequence: sequence }),
    ...(typeof document.updated === 'string' ? { updated: document.updated } : {}),
  };
}

/**
 * The keys of a fetched `jwks.json` for `did`, refused (throws
 * `StaleDidDocumentError`) when its sequence is lower than one the guard
 * has seen for the DID, from a document or an earlier JWKS.
 */
export async function readJwks(did: string, value: unknown, guard: RotationSequenceGuard): Promise<ProjectedJwk[]> {
  if (value === null || typeof value !== 'object' || !Array.isArray((value as { keys?: unknown }).keys)) {
    throw new Error(`jwks of ${did} is not a JWK Set`);
  }
  await guard.assertCurrent(did, value);
  return ((value as { keys: unknown[] }).keys).filter(
    (key): key is ProjectedJwk =>
      typeof key === 'object' &&
      key !== null &&
      (key as ProjectedJwk).kty === 'OKP' &&
      (key as ProjectedJwk).crv === 'Ed25519' &&
      typeof (key as ProjectedJwk).x === 'string' &&
      typeof (key as ProjectedJwk).kid === 'string' &&
      (key as ProjectedJwk).kid.startsWith(`${did}#`),
  );
}

/** One key of a versioned document: current first, then superseded or revoked ones. */
export interface DocumentKey extends KeyValidity {
  kid: string;
  publicKeyJwk: unknown;
}

/**
 * `document` with every key of `keys` after the first appended as a
 * verification method (authentication and assertion) carrying its validity,
 * and the version members set. The first key is the document's own (built
 * by `buildDidDocument`) and must carry no validity: it is current.
 */
export function versionDidDocument<T extends AgentDidDocument>(
  document: T,
  keys: readonly DocumentKey[],
  version: { rotationSequence: number; updated: string },
): T {
  if (!Number.isSafeInteger(version.rotationSequence) || version.rotationSequence < 1) {
    throw new Error('rotationSequence must be a whole number, 1 or more');
  }
  if (rfc3339Instant(version.updated) === undefined) throw new Error('updated must be an RFC 3339 instant');
  const methods = [...document.verificationMethod];
  const authentication = [...document.authentication];
  const assertionMethod = [...document.assertionMethod];
  for (const key of keys) {
    const id = verificationMethodId(document.id, key.kid);
    const existing = methods.findIndex((method) => method.id === id);
    const built = buildDidDocument({ did: document.id, publicKeyJwk: key.publicKeyJwk, kid: id }).verificationMethod[0]!;
    const method = {
      ...built,
      ...(key.validFrom === undefined ? {} : { validFrom: key.validFrom }),
      ...(key.validUntil === undefined ? {} : { validUntil: key.validUntil }),
      ...(key.revoked === undefined ? {} : { revoked: key.revoked }),
    };
    if (existing >= 0) {
      methods[existing] = method;
      continue;
    }
    methods.push(method);
    authentication.push(id);
    assertionMethod.push(id);
  }
  return { ...document, verificationMethod: methods, authentication, assertionMethod, rotationSequence: version.rotationSequence, updated: version.updated };
}
