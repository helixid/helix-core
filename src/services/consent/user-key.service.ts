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
 * UserKeyService (KYA-OS story L3-H points 1 and 8): the user's pairwise
 * did:key, one per (service DID, service user id) per consent cycle.
 *
 * - The key is generated on the first consent of a cycle, in the KeyStore
 *   (subjectType `consent`; stories rule 8), and its DID is the public key
 *   itself: no document is hosted. The user never needs a Helix account.
 * - Within a cycle the same key signs every consent of that user at that
 *   service, and every renewal. Two services never share a key.
 * - Crypto-shredding (`shredExpiredUserKeys`): once every consent the key
 *   signed is closed (withdrawn, or its window ended) and every hop it signed
 *   is past its `validUntil`, the private half is destroyed. Until then the
 *   key keeps re-signing the user's status list, so a revoked hop that has
 *   not expired keeps reading revoked (a stale list would let it through at
 *   L2). The DID string, the hops, the consent records and the audit history
 *   stay. The next consent starts a new cycle with a new key.
 *
 * Nothing here signs a grant: ConsentService does, only on the user's click.
 * `CredentialService.signerFor` never finds these keys, so no other route can
 * sign as a user.
 */

import { createHash } from 'node:crypto';
import {
  KeyStoreKeyShreddedError,
  KeyStoreSigner,
  canonicalize,
  jsonDigest,
  publicDid,
  type AuditTrail,
  type KeyStore,
  type Signer,
} from '../../core/index.js';
import type { ConsentRepository, UserKeyRow } from '../../repositories/consent.repository.js';

/** A key generated for an approval that never signed (the signing failed) is shredded after this long. */
export const ORPHAN_USER_KEY_MS = 60 * 60 * 1000;

export type UserKeyRepository = Pick<
  ConsentRepository,
  'createUserKey' | 'findUserKey' | 'findLiveUserKey' | 'listLiveUserKeys' | 'markUserKeyShredded' | 'listConsents'
>;

export interface UserKeyServiceOptions {
  repo: UserKeyRepository;
  /** Must offer `generateDidKey` (DbKeyStore does). */
  keyStore: KeyStore;
  audit?: AuditTrail | undefined;
  clock?: (() => number) | undefined;
}

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}

/** `sha256:<hex>` of (service DID, service user id): how a service's user is named here; the id itself is never stored. */
export function serviceUserRefOf(serviceDid: string, serviceUserId: string): string {
  return `sha256:${createHash('sha256').update(canonicalize([serviceDid, serviceUserId])).digest('hex')}`;
}

export class UserKeyService {
  readonly #repo: UserKeyRepository;
  readonly #keyStore: KeyStore;
  readonly #audit: AuditTrail | undefined;
  readonly #clock: () => number;
  #timer: ReturnType<typeof setInterval> | undefined;

  constructor(options: UserKeyServiceOptions) {
    if (typeof options.keyStore.generateDidKey !== 'function') {
      throw new Error('UserKeyService: the KeyStore cannot generate a did:key (generateDidKey)');
    }
    this.#repo = options.repo;
    this.#keyStore = options.keyStore;
    this.#audit = options.audit;
    this.#clock = options.clock ?? Date.now;
  }

  #record(name: 'user_key_generated' | 'user_key_shredded', key: UserKeyRow, facts: Record<string, unknown>): void {
    if (this.#audit === undefined) return;
    try {
      this.#audit
        .record({
          eventType: 'configuration.changed',
          action: { category: 'consent', name },
          outcome: 'succeeded',
          correlationId: `user-key-${name}`,
          resource: publicDid(key.did),
          details: {
            family: 'key',
            phase: 'configuration_changed',
            configurationDigest: jsonDigest({ did: key.did, kid: key.kid, serviceDid: key.serviceDid, ...facts }),
          },
        })
        .catch(reportAuditFailure);
    } catch (error) {
      reportAuditFailure(error);
    }
  }

  /** The live key of (service, user) in this cycle, or a new one: the first consent of a cycle generates it. */
  async keyFor(serviceDid: string, serviceUserRef: string): Promise<UserKeyRow> {
    const live = await this.#repo.findLiveUserKey(serviceDid, serviceUserRef);
    if (live) return live;
    const generated = await this.#keyStore.generateDidKey!('consent');
    const key = await this.#repo.createUserKey({ did: generated.did, kid: generated.kid, serviceDid, serviceUserRef });
    this.#record('user_key_generated', key, {});
    return key;
  }

  /** The Signer over a user key (its private half in the KeyStore). */
  signerOf(key: Pick<UserKeyRow, 'did' | 'kid'>): KeyStoreSigner {
    return new KeyStoreSigner(this.#keyStore, key.did, key.kid);
  }

  /**
   * The Signer of a user's own status list (L3-C purpose `status_list`): the
   * live key of a user did:key this deployment generated; undefined for any
   * other DID and once the key is shredded.
   */
  async statusListSignerFor(did: string): Promise<Signer | undefined> {
    if (!did.startsWith('did:key:')) return undefined;
    const key = await this.#repo.findUserKey(did);
    if (!key || key.shreddedAt !== null) return undefined;
    return this.signerOf(key);
  }

  /**
   * Destroys the private half of every user key no consent needs any more:
   * every consent it signed is closed and every hop past its `validUntil`
   * (a key that never signed is shredded after ORPHAN_USER_KEY_MS). Returns
   * the DIDs shredded. The DID string and all records stay.
   */
  async shredExpiredUserKeys(now: number = this.#clock()): Promise<string[]> {
    const shredded: string[] = [];
    for (const key of await this.#repo.listLiveUserKeys()) {
      const consents = await this.#repo.listConsents({ userDid: key.did });
      const done =
        consents.length === 0
          ? key.createdAt.getTime() + ORPHAN_USER_KEY_MS <= now
          : consents.every(
              (consent) => (consent.withdrawnAt !== null || consent.windowUntil.getTime() <= now) && consent.lastHopUntil.getTime() <= now,
            );
      if (!done) continue;
      await this.#keyStore.shred({ did: key.did, kid: key.kid });
      if (await this.#repo.markUserKeyShredded(key.did, new Date(now))) {
        shredded.push(key.did);
        this.#record('user_key_shredded', key, { consents: consents.map((consent) => consent.id) });
      }
    }
    return shredded;
  }

  /** Runs `shredExpiredUserKeys` every `intervalMs` (the job). */
  startShredding(intervalMs: number): void {
    if (this.#timer !== undefined) return;
    this.#timer = setInterval(() => {
      this.shredExpiredUserKeys().catch((error: unknown) => console.error('USER_KEY_SHRED_FAILED', (error as Error).message));
    }, intervalMs);
    this.#timer.unref?.();
  }

  stopShredding(): void {
    if (this.#timer !== undefined) clearInterval(this.#timer);
    this.#timer = undefined;
  }
}

/** Whether `error` is the KeyStore refusing a shredded key (an approval raced the job: the caller starts a new cycle). */
export function isShreddedKeyError(error: unknown): boolean {
  return error instanceof KeyStoreKeyShreddedError;
}
