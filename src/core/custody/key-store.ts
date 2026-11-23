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
 * Where Helix keeps the private keys it holds (KYA-OS stories, Helix-side
 * key storage; story F-3): custodial agents and services, owner keys in
 * `helix` mode, and the consent did:keys of L3-H.
 *
 * Every Helix-held key goes through a KeyStore and nothing else (stories
 * rule 8): no code path reads a private key from a table. The interface
 * never hands private material out. `generate` returns the public JWK,
 * `sign` returns a signature, `shred` destroys the private half for good.
 *
 * Implementations: `DbKeyStore` (database rows wrapped with AES-256-GCM under
 * a key-encryption key from config) now; `KmsKeyStore` is parked for
 * phase 4 (stories rule 12).
 */

import type { Signer } from '../crypto/signer.js';
import type { PublicKeyJwk } from '../did/document.js';

/** Which kind of subject a Helix-held key signs for. */
export type KeyStoreSubjectType = 'agent' | 'service' | 'owner' | 'consent';

/** A key is named by its controller DID and its full verification-method id, `<did>#<fragment>`. */
export interface KeyStoreKeyRef {
  did: string;
  kid: string;
}

export interface KeyStoreGenerateInput extends KeyStoreKeyRef {
  subjectType: KeyStoreSubjectType;
}

/** What a KeyStore says about a key: public facts only. */
export interface KeyStoreKeyInfo extends KeyStoreKeyRef {
  subjectType: KeyStoreSubjectType;
  publicKeyJwk: PublicKeyJwk;
  createdAt: Date;
  /** Set once the private half is destroyed. */
  shreddedAt: Date | null;
}

export interface KeyStore {
  /** Generates a fresh Ed25519 key for `did` under `kid`, keeps the private half, returns the public JWK. */
  generate(input: KeyStoreGenerateInput): Promise<PublicKeyJwk>;
  /** A raw 64-byte Ed25519 signature over `data` with the key `ref` names. */
  sign(ref: KeyStoreKeyRef, data: Uint8Array): Promise<Uint8Array>;
  /** The public JWK of `ref`, or null when the store never held it. A shredded key still has a public half. */
  publicJwk(ref: KeyStoreKeyRef): Promise<PublicKeyJwk | null>;
  /** Destroys the private half of `ref`. True when there was one to destroy. */
  shred(ref: KeyStoreKeyRef): Promise<boolean>;
  /** Every key the store holds or held for `did`, public facts only. */
  list(did: string): Promise<KeyStoreKeyInfo[]>;
  /**
   * Generates a fresh Ed25519 key whose DID is the key itself (`did:key`,
   * story L3-H: a user's pairwise consent identity), keeps the private half
   * under `<did>#<multibase>`, and returns the public facts. A did:key cannot
   * be named before its key exists, so `generate` cannot make one.
   */
  generateDidKey?(subjectType: KeyStoreSubjectType): Promise<KeyStoreKeyRef & { publicKeyJwk: PublicKeyJwk }>;
}

/**
 * A {@link Signer} over a KeyStore key: what Helix-side signing code hands to
 * `signJws`, `signDataIntegrity` (F-1) and the rest, so the code that builds
 * a credential or proof is the same whoever holds the key. The signer holds
 * the key's name, never the key.
 */
export class KeyStoreSigner implements Signer {
  readonly did: string;
  readonly kid: string;
  readonly #store: KeyStore;
  readonly #ref: KeyStoreKeyRef;

  /** `kid` is the full verification-method id (`<did>#key-1`) or its fragment. */
  constructor(store: KeyStore, did: string, kid: string) {
    const hash = kid.indexOf('#');
    const fragment = hash === -1 ? kid : kid.slice(hash + 1);
    if (fragment.length === 0 || (hash > 0 && kid.slice(0, hash) !== did)) {
      throw new Error(`KeyStoreSigner: kid ${kid} is not a verification method of ${did}`);
    }
    this.did = did;
    this.kid = fragment;
    this.#store = store;
    this.#ref = { did, kid: `${did}#${fragment}` };
  }

  /** `<did>#<kid>`, what a JWS header or proof names. */
  get verificationMethodId(): string {
    return this.#ref.kid;
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return this.#store.sign(this.#ref, data);
  }
}
