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
 * DbKeyStore: the KeyStore of KYA-OS story F-3 over database rows
 * (`wrapped_keys`).
 *
 * Each private key is an Ed25519 seed generated here, wrapped with
 * AES-256-GCM under a key-encryption key (KEK) from config, a fresh 96-bit
 * nonce per key, and the row's DID, kid, subject type and KEK id bound in as
 * associated data, so a wrapped key copied onto another row does not
 * unwrap. The plaintext seed exists only inside `generate` and `sign`, and
 * is zeroed before they return. Nothing here returns private material.
 *
 * `KmsKeyStore` (keys that never leave a KMS) is parked for phase 4.
 */

import { createCipheriv, createDecipheriv, randomBytes as nodeRandomBytes } from 'node:crypto';
import * as ed25519 from '@noble/ed25519';
import {
  KeyStoreKeyNotFoundError,
  KeyStoreKeyShreddedError,
  KeyStoreUnavailableError,
  ValidationError,
  base64UrlDecodeStrict,
  base64UrlEncode,
  didKeyFromPublicKey,
  type KeyStore,
  type KeyStoreGenerateInput,
  type KeyStoreKeyInfo,
  type KeyStoreKeyRef,
  type KeyStoreSubjectType,
  type PublicKeyJwk,
} from '../../core/index.js';
import type { NewWrappedKey, WrappedKeyRow } from '../../repositories/custody.repository.js';

export const DB_KEY_STORE_ALGORITHM = 'A256GCM';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/** What DbKeyStore needs from its table; `WrappedKeyRepository` is the production one. */
export interface WrappedKeyTable {
  insert(row: NewWrappedKey): Promise<WrappedKeyRow>;
  find(did: string, kid: string): Promise<WrappedKeyRow | null>;
  list(did: string): Promise<WrappedKeyRow[]>;
  shred(did: string, kid: string, at: Date): Promise<boolean>;
}

export interface DbKeyStoreOptions {
  table: WrappedKeyTable;
  /** The key-encryption key: 64 hex characters (32 bytes). */
  keyEncryptionKey: string;
  /** Names the KEK on every row, so a later KEK rotation knows which key wrapped which row. Default `kek-1`. */
  keyEncryptionKeyId?: string;
  /** Injected for tests. */
  randomBytes?: (size: number) => Uint8Array;
  clock?: () => Date;
}

function requireRef(ref: KeyStoreKeyRef): void {
  if (typeof ref?.did !== 'string' || !ref.did.startsWith('did:')) {
    throw new ValidationError('KeyStore: did must be a DID');
  }
  if (typeof ref.kid !== 'string' || !ref.kid.startsWith(`${ref.did}#`) || ref.kid.length === ref.did.length + 1) {
    throw new ValidationError('KeyStore: kid must be a verification-method id of the DID (<did>#<fragment>)');
  }
}

export class DbKeyStore implements KeyStore {
  readonly #table: WrappedKeyTable;
  readonly #kek: Buffer;
  readonly #kekId: string;
  readonly #randomBytes: (size: number) => Uint8Array;
  readonly #clock: () => Date;

  constructor(options: DbKeyStoreOptions) {
    if (typeof options.keyEncryptionKey !== 'string' || !/^[0-9a-fA-F]{64}$/.test(options.keyEncryptionKey)) {
      throw new KeyStoreUnavailableError('DbKeyStore: the key-encryption key must be 64 hex characters (32 bytes)');
    }
    this.#table = options.table;
    this.#kek = Buffer.from(options.keyEncryptionKey, 'hex');
    this.#kekId = options.keyEncryptionKeyId ?? 'kek-1';
    this.#randomBytes = options.randomBytes ?? ((size: number): Uint8Array => new Uint8Array(nodeRandomBytes(size)));
    this.#clock = options.clock ?? ((): Date => new Date());
  }

  async generate(input: KeyStoreGenerateInput): Promise<PublicKeyJwk> {
    requireRef(input);
    return this.#store(input, this.#seed());
  }

  /** A did:key (story L3-H): the DID is derived from the fresh key, which is kept under `<did>#<multibase>`. */
  async generateDidKey(subjectType: KeyStoreSubjectType): Promise<KeyStoreKeyRef & { publicKeyJwk: PublicKeyJwk }> {
    const seed = this.#seed();
    // A 32-byte seed always has a public key (#seed checked the length); #store zeroes the seed.
    const did = didKeyFromPublicKey(ed25519.getPublicKey(seed));
    const kid = `${did}#${did.slice('did:key:'.length)}`;
    const publicKeyJwk = await this.#store({ did, kid, subjectType }, seed);
    return { did, kid, publicKeyJwk };
  }

  #seed(): Uint8Array {
    const seed = this.#randomBytes(32);
    if (!(seed instanceof Uint8Array) || seed.length !== 32) {
      throw new KeyStoreUnavailableError('DbKeyStore: the random source did not return 32 bytes');
    }
    return seed;
  }

  /** Wraps and stores `seed` under `input`; zeroes it whatever happens. */
  async #store(input: KeyStoreGenerateInput, seed: Uint8Array): Promise<PublicKeyJwk> {
    try {
      const publicKeyJwk: PublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: base64UrlEncode(ed25519.getPublicKey(seed)) };
      const nonce = this.#randomBytes(NONCE_BYTES);
      const cipher = createCipheriv('aes-256-gcm', this.#kek, nonce);
      cipher.setAAD(this.#aad(input.did, input.kid, input.subjectType));
      const ciphertext = Buffer.concat([cipher.update(seed), cipher.final(), cipher.getAuthTag()]);
      await this.#table.insert({
        did: input.did,
        kid: input.kid,
        subjectType: input.subjectType,
        algorithm: DB_KEY_STORE_ALGORITHM,
        kekId: this.#kekId,
        nonce: base64UrlEncode(nonce),
        ciphertext: base64UrlEncode(ciphertext),
        publicKeyJwk,
      });
      return publicKeyJwk;
    } finally {
      seed.fill(0);
    }
  }

  async sign(ref: KeyStoreKeyRef, data: Uint8Array): Promise<Uint8Array> {
    requireRef(ref);
    if (!(data instanceof Uint8Array)) throw new ValidationError('KeyStore: data to sign must be bytes');
    const row = await this.#table.find(ref.did, ref.kid);
    if (!row) throw new KeyStoreKeyNotFoundError(ref.kid);
    if (row.shreddedAt || row.ciphertext.length === 0) throw new KeyStoreKeyShreddedError(ref.kid);
    const seed = this.#unwrap(row);
    try {
      return await ed25519.signAsync(data, seed);
    } finally {
      seed.fill(0);
    }
  }

  async publicJwk(ref: KeyStoreKeyRef): Promise<PublicKeyJwk | null> {
    requireRef(ref);
    const row = await this.#table.find(ref.did, ref.kid);
    return row ? { ...row.publicKeyJwk } : null;
  }

  async shred(ref: KeyStoreKeyRef): Promise<boolean> {
    requireRef(ref);
    return this.#table.shred(ref.did, ref.kid, this.#clock());
  }

  async list(did: string): Promise<KeyStoreKeyInfo[]> {
    const rows = await this.#table.list(did);
    return rows.map((row) => ({
      did: row.did,
      kid: row.kid,
      subjectType: row.subjectType,
      publicKeyJwk: { ...row.publicKeyJwk },
      createdAt: row.createdAt,
      shreddedAt: row.shreddedAt,
    }));
  }

  #aad(did: string, kid: string, subjectType: string): Buffer {
    return Buffer.from(JSON.stringify(['helix-key-store/v1', did, kid, subjectType, this.#kekId]), 'utf8');
  }

  #unwrap(row: WrappedKeyRow): Uint8Array {
    if (row.algorithm !== DB_KEY_STORE_ALGORITHM || row.kekId !== this.#kekId) {
      throw new KeyStoreUnavailableError(`DbKeyStore: key ${row.kid} is wrapped under ${row.algorithm}/${row.kekId}, not this store's key-encryption key`);
    }
    const nonce = base64UrlDecodeStrict(row.nonce);
    const sealed = base64UrlDecodeStrict(row.ciphertext);
    if (!nonce || nonce.length !== NONCE_BYTES || !sealed || sealed.length !== 32 + TAG_BYTES) {
      throw new KeyStoreUnavailableError(`DbKeyStore: key ${row.kid} is not a well-formed wrapped key`);
    }
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.#kek, nonce);
      decipher.setAAD(this.#aad(row.did, row.kid, row.subjectType));
      decipher.setAuthTag(sealed.subarray(32));
      return new Uint8Array(Buffer.concat([decipher.update(sealed.subarray(0, 32)), decipher.final()]));
    } catch {
      throw new KeyStoreUnavailableError(`DbKeyStore: key ${row.kid} does not unwrap under this store's key-encryption key`);
    }
  }
}

export interface KeyEncryptionKeyConfig {
  HELIX_KEY_STORE_KEK?: string | undefined;
  HELIX_KEY_STORE_KEK_ID?: string | undefined;
  HOSTED_KEY_ENCRYPTION_KEY?: string | undefined;
  NODE_ENV?: string | undefined;
}

/**
 * The KEK DbKeyStore wraps with: `HELIX_KEY_STORE_KEK`, else the hosted
 * build's `HOSTED_KEY_ENCRYPTION_KEY`; outside production a random
 * per-process key when neither is set (keys then do not survive a restart).
 * Production without a KEK is refused rather than silently ephemeral.
 */
export function resolveKeyEncryptionKey(
  config: KeyEncryptionKeyConfig,
  randomHex: () => string = () => nodeRandomBytes(32).toString('hex'),
): { keyEncryptionKey: string; keyEncryptionKeyId: string; ephemeral: boolean } {
  const configured = config.HELIX_KEY_STORE_KEK ?? config.HOSTED_KEY_ENCRYPTION_KEY;
  const keyEncryptionKeyId = config.HELIX_KEY_STORE_KEK_ID ?? 'kek-1';
  if (configured) return { keyEncryptionKey: configured, keyEncryptionKeyId, ephemeral: false };
  if (config.NODE_ENV === 'production') {
    throw new KeyStoreUnavailableError('HELIX_KEY_STORE_KEK (or HOSTED_KEY_ENCRYPTION_KEY) is required in production');
  }
  return { keyEncryptionKey: randomHex(), keyEncryptionKeyId: 'ephemeral', ephemeral: true };
}
