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
 * The evidence vault (AUDITABILITY.md, Evidence, retention, and access).
 *
 * An exact payload that must be kept (a request body, a rejected
 * presentation, an exception) never enters the event core. It is encrypted
 * with randomized AES-256-GCM under tenant-bound authenticated data, stored
 * by an opaque object id, and the event carries only the `EvidenceRef`:
 * object id, ciphertext digest, size, suite, key id, nonce and AAD digest.
 * Decryption needs the same AAD, so an object cannot be read under another
 * tenant or purpose, and a reference that does not match its bytes is refused.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { canonicalize } from '../crypto/jcs.js';
import { HelixError } from '../errors/HelixError.js';
import { digestBytes } from './digest.js';
import type { Digest, EvidenceRef, PartyRef } from './types.js';

const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export class AuditEvidenceError extends HelixError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('AUDIT_EVIDENCE_INVALID', message, 400, details);
    this.name = 'AuditEvidenceError';
  }
}

/** An encrypted object as the vault stores it: the reference and the bytes it describes. */
export interface EncryptedEvidence {
  ref: EvidenceRef;
  ciphertext: Uint8Array;
}

export interface EvidenceEncryptorOptions {
  /** 32 bytes, raw or as 64 hex digits. */
  key: Uint8Array | string;
  /** Names the key version in every reference (`encryption.keyId`). */
  keyId: string;
  /** Injectable for deterministic fixtures; default `crypto.randomBytes`. */
  randomBytes?: (length: number) => Uint8Array;
}

export interface EvidenceEncryptInput {
  plaintext: Uint8Array | string;
  mediaType: string;
  /** Tenant-bound authenticated data; see `evidenceAad`. Never empty. */
  aad: Uint8Array;
  /** Commit to the plaintext in the reference (`sha256:` of the plaintext bytes). */
  commitPlaintext?: boolean;
}

/**
 * Authenticated data that binds an evidence object to a tenant and a purpose:
 * the UTF-8 bytes of `JCS({purpose, tenant})`. Both sides derive it; it is
 * never stored beside the ciphertext.
 */
export function evidenceAad(tenant: PartyRef, purpose: string): Uint8Array {
  return Buffer.from(canonicalize({ purpose, tenant }), 'utf8');
}

function toBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
}

function keyBytes(key: Uint8Array | string): Uint8Array {
  const bytes = typeof key === 'string' ? (/^[0-9a-fA-F]{64}$/.test(key) ? Buffer.from(key, 'hex') : undefined) : key;
  if (bytes === undefined || bytes.length !== KEY_BYTES) {
    throw new TypeError('Evidence key must be 32 bytes (raw or 64 hex digits)');
  }
  return bytes;
}

/** Randomized AES-256-GCM evidence encryption with opaque object addressing. */
export class EvidenceEncryptor {
  private readonly key: Uint8Array;
  readonly keyId: string;
  private readonly random: (length: number) => Uint8Array;

  constructor(options: EvidenceEncryptorOptions) {
    this.key = keyBytes(options.key);
    if (options.keyId.length === 0) throw new TypeError('Evidence keyId must be non-empty');
    this.keyId = options.keyId;
    this.random = options.randomBytes ?? ((length): Uint8Array => randomBytes(length));
  }

  encrypt(input: EvidenceEncryptInput): EncryptedEvidence {
    if (input.aad.byteLength === 0) {
      throw new AuditEvidenceError('Evidence encryption requires tenant-scoped authenticated data');
    }
    const plaintext = toBytes(input.plaintext);
    const nonce = this.random(NONCE_BYTES);
    const objectRandom = this.random(16);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce, { authTagLength: TAG_BYTES });
    cipher.setAAD(input.aad);
    const body = cipher.update(plaintext);
    cipher.final();
    // WebCrypto's layout: ciphertext followed by the 16-byte tag.
    const ciphertext = new Uint8Array(body.length + TAG_BYTES);
    ciphertext.set(body);
    ciphertext.set(cipher.getAuthTag(), body.length);
    const ref: EvidenceRef = {
      objectId: `evi_${Buffer.from(objectRandom).toString('base64url')}`,
      ciphertextDigest: digestBytes(ciphertext),
      ...(input.commitPlaintext ? { plaintextCommitment: digestBytes(plaintext) } : {}),
      mediaType: input.mediaType,
      size: String(ciphertext.byteLength),
      encryption: {
        suite: 'A256GCM',
        keyId: this.keyId,
        nonce: Buffer.from(nonce).toString('base64url'),
        aadDigest: digestBytes(input.aad),
      },
    };
    return { ref: Object.freeze(ref), ciphertext };
  }

  /** The plaintext, only for the bytes the reference describes, under this key, with the AAD that was bound. */
  decrypt(object: EncryptedEvidence, aad: Uint8Array): Uint8Array {
    if (aad.byteLength === 0) {
      throw new AuditEvidenceError('Evidence decryption requires tenant-scoped authenticated data');
    }
    const { ref, ciphertext } = object;
    if (ref.encryption.suite !== 'A256GCM' || ref.encryption.keyId !== this.keyId) {
      throw new AuditEvidenceError('Evidence reference names another suite or key', { keyId: ref.encryption.keyId });
    }
    if (digestBytes(ciphertext) !== ref.ciphertextDigest || String(ciphertext.byteLength) !== ref.size) {
      throw new AuditEvidenceError('Evidence ciphertext does not match its reference');
    }
    if (digestBytes(aad) !== ref.encryption.aadDigest) {
      throw new AuditEvidenceError('Evidence authenticated data does not match its reference');
    }
    if (ciphertext.byteLength < TAG_BYTES) {
      throw new AuditEvidenceError('Evidence ciphertext is shorter than its authentication tag');
    }
    const nonce = Buffer.from(ref.encryption.nonce, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', this.key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(ciphertext.subarray(ciphertext.byteLength - TAG_BYTES));
    try {
      const plaintext = decipher.update(ciphertext.subarray(0, ciphertext.byteLength - TAG_BYTES));
      decipher.final();
      if (ref.plaintextCommitment !== undefined && digestBytes(plaintext) !== ref.plaintextCommitment) {
        throw new AuditEvidenceError('Evidence plaintext does not match its commitment');
      }
      return plaintext;
    } catch (error) {
      if (error instanceof AuditEvidenceError) throw error;
      throw new AuditEvidenceError('Evidence AEAD verification failed');
    }
  }
}

/** Where ciphertext lives, apart from the ledger: the sink implements it over the database, tests in memory. */
export interface EvidenceStore {
  /** Stores the object unless its id is taken; an id taken by different bytes is a collision and refused. */
  putIfAbsent(object: EncryptedEvidence): Promise<EvidenceRef>;
  /** The stored object, or null when there is none for that id. */
  get(objectId: string): Promise<EncryptedEvidence | null>;
}

export class MemoryEvidenceStore implements EvidenceStore {
  private readonly objects = new Map<string, EncryptedEvidence>();

  async putIfAbsent(object: EncryptedEvidence): Promise<EvidenceRef> {
    assertEvidenceMatchesRef(object);
    const existing = this.objects.get(object.ref.objectId);
    if (existing !== undefined) {
      if (existing.ref.ciphertextDigest !== object.ref.ciphertextDigest) {
        throw new AuditEvidenceError('Opaque evidence object id collision', { objectId: object.ref.objectId });
      }
      return existing.ref;
    }
    this.objects.set(object.ref.objectId, { ref: object.ref, ciphertext: new Uint8Array(object.ciphertext) });
    return object.ref;
  }

  async get(objectId: string): Promise<EncryptedEvidence | null> {
    const found = this.objects.get(objectId);
    return found === undefined ? null : { ref: found.ref, ciphertext: new Uint8Array(found.ciphertext) };
  }
}

/** Refuses an object whose bytes are not the ones its reference commits to. */
export function assertEvidenceMatchesRef(object: EncryptedEvidence): void {
  if (digestBytes(object.ciphertext) !== object.ref.ciphertextDigest || String(object.ciphertext.byteLength) !== object.ref.size) {
    throw new AuditEvidenceError('Evidence bytes do not match their ciphertext digest or size', { objectId: object.ref.objectId });
  }
}

export type { Digest as EvidenceDigest };
