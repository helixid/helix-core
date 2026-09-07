// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Server-side custody for agent private keys. Ported from
// helix-server-enterprise's original hosted-only implementation — agent
// self-custody has been retired, so every agent key (OSS and enterprise
// alike) is now generated and held here rather than by the agent process.
// This is explicitly an interim, single-shared-key model: one AES-256-GCM
// master key (config.HOSTED_KEY_ENCRYPTION_KEY) encrypts every agent's
// private key. Anyone with that key can decrypt every agent's key — an
// accepted trade-off for now, not a hidden gap. KMS-backed custody and key
// rotation are a deferred fast-follow, not part of this interface's design.
//
// All encrypt/decrypt/sign operations go through this interface rather than
// being called directly at each call site, so swapping in real KMS + key
// rotation later is a one-file change instead of a hunt-and-replace across
// the codebase.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { generateKeyPair, signData, type KeyPair } from '../../core/crypto/keys.js';

const ALGORITHM = 'aes-256-gcm';

export interface EncryptedKeyMaterial {
  encryptedPrivateKey: string;
  iv: string;
  authTag: string;
  algorithm: string;
}

export interface IKeyCustody {
  /** Generates a fresh Ed25519 keypair and encrypts the private key at rest. */
  generateAndEncrypt(): { publicKey: string; encrypted: EncryptedKeyMaterial };
  /** Decrypts and signs in one call — the plaintext private key never leaves this module. */
  sign(data: string, encrypted: EncryptedKeyMaterial): string;
  /**
   * Decrypts, hands the plaintext private key hex to `use` for the duration
   * of that one call, and returns its result — for callers that need more
   * than a raw `sign()` (e.g. VPBuilder.sign(), which needs the key plus a
   * verificationMethodId to construct a whole signed VP). The plaintext key
   * only ever exists inside `use`'s stack frame; the caller never holds it.
   */
  signWith<T>(encrypted: EncryptedKeyMaterial, use: (privateKeyHex: string) => T | Promise<T>): Promise<T>;
}

/**
 * AES-256-GCM implementation backed by a single 32-byte master key.
 * `masterKeyHex` must be 64 hex chars (32 bytes) — see config's
 * `HOSTED_KEY_ENCRYPTION_KEY`.
 */
export class AesGcmKeyCustody implements IKeyCustody {
  private readonly masterKey: Buffer;

  constructor(masterKeyHex: string) {
    if (!/^[0-9a-fA-F]{64}$/.test(masterKeyHex)) {
      throw new Error('AesGcmKeyCustody: master key must be 64 hex chars (32 bytes)');
    }
    this.masterKey = Buffer.from(masterKeyHex, 'hex');
  }

  generateAndEncrypt(): { publicKey: string; encrypted: EncryptedKeyMaterial } {
    const keyPair: KeyPair = generateKeyPair();
    const encrypted = this.encrypt(keyPair.privateKey);
    return { publicKey: keyPair.publicKey, encrypted };
  }

  sign(data: string, encrypted: EncryptedKeyMaterial): string {
    const privateKeyHex = this.decrypt(encrypted);
    return signData(data, privateKeyHex);
  }

  async signWith<T>(
    encrypted: EncryptedKeyMaterial,
    use: (privateKeyHex: string) => T | Promise<T>,
  ): Promise<T> {
    return use(this.decrypt(encrypted));
  }

  private encrypt(plaintextHex: string): EncryptedKeyMaterial {
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.masterKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintextHex, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      encryptedPrivateKey: ciphertext.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      algorithm: ALGORITHM,
    };
  }

  private decrypt(encrypted: EncryptedKeyMaterial): string {
    const decipher = createDecipheriv(ALGORITHM, this.masterKey, Buffer.from(encrypted.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(encrypted.encryptedPrivateKey, 'hex')),
      decipher.final(),
    ]);
    return plaintext.toString('utf8');
  }
}
