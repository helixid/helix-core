// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { describe, expect, it } from 'vitest';
import { verifySignature } from '../../../src/core/crypto/keys.js';
import { AesGcmKeyCustody } from '../../../src/services/key-custody/key-custody.js';

const MASTER_KEY = 'ab'.repeat(32);

describe('AesGcmKeyCustody', () => {
  it('refuses a master key that is not 32 bytes of hex', () => {
    for (const bad of ['', 'ab'.repeat(31), 'zz'.repeat(32), 'ab'.repeat(33)]) {
      expect(() => new AesGcmKeyCustody(bad)).toThrow('master key must be 64 hex chars');
    }
  });

  it('signs with the held key: the signature verifies under the public key it generated', () => {
    const custody = new AesGcmKeyCustody(MASTER_KEY);
    const { publicKey, encrypted } = custody.generateAndEncrypt();
    const signature = custody.sign('payload', encrypted);
    expect(verifySignature(Buffer.from('payload', 'utf8'), signature, publicKey)).toBe(true);
    expect(verifySignature(Buffer.from('other', 'utf8'), signature, publicKey)).toBe(false);
  });

  it('hands the key only to signWith callbacks, and the ciphertext never holds it in the clear', async () => {
    const custody = new AesGcmKeyCustody(MASTER_KEY);
    const { encrypted } = custody.generateAndEncrypt();
    const privateKeyHex = await custody.signWith(encrypted, (key) => key);
    expect(privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(encrypted)).not.toContain(privateKeyHex);
  });

  it('cannot decrypt under another master key', () => {
    const { encrypted } = new AesGcmKeyCustody(MASTER_KEY).generateAndEncrypt();
    expect(() => new AesGcmKeyCustody('cd'.repeat(32)).sign('payload', encrypted)).toThrow();
  });
});
