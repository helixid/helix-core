// Copyright 2026 DgVerse LLP
import { describe, expect, it } from 'vitest';
import { base58btcDecode, base58btcEncode } from '../../../src/core/crypto/vp.js';

describe('base58btc', () => {
  it('preserves leading zero bytes as leading "1" characters', () => {
    const bytes = new Uint8Array([0, 0, 1, 2, 3]);
    const encoded = base58btcEncode(bytes);
    expect(encoded.startsWith('11')).toBe(true);
    expect(Array.from(base58btcDecode(encoded))).toEqual([0, 0, 1, 2, 3]);
  });
});
