// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { createHash, createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalize } from '../../../../src/core/crypto/jcs.js';
import {
  AUDIT_DIGEST_DOMAINS,
  auditDigest,
  auditEventDigest,
  digestBytes,
  digestText,
  jsonDigest,
  keyedCommitmentValue,
  wtf8Bytes,
} from '../../../../src/core/audit/index.js';
import { fixture } from './fixture.js';

describe('domain-separated digests', () => {
  it('is sha256 over domain, NUL and the canonical JSON', () => {
    const value = { b: 1, a: 'x' };
    const expected = createHash('sha256').update(Buffer.concat([Buffer.from('d.v1\0'), Buffer.from(canonicalize(value))])).digest('hex');
    expect(auditDigest('d.v1', value)).toBe(`sha256:${expected}`);
  });

  it('refuses an empty domain or one with NUL', () => {
    expect(() => auditDigest('', {})).toThrow(TypeError);
    expect(() => auditDigest('a\0b', {})).toThrow(TypeError);
  });

  it('digests every fixture event to its recorded digest', () => {
    for (const sample of fixture.events) {
      expect(canonicalize(sample.event)).toBe(sample.canonical);
      expect(auditEventDigest(sample.event)).toBe(sample.digest);
      expect(auditDigest(AUDIT_DIGEST_DOMAINS.event, sample.event)).toBe(sample.digest);
    }
  });

  it('writes WTF-8 for a lone surrogate and UTF-8 otherwise', () => {
    expect(Buffer.from(wtf8Bytes('aé€\u{1f600}'))).toEqual(Buffer.from('aé€\u{1f600}', 'utf8'));
    expect(Buffer.from(wtf8Bytes('\ud800')).toString('hex')).toBe('eda080');
    expect(Buffer.from(wtf8Bytes('\udfff')).toString('hex')).toBe('edbfbf');
    expect(Buffer.from(wtf8Bytes('x\ud83d')).toString('hex')).toBe('78eda0bd');
    expect(digestText('abc')).toBe(digestBytes(Buffer.from('abc')));
    expect(digestText('\ud800')).toBe(digestBytes(Buffer.from('eda080', 'hex')));
  });

  it('jsonDigest hashes the JSON wire form, dropping undefined members', () => {
    expect(jsonDigest({ id: 'did:x', service: undefined })).toBe(`sha256:${createHash('sha256').update('{"id":"did:x"}').digest('hex')}`);
    expect(jsonDigest({ n: Number.POSITIVE_INFINITY })).toBe(`sha256:${createHash('sha256').update('{"n":null}').digest('hex')}`);
    expect(() => jsonDigest({ s: '\ud800' })).toThrow();
  });

  it('keyed commitment is HMAC-SHA256 over the canonical value', () => {
    const key = Buffer.from('k'.repeat(32));
    const expected = createHmac('sha256', key).update(canonicalize({ email: 'a@b.c' })).digest('hex');
    expect(keyedCommitmentValue(key, { email: 'a@b.c' })).toBe(`sha256:${expected}`);
    expect(keyedCommitmentValue(key, { email: 'a@b.c' })).not.toBe(keyedCommitmentValue(Buffer.from('j'.repeat(32)), { email: 'a@b.c' }));
  });
});
