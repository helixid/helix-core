// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  MAX_CHAIN_DIGESTS,
  UNKNOWN_DELEGATION_REF,
  UNSEEN_CODE_POINT_RANGES,
  credentialDigest,
  credentialShownId,
  credentialSignedForm,
  delegationChainDigest,
  delegationChainDigests,
  delegationRef,
  delegationReference,
  digestText,
  hasUnprintableCharacter,
  jsonTextNestingDepth,
  readSignatureBase64,
  sanitizeReference,
  valueNestingDepth,
} from '../../../../src/core/audit/index.js';
import { FIXTURES_DIR, fixture } from './fixture.js';

const C4_ROOT = fixture.delegation_chain.credentials[0];
const C4_LEAF = fixture.delegation_chain.credentials[1];

describe('sanitizeReference', () => {
  it('matches every fixture case', () => {
    for (const item of fixture.references) {
      expect(sanitizeReference(item.input, item.max_length), JSON.stringify(item.input)).toBe(item.output);
    }
  });

  it('keeps a printable in-bound reference and digests the rest', () => {
    expect(sanitizeReference('ok-1')).toBe('ok-1');
    expect(sanitizeReference('')).toBe(digestText(''));
    expect(sanitizeReference('x'.repeat(257))).toBe(digestText('x'.repeat(257)));
    expect(sanitizeReference('a\u0000b')).toBe(digestText('a\u0000b'));
    expect(sanitizeReference('\udc00')).toBe(digestText('\udc00'));
    expect(sanitizeReference('t\u{e0041}')).toBe(digestText('t\u{e0041}'));
    expect(sanitizeReference('\u{1f600}')).toBe('\u{1f600}');
  });

  it('freezes the unseen code points of the vendored suite', () => {
    const vendored = JSON.parse(readFileSync(`${FIXTURES_DIR}kya-os/conformance/unseen-code-points.json`, 'utf8')) as { ranges: [string, string][] };
    expect(UNSEEN_CODE_POINT_RANGES.map(([a, b]) => [a.toString(16).toUpperCase().padStart(4, '0'), b.toString(16).toUpperCase().padStart(4, '0')])).toEqual(vendored.ranges);
    for (const [first, last] of vendored.ranges) {
      expect(hasUnprintableCharacter(String.fromCodePoint(parseInt(first, 16)))).toBe(true);
      expect(hasUnprintableCharacter(String.fromCodePoint(parseInt(last, 16)))).toBe(true);
    }
    expect(hasUnprintableCharacter('plain ascii')).toBe(false);
    expect(hasUnprintableCharacter('\u{10ffff}')).toBe(false);
    expect(hasUnprintableCharacter('\ud83d')).toBe(true);
  });
});

describe('delegationReference', () => {
  it('follows SPEC section 7.8 step 2', () => {
    expect(delegationReference('urn:uuid:1')).toBe('urn:uuid:1');
    expect(delegationReference('unknown')).toBe(digestText('unknown'));
    expect(delegationReference(`sha256:${'a'.repeat(64)}`)).toBe(digestText(`sha256:${'a'.repeat(64)}`));
    expect(delegationReference(`SHA256:${'a'.repeat(64)}`)).toBe(`SHA256:${'a'.repeat(64)}`);
    expect(delegationReference('')).toBe(digestText(''));
    expect(delegationReference('y'.repeat(257))).toBe(digestText('y'.repeat(257)));
    expect(UNKNOWN_DELEGATION_REF).toBe('unknown');
  });
});

describe('nesting depth', () => {
  it('counts a JSON text before parsing, ignoring brackets inside strings', () => {
    expect(jsonTextNestingDepth('{"a":[1,{"b":"[{]}"}]}')).toBe(3);
    expect(jsonTextNestingDepth('"\\"[\\\\"')).toBe(0);
    expect(jsonTextNestingDepth('['.repeat(70) + ']'.repeat(70))).toBe(65);
    expect(jsonTextNestingDepth('['.repeat(64) + ']'.repeat(64))).toBe(64);
    expect(jsonTextNestingDepth('[[]]', 1)).toBe(2);
    expect(jsonTextNestingDepth('[[],[]]')).toBe(2);
  });

  it('counts a parsed value iteratively', () => {
    expect(valueNestingDepth('x')).toBe(0);
    expect(valueNestingDepth(null)).toBe(0);
    expect(valueNestingDepth({})).toBe(1);
    expect(valueNestingDepth({ a: [{ b: null }] })).toBe(3);
    expect(valueNestingDepth(JSON.parse('['.repeat(70) + ']'.repeat(70)))).toBe(65);
    expect(valueNestingDepth([[[]]], 2)).toBe(3);
  });
});

describe('readSignatureBase64', () => {
  it('reads the JWS segment strictly', () => {
    expect(Buffer.from(readSignatureBase64('c2ln', true)!).toString()).toBe('sig');
    expect(Buffer.from(readSignatureBase64('c2ln bmF0', true)!).toString()).toBe('signat');
    expect(Buffer.from(readSignatureBase64('c2lnbg==', true)!).toString()).toBe('sign');
    expect(readSignatureBase64('c2lnbg=', true)).toBeUndefined();
    expect(readSignatureBase64('c2ln+', true)).toBeUndefined();
    expect(readSignatureBase64('c', true)).toBeUndefined();
    expect(readSignatureBase64('', true)).toBeUndefined();
    expect(readSignatureBase64('c2=ln', true)).toBeUndefined();
    expect(readSignatureBase64('c2ln!', true)).toBeUndefined();
  });

  it('reads a proofValue loosely', () => {
    expect(Buffer.from(readSignatureBase64('c2ln/w', false)!)).toEqual(Buffer.from('c2ln/w', 'base64'));
    expect(Buffer.from(readSignatureBase64('c2ln_w', false)!)).toEqual(Buffer.from('c2ln/w', 'base64'));
    expect(Buffer.from(readSignatureBase64('c2ln+w', false)!)).toEqual(Buffer.from('c2ln-w', 'base64url'));
    expect(Buffer.from(readSignatureBase64('c2lnbg===', false)!).toString()).toBe('sign');
    expect(Buffer.from(readSignatureBase64('c2lnbg', false)!).toString()).toBe('sign');
    expect(readSignatureBase64('c2lnb', false)).toBeUndefined();
    expect(readSignatureBase64('c2ln=bmF0', false)).toBeUndefined();
    expect(readSignatureBase64('c2ln*', false)).toBeUndefined();
  });
});

describe('credential signed form, reference and digest (SPEC 7.8, appendix C.4)', () => {
  it('reproduces appendix C.4', () => {
    expect(credentialDigest(C4_ROOT)).toBe('sha256:6fbe4c0f04413cb40ec3b3069bf7c73dc1b6a681765e95ac451672136328712e');
    expect(credentialDigest(C4_LEAF)).toBe('sha256:d29d65862fce70137390bea2859696c7ad80ce88cede778fea1cab24d513eed1');
    const digests = delegationChainDigests([C4_ROOT, C4_LEAF])!;
    expect(digests).toEqual(fixture.delegation_chain.digests);
    expect(delegationChainDigest(digests)).toBe('sha256:2df99ab7f9b80436dba945e0dfb7a37bd7b35400c82bbc72a5c2744f516eb788');
    expect(fixture.delegation_chain.chain_digest).toBe('sha256:2df99ab7f9b80436dba945e0dfb7a37bd7b35400c82bbc72a5c2744f516eb788');
    expect(credentialSignedForm(C4_LEAF)).toEqual({ jwt: 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319', signature: 'c2lnbmF0dXJlLW9mLWxlYWY' });
  });

  it('matches every fixture delegation case', () => {
    for (const item of fixture.delegation) {
      expect(delegationRef(item.credential) ?? null, item.name).toBe(item.delegation_ref);
      expect(credentialDigest(item.credential) ?? null, item.name).toBe(item.credential_digest);
    }
  });

  it('lists no chain for an empty, overlong or partly unsigned chain', () => {
    expect(delegationChainDigests([])).toBeUndefined();
    expect(delegationChainDigests(new Array<unknown>(MAX_CHAIN_DIGESTS + 1).fill(C4_ROOT))).toBeUndefined();
    expect(delegationChainDigests(new Array<unknown>(MAX_CHAIN_DIGESTS).fill(C4_LEAF))).toHaveLength(256);
    expect(delegationChainDigests([C4_ROOT, { id: 'x' }])).toBeUndefined();
    expect(fixture.delegation_chain.too_long_chain_digests).toBeNull();
    expect(fixture.delegation_chain.unsigned_member_digests).toBeNull();
  });

  it('shows ids by the SPEC order and reads JWT payloads strictly', () => {
    expect(credentialShownId({ id: 'a', credentialSubject: { delegation: { id: 'b' } } })).toBe('a');
    expect(credentialShownId({ id: '', credentialSubject: { delegation: { id: 'b' } } })).toBe('b');
    expect(credentialShownId({ credentialSubject: { delegation: 'x' } })).toBeUndefined();
    expect(credentialShownId({ credentialSubject: 'x' })).toBeUndefined();
    expect(credentialShownId(null)).toBeUndefined();
    expect(credentialShownId('a.b')).toBeUndefined();
    expect(credentialShownId('a..c')).toBeUndefined();
    expect(credentialShownId('a.b+c.d')).toBeUndefined();
    const jwt = (payload: unknown) => `h.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.s`;
    expect(credentialShownId(jwt({ vc: 'x' }))).toBeUndefined();
    expect(credentialShownId(jwt({ vc: {}, jti: 'j' }))).toBe('j');
    expect(credentialShownId(jwt({ vc: { credentialSubject: { delegation: { id: 'd' } } } }))).toBe('d');
    expect(credentialShownId(jwt({ vc: { id: 5 } }))).toBeUndefined();
    expect(delegationRef(jwt({ vc: { id: 'unknown' } }))).toBe(digestText('unknown'));
    expect(delegationRef({})).toBeUndefined();
  });

  it('has no signed form for a malformed JWS or credential object', () => {
    expect(credentialSignedForm('h.p')).toBeUndefined();
    expect(credentialSignedForm('.p.s')).toBeUndefined();
    expect(credentialSignedForm('h+.p.s')).toBeUndefined();
    expect(credentialSignedForm('h.p.')).toBeUndefined();
    expect(credentialSignedForm('h.p.c')).toBeUndefined();
    expect(credentialSignedForm(42)).toBeUndefined();
    expect(credentialSignedForm([C4_ROOT])).toBeUndefined();
    expect(credentialSignedForm({ ...(C4_ROOT as object), proof: 'x' })).toBeUndefined();
    expect(credentialSignedForm({ ...(C4_ROOT as object), proof: { proofValue: 5 } })).toBeUndefined();
    expect(credentialSignedForm({ ...(C4_ROOT as object), proof: { proofValue: '====' } })).toBeUndefined();
    expect(credentialDigest({ ...(C4_ROOT as object), note: '\ud800' })).toBeUndefined();
  });
});
