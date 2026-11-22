// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it } from 'vitest';
import {
  AuditEvidenceError,
  EvidenceEncryptor,
  MemoryEvidenceStore,
  assertEvidenceMatchesRef,
  digestBytes,
  evidenceAad,
} from '../../../../src/core/audit/index.js';
import { fixture } from './fixture.js';

const { evidence } = fixture;
const encryptor = () => new EvidenceEncryptor({ key: evidence.key_hex, keyId: evidence.key_id });
const aad = () => evidenceAad(evidence.tenant, evidence.purpose);
const object = () => ({ ref: evidence.ref, ciphertext: new Uint8Array(Buffer.from(evidence.ciphertext_b64url, 'base64url')) });

describe('EvidenceEncryptor', () => {
  it('decrypts the fixture object only with the right AAD', () => {
    expect(Buffer.from(aad()).toString('utf8')).toBe(evidence.aad_utf8);
    expect(Buffer.from(encryptor().decrypt(object(), aad())).toString('utf8')).toBe(evidence.plaintext_utf8);
    expect(() => encryptor().decrypt(object(), evidenceAad(evidence.tenant, evidence.wrong_purpose))).toThrow(AuditEvidenceError);
    expect(() => encryptor().decrypt(object(), evidenceAad(evidence.wrong_tenant, evidence.purpose))).toThrow(/authenticated data/);
    expect(() => encryptor().decrypt(object(), new Uint8Array())).toThrow(/authenticated data/);
    const otherKey = new EvidenceEncryptor({ key: 'f'.repeat(64), keyId: evidence.key_id });
    expect(() => otherKey.decrypt(object(), aad())).toThrow(/AEAD/);
    const otherKeyId = new EvidenceEncryptor({ key: evidence.key_hex, keyId: 'other' });
    expect(() => otherKeyId.decrypt(object(), aad())).toThrow(/another suite or key/);
  });

  it('refuses bytes that do not match the reference', () => {
    const tampered = object();
    tampered.ciphertext[0] = tampered.ciphertext[0]! ^ 1;
    expect(() => encryptor().decrypt(tampered, aad())).toThrow(/does not match its reference/);
    const short = { ref: { ...evidence.ref, size: '3', ciphertextDigest: digestBytes(new Uint8Array([1, 2, 3])) }, ciphertext: new Uint8Array([1, 2, 3]) };
    expect(() => encryptor().decrypt(short, aad())).toThrow(/shorter than its authentication tag/);
    const wrongSize = { ...object(), ref: { ...evidence.ref, size: '1' } };
    expect(() => encryptor().decrypt(wrongSize, aad())).toThrow(/does not match its reference/);
    const wrongCommitment = { ...object(), ref: { ...evidence.ref, plaintextCommitment: `sha256:${'0'.repeat(64)}` as const } };
    expect(() => encryptor().decrypt(wrongCommitment, aad())).toThrow(/commitment/);
  });

  it('encrypts with a fresh nonce and object id, binding the AAD', () => {
    const enc = encryptor();
    const a = enc.encrypt({ plaintext: 'hello', mediaType: 'text/plain', aad: aad() });
    const b = enc.encrypt({ plaintext: Buffer.from('hello'), mediaType: 'text/plain', aad: aad(), commitPlaintext: true });
    expect(a.ref.objectId).not.toBe(b.ref.objectId);
    expect(a.ref.encryption.nonce).not.toBe(b.ref.encryption.nonce);
    expect(a.ref.plaintextCommitment).toBeUndefined();
    expect(b.ref.plaintextCommitment).toBe(digestBytes(Buffer.from('hello')));
    expect(a.ref.size).toBe(String(5 + 16));
    expect(a.ref.encryption).toMatchObject({ suite: 'A256GCM', keyId: evidence.key_id, aadDigest: digestBytes(aad()) });
    expect(Object.isFrozen(a.ref)).toBe(true);
    expect(Buffer.from(enc.decrypt(b, aad())).toString()).toBe('hello');
    expect(() => enc.encrypt({ plaintext: 'x', mediaType: 'text/plain', aad: new Uint8Array() })).toThrow(/authenticated data/);
  });

  it('refuses a bad key or key id', () => {
    expect(() => new EvidenceEncryptor({ key: 'abc', keyId: 'k' })).toThrow(TypeError);
    expect(() => new EvidenceEncryptor({ key: new Uint8Array(16), keyId: 'k' })).toThrow(TypeError);
    expect(() => new EvidenceEncryptor({ key: new Uint8Array(32), keyId: '' })).toThrow(TypeError);
    expect(new EvidenceEncryptor({ key: new Uint8Array(32), keyId: 'k' }).keyId).toBe('k');
  });

  it('has a 400 HelixError code', () => {
    const error = new AuditEvidenceError('x', { a: 1 });
    expect(error.code).toBe('AUDIT_EVIDENCE_INVALID');
    expect(error.httpStatus).toBe(400);
    expect(error.details).toEqual({ a: 1 });
  });
});

describe('MemoryEvidenceStore', () => {
  it('stores once, returns copies, and refuses an id collision', async () => {
    const store = new MemoryEvidenceStore();
    expect(await store.get(evidence.ref.objectId)).toBeNull();
    expect(await store.putIfAbsent(object())).toEqual(evidence.ref);
    expect(await store.putIfAbsent(object())).toEqual(evidence.ref);
    const got = (await store.get(evidence.ref.objectId))!;
    got.ciphertext[0] = got.ciphertext[0]! ^ 1;
    expect((await store.get(evidence.ref.objectId))!.ciphertext).toEqual(object().ciphertext);
    const other = encryptor().encrypt({ plaintext: 'other', mediaType: 'text/plain', aad: aad() });
    await expect(store.putIfAbsent({ ...other, ref: { ...other.ref, objectId: evidence.ref.objectId } })).rejects.toThrow(/collision/);
    await expect(store.putIfAbsent({ ...object(), ciphertext: new Uint8Array([1]) })).rejects.toThrow(/digest or size/);
    expect(() => assertEvidenceMatchesRef({ ...object(), ref: { ...evidence.ref, size: '2' } })).toThrow(AuditEvidenceError);
  });
});
