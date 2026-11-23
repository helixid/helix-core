// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: DbKeyStore wraps Helix-held keys with AES-256-GCM and never hands private material out.
import * as ed25519 from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import {
  KeyStoreKeyNotFoundError,
  KeyStoreKeyShreddedError,
  KeyStoreSigner,
  KeyStoreUnavailableError,
  base64UrlDecodeStrict,
  publicKeyJwkBytes,
  signJws,
  verifyJws,
} from '../../../../src/core/index.js';
import { InMemoryWrappedKeyStorageDriver } from '../../../../src/repositories/drivers/custody.drivers.js';
import { DB_KEY_STORE_ALGORITHM, DbKeyStore, resolveKeyEncryptionKey } from '../../../../src/services/custody/db-key-store.js';

const KEK = '11'.repeat(32);
const DID = 'did:web:helix.example:acme:bot';
const KID = `${DID}#key-1`;

/** A random source that records every seed it hands out, so a test can look for it in what the store returns or keeps. */
function recordingRandom(): { random: (size: number) => Uint8Array; seeds: Uint8Array[] } {
  const seeds: Uint8Array[] = [];
  let counter = 1;
  return {
    seeds,
    random: (size: number) => {
      const bytes = new Uint8Array(size).map((_, index) => (counter * 31 + index * 7) % 256);
      counter += 1;
      if (size === 32) seeds.push(new Uint8Array(bytes));
      return bytes;
    },
  };
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

describe('DbKeyStore', () => {
  it('generates a key, returns only its public JWK, and signs with it', async () => {
    const table = new InMemoryWrappedKeyStorageDriver();
    const store = new DbKeyStore({ table, keyEncryptionKey: KEK });
    const jwk = await store.generate({ did: DID, kid: KID, subjectType: 'agent' });
    expect(Object.keys(jwk).sort()).toEqual(['crv', 'kty', 'x']);
    const message = new TextEncoder().encode('hello');
    const signature = await store.sign({ did: DID, kid: KID }, message);
    expect(signature).toHaveLength(64);
    expect(await ed25519.verifyAsync(signature, message, publicKeyJwkBytes(jwk))).toBe(true);
    expect(await store.publicJwk({ did: DID, kid: KID })).toEqual(jwk);
    expect(await store.publicJwk({ did: DID, kid: `${DID}#key-9` })).toBeNull();
    const [info] = await store.list(DID);
    expect(info).toMatchObject({ did: DID, kid: KID, subjectType: 'agent', publicKeyJwk: jwk, shreddedAt: null });
    expect(Object.keys(info!).sort()).toEqual(['createdAt', 'did', 'kid', 'publicKeyJwk', 'shreddedAt', 'subjectType']);
  });

  it('never exposes the private bytes: not in any return value, not in the stored row, not in the store itself', async () => {
    const table = new InMemoryWrappedKeyStorageDriver();
    const { random, seeds } = recordingRandom();
    const store = new DbKeyStore({ table, keyEncryptionKey: KEK, randomBytes: random });
    const jwk = await store.generate({ did: DID, kid: KID, subjectType: 'service' });
    const seed = seeds[0]!;
    const forms = [hex(seed), Buffer.from(seed).toString('base64url'), Buffer.from(seed).toString('base64')];
    const seen = JSON.stringify({
      jwk,
      list: await store.list(DID),
      publicJwk: await store.publicJwk({ did: DID, kid: KID }),
      rows: table.dump(),
      store,
      signature: hex(await store.sign({ did: DID, kid: KID }, new Uint8Array([1]))),
    });
    for (const form of forms) expect(seen).not.toContain(form);
    expect(Object.keys(store)).toEqual([]);
    // The recorded copy is a real, non-zero seed, so the absence checks above mean something.
    expect(seed).not.toEqual(new Uint8Array(32));
    const [row] = table.dump();
    expect(row).toMatchObject({ algorithm: DB_KEY_STORE_ALGORITHM, kekId: 'kek-1', subjectType: 'service' });
    expect(base64UrlDecodeStrict(row!.nonce)).toHaveLength(12);
    expect(base64UrlDecodeStrict(row!.ciphertext)).toHaveLength(48);
  });

  it('binds each wrapped key to its row: copied under another DID it does not unwrap', async () => {
    const table = new InMemoryWrappedKeyStorageDriver();
    const store = new DbKeyStore({ table, keyEncryptionKey: KEK });
    await store.generate({ did: DID, kid: KID, subjectType: 'agent' });
    const [row] = table.dump();
    const other = 'did:web:helix.example:acme:other';
    await table.insert({ ...row!, did: other, kid: `${other}#key-1` });
    await expect(store.sign({ did: other, kid: `${other}#key-1` }, new Uint8Array([1]))).rejects.toThrow(/does not unwrap/);
  });

  it('refuses a key wrapped under another KEK, a malformed row and a wrong algorithm', async () => {
    const table = new InMemoryWrappedKeyStorageDriver();
    await new DbKeyStore({ table, keyEncryptionKey: KEK }).generate({ did: DID, kid: KID, subjectType: 'agent' });
    const otherKek = new DbKeyStore({ table, keyEncryptionKey: '22'.repeat(32) });
    await expect(otherKek.sign({ did: DID, kid: KID }, new Uint8Array([1]))).rejects.toThrow(KeyStoreUnavailableError);
    const otherId = new DbKeyStore({ table, keyEncryptionKey: KEK, keyEncryptionKeyId: 'kek-2' });
    await expect(otherId.sign({ did: DID, kid: KID }, new Uint8Array([1]))).rejects.toThrow(/not this store's key-encryption key/);
    const [row] = table.dump();
    await table.insert({ ...row!, kid: `${DID}#key-2`, nonce: 'AA' });
    const store = new DbKeyStore({ table, keyEncryptionKey: KEK });
    await expect(store.sign({ did: DID, kid: `${DID}#key-2` }, new Uint8Array([1]))).rejects.toThrow(/well-formed/);
    await table.insert({ ...row!, kid: `${DID}#key-3`, algorithm: 'A128GCM' });
    await expect(store.sign({ did: DID, kid: `${DID}#key-3` }, new Uint8Array([1]))).rejects.toThrow(/A128GCM/);
  });

  it('shreds: the private half is gone, signing refuses, the public half stays', async () => {
    const table = new InMemoryWrappedKeyStorageDriver();
    const store = new DbKeyStore({ table, keyEncryptionKey: KEK, clock: () => new Date('2026-11-21T00:00:00Z') });
    const jwk = await store.generate({ did: DID, kid: KID, subjectType: 'agent' });
    expect(await store.shred({ did: DID, kid: KID })).toBe(true);
    expect(await store.shred({ did: DID, kid: KID })).toBe(false);
    const [row] = table.dump();
    expect(row).toMatchObject({ ciphertext: '', nonce: '', shreddedAt: new Date('2026-11-21T00:00:00Z') });
    await expect(store.sign({ did: DID, kid: KID }, new Uint8Array([1]))).rejects.toThrow(KeyStoreKeyShreddedError);
    expect(await store.publicJwk({ did: DID, kid: KID })).toEqual(jwk);
    await expect(store.sign({ did: DID, kid: `${DID}#nope` }, new Uint8Array([1]))).rejects.toThrow(KeyStoreKeyNotFoundError);
  });

  it('validates its inputs and its configuration', async () => {
    const table = new InMemoryWrappedKeyStorageDriver();
    expect(() => new DbKeyStore({ table, keyEncryptionKey: 'short' })).toThrow(KeyStoreUnavailableError);
    const store = new DbKeyStore({ table, keyEncryptionKey: KEK });
    await expect(store.generate({ did: 'web', kid: 'x', subjectType: 'agent' })).rejects.toThrow(/did must be a DID/);
    await expect(store.generate({ did: DID, kid: 'did:web:other#key-1', subjectType: 'agent' })).rejects.toThrow(/kid must be/);
    await expect(store.generate({ did: DID, kid: `${DID}#`, subjectType: 'agent' })).rejects.toThrow(/kid must be/);
    await expect(store.sign({ did: DID, kid: KID }, 'text' as never)).rejects.toThrow(/bytes/);
    const bad = new DbKeyStore({ table, keyEncryptionKey: KEK, randomBytes: () => new Uint8Array(3) });
    await expect(bad.generate({ did: DID, kid: KID, subjectType: 'agent' })).rejects.toThrow(/32 bytes/);
  });

  it('is a Signer backend: a JWS made through KeyStoreSigner verifies against the public JWK', async () => {
    const store = new DbKeyStore({ table: new InMemoryWrappedKeyStorageDriver(), keyEncryptionKey: KEK });
    const jwk = await store.generate({ did: DID, kid: KID, subjectType: 'owner' });
    const jws = await signJws({ sub: DID }, new KeyStoreSigner(store, DID, KID));
    expect(verifyJws(jws, jwk, { expectedKid: KID }).payload).toEqual({ sub: DID });
  });
});

describe('resolveKeyEncryptionKey', () => {
  it('prefers HELIX_KEY_STORE_KEK, then HOSTED_KEY_ENCRYPTION_KEY, then an ephemeral key outside production', () => {
    expect(resolveKeyEncryptionKey({ HELIX_KEY_STORE_KEK: KEK, HELIX_KEY_STORE_KEK_ID: 'kek-7', HOSTED_KEY_ENCRYPTION_KEY: '22'.repeat(32) })).toEqual({
      keyEncryptionKey: KEK,
      keyEncryptionKeyId: 'kek-7',
      ephemeral: false,
    });
    expect(resolveKeyEncryptionKey({ HOSTED_KEY_ENCRYPTION_KEY: '22'.repeat(32) })).toEqual({ keyEncryptionKey: '22'.repeat(32), keyEncryptionKeyId: 'kek-1', ephemeral: false });
    expect(resolveKeyEncryptionKey({ NODE_ENV: 'development' }, () => 'ab'.repeat(32))).toEqual({ keyEncryptionKey: 'ab'.repeat(32), keyEncryptionKeyId: 'ephemeral', ephemeral: true });
    expect(resolveKeyEncryptionKey({}).keyEncryptionKey).toMatch(/^[0-9a-f]{64}$/);
    expect(() => resolveKeyEncryptionKey({ NODE_ENV: 'production' })).toThrow(/required in production/);
  });
});
