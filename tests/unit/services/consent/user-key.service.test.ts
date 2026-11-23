// Copyright 2026 DgVerse LLP
// KYA-OS story L3-H point 8: the user key lifecycle. One key per (service, user) per consent cycle, kept
// while any consent may still renew or any hop it signed is alive, then crypto-shredded: the private half is
// destroyed; the DID string, the hops, the consent record and the audit history stay.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ErrorCode, KeyStoreSigner, verifyDelegationHop, type KeyStore } from '../../../../src/core/index.js';
import { ConsentRepository } from '../../../../src/repositories/consent.repository.js';
import { ORPHAN_USER_KEY_MS, UserKeyService, isShreddedKeyError, serviceUserRefOf } from '../../../../src/services/consent/user-key.service.js';
import { SERVICE, consentWorld } from './harness.js';

afterEach(() => {
  vi.useRealTimers();
});

describe('UserKeyService', () => {
  it('needs a KeyStore that can generate a did:key', () => {
    const keyStore = { generate: vi.fn(), sign: vi.fn(), publicJwk: vi.fn(), shred: vi.fn(), list: vi.fn() } as unknown as KeyStore;
    expect(() => new UserKeyService({ repo: new ConsentRepository(), keyStore })).toThrow(/generateDidKey/);
  });

  it('names a service user by a digest of (service DID, user id), never the id', () => {
    const ref = serviceUserRefOf(SERVICE.did, 'alice@example.com');
    expect(ref).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(ref).not.toBe(serviceUserRefOf('did:web:other.example', 'alice@example.com'));
    expect(ref).not.toContain('alice');
  });

  it('keeps the private half in the KeyStore as subjectType consent; the row holds public facts only', async () => {
    const world = consentWorld();
    const key = await world.userKeys.keyFor(SERVICE.did, 'ref-1');
    expect(key.did).toMatch(/^did:key:z6Mk/);
    expect(key.kid).toBe(`${key.did}#${key.did.slice('did:key:'.length)}`);
    expect(await world.userKeys.keyFor(SERVICE.did, 'ref-1')).toEqual(key);
    const [stored] = await world.keyTable.list(key.did);
    expect(stored).toMatchObject({ subjectType: 'consent', kid: key.kid, shreddedAt: null });
    expect(JSON.stringify(await world.repo.findUserKey(key.did))).not.toMatch(/ciphertext|nonce|"d"/);
    expect(world.userKeys.signerOf(key)).toBeInstanceOf(KeyStoreSigner);
  });

  it('signs the user list only for a live user did:key it generated', async () => {
    const world = consentWorld();
    const key = await world.userKeys.keyFor(SERVICE.did, 'ref-1');
    expect((await world.userKeys.statusListSignerFor(key.did))?.did).toBe(key.did);
    expect(await world.userKeys.statusListSignerFor(SERVICE.did)).toBeUndefined();
    expect(await world.userKeys.statusListSignerFor('did:key:z6MkunknownXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')).toBeUndefined();
    await world.repo.markUserKeyShredded(key.did, new Date());
    expect(await world.userKeys.statusListSignerFor(key.did)).toBeUndefined();
  });
});

describe('shredExpiredUserKeys (crypto-shredding)', () => {
  it('keeps the key while the window is open, shreds it once the window ended and the last hop expired', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo({ hopLifetimeSeconds: 60, grant: world.grant({ windowSeconds: 120 }) });
    const did = approved.hop.issuer;
    world.advance(61); // the hop expired, but the window still allows a renewal
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([]);
    world.advance(30);
    const renewed = await world.consent.renewHop(await world.renewalJws({ consentId: approved.consentId }), 'r');
    world.advance(30); // the window ended (121 s); the renewed hop lives until 120 s... already past it
    expect(Date.parse(renewed.hop.validUntil)).toBeLessThanOrEqual(world.now());
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([did]);
    // Gone: the private half; kept: the DID string, the hops, the consent record, the audit history.
    const [wrapped] = await world.keyTable.list(did);
    expect(wrapped).toMatchObject({ ciphertext: '', nonce: '' });
    expect(wrapped!.shreddedAt).not.toBeNull();
    const signer = world.userKeys.signerOf((await world.repo.findUserKey(did))!);
    await expect(signer.sign(new Uint8Array([1]))).rejects.toMatchObject({ code: ErrorCode.KEY_STORE_KEY_SHREDDED });
    expect((await world.repo.findUserKey(did))!.shreddedAt).not.toBeNull();
    expect((await world.repo.findConsent(approved.consentId))!.userDid).toBe(did);
    expect(await world.vcRepo.findByVcId(approved.hop.id)).not.toBeNull();
    expect(await verifyDelegationHop(approved.hop, world.resolve)).toMatchObject({ ok: true });
    const shredEvent = world.audit.ofType('configuration.changed').find((event) => event.action.name === 'user_key_shredded');
    expect(shredEvent?.resource).toEqual({ kind: 'public_did', did });
    // Nothing left to shred; the next consent gets a new key (a new cycle).
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([]);
    const next = await world.consentTo();
    expect(next.approved.hop.issuer).not.toBe(did);
  });

  it('after a withdrawal keeps the key until every revoked hop has expired, so its list stays signed', async () => {
    const world = consentWorld();
    const { approved } = await world.consentTo({ hopLifetimeSeconds: 300 });
    await world.consent.withdrawConsent(await world.withdrawalJws({ consentId: approved.consentId }), 'r');
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([]);
    expect(await world.bitOf(approved.hop)).toEqual({ issuer: approved.hop.issuer, bit: true });
    world.advance(301);
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([approved.hop.issuer]);
  });

  it('keeps a key while any consent of the cycle is open', async () => {
    const world = consentWorld();
    const short = await world.consentTo({ hopLifetimeSeconds: 10, grant: world.grant({ windowSeconds: 20 }) });
    await world.consentTo({ hopLifetimeSeconds: 10, grant: world.grant({ scopes: ['orders:write'], windowSeconds: 3600 }) });
    world.advance(30);
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([]);
    world.advance(3600);
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([short.approved.hop.issuer]);
  });

  it('shreds a key that never signed after an hour, and tolerates a key already marked', async () => {
    const world = consentWorld();
    const orphan = await world.userKeys.keyFor(SERVICE.did, 'ref-orphan');
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([]);
    world.advance(ORPHAN_USER_KEY_MS / 1000 + 1);
    const mark = world.repo.markUserKeyShredded.bind(world.repo);
    world.repo.markUserKeyShredded = async () => false; // another instance marked it first
    expect(await world.userKeys.shredExpiredUserKeys()).toEqual([]);
    world.repo.markUserKeyShredded = mark;
    expect((await world.keyTable.list(orphan.did))[0]!.ciphertext).toBe('');
  });

  it('runs as a job until stopped, and reports a failing run', async () => {
    vi.useFakeTimers();
    const world = consentWorld();
    const shred = vi.spyOn(world.userKeys, 'shredExpiredUserKeys').mockRejectedValueOnce(new Error('db down')).mockResolvedValue([]);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    world.userKeys.startShredding(1000);
    world.userKeys.startShredding(1000);
    await vi.advanceTimersByTimeAsync(2500);
    expect(shred).toHaveBeenCalledTimes(2);
    expect(error).toHaveBeenCalledWith('USER_KEY_SHRED_FAILED', 'db down');
    world.userKeys.stopShredding();
    world.userKeys.stopShredding();
    await vi.advanceTimersByTimeAsync(5000);
    expect(shred).toHaveBeenCalledTimes(2);
    error.mockRestore();
  });

  it('reports an audit failure without breaking the job', async () => {
    const world = consentWorld();
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    vi.spyOn(world.audit, 'record').mockImplementation(() => {
      throw new Error('sink down');
    });
    await world.userKeys.keyFor(SERVICE.did, 'ref-a');
    vi.spyOn(world.audit, 'record').mockRejectedValue(new Error('sink down later'));
    await world.userKeys.keyFor(SERVICE.did, 'ref-b');
    await Promise.resolve();
    expect(error).toHaveBeenCalledWith('AUDIT_RECORD_FAILED', 'sink down');
    error.mockRestore();
    const silent = new UserKeyService({ repo: world.repo, keyStore: world.keyStore });
    expect((await silent.keyFor(SERVICE.did, 'ref-c')).did).toMatch(/^did:key:/);
  });

  it('tells a shredded-key refusal from any other error', async () => {
    const world = consentWorld();
    const key = await world.userKeys.keyFor(SERVICE.did, 'ref-1');
    await world.keyStore.shred({ did: key.did, kid: key.kid });
    const caught = await world.userKeys.signerOf(key).sign(new Uint8Array([1])).catch((error: unknown) => error);
    expect(isShreddedKeyError(caught)).toBe(true);
    expect(isShreddedKeyError(new Error('x'))).toBe(false);
  });
});
