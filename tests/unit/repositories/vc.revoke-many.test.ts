// Copyright 2026 DgVerse LLP
// KYA-OS story L3-C: revoking a cascade at once (every bit set on its list, every record marked, one transaction),
// on the in-memory driver, a real SqliteStore and the Prisma driver (its transaction and row lock).
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_STATUS_LIST_ID,
  bareEncodedList,
  buildStatusListCredential,
  createStatusList,
  getBit,
  issuerOfStatusListId,
  multibaseEncodedList,
  statusListIdFor,
  unsignedStatusListCredential,
  EnvSigner,
  derivePublicKey,
  publicKeyToMultibase,
  verifyDataIntegrity,
} from '../../../src/core/index.js';
import { SqliteStore } from '../../../src/storage/sqlite.js';
import { VcRepository } from '../../../src/repositories/vc.repository.js';
import { PrismaVcStorageDriver } from '../../../src/repositories/drivers/vc.drivers.js';
import { testDidDocument } from '../../utils/didDocuments.js';

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const record = (vcId: string, index: number) => ({ vcId, subjectDid: 'did:key:z6MkAgent', subjectType: 'agent', statusListIndex: index, expiresAt: null, vcJson: { id: vcId } });

async function exercise(repo: VcRepository): Promise<void> {
  await repo.createStatusList('a', createStatusList(64));
  await repo.createStatusList('b', createStatusList(64));
  for (const [vcId, index] of [['v1', 1], ['v2', 5], ['v3', 2], ['v4', 0]] as const) await repo.createVc(record(vcId, index));
  const revoked = await repo.revokeVcs([
    { vcId: 'v1', listId: 'a', index: 1 },
    { vcId: 'v2', listId: 'a', index: 5 },
    { vcId: 'v3', listId: 'b', index: 2 },
    { vcId: 'v4' },
  ]);
  expect(revoked.map((entry) => entry.vcId)).toEqual(['v1', 'v2', 'v3', 'v4']);
  for (const entry of revoked) expect(entry.revokedAt).toBeInstanceOf(Date);
  const a = (await repo.findStatusListById('a'))!.encodedList;
  const b = (await repo.findStatusListById('b'))!.encodedList;
  expect([getBit(a, 1), getBit(a, 5), getBit(a, 0), getBit(b, 2), getBit(b, 1)]).toEqual([1, 1, 0, 1, 0]);
  await expect(repo.revokeVcs([{ vcId: 'v1', listId: 'missing', index: 0 }])).rejects.toThrow(/Status list not found/);
}

describe('VcRepository.revokeVcs', () => {
  it('in memory', async () => {
    const repo = new VcRepository();
    await exercise(repo);
    await expect(repo.revokeVcs([{ vcId: 'nope' }])).rejects.toThrow(/VC not found/);
  });

  it('on SQLite, in one transaction', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'helix-revoke-'));
    dirs.push(dir);
    const repo = new VcRepository(undefined, new SqliteStore(join(dir, 'helixid.sqlite')));
    await exercise(repo);
    await expect(repo.revokeVcs([{ vcId: 'nope' }])).rejects.toThrow(/VC not found/);
  });

  it('on Prisma: one transaction, each list row locked before it is read', async () => {
    const lists = new Map<string, { listId: string; encodedList: string; nextIndex: number }>([['a', { listId: 'a', encodedList: createStatusList(64), nextIndex: 0 }]]);
    const order: string[] = [];
    const tx = {
      $queryRawUnsafe: vi.fn(async (sql: string, listId: string) => {
        order.push(`lock ${listId}`);
        expect(sql).toMatch(/FOR UPDATE/);
        return [];
      }),
      statusListEntry: {
        findUnique: vi.fn(async ({ where }: { where: { listId: string } }) => lists.get(where.listId) ?? null),
        update: vi.fn(async ({ where, data }: { where: { listId: string }; data: { encodedList: string } }) => {
          order.push(`write ${where.listId}`);
          lists.set(where.listId, { ...lists.get(where.listId)!, encodedList: data.encodedList });
        }),
      },
      vc: { update: vi.fn(async ({ where, data }: { where: { vcId: string }; data: { revokedAt: Date } }) => ({ vcId: where.vcId, revokedAt: data.revokedAt })) },
    };
    const prisma = { $transaction: vi.fn(async (work: (client: unknown) => unknown) => work(tx)) };
    const driver = new PrismaVcStorageDriver(prisma as never);
    const revoked = await driver.revokeVcs([{ vcId: 'v1', listId: 'a', index: 3 }, { vcId: 'v2' }]);
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    expect(order).toEqual(['lock a', 'write a']);
    expect(getBit(lists.get('a')!.encodedList, 3)).toBe(1);
    expect(revoked.map((entry) => entry.vcId)).toEqual(['v1', 'v2']);
    await expect(driver.revokeVcs([{ vcId: 'v1', listId: 'missing', index: 0 }])).rejects.toThrow(/Status list not found/);
    // A client without raw queries (a mock) still revokes, without the lock.
    const plain = new PrismaVcStorageDriver({ $transaction: async (work: (client: unknown) => unknown) => work({ ...tx, $queryRawUnsafe: undefined }) } as never);
    expect((await plain.revokeVcs([{ vcId: 'v3', listId: 'a', index: 4 }])).map((entry) => entry.vcId)).toEqual(['v3']);
  });
});

describe('status-list credentials and ids (story L3-C)', () => {
  const KEY = '5'.repeat(64);
  const did = `did:key:${publicKeyToMultibase(derivePublicKey(KEY))}`;
  const signer = new EnvSigner({ did, envVar: 'K', env: { K: KEY } });

  it('builds a signed Bitstring Status List v1.0 with its window; refuses an empty window', async () => {
    const encodedList = createStatusList(16);
    const list = await buildStatusListCredential({ id: 'https://api.example/v1/status-list/x', issuer: did, encodedList, validFrom: '2026-01-01T00:00:00Z', validUntil: '2026-01-01T01:00:00Z' }, signer);
    expect(list.credentialSubject.encodedList).toBe(`u${encodedList}`);
    expect(list.proof).toMatchObject({ cryptosuite: 'eddsa-jcs-2022', created: '2026-01-01T00:00:00Z' });
    const verdict = await verifyDataIntegrity(list as unknown as Record<string, unknown>, (async () => testDidDocument(did, derivePublicKey(KEY))) as never);
    expect(verdict.ok).toBe(true);
    await expect(buildStatusListCredential({ id: 'x', issuer: did, encodedList, validFrom: '2026-01-01T01:00:00Z', validUntil: '2026-01-01T01:00:00Z' }, signer)).rejects.toThrow(/after validFrom/);
    expect(unsignedStatusListCredential({ id: 'x', issuer: did, encodedList: `u${encodedList}`, validFrom: 'a', validUntil: 'b' }).credentialSubject.encodedList).toBe(`u${encodedList}`);
    expect(multibaseEncodedList('uX')).toBe('uX');
    expect(bareEncodedList('uX')).toBe('X');
    expect(bareEncodedList('H4s')).toBe('H4s');
  });

  it('gives each issuer DID one list id that names it, the Helix issuer the platform list', () => {
    const helix = 'did:key:z6MkHelix';
    expect(statusListIdFor(helix, helix)).toBe(DEFAULT_STATUS_LIST_ID);
    const id = statusListIdFor('did:web:owner.example:orgs:acme', helix);
    expect(id).toMatch(/^iss-[A-Za-z0-9_-]+$/);
    expect(issuerOfStatusListId(id, helix)).toBe('did:web:owner.example:orgs:acme');
    expect(issuerOfStatusListId(DEFAULT_STATUS_LIST_ID, helix)).toBe(helix);
    expect(issuerOfStatusListId('other', helix)).toBeUndefined();
    expect(issuerOfStatusListId('iss-!!', helix)).toBeUndefined();
    expect(issuerOfStatusListId(`iss-${Buffer.from('not a did').toString('base64url')}`, helix)).toBeUndefined();
  });
});

describe('publicDidResolver (story L3-C)', () => {
  it('lists a did:key\'s one key under both its W3C method id and Helix\'s key-1; other DIDs as resolved', async () => {
    const { publicDidResolver } = await import('../../../src/services/revocation/public-resolver.js');
    const { resolveDID } = await import('../../../src/core/index.js');
    const did = `did:key:${publicKeyToMultibase(derivePublicKey('7'.repeat(64)))}`;
    const resolve = publicDidResolver(resolveDID);
    const document = (await resolve(did)) as unknown as { verificationMethod: Array<{ id: string; publicKeyMultibase?: string }>; assertionMethod: string[] };
    const standard = `${did}#${did.slice('did:key:'.length)}`;
    expect(document.verificationMethod.map((method) => method.id)).toEqual([`${did}#key-1`, standard]);
    expect(document.verificationMethod[1]!.publicKeyMultibase).toBe(document.verificationMethod[0]!.publicKeyMultibase);
    expect(document.assertionMethod).toContain(standard);
    const web = { id: 'did:web:x.example', verificationMethod: [] } as never;
    expect(await publicDidResolver(async () => web)('did:web:x.example')).toBe(web);
    const bare = { id: did, verificationMethod: [] } as never;
    expect(await publicDidResolver(async () => bare)(did)).toBe(bare);
    // A resolver that only knows Helix's #key-1 (core's resolveDID lists both itself since the F-1 kid fix).
    const helixOnly = (await import('../../../src/core/index.js')).buildDIDDocument(did, derivePublicKey('7'.repeat(64)));
    const widened = (await publicDidResolver(async () => helixOnly)(did)) as unknown as { verificationMethod: Array<{ id: string }>; assertionMethod: string[]; authentication: string[] };
    expect(widened.verificationMethod.map((method) => method.id)).toEqual([`${did}#key-1`, standard]);
    expect(widened.assertionMethod).toContain(standard);
    expect(widened.authentication).toContain(standard);
    const already = { id: did, verificationMethod: [{ id: standard }] } as never;
    expect(await publicDidResolver(async () => already)(did)).toBe(already);
  });

  it('refuses a document older than one it already served (story C-E point 2)', async () => {
    const { publicDidResolver } = await import('../../../src/services/revocation/public-resolver.js');
    const served = [{ id: 'did:web:x.example', rotationSequence: 2 }, { id: 'did:web:x.example', rotationSequence: 1 }];
    const resolve = publicDidResolver(async () => served.shift() as never);
    expect(await resolve('did:web:x.example')).toMatchObject({ rotationSequence: 2 });
    await expect(resolve('did:web:x.example')).rejects.toThrow(/lower than 2/);
  });
});
