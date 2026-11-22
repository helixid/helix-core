// Copyright 2026 DgVerse LLP
// KYA-OS story F-3 against PostgreSQL: the migration's tables, the Prisma drivers, and a self-custody agent leaving no private key in the database.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { createTestPrisma } from '../utils/prisma.js';
import { CustodyRepository, WrappedKeyRepository } from '../../src/repositories/custody.repository.js';
import { DidRepository } from '../../src/repositories/did.repository.js';
import { ServiceRepository } from '../../src/repositories/service.repository.js';
import { DbKeyStore } from '../../src/services/custody/db-key-store.js';
import { CustodyService } from '../../src/services/custody/custody.service.js';
import { TestAuditLogger } from '../utils/TestAuditLogger.js';
import { clientKey, enrollmentSignature, rotationProof } from '../unit/services/custody/harness.js';

let prisma: PrismaClient;
const suffix = Math.random().toString(16).slice(2, 10);

beforeAll(() => {
  prisma = createTestPrisma();
});

afterAll(async () => {
  await prisma.$executeRawUnsafe(`DELETE FROM custody_keys WHERE did LIKE '%${suffix}%'`);
  await prisma.$executeRawUnsafe(`DELETE FROM custody_records WHERE did LIKE '%${suffix}%'`);
  await prisma.$executeRawUnsafe(`DELETE FROM wrapped_keys WHERE did LIKE '%${suffix}%'`);
  await prisma.$executeRawUnsafe(`DELETE FROM did_updates WHERE "didId" LIKE '%${suffix}%'`);
  await prisma.$executeRawUnsafe(`DELETE FROM services WHERE did LIKE '%${suffix}%'`);
  await prisma.$executeRawUnsafe(`DELETE FROM dids WHERE id LIKE '%${suffix}%'`);
  await prisma.$disconnect();
});

function service(): { custody: CustodyService; wrapped: WrappedKeyRepository; records: CustodyRepository } {
  const records = new CustodyRepository(prisma);
  const wrapped = new WrappedKeyRepository(prisma);
  const custody = new CustodyService({
    records,
    keyStore: new DbKeyStore({ table: wrapped, keyEncryptionKey: '7c'.repeat(32) }),
    didRepository: new DidRepository(prisma),
    credentials: { issueVC: async () => ({ vcId: `vc:${suffix}`, vc: {} }), revokeVC: async () => ({}) },
    services: new ServiceRepository(prisma),
    auditLogger: new TestAuditLogger(),
    host: `helix-${suffix}.example`,
  });
  return { custody, wrapped, records };
}

const context = { requestId: 'req_pg', actor: 'admin' };

describe('custody on PostgreSQL', () => {
  it('a self-custody agent: no wrapped key and no private material in any custody table', async () => {
    const { custody } = service();
    const key = clientKey();
    const created = await custody.createAgent({ name: `Self ${suffix}`, scopes: ['read:orders'], keyCustody: 'self' }, context);
    const challenge = await custody.enrollmentChallenge(created.enrollmentToken);
    const enrolled = await custody.enroll(
      { enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, challenge.nonce) },
      context,
    );
    expect(enrolled).toMatchObject({ status: 'active', keyCustody: 'self', credentialVcId: `vc:${suffix}` });
    expect(await prisma.$queryRawUnsafe(`SELECT count(*)::int AS n FROM wrapped_keys WHERE did = $1`, enrolled.did)).toEqual([{ n: 0 }]);
    expect(await prisma.$queryRawUnsafe(`SELECT count(*)::int AS n FROM did_keys WHERE did = $1`, enrolled.did)).toEqual([{ n: 0 }]);
    const rows = JSON.stringify([
      await prisma.$queryRawUnsafe(`SELECT * FROM custody_records WHERE did = $1`, enrolled.did),
      await prisma.$queryRawUnsafe(`SELECT * FROM custody_keys WHERE did = $1`, enrolled.did),
      await prisma.$queryRawUnsafe(`SELECT * FROM dids WHERE id = $1`, enrolled.did),
    ]);
    for (const form of key.forms) expect(rows).not.toContain(form);
  });

  it('a custodial agent: one wrapped row, signing, rotation to self shreds it', async () => {
    const { custody, wrapped } = service();
    const agent = await custody.createAgent({ name: `Custodial ${suffix}`, keyCustody: 'helix' }, context);
    const [row] = await wrapped.list(agent.did);
    expect(row).toMatchObject({ algorithm: 'A256GCM', subjectType: 'agent', shreddedAt: null });
    expect(row!.ciphertext.length).toBeGreaterThan(0);
    expect((await custody.sign(agent.did, { payload: 'AQID' }, context, 'agent')).signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
    const key = clientKey();
    const changed = await custody.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: rotationProof(key, agent.did, `${agent.did}#key-2`) }, context);
    expect(changed.previousKeyShredded).toBe(true);
    const [after] = await wrapped.list(agent.did);
    expect(after).toMatchObject({ ciphertext: '', nonce: '' });
    expect(after!.shreddedAt).toBeInstanceOf(Date);
    const report = await custody.conformanceSubjects();
    expect(report.find((subject) => subject.did === agent.did)).toMatchObject({ keyCustody: 'self' });
  });

  it('stores requestedDomains and maxDelegationDepth on PostgreSQL', async () => {
    const { custody, records } = service();
    const agent = await custody.createAgent({ name: `Router ${suffix}`, keyCustody: 'helix', requestedDomains: ['orders.example'], maxDelegationDepth: 4 }, context);
    expect(await records.findRecord(agent.did)).toMatchObject({ requestedDomains: ['https://orders.example'], maxDelegationDepth: 4 });
    const [row] = await prisma.$queryRawUnsafe<{ requestedDomains: unknown; maxDelegationDepth: number }[]>(
      'SELECT "requestedDomains", "maxDelegationDepth" FROM custody_records WHERE did = $1',
      agent.did,
    );
    expect(row).toEqual({ requestedDomains: ['https://orders.example'], maxDelegationDepth: 4 });
  });

  it('a self-custody service and the record listing', async () => {
    const { custody, records } = service();
    const created = await custody.createService({ name: `svc-${suffix}`, domain: 'svc.example', requiredScopes: ['a'], keyCustody: 'self', publicKeyJwk: clientKey().publicKeyJwk }, context);
    expect(created.service?.did).toBe(created.did);
    expect((await records.listRecords({ subjectType: 'service', dids: [created.did] })).map((row) => row.did)).toEqual([created.did]);
  });
});
