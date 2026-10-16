// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  DelegateeNotAnAgentError,
  ServiceKeyNotFoundError,
  ServiceRevokedError,
  verifyEd25519Proof,
  buildDIDDocument,
  HelixError,
} from '../../../src/core/index.js';
import { DidKeyRepository } from '../../../src/repositories/did-key.repository.js';
import { ServiceRepository } from '../../../src/repositories/service.repository.js';
import { AesGcmKeyCustody } from '../../../src/services/key-custody/key-custody.js';
import { ServiceProviderService } from '../../../src/services/service-provider/service-provider.service.js';
import { MockVCService } from '../../mocks/MockVCService.js';

const MASTER_KEY = 'a'.repeat(64);
const ENROLL = { name: 'orders', domain: 'orders.example', requiredScope: 'read:orders' };

describe('ServiceProviderService', () => {
  let didKeys: DidKeyRepository;
  let services: ServiceRepository;
  let keyCustody: AesGcmKeyCustody;
  let vcService: MockVCService;
  let didService: any;
  let audit: any;
  let service: ServiceProviderService;
  let publicKeys: Record<string, string>;

  beforeEach(() => {
    didKeys = new DidKeyRepository();
    services = new ServiceRepository();
    keyCustody = new AesGcmKeyCustody(MASTER_KEY);
    vcService = new MockVCService();
    publicKeys = {};
    didService = {
      createDID: vi.fn(async (publicKeyHex: string, subjectType: string) => {
        const did = `did:web:api.example:${subjectType}s:${publicKeyHex.slice(0, 8)}`;
        publicKeys[did] = publicKeyHex;
        return { did, didDocument: buildDIDDocument(did, publicKeyHex), hederaTransactionId: 'x' };
      }),
    };
    audit = { log: vi.fn() };
    service = new ServiceProviderService(didService, vcService, services, didKeys, keyCustody, audit);
  });

  async function onboardedAgent(): Promise<string> {
    const { publicKey, encrypted } = keyCustody.generateAndEncrypt();
    const did = `did:key:z${publicKey.slice(0, 16)}`;
    await didKeys.create({ did, subjectType: 'agent', ...encrypted });
    return did;
  }

  it('enrolls a service: row in services, custody key stored, DID created as a service', async () => {
    const record = await service.enroll(ENROLL, 'req-1');
    expect(record.did).toContain(':services:');
    expect(record.id).toMatch(/^svc:[0-9a-f]{12}$/);
    expect(await services.findByDid(record.did)).toMatchObject({ name: 'orders', revokedAt: null });
    expect((await didKeys.findByDid(record.did))?.subjectType).toBe('service');
    expect(didService.createDID).toHaveBeenCalledWith(expect.any(String), 'service', [], 'req-1');
  });

  it('refuses to enroll a name that is already taken', async () => {
    await service.enroll(ENROLL, 'r');
    await expect(service.enroll(ENROLL, 'r')).rejects.toMatchObject({ code: 'SERVICE_ALREADY_EXISTS' });
  });

  it('issues a grant signed by the service key, naming the user, and stores it with its status index', async () => {
    const { did: serviceDid } = await service.enroll(ENROLL, 'r');
    const agentDid = await onboardedAgent();
    const { grantVC } = await service.issueDelegationGrant(
      { serviceDid, agentDid, userDid: 'did:web:mock.local:users:alice', scopes: ['read:calendar'] },
      'req-2',
    );

    expect(grantVC.issuer).toBe(serviceDid);
    expect(grantVC.type).toContain('DelegationGrantCredential');
    expect(grantVC.credentialSubject).toMatchObject({
      id: agentDid,
      userDid: 'did:web:mock.local:users:alice',
      scopes: ['read:calendar'],
      durability: 'standing',
      serviceDid,
    });
    expect(grantVC.credentialStatus?.statusListIndex).toBe('0');

    const { proof, ...unsigned } = grantVC;
    expect(await verifyEd25519Proof(unsigned, proof, buildDIDDocument(serviceDid, publicKeys[serviceDid]!))).toBe(true);
    expect(vcService.registeredGrants.map((vc) => vc.id)).toEqual([grantVC.id]);
  });

  it('refuses an unknown, revoked, or key-less service', async () => {
    const agentDid = await onboardedAgent();
    const base = { agentDid, userDid: 'did:key:zU', scopes: ['x'] };
    await expect(service.issueDelegationGrant({ ...base, serviceDid: 'did:key:zNope' }, 'r')).rejects.toMatchObject({
      code: 'SERVICE_NOT_FOUND',
    });

    const record = await service.enroll(ENROLL, 'r');
    await services.revoke(record.id);
    await expect(service.issueDelegationGrant({ ...base, serviceDid: record.did }, 'r')).rejects.toBeInstanceOf(
      ServiceRevokedError,
    );

    await services.create({ id: 'svc:nokey', did: 'did:key:zNoKey', name: 'n', domain: 'd', requiredScope: 's', description: null, framework: null });
    await expect(service.issueDelegationGrant({ ...base, serviceDid: 'did:key:zNoKey' }, 'r')).rejects.toBeInstanceOf(
      ServiceKeyNotFoundError,
    );
  });

  it('refuses a delegatee this server did not onboard as an agent', async () => {
    const { did: serviceDid } = await service.enroll(ENROLL, 'r');
    await expect(
      service.issueDelegationGrant({ serviceDid, agentDid: 'did:key:zStranger', userDid: 'did:key:zU', scopes: ['x'] }, 'r'),
    ).rejects.toBeInstanceOf(DelegateeNotAnAgentError);
    // A service DID is not an agent either.
    const { did: otherService } = await service.enroll({ ...ENROLL, name: 'other' }, 'r');
    await expect(
      service.issueDelegationGrant({ serviceDid, agentDid: otherService, userDid: 'did:key:zU', scopes: ['x'] }, 'r'),
    ).rejects.toBeInstanceOf(DelegateeNotAnAgentError);
  });

  it('validates the grant input', async () => {
    const { did: serviceDid } = await service.enroll(ENROLL, 'r');
    const agentDid = await onboardedAgent();
    const base = { serviceDid, agentDid, userDid: 'did:key:zU', scopes: ['x'] };
    for (const bad of [
      { ...base, scopes: [] },
      { ...base, userDid: 'alice@example.com' },
      { ...base, agentDid: serviceDid },
      { ...base, durability: 'forever' as never },
    ]) {
      await expect(service.issueDelegationGrant(bad, 'r')).rejects.toBeInstanceOf(HelixError);
    }
  });
});
