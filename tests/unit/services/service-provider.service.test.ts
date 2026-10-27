// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AgentActiveCredentialNotFoundError,
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
const ENROLL = { name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'] };

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
    // The agent's own onboarding credential: what any consent to it may grant.
    vcService.setActiveVC(agentVC(['read:calendar', 'a', 'b', 'x']));
  });

  function agentVC(privilegeScopes: string[], extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      id: 'vc:test:agent',
      type: ['VerifiableCredential', 'HelixAgentCredential'],
      credentialSubject: { privilegeScopes, ...extra },
    };
  }

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

  it('enrolls with several scopes, split by the scope rule and de-duplicated', async () => {
    const record = await service.enroll(
      { ...ENROLL, requiredScopes: ['calendar.events,calendar.freebusy', ' https://www.googleapis.com/auth/gmail.readonly\tcalendar.events '] },
      'r',
    );
    expect(record.requiredScopes).toEqual([
      'calendar.events',
      'calendar.freebusy',
      'https://www.googleapis.com/auth/gmail.readonly',
    ]);
    expect((await services.findByDid(record.did))?.requiredScopes).toEqual(record.requiredScopes);
  });

  it('refuses to enroll without a scope', async () => {
    await expect(service.enroll({ ...ENROLL, requiredScopes: [' , '] }, 'r')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
    });
  });

  it('refuses a grant whose scopes contain whitespace', async () => {
    const { did: serviceDid } = await service.enroll(ENROLL, 'r');
    const agentDid = await onboardedAgent();
    await expect(
      service.issueDelegationGrant({ serviceDid, agentDid, userDid: 'did:web:u', scopes: ['read calendar'] }, 'r'),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
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

    await services.create({ id: 'svc:nokey', did: 'did:key:zNoKey', name: 'n', domain: 'd', requiredScopes: ['s'], description: null, framework: null });
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

  it('refuses an agent with no active HelixAgentCredential', async () => {
    const { did: serviceDid } = await service.enroll(ENROLL, 'r');
    const agentDid = await onboardedAgent();
    vcService.setActiveVC(null);
    await expect(
      service.issueDelegationGrant({ serviceDid, agentDid, userDid: 'did:key:zU', scopes: ['x'] }, 'r'),
    ).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
    expect(vcService.registeredGrants).toEqual([]);
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

  describe('grant scopes are bounded by the agent\'s own credential', () => {
    const userDid = 'did:web:mock.local:users:alice';

    it('refuses a scope the agent was not onboarded with, naming it', async () => {
      const { did: serviceDid } = await service.enroll(ENROLL, 'r');
      const agentDid = await onboardedAgent();
      await expect(
        service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['a', 'write:payments'] }, 'r'),
      ).rejects.toMatchObject({ code: 'CONSENT_GRANT_SCOPE_NOT_ALLOWED', message: expect.stringContaining('write:payments') });
      expect(vcService.registeredGrants).toEqual([]);
    });

    it('lets accept-terms through without the agent holding it', async () => {
      const { did: serviceDid } = await service.enroll(ENROLL, 'r');
      const agentDid = await onboardedAgent();
      const { grantVC } = await service.issueDelegationGrant(
        { serviceDid, agentDid, userDid, scopes: ['a', 'accept-terms'] },
        'r',
      );
      expect(grantVC.credentialSubject).toMatchObject({ scopes: ['a', 'accept-terms'] });
    });

    it('refuses a grant of nothing but accept-terms', async () => {
      const { did: serviceDid } = await service.enroll(ENROLL, 'r');
      const agentDid = await onboardedAgent();
      await expect(
        service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['accept-terms'] }, 'r'),
      ).rejects.toMatchObject({ code: 'CONSENT_NO_GRANTABLE_SCOPES' });
    });

    it('ignores credentials delegated to the agent: only its own scopes count', async () => {
      const { did: serviceDid } = await service.enroll(ENROLL, 'r');
      const agentDid = await onboardedAgent();
      vcService.setActiveVC(agentVC(['delegated:scope'], { delegatedFrom: 'did:key:zParent' }));
      // Its only active credential is delegated, so it has no scopes of its own.
      await expect(
        service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['delegated:scope'] }, 'r'),
      ).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
    });

    it('records allowDelegation on the grant when given, and leaves it out otherwise', async () => {
      const { did: serviceDid } = await service.enroll(ENROLL, 'r');
      const agentDid = await onboardedAgent();
      const withFlag = await service.issueDelegationGrant(
        { serviceDid, agentDid, userDid, scopes: ['a'], allowDelegation: false },
        'r1',
      );
      expect(withFlag.grantVC.credentialSubject).toMatchObject({ allowDelegation: false });
      const without = await service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['b'] }, 'r2');
      expect(without.grantVC.credentialSubject).not.toHaveProperty('allowDelegation');
      await expect(
        service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['a'], allowDelegation: 'yes' as never }, 'r3'),
      ).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
    });
  });

  describe('getAgentScopes', () => {
    it('returns the union of the agent\'s own active credentials\' scopes', async () => {
      const agentDid = await onboardedAgent();
      expect(await service.getAgentScopes(agentDid)).toEqual({ agentDid, scopes: ['read:calendar', 'a', 'b', 'x'] });
    });

    it('refuses a DID this server did not onboard as an agent, and a non-DID', async () => {
      await expect(service.getAgentScopes('did:key:zStranger')).rejects.toBeInstanceOf(DelegateeNotAnAgentError);
      await expect(service.getAgentScopes('alice')).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
    });

    it('refuses an agent with no active credential of its own', async () => {
      const agentDid = await onboardedAgent();
      vcService.setActiveVC(null);
      await expect(service.getAgentScopes(agentDid)).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
    });
  });

  describe('one grant per (user, agent, service, scope set)', () => {
    const userDid = 'did:web:mock.local:users:alice';
    let serviceDid: string;
    let agentDid: string;

    beforeEach(async () => {
      serviceDid = (await service.enroll(ENROLL, 'r')).did;
      agentDid = await onboardedAgent();
    });

    it('consenting again to the same scopes refreshes the grant: new VC issued, old one revoked and chained', async () => {
      const first = await service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['b', 'a'] }, 'r1');
      // Same set, listed differently and with a repeat: still the same grant.
      const second = await service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['a', 'b', 'a'] }, 'r2');

      expect(second.grantVC.id).not.toBe(first.grantVC.id);
      expect(second.grantVC.credentialSubject).toMatchObject({ scopes: ['a', 'b'] });
      expect(second.replacedVcIds).toEqual([first.grantVC.id]);
      expect(second.revokedVcIds).toEqual([]);
      expect(vcService.revokedVcIds).toEqual([first.grantVC.id]);
      expect(vcService.renewals).toEqual([{ oldVcId: first.grantVC.id, newVcId: second.grantVC.id }]);
      expect(await vcService.listActiveGrants({ agentDid, serviceDid, userDid })).toEqual([second.grantVC]);
      // The grant was stored before anything was revoked, and with the rule's options.
      expect(vcService.registeredGrants.map((vc) => vc.id)).toEqual([first.grantVC.id, second.grantVC.id]);
    });

    it('a different scope set is a new grant beside the existing one', async () => {
      const first = await service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['a'] }, 'r1');
      const second = await service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['a', 'b'] }, 'r2');

      expect(second.replacedVcIds).toEqual([]);
      expect(second.revokedVcIds).toEqual([]);
      expect(vcService.revokedVcIds).toEqual([]);
      expect((await vcService.listActiveGrants({ agentDid, serviceDid, userDid })).map((vc) => vc.id)).toEqual([
        first.grantVC.id,
        second.grantVC.id,
      ]);
    });

    it('revokeExisting leaves the new grant as the only one standing', async () => {
      const first = await service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['a'] }, 'r1');
      const same = await service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['b'] }, 'r2');
      const third = await service.issueDelegationGrant(
        { serviceDid, agentDid, userDid, scopes: ['b'], revokeExisting: true },
        'r3',
      );

      expect(third.replacedVcIds).toEqual([same.grantVC.id]);
      expect(third.revokedVcIds).toEqual([first.grantVC.id]);
      expect(await vcService.listActiveGrants({ agentDid, serviceDid, userDid })).toEqual([third.grantVC]);
    });

    it('grants for another user or another agent are never touched', async () => {
      const otherUser = await service.issueDelegationGrant(
        { serviceDid, agentDid, userDid: 'did:web:mock.local:users:bob', scopes: ['a'] },
        'r1',
      );
      const otherAgent = await service.issueDelegationGrant(
        { serviceDid, agentDid: await onboardedAgent(), userDid, scopes: ['a'] },
        'r2',
      );
      await service.issueDelegationGrant({ serviceDid, agentDid, userDid, scopes: ['a'], revokeExisting: true }, 'r3');

      expect(vcService.revokedVcIds).toEqual([]);
      expect(vcService.registeredGrants.map((vc) => vc.id)).toContain(otherUser.grantVC.id);
      expect(vcService.registeredGrants.map((vc) => vc.id)).toContain(otherAgent.grantVC.id);
    });
  });
});
