// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TestAuditTrail } from '../../utils/TestAuditTrail.js';
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
  let audit: TestAuditTrail;
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
    audit = new TestAuditTrail();
    service = new ServiceProviderService(didService, vcService, services, didKeys, keyCustody, audit);
    // What onboarding leaves the agent with (story F-1): an identity
    // credential and one capability attestation per scope. The attested
    // capabilities are what any consent to it may grant.
    vcService.setActiveVCs(agentCredentials(['read:calendar', 'a', 'b', 'x']));
  });

  function identity(): Record<string, unknown> {
    return {
      id: 'urn:uuid:identity',
      type: ['VerifiableCredential', 'AgentIdentityCredential'],
      credentialSubject: { id: 'did:key:zAgent', name: 'agent', responsibleParty: 'did:key:zOwner' },
    };
  }

  function attestation(capability: string): Record<string, unknown> {
    return {
      id: `urn:uuid:attestation-${capability}`,
      type: ['VerifiableCredential', 'CapabilityAttestationCredential'],
      credentialSubject: { id: 'did:key:zAgent', capability },
    };
  }

  function agentCredentials(scopes: string[]): Array<Record<string, unknown>> {
    return [identity(), ...scopes.map(attestation)];
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

  it('refuses to enroll with a scope the scope rule rejects', async () => {
    await expect(service.enroll({ ...ENROLL, requiredScopes: ['x'.repeat(300)] }, 'r')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      message: expect.stringContaining('requiredScopes'),
    });
    expect(didService.createDID).not.toHaveBeenCalled();
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

  it('refuses to enroll a name that is already taken', async () => {
    await service.enroll(ENROLL, 'r');
    await expect(service.enroll(ENROLL, 'r')).rejects.toMatchObject({ code: 'SERVICE_ALREADY_EXISTS' });
  });

  describe('getAgentScopes', () => {
    it('returns the capabilities of the agent\'s active attestations, each once, in issuance order', async () => {
      const agentDid = await onboardedAgent();
      expect(await service.getAgentScopes(agentDid)).toEqual({ agentDid, scopes: ['read:calendar', 'a', 'b', 'x'] });
      // A repeated capability counts once; an attestation naming no capability counts for nothing.
      const unnamed = { ...attestation('ignored'), credentialSubject: { id: 'did:key:zAgent' } };
      vcService.setActiveVCs([identity(), attestation('b'), attestation('a'), attestation('b'), unnamed]);
      expect(await service.getAgentScopes(agentDid)).toEqual({ agentDid, scopes: ['b', 'a'] });
    });

    it('an identity credential with no attestations has no scopes', async () => {
      const agentDid = await onboardedAgent();
      vcService.setActiveVCs([identity()]);
      expect(await service.getAgentScopes(agentDid)).toEqual({ agentDid, scopes: [] });
    });

    it('refuses a DID this server did not onboard as an agent, and a non-DID', async () => {
      await expect(service.getAgentScopes('did:key:zStranger')).rejects.toBeInstanceOf(DelegateeNotAnAgentError);
      await expect(service.getAgentScopes('alice')).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
    });

    it('refuses an agent with no active identity credential', async () => {
      const agentDid = await onboardedAgent();
      vcService.setActiveVC(null);
      await expect(service.getAgentScopes(agentDid)).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
      vcService.setActiveVCs([attestation('a')]);
      await expect(service.getAgentScopes(agentDid)).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
    });
  });

});
