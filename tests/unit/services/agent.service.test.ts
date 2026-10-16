// Copyright 2026 DgVerse LLP
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { AgentService } from '../../../src/services/agent/agent.service.js';
import {
  AgentKeyNotFoundError,
  AgentActiveCredentialNotFoundError,
  MaxDelegationDepthExceededError,
} from '../../../src/core/index.js';

const TEST_PRIVATE_KEY_HEX = '00'.repeat(32);

describe('AgentService Unit Tests', () => {
  let repository: any;
  let didService: any;
  let vcService: any;
  let auditLogger: any;
  let agentKeyRepository: any;
  let keyCustody: any;
  let agentService: AgentService;

  beforeEach(() => {
    repository = {
      findServiceByName: vi.fn(),
      createService: vi.fn(),
      findEnrollmentTokenByHash: vi.fn(),
      findEnrollmentTokenById: vi.fn(),
      burnEnrollmentTokenAtomically: vi.fn(),
      createChallenge: vi.fn(),
      findChallengeById: vi.fn(),
      markChallengeVerified: vi.fn(),
      getServiceByName: vi.fn(),
      listActiveServices: vi.fn(),
      createEnrollmentToken: vi.fn(),
    };
    didService = {
      createDID: vi.fn(),
      resolveDID: vi.fn(),
      prepareDIDCreation: vi.fn().mockResolvedValue({ stateJson: '{}', signingPayloadHex: 'ab'.repeat(32) }),
    };
    vcService = {
      issueVC: vi.fn(),
      findActiveBySubjectDid: vi.fn(),
      findActiveByVcIdForSubject: vi.fn(),
      listActiveBySubjectDid: vi.fn(),
      registerSignedVC: vi.fn(),
    };
    auditLogger = { log: vi.fn() };
    agentKeyRepository = { create: vi.fn(), findByDid: vi.fn() };
    keyCustody = {
      generateAndEncrypt: vi.fn(),
      sign: vi.fn(),
      signWith: vi.fn((_encrypted: unknown, use: (key: string) => unknown) => use(TEST_PRIVATE_KEY_HEX)),
    };

    agentService = new AgentService(
      repository,
      didService,
      vcService,
      auditLogger,
      agentKeyRepository,
      keyCustody,
    );
  });

  describe('generateEnrollmentToken', () => {
    it('successfully generates and persists a token', async () => {
      const result = await agentService.generateEnrollmentToken({ 
        agentName: 'test', 
        requestedScopes: ['read'],
        requestedDomains: ['https://example.com']
      }, 'req-1');
      expect(result.token).toBeDefined();
      expect(repository.createEnrollmentToken).toHaveBeenCalled();
    });

    describe('expiry', () => {
      afterEach(() => {
        vi.useRealTimers();
      });

      it('expires at the same time of day, `expiry` days later', async () => {
        vi.useFakeTimers();
        const now = new Date(2026, 9, 15, 16, 0, 0);
        vi.setSystemTime(now);
        const result = await agentService.generateEnrollmentToken(
          { agentName: 'test', requestedScopes: ['read'], expiry: 1 },
          'req-1',
        );
        expect(new Date(result.expiresAt!)).toEqual(new Date(2026, 9, 16, 16, 0, 0));
        expect(repository.createEnrollmentToken).toHaveBeenCalledWith(
          expect.objectContaining({ expiresAt: new Date(2026, 9, 16, 16, 0, 0) }),
        );
      });

      it.each([undefined, null, ''])('stores no expiry when expiry=%j', async (expiry) => {
        const result = await agentService.generateEnrollmentToken(
          { agentName: 'test', requestedScopes: ['read'], expiry: expiry as number | null },
          'req-1',
        );
        expect(result.expiresAt).toBeUndefined();
        expect(repository.createEnrollmentToken.mock.calls[0][0]).toMatchObject({ expiresAt: null });
      });

      it.each([0, -1, 1.5, Number.NaN])('rejects expiry=%s with INVALID_EXPIRY', async (expiry) => {
        await expect(
          agentService.generateEnrollmentToken({ agentName: 'test', requestedScopes: ['read'], expiry }, 'req-1'),
        ).rejects.toMatchObject({ code: 'INVALID_EXPIRY', httpStatus: 400 });
        expect(repository.createEnrollmentToken).not.toHaveBeenCalled();
      });
    });
  });

  describe('processOnboardCreateChallenge', () => {
    const rawToken = 'enroll:abc';
    const publicKeyHex = 'a'.repeat(64);

    it('throws VALIDATION_ERROR for invalid public key', async () => {
      await expect(agentService.processOnboardCreateChallenge({ enrollmentToken: rawToken, publicKeyHex: 'short', domains: [] }, 'req-1'))
        .rejects.toMatchObject({ code: 'INVALID_PUBLIC_KEY' });
    });

    it('throws INVALID_SERVICE_ENDPOINT_URL for non-web domain', async () => {
      await expect(agentService.processOnboardCreateChallenge({ enrollmentToken: rawToken, publicKeyHex, domains: ['ftp://unsafe.com'] }, 'req-1'))
        .rejects.toMatchObject({ code: 'INVALID_SERVICE_ENDPOINT_URL' });
    });
  });

  describe('issueUserChallenge', () => {
    it('successfully creates a user challenge', async () => {
      didService.resolveDID.mockResolvedValue({});
      const result = await agentService.issueUserChallenge({ did: 'did:1', purpose: 'user_verification' }, 'req-1');
      expect(result.challengeId).toBeDefined();
      expect(repository.createChallenge).toHaveBeenCalled();
    });
  });

  describe('signVP', () => {
    const agentDid = 'did:key:z6Mktestagent';

    it('throws AgentKeyNotFoundError when no server-held key exists for the DID', async () => {
      agentKeyRepository.findByDid.mockResolvedValue(null);
      await expect(
        agentService.signVP({ did: agentDid, targetService: 'https://svc.example.com' }, 'req-1'),
      ).rejects.toBeInstanceOf(AgentKeyNotFoundError);
      expect(vcService.findActiveBySubjectDid).not.toHaveBeenCalled();
    });

    it('throws AgentActiveCredentialNotFoundError when the agent has no active credential', async () => {
      agentKeyRepository.findByDid.mockResolvedValue({
        did: agentDid,
        encryptedPrivateKey: 'x',
        iv: 'x',
        authTag: 'x',
        algorithm: 'aes-256-gcm',
      });
      vcService.findActiveBySubjectDid.mockResolvedValue(null);
      await expect(
        agentService.signVP({ did: agentDid, targetService: 'https://svc.example.com' }, 'req-1'),
      ).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
    });

    it('signs and returns a VP for the agent, looking up the active HelixAgentCredential', async () => {
      agentKeyRepository.findByDid.mockResolvedValue({
        did: agentDid,
        encryptedPrivateKey: 'x',
        iv: 'x',
        authTag: 'x',
        algorithm: 'aes-256-gcm',
      });
      vcService.findActiveBySubjectDid.mockResolvedValue({
        id: 'vc:test:1',
        type: ['VerifiableCredential', 'HelixAgentCredential'],
        credentialSubject: { id: agentDid, privilegeScopes: ['read'] },
      });

      const result = await agentService.signVP(
        { did: agentDid, targetService: 'https://svc.example.com' },
        'req-1',
      );

      expect(vcService.findActiveBySubjectDid).toHaveBeenCalledWith(agentDid, 'HelixAgentCredential');
      expect(result.signedVP.holder).toBe(agentDid);
      expect(result.signedVP.proof).toBeDefined();
      expect(auditLogger.log).toHaveBeenCalledWith(
        'AGENT_VP_SIGNED',
        expect.objectContaining({ agentDid, targetService: 'https://svc.example.com' }),
      );
    });
  });

  describe('delegateAuthority', () => {
    const delegatorDid = 'did:key:z6Mktestdelegator';
    const subAgentDid = 'did:key:z6Mktestsubagent';
    const keyRecord = {
      did: delegatorDid,
      encryptedPrivateKey: 'x',
      iv: 'x',
      authTag: 'x',
      algorithm: 'aes-256-gcm',
    };
    const fromVC = {
      id: 'vc:test:delegator',
      type: ['VerifiableCredential', 'HelixAgentCredential'],
      credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders'], maxDelegationDepth: 1 },
    };

    it('throws AgentKeyNotFoundError when no server-held key exists for the delegator DID', async () => {
      agentKeyRepository.findByDid.mockResolvedValue(null);
      await expect(
        agentService.delegateAuthority(
          { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600 },
          'req-1',
        ),
      ).rejects.toBeInstanceOf(AgentKeyNotFoundError);
      expect(vcService.listActiveBySubjectDid).not.toHaveBeenCalled();
    });

    it('throws AgentActiveCredentialNotFoundError when the delegator has no active credential', async () => {
      agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
      vcService.listActiveBySubjectDid.mockResolvedValue([]);
      await expect(
        agentService.delegateAuthority(
          { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600 },
          'req-1',
        ),
      ).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
    });

    it('throws AgentActiveCredentialNotFoundError when the only active credential has no remaining delegation depth', async () => {
      agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
      // maxDelegationDepth: 0 -- covers the requested scope, but has no
      // budget left to delegate at all; filtered out of the candidate list
      // entirely rather than reaching prepareDelegation's own depth check.
      vcService.listActiveBySubjectDid.mockResolvedValue([
        { id: 'vc:test:no-depth', credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders'], maxDelegationDepth: 0 } },
      ]);
      await expect(
        agentService.delegateAuthority(
          { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600 },
          'req-1',
        ),
      ).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
    });

    it('throws VPMultipleActiveVCError when more than one active credential is eligible, instead of guessing', async () => {
      agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
      vcService.listActiveBySubjectDid.mockResolvedValue([
        { id: 'vc:test:a', credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders'], maxDelegationDepth: 1 } },
        { id: 'vc:test:b', credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders', 'write:orders'], maxDelegationDepth: 2 } },
      ]);
      await expect(
        agentService.delegateAuthority(
          { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600 },
          'req-1',
        ),
      ).rejects.toMatchObject({ code: 'VP_MULTIPLE_ACTIVE_VC' });
    });

    it('pins the fromVC by vcId when one is given, instead of looking up by subject', async () => {
      agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
      vcService.findActiveByVcIdForSubject.mockResolvedValue(fromVC);

      await agentService.delegateAuthority(
        { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600, vcId: 'vc:test:delegator' },
        'req-1',
      );

      expect(vcService.findActiveByVcIdForSubject).toHaveBeenCalledWith(
        'vc:test:delegator',
        delegatorDid,
        'HelixAgentCredential',
      );
      expect(vcService.listActiveBySubjectDid).not.toHaveBeenCalled();
    });

    it('builds and signs a delegation VC with the custody-held key, stores it and logs VC_DELEGATED', async () => {
      agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
      vcService.listActiveBySubjectDid.mockResolvedValue([fromVC]);

      const result = await agentService.delegateAuthority(
        { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600 },
        'req-1',
      );

      expect(vcService.listActiveBySubjectDid).toHaveBeenCalledWith(delegatorDid, 'HelixAgentCredential');
      expect(keyCustody.signWith).toHaveBeenCalledWith(keyRecord, expect.any(Function));
      const delegatedVC = result.delegatedVC as unknown as {
        issuer: string;
        credentialSubject: Record<string, unknown>;
        delegationChain: unknown[];
        proof: { verificationMethod: string };
      };
      expect(delegatedVC.issuer).toBe(delegatorDid);
      expect(delegatedVC.credentialSubject).toMatchObject({
        id: subAgentDid,
        privilegeScopes: ['read:orders'],
        delegatedFrom: delegatorDid,
        delegationDepth: 1,
        parentVcId: 'vc:test:delegator',
      });
      expect(delegatedVC.delegationChain).toEqual([fromVC]);
      expect(delegatedVC.proof.verificationMethod).toBe(`${delegatorDid}#key-1`);
      expect(vcService.registerSignedVC).toHaveBeenCalledWith(result.delegatedVC);
      expect(auditLogger.log).toHaveBeenCalledWith(
        'VC_DELEGATED',
        expect.objectContaining({
          delegatorDid,
          delegateDid: subAgentDid,
          scopes: ['read:orders'],
          delegatedVcId: result.delegatedVC.id,
        }),
      );
    });

    it('rejects delegation beyond maxDelegationDepth before signing', async () => {
      agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
      vcService.findActiveByVcIdForSubject.mockResolvedValue({
        ...fromVC,
        credentialSubject: { ...fromVC.credentialSubject, delegationDepth: 1, maxDelegationDepth: 1 },
      });

      await expect(
        agentService.delegateAuthority(
          { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600, vcId: 'vc:test:delegator' },
          'req-1',
        ),
      ).rejects.toBeInstanceOf(MaxDelegationDepthExceededError);
      expect(vcService.registerSignedVC).not.toHaveBeenCalled();
    });
  });

});
