// Copyright 2026 DgVerse LLP
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { AgentService } from '../../../src/services/agent/agent.service.js';
import { AgentKeyNotFoundError, AgentActiveCredentialNotFoundError } from '../../../src/core/index.js';

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
    vcService = { issueVC: vi.fn(), findActiveBySubjectDid: vi.fn() };
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
  });

  describe('processOnboardStep1', () => {
    const rawToken = 'enroll:abc';
    const publicKeyHex = 'a'.repeat(64);

    it('throws VALIDATION_ERROR for invalid public key', async () => {
      await expect(agentService.processOnboardStep1({ enrollmentToken: rawToken, publicKeyHex: 'short', domains: [] }, 'req-1'))
        .rejects.toMatchObject({ code: 'INVALID_PUBLIC_KEY' });
    });

    it('throws INVALID_SERVICE_ENDPOINT_URL for non-https domain', async () => {
      await expect(agentService.processOnboardStep1({ enrollmentToken: rawToken, publicKeyHex, domains: ['http://unsafe.com'] }, 'req-1'))
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

});
