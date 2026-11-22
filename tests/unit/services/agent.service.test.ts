// Copyright 2026 DgVerse LLP
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { AgentService } from '../../../src/services/agent/agent.service.js';
import { TestAuditTrail } from '../../utils/TestAuditTrail.js';

const TEST_PRIVATE_KEY_HEX = '00'.repeat(32);

describe('AgentService Unit Tests', () => {
  let repository: any;
  let didService: any;
  let vcService: any;
  let auditLogger: TestAuditTrail;
  let agentKeyRepository: any;
  let keyCustody: any;
  let credentialService: any;
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
      claimStatusListEntry: vi.fn().mockResolvedValue({
        statusList: { credentialSubject: { encodedList: '' } },
        statusListCredentialUrl: 'http://localhost/v1/status-list/helix-status-list-1',
        statusListIndex: 42,
      }),
    };
    auditLogger = new TestAuditTrail();
    agentKeyRepository = { create: vi.fn(), findByDid: vi.fn() };
    keyCustody = {
      generateAndEncrypt: vi.fn(),
      sign: vi.fn(),
      signWith: vi.fn((_encrypted: unknown, use: (key: string) => unknown) => use(TEST_PRIVATE_KEY_HEX)),
    };

    credentialService = {
      issuerDid: 'did:key:z6MkHelixIssuer',
      issueIdentity: vi.fn().mockResolvedValue({ id: 'urn:uuid:identity', credentialSubject: {} }),
      issueAttestations: vi.fn().mockResolvedValue([]),
    };

    agentService = new AgentService(
      repository,
      didService,
      vcService,
      auditLogger,
      agentKeyRepository,
      keyCustody,
      credentialService,
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

  describe('verifyUserChallenge', () => {
    const challengeId = 'ch-1';
    const did = 'did:key:z6MkUser';
    const goodSignature = 'a'.repeat(128);
    const future = new Date(Date.now() + 60_000);
    const challenge = (overrides: Record<string, unknown> = {}) => ({
      id: challengeId,
      did,
      purpose: 'user_verification',
      nonce: 'ab'.repeat(16),
      expiresAt: future,
      verifiedAt: null,
      ...overrides,
    });

    it('throws ChallengeNotFoundError when the challenge does not exist', async () => {
      repository.findChallengeById.mockResolvedValue(null);
      await expect(agentService.verifyUserChallenge(challengeId, { signature: goodSignature }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_NOT_FOUND' });
    });

    it('throws ChallengeNotFoundError when the challenge has another purpose', async () => {
      repository.findChallengeById.mockResolvedValue(challenge({ purpose: 'onboarding' }));
      await expect(agentService.verifyUserChallenge(challengeId, { signature: goodSignature }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_NOT_FOUND' });
    });

    it('throws ChallengeExpiredError once the challenge has expired', async () => {
      repository.findChallengeById.mockResolvedValue(challenge({ expiresAt: new Date(Date.now() - 1) }));
      await expect(agentService.verifyUserChallenge(challengeId, { signature: goodSignature }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_EXPIRED' });
    });

    it('throws ChallengeAlreadyVerifiedError when the challenge was already used', async () => {
      repository.findChallengeById.mockResolvedValue(challenge({ verifiedAt: new Date() }));
      await expect(agentService.verifyUserChallenge(challengeId, { signature: goodSignature }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_ALREADY_VERIFIED' });
    });

    it('rejects a signature that is not 64 hex bytes before resolving the DID', async () => {
      repository.findChallengeById.mockResolvedValue(challenge());
      await expect(agentService.verifyUserChallenge(challengeId, { signature: 'nope' }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_SIGNATURE_INVALID' });
      expect(didService.resolveDID).not.toHaveBeenCalled();
    });

    it('rejects when the DID document has no Ed25519 verification method', async () => {
      repository.findChallengeById.mockResolvedValue(challenge());
      didService.resolveDID.mockResolvedValue({ didDocument: { verificationMethod: [{ type: 'JsonWebKey2020' }] } });
      await expect(agentService.verifyUserChallenge(challengeId, { signature: goodSignature }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_SIGNATURE_INVALID' });
    });

    it('rejects when the Ed25519 method carries neither publicKeyHex nor a multibase key', async () => {
      repository.findChallengeById.mockResolvedValue(challenge());
      didService.resolveDID.mockResolvedValue({ document: { verificationMethod: [{ type: 'Ed25519VerificationKey2020' }] } });
      await expect(agentService.verifyUserChallenge(challengeId, { signature: goodSignature }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_SIGNATURE_INVALID' });
    });

    it('rejects a signature that does not verify against publicKeyHex', async () => {
      repository.findChallengeById.mockResolvedValue(challenge());
      didService.resolveDID.mockResolvedValue({
        verificationMethod: [{ type: 'Ed25519VerificationKey2020', publicKeyHex: '00'.repeat(32) }],
      });
      await expect(agentService.verifyUserChallenge(challengeId, { signature: goodSignature }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_SIGNATURE_INVALID' });
      expect(repository.markChallengeVerified).not.toHaveBeenCalled();
    });

    it('rejects a signature that does not verify against a multibase key', async () => {
      repository.findChallengeById.mockResolvedValue(challenge());
      didService.resolveDID.mockResolvedValue({
        verificationMethod: [{
          type: 'Ed25519VerificationKey2020',
          publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        }],
      });
      await expect(agentService.verifyUserChallenge(challengeId, { signature: goodSignature }, 'req-1'))
        .rejects.toMatchObject({ code: 'CHALLENGE_SIGNATURE_INVALID' });
      expect(repository.markChallengeVerified).not.toHaveBeenCalled();
    });
  });
});
