// Copyright 2026 DgVerse LLP
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { AgentService } from '../../../src/services/agent/agent.service.js';
import {
  AgentKeyNotFoundError,
  AgentActiveCredentialNotFoundError,
  MaxDelegationDepthExceededError,
  DelegateeNotAnAgentError,
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
      claimStatusListEntry: vi.fn().mockResolvedValue({
        statusList: { credentialSubject: { encodedList: '' } },
        statusListCredentialUrl: 'http://localhost/v1/status-list/helix-status-list-1',
        statusListIndex: 42,
      }),
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
        agentService.signVP({ did: agentDid, targetService: 'did:web:svc.example.com' }, 'req-1'),
      ).rejects.toBeInstanceOf(AgentKeyNotFoundError);
      expect(vcService.listActiveBySubjectDid).not.toHaveBeenCalled();
    });

    it('throws AgentActiveCredentialNotFoundError when the agent has no active credential', async () => {
      agentKeyRepository.findByDid.mockResolvedValue({
        did: agentDid,
        encryptedPrivateKey: 'x',
        iv: 'x',
        authTag: 'x',
        algorithm: 'aes-256-gcm',
      });
      vcService.listActiveBySubjectDid.mockResolvedValue([]);
      await expect(
        agentService.signVP({ did: agentDid, targetService: 'did:web:svc.example.com' }, 'req-1'),
      ).rejects.toBeInstanceOf(AgentActiveCredentialNotFoundError);
    });

    it('signs and returns a VP for the agent, presenting every active HelixAgentCredential', async () => {
      agentKeyRepository.findByDid.mockResolvedValue({
        did: agentDid,
        encryptedPrivateKey: 'x',
        iv: 'x',
        authTag: 'x',
        algorithm: 'aes-256-gcm',
      });
      vcService.listActiveBySubjectDid.mockResolvedValue([
        {
          id: 'vc:test:1',
          type: ['VerifiableCredential', 'HelixAgentCredential'],
          credentialSubject: { id: agentDid, privilegeScopes: ['read'] },
        },
        {
          id: 'vc:test:2',
          type: ['VerifiableCredential', 'HelixAgentCredential'],
          credentialSubject: { id: agentDid, privilegeScopes: ['write'] },
        },
      ]);

      const result = await agentService.signVP(
        { did: agentDid, targetService: 'did:web:svc.example.com' },
        'req-1',
      );

      expect(vcService.listActiveBySubjectDid).toHaveBeenCalledWith(agentDid, 'HelixAgentCredential');
      expect(result.signedVP.holder).toBe(agentDid);
      expect(result.signedVP.proof).toBeDefined();
      expect(result.signedVP.verifiableCredential.map((vc) => vc['id'])).toEqual(['vc:test:1', 'vc:test:2']);
      expect(auditLogger.log).toHaveBeenCalledWith(
        'AGENT_VP_SIGNED',
        expect.objectContaining({
          agentDid,
          targetService: 'did:web:svc.example.com',
          vcIds: ['vc:test:1', 'vc:test:2'],
        }),
      );
    });

    describe('on a user\'s behalf', () => {
      const serviceDid = 'did:web:svc.example.com';
      const userDid = 'did:web:mock.local:users:alice';
      const agentVC = {
        id: 'vc:test:1',
        type: ['VerifiableCredential', 'HelixAgentCredential'],
        credentialSubject: { id: agentDid, privilegeScopes: ['read', 'write'] },
      };
      const grant = (id: string, scopes: string[]) => ({
        id,
        type: ['VerifiableCredential', 'DelegationGrantCredential'],
        issuer: serviceDid,
        credentialSubject: { id: agentDid, type: 'DelegationGrant', userDid, scopes, durability: 'standing' },
      });

      beforeEach(() => {
        agentKeyRepository.findByDid.mockResolvedValue({
          did: agentDid,
          encryptedPrivateKey: 'x',
          iv: 'x',
          authTag: 'x',
          algorithm: 'aes-256-gcm',
        });
        vcService.listActiveBySubjectDid.mockResolvedValue([agentVC]);
        vcService.listActiveGrants = vi.fn();
      });

      it('rejects a targetService that is not a DID before touching anything', async () => {
        await expect(
          agentService.signVP({ did: agentDid, targetService: 'orders', userDid }, 'req-1'),
        ).rejects.toMatchObject({ code: 'VALIDATION_ERROR' });
        expect(agentKeyRepository.findByDid).not.toHaveBeenCalled();
      });

      it('looks up every active grant for (user, agent, service) and presents them all', async () => {
        vcService.listActiveGrants.mockResolvedValue([grant('vc:g1', ['read']), grant('vc:g2', ['write'])]);

        const { signedVP } = await agentService.signVP(
          { did: agentDid, targetService: serviceDid, userDid },
          'req-1',
        );

        expect(vcService.listActiveGrants).toHaveBeenCalledWith({ agentDid, serviceDid, userDid });
        expect(signedVP.verifiableCredential.map((vc) => vc['id'])).toEqual(['vc:test:1', 'vc:g1', 'vc:g2']);
        expect(signedVP.delegatedBy).toBe(userDid);
        expect(auditLogger.log).toHaveBeenCalledWith(
          'AGENT_VP_SIGNED',
          expect.objectContaining({ userDid, grantVcIds: ['vc:g1', 'vc:g2'] }),
        );
      });

      it('throws ConsentGrantNotFoundError when the user has no active grant', async () => {
        vcService.listActiveGrants.mockResolvedValue([]);
        await expect(
          agentService.signVP({ did: agentDid, targetService: serviceDid, userDid }, 'req-1'),
        ).rejects.toMatchObject({ code: 'CONSENT_GRANT_NOT_FOUND', httpStatus: 404 });
      });

      describe('consent passes down a delegation', () => {
        const parentDid = 'did:key:z6Mkparent';
        const grandparentDid = 'did:key:z6Mkgrandparent';
        const link = (id: string, did: string) => ({
          id,
          type: ['VerifiableCredential', 'HelixAgentCredential'],
          credentialSubject: { id: did, privilegeScopes: ['read', 'write'] },
        });
        // This agent's own onboarding credential (agentVC, read+write) plus
        // one delegated to it by parentDid, narrowed to read.
        const delegatedVC = (chain: Array<ReturnType<typeof link>>) => ({
          id: 'vc:delegated:1',
          type: ['VerifiableCredential', 'HelixAgentCredential'],
          credentialSubject: { id: agentDid, privilegeScopes: ['read'], delegatedFrom: parentDid },
          delegationChain: chain,
        });
        const grantTo = (id: string, holder: string) => ({
          ...grant(id, ['read']),
          credentialSubject: { id: holder, type: 'DelegationGrant', userDid, scopes: ['read'], durability: 'standing' },
        });
        const grantsByHolder = (byHolder: Record<string, unknown[]>) =>
          vcService.listActiveGrants.mockImplementation(async ({ agentDid: holder }: { agentDid: string }) => byHolder[holder] ?? []);

        it("uses the delegator's grant, presenting only the delegated credential that chains to it", async () => {
          vcService.listActiveBySubjectDid.mockResolvedValue([agentVC, delegatedVC([link('vc:parent', parentDid)])]);
          grantsByHolder({ [parentDid]: [grantTo('vc:g-parent', parentDid)] });

          const { signedVP } = await agentService.signVP({ did: agentDid, targetService: serviceDid, userDid }, 'req-1');

          expect(vcService.listActiveGrants).toHaveBeenCalledWith({ agentDid, serviceDid, userDid });
          expect(vcService.listActiveGrants).toHaveBeenCalledWith({ agentDid: parentDid, serviceDid, userDid });
          // Not agentVC: with it, the verifier's union of agent scopes would
          // include write, which the delegator never delegated.
          expect(signedVP.verifiableCredential.map((vc) => vc['id'])).toEqual(['vc:delegated:1', 'vc:g-parent']);
          expect(signedVP.delegatedBy).toBe(userDid);
          expect(auditLogger.log).toHaveBeenCalledWith(
            'AGENT_VP_SIGNED',
            expect.objectContaining({ vcIds: ['vc:delegated:1'], grantVcIds: ['vc:g-parent'], grantHolderDids: [parentDid] }),
          );
        });

        it("prefers the agent's own grant and never looks further up", async () => {
          vcService.listActiveBySubjectDid.mockResolvedValue([agentVC, delegatedVC([link('vc:parent', parentDid)])]);
          grantsByHolder({ [agentDid]: [grant('vc:g-own', ['read'])], [parentDid]: [grantTo('vc:g-parent', parentDid)] });

          const { signedVP } = await agentService.signVP({ did: agentDid, targetService: serviceDid, userDid }, 'req-1');

          expect(vcService.listActiveGrants).toHaveBeenCalledTimes(1);
          expect(signedVP.verifiableCredential.map((vc) => vc['id'])).toEqual(['vc:test:1', 'vc:delegated:1', 'vc:g-own']);
        });

        it('walks the whole chain, nearest delegator first', async () => {
          vcService.listActiveBySubjectDid.mockResolvedValue([
            delegatedVC([link('vc:grandparent', grandparentDid), link('vc:parent', parentDid)]),
          ]);
          grantsByHolder({ [grandparentDid]: [grantTo('vc:g-grandparent', grandparentDid)] });

          const { signedVP } = await agentService.signVP({ did: agentDid, targetService: serviceDid, userDid }, 'req-1');

          const holders = vcService.listActiveGrants.mock.calls.map(([lookup]: [{ agentDid: string }]) => lookup.agentDid);
          expect(holders).toEqual([agentDid, parentDid, grandparentDid]);
          expect(signedVP.verifiableCredential.map((vc) => vc['id'])).toEqual(['vc:delegated:1', 'vc:g-grandparent']);
        });

        it('still throws ConsentGrantNotFoundError when no agent in the chain holds a grant', async () => {
          vcService.listActiveBySubjectDid.mockResolvedValue([agentVC, delegatedVC([link('vc:parent', parentDid)])]);
          grantsByHolder({});

          await expect(
            agentService.signVP({ did: agentDid, targetService: serviceDid, userDid }, 'req-1'),
          ).rejects.toMatchObject({ code: 'CONSENT_GRANT_NOT_FOUND' });
        });
      });

      it('presents only the agent credential when no user is named', async () => {
        const { signedVP } = await agentService.signVP({ did: agentDid, targetService: serviceDid }, 'req-1');
        expect(vcService.listActiveGrants).not.toHaveBeenCalled();
        expect(signedVP.verifiableCredential).toHaveLength(1);
        expect(signedVP).not.toHaveProperty('delegatedBy');
      });
    });
  });

  describe('delegateAuthority', () => {
    const delegatorDid = 'did:key:z6Mktestdelegator';
    const subAgentDid = 'did:key:z6Mktestsubagent';
    const keyRecord = {
      did: delegatorDid,
      subjectType: 'agent',
      encryptedPrivateKey: 'x',
      iv: 'x',
      authTag: 'x',
      algorithm: 'aes-256-gcm',
    };

    // By default the delegatee is a registered, active agent; the tests
    // about the delegator override these per case.
    beforeEach(() => {
      vcService.listActiveBySubjectDid.mockResolvedValue([
        { id: 'vc:test:subagent', credentialSubject: { id: subAgentDid, privilegeScopes: ['read:profile'] } },
      ]);
    });
    const fromVC = {
      id: 'vc:test:delegator',
      type: ['VerifiableCredential', 'HelixAgentCredential'],
      credentialSubject: { id: delegatorDid, privilegeScopes: ['read:orders'], maxDelegationDepth: 1 },
    };

    describe('the delegatee must be a registered, active agent', () => {
      const delegate = () =>
        agentService.delegateAuthority(
          { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600, vcId: 'vc:test:delegator' },
          'req-1',
        );
      beforeEach(() => {
        vcService.findActiveByVcIdForSubject.mockResolvedValue(fromVC);
      });

      it('refuses a DID this server never onboarded, before signing anything', async () => {
        agentKeyRepository.findByDid.mockImplementation(async (did: string) => (did === delegatorDid ? keyRecord : null));
        await expect(delegate()).rejects.toMatchObject({ code: 'DELEGATEE_NOT_AN_AGENT', httpStatus: 404 });
        expect(keyCustody.signWith).not.toHaveBeenCalled();
        expect(vcService.registerSignedVC).not.toHaveBeenCalled();
      });

      it('refuses a DID whose key belongs to something other than an agent (e.g. a service)', async () => {
        agentKeyRepository.findByDid.mockImplementation(async (did: string) =>
          did === delegatorDid ? keyRecord : { ...keyRecord, did, subjectType: 'service' },
        );
        await expect(delegate()).rejects.toMatchObject({ code: 'DELEGATEE_NOT_AN_AGENT' });
      });

      it("hands the deployment's authorizeDelegatee the delegatee and the source credential, before reserving or signing", async () => {
        agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
        const seen: Array<{ to: string; fromVcId: string }> = [];
        await agentService.delegateAuthority(
          { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600, vcId: 'vc:test:delegator' },
          'req-1',
          {
            authorizeDelegatee: async ({ to, fromVC }) => {
              seen.push({ to, fromVcId: fromVC.id });
              expect(vcService.claimStatusListEntry).not.toHaveBeenCalled();
              expect(keyCustody.signWith).not.toHaveBeenCalled();
            },
          },
        );
        expect(seen).toEqual([{ to: subAgentDid, fromVcId: 'vc:test:delegator' }]);
      });

      it('a refusal from authorizeDelegatee stops the delegation before anything is reserved or signed', async () => {
        agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
        await expect(
          agentService.delegateAuthority(
            { did: delegatorDid, to: subAgentDid, scopes: ['read:orders'], expiresIn: 3600, vcId: 'vc:test:delegator' },
            'req-1',
            { authorizeDelegatee: async ({ to }) => Promise.reject(new DelegateeNotAnAgentError(to)) },
          ),
        ).rejects.toMatchObject({ code: 'DELEGATEE_NOT_AN_AGENT' });
        expect(vcService.claimStatusListEntry).not.toHaveBeenCalled();
        expect(keyCustody.signWith).not.toHaveBeenCalled();
        expect(vcService.registerSignedVC).not.toHaveBeenCalled();
      });

      it('refuses an agent that no longer holds an active credential', async () => {
        agentKeyRepository.findByDid.mockResolvedValue(keyRecord);
        vcService.listActiveBySubjectDid.mockResolvedValue([]);
        await expect(delegate()).rejects.toMatchObject({ code: 'DELEGATEE_NOT_AN_AGENT' });
        expect(vcService.listActiveBySubjectDid).toHaveBeenCalledWith(subAgentDid, 'HelixAgentCredential');
      });
    });

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
      // The delegator's credential is never looked up by subject when pinned
      // (the only subject lookup is the delegatee check).
      expect(vcService.listActiveBySubjectDid).not.toHaveBeenCalledWith(delegatorDid, 'HelixAgentCredential');
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
      // Its own revocation entry, signed into the credential, so the chain
      // walk can see this one delegation revoked.
      expect(vcService.claimStatusListEntry).toHaveBeenCalledTimes(1);
      expect((result.delegatedVC as { credentialStatus?: unknown }).credentialStatus).toEqual({
        id: 'http://localhost/v1/status-list/helix-status-list-1#42',
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '42',
        statusListCredential: 'http://localhost/v1/status-list/helix-status-list-1',
      });
      expect(vcService.registerSignedVC).toHaveBeenCalledWith(result.delegatedVC, { revokeExisting: undefined });
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
