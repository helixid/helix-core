import { createHash, randomBytes } from 'node:crypto';
import {
  AgentAlreadyOnboardedError,
  AgentActiveCredentialNotFoundError,
  AgentKeyNotFoundError,
  AuditEvents,
  ChallengeAlreadyVerifiedError,
  ChallengeExpiredError,
  ChallengeNotFoundError,
  ChallengeSignatureInvalidError,
  ErrorCode,
  EnrollmentTokenAlreadyUsedError,
  EnrollmentTokenExpiredError,
  EnrollmentTokenNotFoundError,
  base58btcDecode,
  signBytes,
  verifySignature,
  VPBuilder,
  type HelixError,
  type IAuditLogger,
  type SignedVC,
  type SignedVP,
} from '../../core/index.js';
import type { AgentRepository } from '../../repositories/agent.repository.js';
import type { AgentKeyRepository } from '../../repositories/agent-key.repository.js';
import type { IDIDService } from '../did/IDIDService.js';
import type { IVCService } from '../vc/IVCService.js';
import type { IKeyCustody } from '../key-custody/key-custody.js';
import type {
  IAgentService,
  ChallengeResult,
} from './IAgentService.js';

type DIDVerificationMethodLike = {
  type?: unknown;
  publicKeyHex?: unknown;
  publicKeyMultibase?: unknown;
};

type DIDDocumentLike = {
  verificationMethod?: DIDVerificationMethodLike[];
};

type DIDResolveLike = DIDDocumentLike & {
  document?: DIDDocumentLike;
  didDocument?: DIDDocumentLike;
};

/**
 * sha256 hex of an enrollment/bootstrap token — exported so a downstream
 * product needing to attribute a token/challenge/VC back to something it
 * tracks itself (e.g. a hosted account) can independently derive the same
 * lookup key this service uses internally, without this service needing to
 * know that concept exists.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

function ensureHttps(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}

function extractPublicKeyHex(doc: Awaited<ReturnType<IDIDService['resolveDID']>>): string {
  const wrapped = doc as DIDResolveLike;
  const document = wrapped.document ?? wrapped.didDocument ?? wrapped;
  const method = document.verificationMethod?.find(
    (item) => typeof item.type === 'string' && item.type.includes('Ed25519'),
  );
  if (!method) {
    throw new ChallengeSignatureInvalidError();
  }
  if (typeof method.publicKeyHex === 'string') {
    return method.publicKeyHex;
  }
  if (typeof method.publicKeyMultibase === 'string' && method.publicKeyMultibase.startsWith('z')) {
    const decoded = base58btcDecode(method.publicKeyMultibase.slice(1));
    return Buffer.from(decoded.slice(2)).toString('hex');
  }
  throw new ChallengeSignatureInvalidError();
}

export class AgentService implements IAgentService {
  constructor(
    private readonly repository: AgentRepository,
    private readonly didService: IDIDService,
    private readonly vcService: IVCService,
    private readonly auditLogger: IAuditLogger,
    private readonly agentKeyRepository: AgentKeyRepository,
    private readonly keyCustody: IKeyCustody,
    private readonly enrollmentTokenTtlSeconds = 900,
    private readonly challengeTtlSeconds = 300,
  ) {}

  async generateEnrollmentToken(
    input: {
      agentName: string;
      requestedScopes: string[];
      requestedDomains?: string[];
      maxDelegationDepth?: number;
    },
    requestId: string,
  ): Promise<{ token: string; expiresAt: string }> {
    const token = `enroll:${randomBytes(12).toString('hex')}`;
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + this.enrollmentTokenTtlSeconds * 1000);
    await this.repository.createEnrollmentToken({
      tokenHash,
      agentName: input.agentName,
      requestedScopes: JSON.stringify(input.requestedScopes),
      requestedDomains: JSON.stringify(input.requestedDomains ?? []),
      maxDelegationDepth: input.maxDelegationDepth ?? 0,
      expiresAt,
    });
    this.auditLogger.log(AuditEvents.ENROLLMENT_TOKEN_GENERATED, {
      requestId,
      tokenIdHash: tokenHash,
      agentName: input.agentName,
      requestedScopes: input.requestedScopes,
      expiresAt: expiresAt.toISOString(),
    });
    return { token, expiresAt: expiresAt.toISOString() };
  }

  /**
   * Single-call, server-custody onboarding. Agent self-custody has been
   * retired — the server generates the keypair itself (via `keyCustody`)
   * and internally drives the same processOnboardStep1/processOnboardVerify
   * pair a self-custody caller used to drive over two client round trips,
   * self-signing both the challenge nonce and (for did:hedera) the DID
   * creation payload. The resulting private key is stored encrypted in
   * `agentKeyRepository`, never returned to the caller.
   */
  async onboardWithCustody(
    input: { enrollmentToken: string; domains?: string[] },
    requestId: string,
  ): Promise<{ agentDid: string; vcId: string }> {
    const { publicKey, encrypted } = this.keyCustody.generateAndEncrypt();

    const challenge = await this.processOnboardStep1(
      {
        enrollmentToken: input.enrollmentToken,
        publicKeyHex: publicKey,
        ...(input.domains ? { domains: input.domains } : {}),
      },
      requestId,
    );

    const signature = await this.keyCustody.signWith(encrypted, (privateKeyHex) =>
      signBytes(Buffer.from(challenge.nonce, 'hex'), privateKeyHex),
    );
    const didCreateSignature = challenge.didCreateSigningPayloadHex
      ? await this.keyCustody.signWith(encrypted, (privateKeyHex) =>
          signBytes(Buffer.from(challenge.didCreateSigningPayloadHex!, 'hex'), privateKeyHex),
        )
      : undefined;

    const result = await this.processOnboardVerify(
      {
        challengeId: challenge.challengeId,
        signature,
        ...(didCreateSignature ? { didCreateSignature } : {}),
      },
      requestId,
    );

    await this.agentKeyRepository.create({ did: result.agentDid, ...encrypted });

    return { agentDid: result.agentDid, vcId: result.vcId };
  }

  /**
   * Signs a VP on behalf of a server-custody agent — the caller never has,
   * and never can have, the private key, so "present a VP" is an API call
   * instead of a local VPBuilder.sign(). By default looks up the agent's
   * one active HelixAgentCredential itself; pass `vcId` to pin a specific
   * credential instead (e.g. when more than one active VC exists for the
   * DID, which findActiveBySubjectDid rejects as ambiguous). An optional
   * `grantVC` (an SP-issued DelegationGrantCredential the caller already
   * holds — not secret material, just data to include) is passed straight
   * through to VPBuilder's second credential slot, for the consent-grant
   * flow (spec §2a): the grant itself is never held or looked up
   * server-side, only composed into the VP being signed.
   */
  async signVP(
    input: { did: string; targetService: string; userDid?: string; grantVC?: SignedVC; vcId?: string },
    requestId: string,
  ): Promise<{ signedVP: SignedVP }> {
    const keyRecord = await this.agentKeyRepository.findByDid(input.did);
    if (!keyRecord) {
      throw new AgentKeyNotFoundError(input.did);
    }

    const vcJson = input.vcId
      ? await this.vcService.findActiveByVcIdForSubject(input.vcId, input.did, 'HelixAgentCredential')
      : await this.vcService.findActiveBySubjectDid(input.did, 'HelixAgentCredential');
    if (!vcJson) {
      throw new AgentActiveCredentialNotFoundError(input.did);
    }

    const credentials = input.grantVC ? [vcJson as SignedVC, input.grantVC] : [vcJson as SignedVC];
    const signedVP = await this.keyCustody.signWith(keyRecord, (privateKeyHex) =>
      new VPBuilder({
        credentials,
        holderDid: input.did,
        ...(input.userDid ? { userDid: input.userDid } : {}),
        targetService: input.targetService,
      }).sign(privateKeyHex, `${input.did}#key-1`),
    );

    this.auditLogger.log(AuditEvents.AGENT_VP_SIGNED, {
      requestId,
      agentDid: input.did,
      targetService: input.targetService,
    });

    return { signedVP };
  }

  async processOnboardStep1(
    input: { enrollmentToken: string; publicKeyHex: string; domains?: string[] },
    requestId: string,
  ): Promise<ChallengeResult> {
    if (!/^[0-9a-f]{64}$/i.test(input.publicKeyHex)) {
      throw Object.assign(new Error('Invalid public key'), {
        code: 'INVALID_PUBLIC_KEY',
        httpStatus: 400,
      });
    }
    for (const domain of input.domains ?? []) {
      if (!ensureHttps(domain)) {
        throw Object.assign(new Error('Invalid domain URL'), {
          code: 'INVALID_SERVICE_ENDPOINT_URL',
          httpStatus: 400,
        });
      }
    }

    const tokenHash = hashToken(input.enrollmentToken);
    const tokenRecord = await this.repository.findEnrollmentTokenByHash(tokenHash);
    if (!tokenRecord) {
      throw new EnrollmentTokenNotFoundError();
    }
    if (tokenRecord.usedAt) {
      throw new EnrollmentTokenAlreadyUsedError();
    }
    if (tokenRecord.expiresAt.getTime() <= Date.now()) {
      this.auditLogger.log(AuditEvents.ENROLLMENT_TOKEN_REJECTED, {
        requestId,
        tokenIdHash: tokenHash,
        reason: 'expired',
        timestamp: new Date().toISOString(),
      });
      throw new EnrollmentTokenExpiredError();
    }

    const burned = await this.repository.burnEnrollmentTokenAtomically(tokenHash);
    if (!burned) {
      throw new EnrollmentTokenAlreadyUsedError();
    }

    let didCreateRequest;
    try {
      didCreateRequest = await this.didService.prepareDIDCreation(input.publicKeyHex);
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error) {
        throw error;
      }
      const message = error instanceof Error ? error.message : 'Hedera DID creation request failed';
      throw Object.assign(new Error(message), {
        code: ErrorCode.HEDERA_ANCHOR_FAILED,
        httpStatus: 502,
      });
    }
    const challengeId = `chal:${randomBytes(8).toString('hex')}`;
    const nonce = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + this.challengeTtlSeconds * 1000);
    await this.repository.createChallenge({
      challengeId,
      nonce,
      did: '',
      purpose: 'agent_onboarding',
      pendingPublicKeyHex: input.publicKeyHex,
      pendingDomains: JSON.stringify(input.domains ?? []),
      pendingDidCreateStateJson: didCreateRequest.stateJson,
      pendingDidCreatePayloadHex: didCreateRequest.signingPayloadHex,
      expiresAt,
      enrollmentTokenId: tokenRecord.id,
    });

    this.auditLogger.log(AuditEvents.ENROLLMENT_TOKEN_CONSUMED, {
      requestId,
      tokenIdHash: tokenHash,
      timestamp: new Date().toISOString(),
    });
    this.auditLogger.log(AuditEvents.CHALLENGE_ISSUED, {
      requestId,
      challengeId,
      did: '',
      purpose: 'agent_onboarding',
      expiresAt: expiresAt.toISOString(),
    });

    return {
      challengeId,
      nonce,
      expiresAt: expiresAt.toISOString(),
      didCreateSigningPayloadHex: didCreateRequest.signingPayloadHex,
    };
  }

  async processOnboardVerify(
    input: { challengeId: string; signature: string; didCreateSignature?: string },
    requestId: string,
  ): Promise<{
    agentDid: string;
    vc: Record<string, unknown>;
    hederaTransactionId: string;
    vcId: string;
  }> {
    const challenge = await this.repository.findChallengeById(input.challengeId);
    if (!challenge || challenge.purpose !== 'agent_onboarding') {
      throw new ChallengeNotFoundError();
    }
    if (challenge.expiresAt.getTime() <= Date.now()) {
      throw new ChallengeExpiredError();
    }
    if (challenge.verifiedAt) {
      throw new ChallengeAlreadyVerifiedError();
    }
    if (!/^[0-9a-f]{128}$/i.test(input.signature)) {
      throw new ChallengeSignatureInvalidError();
    }
    const validSignature = await verifySignature(
      Buffer.from(challenge.nonce, 'hex'),
      input.signature,
      challenge.pendingPublicKeyHex ?? '',
    );
    if (!validSignature) {
      throw new ChallengeSignatureInvalidError();
    }
    if (
      challenge.pendingDidCreateStateJson &&
      !/^[0-9a-f]{128}$/i.test(input.didCreateSignature ?? '')
    ) {
      throw new ChallengeSignatureInvalidError('DID creation signature is invalid');
    }

    const enrollmentToken = challenge.enrollmentTokenId
      ? await this.repository.findEnrollmentTokenById(challenge.enrollmentTokenId)
      : null;

    let didResult;
    try {
      didResult = await this.didService.createDID(
        challenge.pendingPublicKeyHex ?? '',
        'agent',
        JSON.parse(challenge.pendingDomains ?? '[]') as string[],
        requestId,
        challenge.pendingDidCreateStateJson && input.didCreateSignature
          ? {
              stateJson: challenge.pendingDidCreateStateJson,
              signatureHex: input.didCreateSignature,
            }
          : undefined,
      );
    } catch (error) {
      if (
        error &&
        typeof error === 'object' &&
        'code' in error &&
        error.code === ErrorCode.DID_ALREADY_EXISTS
      ) {
        throw new AgentAlreadyOnboardedError();
      }
      throw error;
    }

    const scopes = enrollmentToken
      ? (JSON.parse(enrollmentToken.requestedScopes) as string[])
      : ['read:orders'];
    const agentName = enrollmentToken?.agentName ?? 'Agent';
    const vc = await this.vcService.issueVC(
      {
        subjectDid: didResult.did,
        subjectType: 'agent',
        privilegeScopes: scopes,
        agentName,
        delegationDepth: 0,
        maxDelegationDepth: enrollmentToken?.maxDelegationDepth ?? 0,
        expiresInSeconds: this.enrollmentTokenTtlSeconds * 100,
      },
      requestId,
    );

    await this.repository.markChallengeVerified(input.challengeId);
    this.auditLogger.log(AuditEvents.CHALLENGE_VERIFIED, {
      requestId,
      challengeId: input.challengeId,
      did: didResult.did,
      purpose: 'agent_onboarding',
      success: true,
    });
    this.auditLogger.log(AuditEvents.AGENT_ONBOARDED, {
      requestId,
      agentDid: didResult.did,
      agentName,
      hederaTransactionId: didResult.hederaTransactionId,
    });

    return {
      agentDid: didResult.did,
      vc: vc.vc,
      hederaTransactionId: didResult.hederaTransactionId,
      vcId: vc.vcId,
    };
  }

  async issueUserChallenge(
    input: { did: string; purpose: 'user_verification' },
    requestId: string,
  ): Promise<ChallengeResult> {
    await this.didService.resolveDID(input.did);
    const challengeId = `chal:${randomBytes(8).toString('hex')}`;
    const nonce = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + this.challengeTtlSeconds * 1000);
    await this.repository.createChallenge({
      challengeId,
      nonce,
      did: input.did,
      purpose: 'user_verification',
      pendingPublicKeyHex: null,
      pendingDomains: null,
      expiresAt,
      enrollmentTokenId: null,
    });
    this.auditLogger.log(AuditEvents.CHALLENGE_ISSUED, {
      requestId,
      challengeId,
      did: input.did,
      purpose: input.purpose,
      expiresAt: expiresAt.toISOString(),
    });
    return { challengeId, nonce, expiresAt: expiresAt.toISOString() };
  }

  async verifyUserChallenge(
    challengeId: string,
    input: { signature: string },
    requestId: string,
  ): Promise<{ did: string; verified: true; vc?: Record<string, unknown> }> {
    const challenge = await this.repository.findChallengeById(challengeId);
    if (!challenge || challenge.purpose !== 'user_verification') {
      throw new ChallengeNotFoundError();
    }
    if (challenge.expiresAt.getTime() <= Date.now()) {
      throw new ChallengeExpiredError();
    }
    if (challenge.verifiedAt) {
      throw new ChallengeAlreadyVerifiedError();
    }
    if (!/^[0-9a-f]{128}$/i.test(input.signature)) {
      throw new ChallengeSignatureInvalidError();
    }
    const didDocument = await this.didService.resolveDID(challenge.did);
    const publicKeyHex = extractPublicKeyHex(didDocument);
    const validSignature = await verifySignature(
      Buffer.from(challenge.nonce, 'hex'),
      input.signature,
      publicKeyHex,
    );
    if (!validSignature) {
      throw new ChallengeSignatureInvalidError();
    }
    await this.repository.markChallengeVerified(challengeId);
    let vc = await this.vcService.findActiveBySubjectDid(challenge.did);
    if (!vc) {
      const issued = await this.vcService.issueVC(
        {
          subjectDid: challenge.did,
          subjectType: 'user',
          userId: challenge.did,
          expiresInSeconds: 7_776_000,
        },
        requestId,
      );
      vc = issued.vc;
    }
    this.auditLogger.log(AuditEvents.CHALLENGE_VERIFIED, {
      requestId,
      challengeId,
      did: challenge.did,
      purpose: 'user_verification',
      success: true,
    });
    this.auditLogger.log(AuditEvents.USER_DID_VERIFIED, {
      requestId,
      userDid: challenge.did,
      timestamp: new Date().toISOString(),
    });
    return { did: challenge.did, verified: true, vc };
  }

}

export function mapAgentError(error: unknown): {
  statusCode: number;
  code: string;
  message: string;
} {
  if (error && typeof error === 'object' && 'code' in error && 'httpStatus' in error) {
    const typed = error as HelixError;
    return { statusCode: typed.httpStatus, code: typed.code, message: typed.message };
  }
  return { statusCode: 500, code: 'INTERNAL_ERROR', message: 'Internal server error' };
}
