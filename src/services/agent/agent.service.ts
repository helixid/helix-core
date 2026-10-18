import { createHash, randomBytes } from 'node:crypto';
import {
  buildDelegationVC,
  AgentAlreadyOnboardedError,
  AgentActiveCredentialNotFoundError,
  AgentKeyNotFoundError,
  AuditEvents,
  ChallengeAlreadyVerifiedError,
  ChallengeExpiredError,
  ChallengeNotFoundError,
  ChallengeSignatureInvalidError,
  ConsentGrantNotFoundError,
  ErrorCode,
  HelixError,
  EnrollmentTokenAlreadyUsedError,
  EnrollmentTokenExpiredError,
  EnrollmentTokenNotFoundError,
  base58btcDecode,
  signBytes,
  verifySignature,
  VPBuilder,
  VPMultipleActiveVCError,
  type IAuditLogger,
  type SignedVC,
  type SignedVP,
} from '../../core/index.js';
import type { AgentRepository } from '../../repositories/agent.repository.js';
import type { DidKeyRepository } from '../../repositories/did-key.repository.js';
import type { IDIDService } from '../did/IDIDService.js';
import type { IVCService } from '../vc/IVCService.js';
import type { IKeyCustody } from '../key-custody/key-custody.js';
import type {
  IAgentService,
  ChallengeResult,
  DelegateAuthorityResult,
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

/**
 * Accepts `http(s)://host[...]` or a bare host like `example.com` (assumed
 * https). Returns the normalized URL, or null if it isn't a usable web URL.
 */
function normalizeDomain(domain: string): string | null {
  const trimmed = domain.trim();
  if (!trimmed) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const url = new URL(candidate);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.hostname ? candidate : null;
  } catch {
    return null;
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
    private readonly agentKeyRepository: DidKeyRepository,
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
      /**
       * Whole days until the token expires, at the same time of day as now.
       * null, undefined or '' means the token has no expiry.
       */
      expiry?: number | null;
    },
    requestId: string,
  ): Promise<{ token: string; expiresAt?: string }> {
    // '' can still arrive at runtime from a JSON body even though the type says number.
    const expiry = input.expiry === null || (input.expiry as unknown) === '' ? undefined : input.expiry;
    if (expiry !== undefined && !(Number.isInteger(expiry) && expiry > 0)) {
      throw Object.assign(new Error('expiry must be a positive whole number of days'), {
        code: 'INVALID_EXPIRY',
        httpStatus: 400,
      });
    }
    const token = `enroll:${randomBytes(12).toString('hex')}`;
    const tokenHash = hashToken(token);
    let expiresAt: Date | undefined;
    if (expiry !== undefined) {
      expiresAt = new Date();
      // Calendar-day arithmetic keeps the wall-clock time (4 PM + 1 day -> 4 PM tomorrow) across DST changes.
      expiresAt.setDate(expiresAt.getDate() + expiry);
    }
    await this.repository.createEnrollmentToken({
      tokenHash,
      agentName: input.agentName,
      requestedScopes: JSON.stringify(input.requestedScopes),
      requestedDomains: JSON.stringify(input.requestedDomains ?? []),
      maxDelegationDepth: input.maxDelegationDepth ?? 0,
      expiresAt: expiresAt ?? null,
    });
    // this.auditLogger.log(AuditEvents.ENROLLMENT_TOKEN_GENERATED, {
    //   requestId,
    //   tokenIdHash: tokenHash,
    //   agentName: input.agentName,
    //   requestedScopes: input.requestedScopes,
    //   expiresAt: expiresAt.toISOString(),
    // });
    return { token, ...(expiresAt ? { expiresAt: expiresAt.toISOString() } : {}) };
  }

  /**
   * Single-call, server-custody onboarding. Agent self-custody has been
   * retired — the server generates the keypair itself (via `keyCustody`)
   * and internally drives the same processOnboardCreateChallenge/processOnboardVerify
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

    const challenge = await this.processOnboardCreateChallenge(
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

    await this.agentKeyRepository.create({ did: result.agentDid, subjectType: 'agent', ...encrypted });

    return { agentDid: result.agentDid, vcId: result.vcId };
  }

  /**
   * Signs a VP on behalf of a server-custody agent — the caller never has,
   * and never can have, the private key, so "present a VP" is an API call
   * instead of a local VPBuilder.sign(). By default looks up the agent's
   * one active HelixAgentCredential itself; pass `vcId` to pin a specific
   * credential instead (e.g. when more than one active VC exists for the
   * DID, which findActiveBySubjectDid rejects as ambiguous).
   *
   * The VP carries every active HelixAgentCredential the agent holds (its
   * own, plus any delegated to it) -- the verifier takes the union of their
   * scopes -- or just the one named by `vcId`.
   *
   * `targetService` is the DID of the service the VP is for. With a
   * `userDid`, the VP is the agent acting on that user's behalf, and the
   * consent that allows it is looked up here: every active
   * DelegationGrantCredential that service issued to this agent for that
   * user goes into the VP (the verifier takes the union of their scopes).
   * No such grant means the user has not consented, and the caller should
   * send them to the service's consent screen. A caller that already holds
   * a grant may pass it as `grantVC` instead, bypassing the lookup.
   */
  async signVP(
    input: { did: string; targetService: string; userDid?: string; grantVC?: SignedVC; vcId?: string },
    requestId: string,
  ): Promise<{ signedVP: SignedVP }> {
    if (typeof input.targetService !== 'string' || !input.targetService.startsWith('did:')) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'targetService must be the service DID', 400);
    }

    const keyRecord = await this.agentKeyRepository.findByDid(input.did);
    if (!keyRecord) {
      throw new AgentKeyNotFoundError(input.did);
    }

    const agentVCs = (
      input.vcId
        ? [await this.vcService.findActiveByVcIdForSubject(input.vcId, input.did, 'HelixAgentCredential')]
        : await this.vcService.listActiveBySubjectDid(input.did, 'HelixAgentCredential')
    ).filter((vc): vc is Record<string, unknown> => vc !== null) as SignedVC[];
    if (agentVCs.length === 0) {
      throw new AgentActiveCredentialNotFoundError(input.did);
    }

    let grants: SignedVC[] = input.grantVC ? [input.grantVC] : [];
    if (!input.grantVC && input.userDid) {
      grants = await this.vcService.listActiveGrants({
        agentDid: input.did,
        serviceDid: input.targetService,
        userDid: input.userDid,
      });
      if (grants.length === 0) {
        throw new ConsentGrantNotFoundError(input.did, input.targetService, input.userDid);
      }
    }

    const credentials = [...agentVCs, ...grants];
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
      ...(input.userDid ? { userDid: input.userDid } : {}),
      vcIds: agentVCs.map((vc) => vc.id),
      grantVcIds: grants.map((grant) => grant.id),
    });

    return { signedVP };
  }

  /**
   * Delegates a slice of a server-custody agent's authority to another DID —
   * the custodial counterpart to the SDK's local delegate(), which needs a
   * wallet's own private key and so has had nothing legitimate to call since
   * agent self-custody was retired (see helix-sdk-js's delegation.ts and
   * helix-sdk-py's agent_delegation_demo.py for the prior state of that gap).
   *
   * Mirrors signVP() exactly: same key lookup, same "which active credential"
   * resolution (default to the one active HelixAgentCredential, or pin one
   * via vcId when more than one exists -- e.g. this agent already holds a
   * VC delegated to it, alongside its own onboarding VC).
   */
  async delegateAuthority(
    input: { did: string; to: string; scopes: string[]; expiresIn: number; vcId?: string; revokeExisting?: boolean },
    requestId: string,
  ): Promise<DelegateAuthorityResult> {
    const keyRecord = await this.agentKeyRepository.findByDid(input.did);
    if (!keyRecord) {
      throw new AgentKeyNotFoundError(input.did);
    }

    const fromVC = input.vcId
      ? await this.vcService.findActiveByVcIdForSubject(input.vcId, input.did, 'HelixAgentCredential')
      : await this.resolveDelegationSourceVC(input.did, input.scopes);
    if (!fromVC) {
      throw new AgentActiveCredentialNotFoundError(input.did);
    }

    // buildDelegationVC() does the scope-subset and max-depth checks and
    // signs with the custody-held key, all in-process -- there is no
    // prepare/finalize round trip because nobody outside holds a key.
    const delegatedVC = await this.keyCustody.signWith(keyRecord, (privateKeyHex) =>
      buildDelegationVC(
        { to: input.to, scopes: input.scopes, expiresIn: input.expiresIn, fromVC: fromVC as SignedVC },
        { did: input.did, privateKeyHex },
      ),
    );

    // Without this, the delegate DID could never be looked up again by
    // vcId/subjectDid, so a second hop of delegation would always fail.
    // registerSignedVC() stores it as-is, already signed by the delegator,
    // and applies the one-credential-per-scope-set rule against whatever
    // this delegator already delegated to the same DID.
    const reconciled = await this.vcService.registerSignedVC(delegatedVC, {
      revokeExisting: input.revokeExisting,
    });

    this.auditLogger.log(AuditEvents.VC_DELEGATED, {
      requestId,
      delegatorDid: input.did,
      delegateDid: input.to,
      scopes: input.scopes,
      delegatedVcId: delegatedVC.id,
      ...reconciled,
    });

    return { delegatedVC, ...reconciled };
  }

  /**
   * Picks which of `did`'s active HelixAgentCredentials to delegate from
   * when the caller didn't pin one via vcId — needed once an agent can hold
   * more than one (its own onboarding VC, plus whatever it's been delegated)
   * for delegateAuthority()'s default, no-vcId path to still work past the
   * first hop. Eligible means: covers every scope being delegated, and has
   * remaining delegation budget (delegationDepth + 1 <= maxDelegationDepth).
   * Exactly one eligible candidate is the expected, common case; zero means
   * "no active credential lets you do this" (same AgentActiveCredentialNotFoundError
   * the caller would see for a nonexistent VC); more than one is genuine
   * ambiguity this can't resolve on the caller's behalf (e.g. two separately
   * delegated grants both cover the requested scopes) -- vcId is how the
   * caller breaks that tie explicitly.
   */
  private async resolveDelegationSourceVC(
    did: string,
    requestedScopes: string[],
  ): Promise<Record<string, unknown> | null> {
    const candidates = await this.vcService.listActiveBySubjectDid(did, 'HelixAgentCredential');
    const eligible = candidates.filter((vc) => {
      const subject = (vc as { credentialSubject?: Record<string, unknown> }).credentialSubject ?? {};
      const scopes = Array.isArray(subject['privilegeScopes']) ? (subject['privilegeScopes'] as string[]) : [];
      const hasAllScopes = requestedScopes.every((scope) => scopes.includes(scope));
      const depth = typeof subject['delegationDepth'] === 'number' ? (subject['delegationDepth'] as number) : 0;
      const maxDepth =
        typeof subject['maxDelegationDepth'] === 'number' ? (subject['maxDelegationDepth'] as number) : 0;
      return hasAllScopes && depth + 1 <= maxDepth;
    });

    if (eligible.length === 0) return null;
    if (eligible.length === 1) return eligible[0]!;
    throw new VPMultipleActiveVCError(
      `Multiple eligible credentials found for ${did} to delegate ${requestedScopes.join(', ')} from -- pass vcId to pick one explicitly`,
    );
  }

  async processOnboardCreateChallenge(
    input: { enrollmentToken: string; publicKeyHex: string; domains?: string[] },
    requestId: string,
  ): Promise<ChallengeResult> {
    if (!/^[0-9a-f]{64}$/i.test(input.publicKeyHex)) {
      throw Object.assign(new Error('Invalid public key'), {
        code: 'INVALID_PUBLIC_KEY',
        httpStatus: 400,
      });
    }
    const domains: string[] = [];
    for (const domain of input.domains ?? []) {
      const normalized = normalizeDomain(domain);
      if (!normalized) {
        throw Object.assign(new Error('Invalid domain URL'), {
          code: 'INVALID_SERVICE_ENDPOINT_URL',
          httpStatus: 400,
        });
      }
      domains.push(normalized);
    }

    const tokenHash = hashToken(input.enrollmentToken);
    const tokenRecord = await this.repository.findEnrollmentTokenByHash(tokenHash);
    if (!tokenRecord) {
      throw new EnrollmentTokenNotFoundError();
    }
    if (tokenRecord.usedAt) {
      throw new EnrollmentTokenAlreadyUsedError();
    }
    if (tokenRecord.expiresAt && tokenRecord.expiresAt.getTime() <= Date.now()) {
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
      pendingDomains: JSON.stringify(domains),
      pendingDidCreateStateJson: didCreateRequest.stateJson,
      pendingDidCreatePayloadHex: didCreateRequest.signingPayloadHex,
      expiresAt,
      enrollmentTokenId: tokenRecord.id,
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
        expiresAt: enrollmentToken?.expiresAt ?? null,
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
