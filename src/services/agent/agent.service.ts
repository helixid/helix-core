import { createHash, randomBytes } from 'node:crypto';
import {
  AgentAlreadyOnboardedError,
  ChallengeAlreadyVerifiedError,
  ChallengeExpiredError,
  ChallengeNotFoundError,
  ChallengeSignatureInvalidError,
  ErrorCode,
  HelixError,
  EnrollmentTokenAlreadyUsedError,
  EnrollmentTokenExpiredError,
  EnrollmentTokenNotFoundError,
  base58btcDecode,
  findScopeProblem,
  parseScopes,
  signBytes,
  verifySignature,
  publicDid,
  type AuditEventInput,
  type AuditTrail,
  type PartyRef,
  type SignedCapabilityAttestation,
  type SignedIdentityCredential,
} from '../../core/index.js';
import type { AgentRepository } from '../../repositories/agent.repository.js';
import type { DidKeyRepository } from '../../repositories/did-key.repository.js';
import type { IDIDService } from '../did/IDIDService.js';
import type { IVCService } from '../vc/IVCService.js';
import type { IKeyCustody } from '../key-custody/key-custody.js';
import type { CredentialService } from '../credentials/credential.service.js';
import type { IAgentService, ChallengeResult } from './IAgentService.js';

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
export function normalizeDomain(domain: string): string | null {
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


const DID_PATTERN = /^did:[^\r\n]+$/;

/** A `public_did` reference, or nothing when the value is not a DID: the event then names no party rather than failing validation. */
function didRef(value: string | undefined): PartyRef | undefined {
  return value !== undefined && DID_PATTERN.test(value) ? publicDid(value) : undefined;
}

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}

/** The `consentRef` an enrollment token is recorded by: the digest the token row is keyed on, never the token. */
function tokenRef(tokenHash: string): string {
  return `sha256:${tokenHash}`;
}

export class AgentService implements IAgentService {
  constructor(
    private readonly repository: AgentRepository,
    private readonly didService: IDIDService,
    private readonly vcService: IVCService,
    private readonly auditTrail: AuditTrail,
    private readonly agentKeyRepository: DidKeyRepository,
    private readonly keyCustody: IKeyCustody,
    /** Issues the split credentials of KYA-OS story F-1 at onboarding. */
    private readonly credentialService: CredentialService,
    private readonly enrollmentTokenTtlSeconds = 900,
    private readonly challengeTtlSeconds = 300,
  ) {}

  /** Records one typed audit event; a failure to record never breaks the request. */
  private audit(input: AuditEventInput): void {
    try {
      this.auditTrail.record(input).catch(reportAuditFailure);
    } catch (error) {
      reportAuditFailure(error);
    }
  }

  async generateEnrollmentToken(
    input: {
      agentName: string;
      requestedScopes: string[];
      requestedDomains?: string[];
      /**
       * Whole days until the token expires, at the same time of day as now.
       * null, undefined or '' means the token has no expiry.
       */
      expiry?: number | null;
    },
    requestId: string,
  ): Promise<{ token: string; expiresAt?: string }> {
    // A JSON body may leave it out; the token row needs it, so refuse here (400), not at the database (500).
    if (typeof input.agentName !== 'string' || input.agentName.trim() === '') {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'agentName is required', 400);
    }
    // '' can still arrive at runtime from a JSON body even though the type says number.
    const expiry = input.expiry === null || (input.expiry as unknown) === '' ? undefined : input.expiry;
    if (expiry !== undefined && !(Number.isInteger(expiry) && expiry > 0)) {
      throw Object.assign(new Error('expiry must be a positive whole number of days'), {
        code: 'INVALID_EXPIRY',
        httpStatus: 400,
      });
    }
    // Checked here, not only when the credential is issued, so a bad scope is
    // refused when the token is minted rather than at onboarding.
    const requestedScopes = Array.isArray(input.requestedScopes) ? parseScopes(input.requestedScopes) : [];
    const scopeProblem = Array.isArray(input.requestedScopes)
      ? findScopeProblem(requestedScopes)
      : 'requestedScopes must be an array';
    if (scopeProblem) {
      throw new HelixError(ErrorCode.VC_INVALID_PRIVILEGE_SCOPE, `Invalid scopes: ${scopeProblem}`, 400);
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
      requestedScopes: JSON.stringify(requestedScopes),
      requestedDomains: JSON.stringify(input.requestedDomains ?? []),
      maxDelegationDepth: 0,
      expiresAt: expiresAt ?? null,
    });
    this.audit({
      eventType: 'credential.required',
      action: { category: 'enrollment', name: 'token_generated' },
      outcome: 'succeeded',
      correlationId: requestId,
      details: { family: 'consent', phase: 'credential_required', consentRef: tokenRef(tokenHash) },
    });
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
    input: { enrollmentToken: string; domains?: string[]; ownerDid?: string },
    requestId: string,
  ): Promise<{
    agentDid: string;
    vcId: string;
    identity: SignedIdentityCredential;
    attestations: SignedCapabilityAttestation[];
  }> {
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
      input.ownerDid === undefined ? {} : { ownerDid: input.ownerDid },
    );

    await this.agentKeyRepository.create({ did: result.agentDid, subjectType: 'agent', ...encrypted });

    return { agentDid: result.agentDid, vcId: result.vcId, identity: result.identity, attestations: result.attestations };
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
      this.audit({
        eventType: 'credential.failed',
        action: { category: 'enrollment', name: 'token_rejected' },
        outcome: 'failed',
        correlationId: requestId,
        reason: { code: 'enrollment_token_expired' },
        details: { family: 'consent', phase: 'credential_failed', consentRef: tokenRef(tokenHash) },
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

    this.audit({
      eventType: 'credential.verified',
      action: { category: 'enrollment', name: 'token_consumed' },
      outcome: 'succeeded',
      correlationId: requestId,
      details: { family: 'consent', phase: 'credential_verified', consentRef: tokenRef(tokenHash) },
    });
    // The agent has no DID yet, so this challenge names no actor.
    this.audit({
      eventType: 'credential.required',
      action: { category: 'challenge', name: 'agent_onboarding' },
      outcome: 'succeeded',
      correlationId: requestId,
      details: { family: 'consent', phase: 'credential_required', consentRef: challengeId },
    });

    return {
      challengeId,
      nonce,
      expiresAt: expiresAt.toISOString(),
      didCreateSigningPayloadHex: didCreateRequest.signingPayloadHex,
    };
  }

  /**
   * Finishes onboarding: creates the DID, then issues the split credential
   * set of KYA-OS story F-1 — one identity credential (no scopes) naming
   * `ownerDid` as the responsible party, and one capability attestation per
   * scope the enrollment token asked for, signed by the Helix issuer. The
   * returned `vc` and `vcId` are the identity credential.
   */
  async processOnboardVerify(
    input: { challengeId: string; signature: string; didCreateSignature?: string },
    requestId: string,
    options: { ownerDid?: string } = {},
  ): Promise<{
    agentDid: string;
    vc: Record<string, unknown>;
    hederaTransactionId: string;
    vcId: string;
    identity: SignedIdentityCredential;
    attestations: SignedCapabilityAttestation[];
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
    const validUntil = enrollmentToken?.expiresAt ?? null;
    const identity = await this.credentialService.issueIdentity(
      {
        agentDid: didResult.did,
        name: agentName,
        ownerDid: options.ownerDid ?? this.credentialService.issuerDid,
        validUntil,
      },
      requestId,
    );
    const attestations = await this.credentialService.issueAttestations(
      { agentDid: didResult.did, capabilities: scopes, validUntil },
      requestId,
    );

    await this.repository.markChallengeVerified(input.challengeId);
    this.audit({
      eventType: 'credential.verified',
      action: { category: 'challenge', name: 'agent_onboarding' },
      outcome: 'succeeded',
      correlationId: requestId,
      actor: publicDid(didResult.did),
      details: { family: 'consent', phase: 'credential_verified', consentRef: input.challengeId },
    });
    this.audit({
      eventType: 'credential.verified',
      action: { category: 'onboarding', name: 'agent_onboarded' },
      outcome: 'succeeded',
      correlationId: requestId,
      actor: publicDid(didResult.did),
      details: { family: 'consent', phase: 'credential_verified', consentRef: identity.id },
    });

    return {
      agentDid: didResult.did,
      vc: identity as unknown as Record<string, unknown>,
      hederaTransactionId: didResult.hederaTransactionId,
      vcId: identity.id,
      identity,
      attestations,
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
    const actor = didRef(input.did);
    this.audit({
      eventType: 'credential.required',
      action: { category: 'challenge', name: input.purpose },
      outcome: 'succeeded',
      correlationId: requestId,
      ...(actor !== undefined ? { actor } : {}),
      details: { family: 'consent', phase: 'credential_required', consentRef: challengeId },
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
    const actor = didRef(challenge.did);
    this.audit({
      eventType: 'credential.verified',
      action: { category: 'challenge', name: 'user_verification' },
      outcome: 'succeeded',
      correlationId: requestId,
      ...(actor !== undefined ? { actor } : {}),
      details: { family: 'consent', phase: 'credential_verified', consentRef: challengeId },
    });
    this.audit({
      eventType: 'credential.verified',
      action: { category: 'user_verification' },
      outcome: 'succeeded',
      correlationId: requestId,
      ...(actor !== undefined ? { actor } : {}),
      details: { family: 'consent', phase: 'credential_verified' },
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
