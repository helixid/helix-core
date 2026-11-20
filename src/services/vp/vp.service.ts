import { randomBytes } from 'node:crypto';
import {
  DEFAULT_SIGNING_KEY_ENV_VAR,
  EnvSigner,
  HelixError,
  VPInvalidStructureError,
  VPVerificationFailedError,
  credentialDigest,
  delegationChainDigests,
  delegationRef,
  fetchStatusList,
  jsonDigest,
  issueJWT,
  publicDid,
  signedVPSchema,
  verifyVP as verifyVPCore,
  type AuditEventInput,
  type AuditTrail,
  type AuthorizationEvidence,
  type Digest,
  type EvidenceRef,
  type HelixJWTPayload,
  type PartyRef,
  type SignedVP,
  type Signer,
  type StatusListCredential,
  type StatusListResolver,
  type VerifyVPResult,
} from '../../core/index.js';
import type { IVCService } from '../vc/IVCService.js';
import type { IVPService, VPVerificationResult } from './IVPService.js';

type HelixHttpErrorLike = {
  code: string;
  httpStatus: number;
  message: string;
};

interface JWTSessionOptions {
  /** Ed25519 private key hex, as HELIX_SIGNING_KEY holds it. Used only through an EnvSigner. */
  signingKey: string;
  issuerDid: string;
  ttlSeconds: number;
}

const DID_PATTERN = /^did:[^\r\n]+$/;

/** A `public_did` reference, or nothing when the value is not a DID: the event then names no party rather than failing validation. */
function didRef(value: string | undefined): PartyRef | undefined {
  return value !== undefined && DID_PATTERN.test(value) ? publicDid(value) : undefined;
}

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}

/**
 * Who the rejected VP claimed to be from, read off the raw, unverified
 * payload on purpose: rejection can happen at schema parsing, before a parsed
 * value exists. Nothing else is taken from it; the read is guarded so a
 * malformed VP yields no actor instead of throwing out of the rejection audit.
 */
function readAttemptedHolder(signedVP: SignedVP): PartyRef | undefined {
  try {
    const holder = (signedVP as unknown as Record<string, unknown> | null | undefined)?.['holder'];
    return didRef(typeof holder === 'string' ? holder : undefined);
  } catch {
    return undefined;
  }
}

function isAgentCredential(credential: Record<string, unknown>): boolean {
  const type = credential['type'];
  return Array.isArray(type) && type.includes('HelixAgentCredential');
}

/** The credential's embedded chain root first, then the credential itself. */
function credentialChain(credential: Record<string, unknown>): unknown[] {
  const chain = credential['delegationChain'];
  return [...(Array.isArray(chain) ? chain : []), credential];
}

/**
 * SPEC section 7.8 evidence for a verified presentation: the presented agent
 * credential (the last one, as the verifier reads it) by reference and digest,
 * and one digest per credential evaluated, root first, in presentation order.
 */
function delegationEvidence(credentials: ReadonlyArray<Record<string, unknown>>): AuthorizationEvidence {
  const agentCredentials = credentials.filter(isAgentCredential);
  const presented = agentCredentials.at(-1);
  const ref = presented === undefined ? undefined : delegationRef(presented);
  const digest = presented === undefined ? undefined : credentialDigest(presented);
  const chainDigests = delegationChainDigests(agentCredentials.flatMap(credentialChain));
  return {
    source: 'delegation',
    decision: 'allowed',
    ...(ref !== undefined ? { delegationRef: ref } : {}),
    ...(digest !== undefined ? { delegationCredentialDigest: digest } : {}),
    ...(chainDigests !== undefined ? { delegationChainDigests: chainDigests } : {}),
  };
}

export class VPService implements IVPService {
  private readonly statusListResolver: StatusListResolver;

  constructor(
    private readonly vcService: IVCService,
    private readonly auditTrail: AuditTrail,
    apiBaseUrl: string,
    private readonly jwtSessionOptions?: JWTSessionOptions,
  ) {
    // §4.3 local-repo fast path: this API's own hosted lists are read straight
    // from the repository; everything else (SP-hosted lists included) goes
    // over HTTP exactly like any other verifier. Either way the result still
    // passes core's schema validation before getBit() — the fast path changes
    // how the bytes are obtained, not whether they're validated.
    const ownListPrefix = `${apiBaseUrl.replace(/\/$/, '')}/v1/status-list/`;
    this.statusListResolver = async (statusListUrl: string): Promise<StatusListCredential> => {
      if (statusListUrl.startsWith(ownListPrefix)) {
        const listId = decodeURIComponent(
          statusListUrl.slice(ownListPrefix.length).split(/[#?]/, 1)[0] ?? '',
        );
        return (await this.vcService.getStatusList(listId)) as StatusListCredential;
      }
      return fetchStatusList(statusListUrl);
    };
  }

  /** Records one typed audit event; a failure to record never breaks the request. */
  private audit(input: AuditEventInput): void {
    try {
      this.auditTrail.record(input).catch(reportAuditFailure);
    } catch (error) {
      reportAuditFailure(error);
    }
  }

  /**
   * `proof.rejected` with the error code as the reason. The exception text
   * is kept only as encrypted evidence; without a vault it is dropped, and it
   * never reaches the event itself.
   */
  private async auditRejection(
    requestId: string,
    code: string,
    internalReason: string,
    holder: PartyRef | undefined,
  ): Promise<void> {
    const reason: { code: string; detailRef?: EvidenceRef } = { code };
    try {
      reason.detailRef = await this.auditTrail.evidence(internalReason, 'text/plain', 'vp.rejection.reason');
    } catch {
      // No evidence vault: the message is dropped.
    }
    this.audit({
      eventType: 'proof.rejected',
      action: { category: 'presentation', name: 'vp_verified' },
      outcome: 'failed',
      correlationId: requestId,
      reason,
      ...(holder !== undefined ? { actor: holder } : {}),
      details: { family: 'proof', phase: 'rejected', verificationCode: code },
    });
  }

  /**
   * The session JWT is signed through the Signer interface (KYA-OS L1-C), so
   * issueJWT never reads a key itself. The API's key is the HELIX_SIGNING_KEY
   * secret the config loaded; the EnvSigner reads it from that one-entry
   * environment at each signature and holds nothing in between.
   */
  private sessionSigner(): Signer {
    const options = this.jwtSessionOptions!;
    return new EnvSigner({
      did: options.issuerDid,
      envVar: DEFAULT_SIGNING_KEY_ENV_VAR,
      env: { [DEFAULT_SIGNING_KEY_ENV_VAR]: options.signingKey },
    });
  }

  async verifyVP(
    signedVP: SignedVP,
    requestId: string,
    options: { issueSession?: boolean; expectedTargetService?: string; allowSelfSigned?: boolean } = {},
  ): Promise<VPVerificationResult> {
    let vpId = 'unknown';
    try {
      const parsed = signedVPSchema.safeParse(signedVP);
      if (!parsed.success) {
        throw new VPInvalidStructureError();
      }
      vpId = parsed.data.id;

      // Single verification implementation (§2.1): everything — VP checks,
      // credential checks, embedded delegation-chain walk, grant matching,
      // revocation — happens inside core's verifyVP().
      const result: VerifyVPResult = await verifyVPCore(parsed.data as SignedVP, {
        statusListResolver: this.statusListResolver,
        ...(options.expectedTargetService !== undefined
          ? { expectedTargetService: options.expectedTargetService }
          : {}),
        ...(options.allowSelfSigned !== undefined
          ? { allowSelfSigned: options.allowSelfSigned }
          : {}),
      });

      const verifiedAt = new Date().toISOString();
      // §7.3: exactly one proof.verified event after the core call returns — no
      // mid-verification chain-walk events. The VP is identified by its digest.
      const targetRef = didRef(parsed.data.targetService);
      const userRef = didRef(parsed.data.delegatedBy);
      this.audit({
        eventType: 'proof.verified',
        action: { category: 'presentation', name: 'vp_verified' },
        outcome: 'succeeded',
        correlationId: requestId,
        actor: publicDid(result.agentDid),
        ...(targetRef !== undefined ? { resource: targetRef } : {}),
        ...(userRef !== undefined ? { responsibleParty: userRef } : {}),
        authorization: delegationEvidence(parsed.data.verifiableCredential),
        details: {
          family: 'proof',
          phase: 'verified',
          proofDigest: jsonDigest(signedVP) as Digest,
          verificationCode: 'VP_VERIFIED',
        },
      });

      const response: VPVerificationResult = {
        valid: true,
        agentDid: result.agentDid,
        targetService: parsed.data.targetService,
        verifiedAt,
        privilegeScopes: result.privilegeScopes,
        effectiveScopes: result.effectiveScopes,
        vpId: result.vpId,
        delegationChain: result.delegationChain,
        ...(result.warning !== undefined ? { warning: result.warning } : {}),
      };
      if (parsed.data.delegatedBy !== undefined) {
        response.userDid = parsed.data.delegatedBy;
      }

      if (options.issueSession) {
        if (!this.jwtSessionOptions) {
          throw new Error('jwt_session_not_configured');
        }
        const nowSeconds = Math.floor(Date.now() / 1000);
        const expiresAtSeconds = nowSeconds + this.jwtSessionOptions.ttlSeconds;
        const payload: HelixJWTPayload = {
          iss: this.jwtSessionOptions.issuerDid,
          sub: result.agentDid,
          iat: nowSeconds,
          exp: expiresAtSeconds,
          jti: `jwt:${randomBytes(16).toString('hex')}`,
          userDid: parsed.data.delegatedBy ?? result.agentDid,
          targetService: parsed.data.targetService,
          // §2.7 / §9.4 A2: the session carries enforcement scopes — the grant
          // intersection when a grant was presented, not the raw VC scopes.
          scopes: result.effectiveScopes,
          vpId,
        };
        const token = await issueJWT(payload, this.sessionSigner());
        const sessionExpiresAt = new Date(expiresAtSeconds * 1000).toISOString();
        // The session is named by a commitment to its jti, never the jti or the token.
        const sessionUserRef = didRef(payload.userDid);
        this.audit({
          eventType: 'session.established',
          action: { category: 'session', name: 'jwt_issued' },
          outcome: 'succeeded',
          correlationId: requestId,
          actor: publicDid(payload.sub),
          ...(targetRef !== undefined ? { resource: targetRef } : {}),
          ...(sessionUserRef !== undefined ? { responsibleParty: sessionUserRef } : {}),
          session: { ref: { kind: 'keyed_commitment', value: jsonDigest(payload.jti) as Digest, keyId: 'jwt-jti-v1' } },
          details: { family: 'session', phase: 'established' },
        });
        response.session = {
          token,
          expiresAt: sessionExpiresAt,
          publicKeyEndpoint: '/v1/sessions/public-key',
        };
      }

      return response;
    } catch (error) {
      const internalReason =
        error instanceof Error
          ? `${error.message}${'code' in error ? ` [code=${(error as { code?: string }).code}]` : ''}`
          : String(error);
      // §7.3: exactly one proof.rejected event; the failure code is the
      // reason, the message is evidence at most.
      const code = error instanceof HelixError ? error.code : 'VP_VERIFICATION_FAILED';
      void this.auditRejection(requestId, code, internalReason, readAttemptedHolder(signedVP));
      // Preserve the specific failure (expired, revoked, signature invalid,
      // wrong target service, etc.) for the caller — parity with local
      // verifyVP(), which throws these directly. Only genuinely unexpected
      // (non-HelixError) failures collapse to the generic error, so we don't
      // leak internals we don't recognize as a stable, intentional error type.
      if (error instanceof HelixError) {
        throw error;
      }
      throw new VPVerificationFailedError();
    }
  }
}

export function mapErrorToResponse(error: unknown): {
  statusCode: number;
  code: string;
  message: string;
} {
  if (error && typeof error === 'object' && 'code' in error && 'httpStatus' in error) {
    const typed = error as HelixHttpErrorLike;
    return { statusCode: typed.httpStatus, code: typed.code, message: typed.message };
  }
  return { statusCode: 500, code: 'INTERNAL_ERROR', message: 'Internal server error' };
}
