import type { SignedVC, SignedVP } from '../../core/index.js';
import type { ReconcileResult } from '../vc/IVCService.js';

export interface EnrollmentTokenResult {
  token: string;
  /** Absent when the token has no expiry. */
  expiresAt?: string;
}

export interface ChallengeResult {
  challengeId: string;
  nonce: string;
  expiresAt: string;
  didCreateSigningPayloadHex?: string;
}

export interface OnboardVerifyResult {
  agentDid: string;
  vc: Record<string, unknown>;
  hederaTransactionId: string;
  vcId: string;
}

export interface OnboardWithCustodyResult {
  agentDid: string;
  vcId: string;
}

export interface SignVPResult {
  signedVP: SignedVP;
}

/** The delegated VC, plus what storing it did to earlier delegations from the same delegator to the same DID. */
export interface DelegateAuthorityResult extends Partial<ReconcileResult> {
  delegatedVC: SignedVC;
}

export interface UserChallengeVerifyResult {
  did: string;
  verified: true;
  vc?: Record<string, unknown>;
}

export interface IAgentService {
  generateEnrollmentToken(
    input: {
      agentName: string;
      requestedScopes: string[];
      requestedDomains?: string[];
      maxDelegationDepth?: number;
      expiry?: number | null;
    },
    requestId: string,
  ): Promise<EnrollmentTokenResult>;
  processOnboardCreateChallenge(
    input: { enrollmentToken: string; publicKeyHex: string; domains?: string[] },
    requestId: string,
  ): Promise<ChallengeResult>;
  processOnboardVerify(
    input: { challengeId: string; signature: string; didCreateSignature?: string },
    requestId: string,
  ): Promise<OnboardVerifyResult>;
  onboardWithCustody(
    input: { enrollmentToken: string; domains?: string[]; expiry?: number },
    requestId: string,
  ): Promise<OnboardWithCustodyResult>;
  signVP(
    input: { did: string; targetService: string; userDid?: string },
    requestId: string,
  ): Promise<SignVPResult>;
  delegateAuthority(
    input: { did: string; to: string; scopes: string[]; expiresIn: number; vcId?: string; revokeExisting?: boolean },
    requestId: string,
    options?: DelegateAuthorityOptions,
  ): Promise<DelegateAuthorityResult>;
  issueUserChallenge(
    input: { did: string; purpose: 'user_verification' },
    requestId: string,
  ): Promise<ChallengeResult>;
  verifyUserChallenge(
    challengeId: string,
    input: { signature: string },
    requestId: string,
  ): Promise<UserChallengeVerifyResult>;
}

export interface DelegateAuthorityOptions {
  /**
   * A deployment's own say over who may receive a delegation, given the
   * delegatee and the credential being delegated from (its chain shows where
   * the authority started). Called once both are known and the delegatee is
   * confirmed registered, before anything is reserved or signed; throwing
   * refuses the delegation.
   */
  authorizeDelegatee?: (context: { to: string; fromVC: SignedVC }) => Promise<void>;
}
