import type { SignedVC, SignedVP } from '../../core/index.js';

export interface EnrollmentTokenResult {
  token: string;
  expiresAt: string;
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

export interface DelegateAuthorityResult {
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
    },
    requestId: string,
  ): Promise<EnrollmentTokenResult>;
  processOnboardStep1(
    input: { enrollmentToken: string; publicKeyHex: string; domains?: string[] },
    requestId: string,
  ): Promise<ChallengeResult>;
  processOnboardVerify(
    input: { challengeId: string; signature: string; didCreateSignature?: string },
    requestId: string,
  ): Promise<OnboardVerifyResult>;
  onboardWithCustody(
    input: { enrollmentToken: string; domains?: string[] },
    requestId: string,
  ): Promise<OnboardWithCustodyResult>;
  signVP(
    input: { did: string; targetService: string; userDid?: string; grantVC?: SignedVC; vcId?: string },
    requestId: string,
  ): Promise<SignVPResult>;
  delegateAuthority(
    input: { did: string; to: string; scopes: string[]; expiresIn: number; vcId?: string },
    requestId: string,
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
