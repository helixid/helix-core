import type { SignedCapabilityAttestation, SignedIdentityCredential, SignedVP } from '../../core/index.js';

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

/**
 * KYA-OS story F-1: onboarding issues the split credential set. `vc` and
 * `vcId` are the identity credential; `attestations` one per scope.
 */
export interface OnboardVerifyResult {
  agentDid: string;
  vc: Record<string, unknown>;
  hederaTransactionId: string;
  vcId: string;
  identity: SignedIdentityCredential;
  attestations: SignedCapabilityAttestation[];
}

export interface OnboardWithCustodyResult {
  agentDid: string;
  /** The identity credential's id. */
  vcId: string;
  identity: SignedIdentityCredential;
  attestations: SignedCapabilityAttestation[];
}

export interface SignVPResult {
  signedVP: SignedVP;
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
    options?: { ownerDid?: string },
  ): Promise<OnboardVerifyResult>;
  onboardWithCustody(
    input: { enrollmentToken: string; domains?: string[]; expiry?: number; ownerDid?: string },
    requestId: string,
  ): Promise<OnboardWithCustodyResult>;
  signVP(
    input: { did: string; targetService: string; userDid?: string },
    requestId: string,
  ): Promise<SignVPResult>;
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
