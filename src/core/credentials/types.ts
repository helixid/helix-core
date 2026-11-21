// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * The three credentials of KYA-OS story F-1 (credential split), plus the
 * optional IdentityVerificationCredential of story C-B.
 *
 * - identity: who the agent is and who answers for it (`responsibleParty`);
 *   no scopes, reissued only on rotation or offboarding;
 * - capability attestation: one per scope, what the agent may claim on its
 *   Entity Card (SPEC-ENTITY-CARD.md §9.2);
 * - delegation hop: one `DelegationCredential` per hop in the SPEC.md §6.10
 *   shape, the only place authority comes from.
 *
 * All three are W3C VC 2.0 documents revoked through a Bitstring Status List
 * entry and signed with a `DataIntegrityProof` of cryptosuite
 * `eddsa-jcs-2022` (./data-integrity.ts).
 */

export const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const ZCAP_CONTEXT = 'https://w3id.org/security/zcap/v1';
export const KYA_OS_DELEGATION_CONTEXT = 'https://kya-os.org/ns/delegation/v1';
export const HELIX_CONTEXT = 'https://helixid.io/contexts/v1';

export const IDENTITY_CREDENTIAL_TYPE = 'AgentIdentityCredential';
export const CAPABILITY_ATTESTATION_TYPE = 'CapabilityAttestationCredential';
export const DELEGATION_CREDENTIAL_TYPE = 'DelegationCredential';
export const IDENTITY_VERIFICATION_TYPE = 'IdentityVerificationCredential';

/** The `@context` of every hop, in the order SPEC.md §6.10 lists it. */
export const DELEGATION_HOP_CONTEXT: readonly string[] = [VC_V2_CONTEXT, ZCAP_CONTEXT, KYA_OS_DELEGATION_CONTEXT];

/** W3C Bitstring Status List v1.0 entry (the StatusList2021Entry successor). */
export interface BitstringStatusEntry {
  id?: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation' | 'suspension';
  statusListIndex: string;
  statusListCredential: string;
  statusSize?: number;
}

export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
}

export type Signed<T> = T & { proof: DataIntegrityProof };

export interface IdentityCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: {
    id: string;
    name: string;
    responsibleParty: string;
  };
  credentialStatus: BitstringStatusEntry;
}

export interface CapabilityAttestationCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: {
    id: string;
    capability: string;
  };
  credentialStatus: BitstringStatusEntry;
}

/** A monotone-narrowing constraint on a hop; unknown types are replicated verbatim down the chain. */
export interface Caveat {
  type: string;
  date?: string;
  limit?: string;
  currency?: string;
  [member: string]: unknown;
}

/** The attenuated ZCAP-LD capability a hop carries as its `credentialSubject`. */
export interface ZcapCapability {
  id: string;
  invoker?: string;
  controller?: string;
  parentCapability: string;
  invocationTarget: string;
  allowedAction: string[];
  caveats?: Caveat[];
}

/** One delegation hop: SPEC.md §6.10 (VC 2.0 + ZCAP-LD, Bitstring status, eddsa-jcs-2022). */
export interface DelegationCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom?: string;
  validUntil: string;
  credentialSubject: ZcapCapability;
  credentialStatus: BitstringStatusEntry;
}

export type VerificationLevel = 'basic' | 'enhanced' | 'loa3';

/** KYC/KYB on the responsible party: the fact and the level, never PII (SPEC.md §6.10). */
export interface IdentityVerificationCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: {
    id: string;
    subjectType: 'individual' | 'organization';
    verificationLevel: VerificationLevel;
    provider?: string;
  };
  credentialStatus: BitstringStatusEntry;
}

export type SignedIdentityCredential = Signed<IdentityCredential>;
export type SignedCapabilityAttestation = Signed<CapabilityAttestationCredential>;
export type SignedDelegationHop = Signed<DelegationCredential>;
export type SignedIdentityVerification = Signed<IdentityVerificationCredential>;

/** `'*'` trusts every issuer (the shipped default, stories rule 9); a list trusts those DIDs only. */
export type TrustedIssuers = '*' | readonly string[];
export const TRUST_ALL_ISSUERS: TrustedIssuers = '*';

/** Default clock tolerance for validity windows, the reference verifier's 120 seconds. */
export const DEFAULT_CLOCK_SKEW_MS = 120_000;
export const MAX_CLOCK_SKEW_MS = 600_000;
