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
 * The identity credential (story F-1 point 1): agent DID, name, owner DID as
 * `responsibleParty`, a status entry and an `eddsa-jcs-2022` proof. No
 * scopes. Also the optional IdentityVerificationCredential of story C-B
 * (KYC/KYB level on the responsible party, never PII).
 */

import { randomUUID } from 'node:crypto';
import type { Signer } from '../crypto/signer.js';
import { signDataIntegrity, verifyDataIntegrity, type DidResolver } from './data-integrity.js';
import { credentialSchemaViolations, describeViolations, windowVerdict } from './validation.js';
import {
  HELIX_CONTEXT,
  IDENTITY_CREDENTIAL_TYPE,
  IDENTITY_VERIFICATION_TYPE,
  VC_V2_CONTEXT,
  type BitstringStatusEntry,
  type IdentityCredential,
  type IdentityVerificationCredential,
  type SignedIdentityCredential,
  type SignedIdentityVerification,
  type VerificationLevel,
} from './types.js';

export interface BuildIdentityCredentialInput {
  agentDid: string;
  name: string;
  /** The owner's DID: the party that answers for the agent (SPEC-ENTITY-CARD.md §10.2). */
  ownerDid: string;
  statusEntry: BitstringStatusEntry;
  /** Default: a fresh `urn:uuid:`. */
  id?: string;
  /** Default: now. */
  validFrom?: string;
  validUntil?: string;
  /** The proof's `created`; default now. */
  proofCreated?: string;
}

export type CredentialRefusal = { ok: false; reason: string; message: string };

export type IdentityVerification =
  | { ok: true; credential: SignedIdentityCredential; agentDid: string; responsibleParty: string }
  | CredentialRefusal;

export interface VerifyIdentityOptions {
  /** The agent the credential must be about, when the caller knows it. */
  agentDid?: string;
  /** Epoch ms; default `Date.now()`. */
  now?: number;
  maxClockSkewMs?: number;
}

export function requireDid(value: string, what: string): void {
  if (typeof value !== 'string' || !value.startsWith('did:')) {
    throw new Error(`${what} must be a DID`);
  }
}

export async function buildIdentityCredential(
  input: BuildIdentityCredentialInput,
  signer: Signer,
): Promise<SignedIdentityCredential> {
  requireDid(input.agentDid, 'agentDid');
  requireDid(input.ownerDid, 'ownerDid');
  if (typeof input.name !== 'string' || input.name.trim() === '') {
    throw new Error('name must be a non-empty string');
  }
  const credential: IdentityCredential = {
    '@context': [VC_V2_CONTEXT, HELIX_CONTEXT],
    id: input.id ?? `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', IDENTITY_CREDENTIAL_TYPE],
    issuer: signer.did,
    validFrom: input.validFrom ?? new Date().toISOString(),
    ...(input.validUntil === undefined ? {} : { validUntil: input.validUntil }),
    credentialSubject: {
      id: input.agentDid,
      name: input.name,
      responsibleParty: input.ownerDid,
    },
    credentialStatus: input.statusEntry,
  };
  const signed = await signDataIntegrity(
    credential as unknown as Record<string, unknown>,
    signer,
    input.proofCreated === undefined ? {} : { created: input.proofCreated },
  );
  return signed as unknown as SignedIdentityCredential;
}

/**
 * Schema, window and proof of an identity credential. Revocation is the
 * caller's status-list read (`isRevokedIn`), so this stays free of I/O
 * beyond the issuer's DID document.
 */
export async function verifyIdentityCredential(
  value: unknown,
  resolveDid: DidResolver,
  options: VerifyIdentityOptions = {},
): Promise<IdentityVerification> {
  const violations = credentialSchemaViolations('identity', value);
  if (violations.length > 0) {
    return { ok: false, reason: 'schema_invalid', message: describeViolations(violations) };
  }
  const credential = value as SignedIdentityCredential;
  if (options.agentDid !== undefined && credential.credentialSubject.id !== options.agentDid) {
    return { ok: false, reason: 'subject_mismatch', message: 'credentialSubject.id is not the expected agent' };
  }
  const window = windowVerdict(credential.validFrom, credential.validUntil, options.now ?? Date.now(), options.maxClockSkewMs);
  if (window !== 'inside') {
    return { ok: false, reason: `credential_${window}`, message: `credential is ${window.replace(/_/g, ' ')}` };
  }
  const proof = await verifyDataIntegrity(credential as unknown as Record<string, unknown>, resolveDid);
  if (!proof.ok) return proof;
  return {
    ok: true,
    credential,
    agentDid: credential.credentialSubject.id,
    responsibleParty: credential.credentialSubject.responsibleParty,
  };
}

export interface BuildIdentityVerificationInput {
  /** The responsible party the verification is about. */
  subjectDid: string;
  subjectType: 'individual' | 'organization';
  verificationLevel: VerificationLevel;
  provider?: string;
  validUntil: string;
  statusEntry: BitstringStatusEntry;
  id?: string;
  validFrom?: string;
  proofCreated?: string;
}

const VERIFICATION_LEVELS: readonly VerificationLevel[] = ['basic', 'enhanced', 'loa3'];

/** KYC/KYB on the responsible party: the fact and the level only (story C-B point 5). */
export async function buildIdentityVerificationCredential(
  input: BuildIdentityVerificationInput,
  signer: Signer,
): Promise<SignedIdentityVerification> {
  requireDid(input.subjectDid, 'subjectDid');
  if (!VERIFICATION_LEVELS.includes(input.verificationLevel)) {
    throw new Error(`verificationLevel must be one of ${VERIFICATION_LEVELS.join(', ')}`);
  }
  if (input.subjectType !== 'individual' && input.subjectType !== 'organization') {
    throw new Error('subjectType must be individual or organization');
  }
  const credential: IdentityVerificationCredential = {
    '@context': [VC_V2_CONTEXT, HELIX_CONTEXT],
    id: input.id ?? `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', IDENTITY_VERIFICATION_TYPE],
    issuer: signer.did,
    validFrom: input.validFrom ?? new Date().toISOString(),
    validUntil: input.validUntil,
    credentialSubject: {
      id: input.subjectDid,
      subjectType: input.subjectType,
      verificationLevel: input.verificationLevel,
      ...(input.provider === undefined ? {} : { provider: input.provider }),
    },
    credentialStatus: input.statusEntry,
  };
  const signed = await signDataIntegrity(
    credential as unknown as Record<string, unknown>,
    signer,
    input.proofCreated === undefined ? {} : { created: input.proofCreated },
  );
  return signed as unknown as SignedIdentityVerification;
}

export type IdentityVerificationVerdict =
  | { ok: true; credential: SignedIdentityVerification; verificationLevel: VerificationLevel }
  | CredentialRefusal;

/** Type, subject, level, window and proof of an IdentityVerificationCredential. */
export async function verifyIdentityVerificationCredential(
  value: unknown,
  resolveDid: DidResolver,
  options: { subjectDid?: string; now?: number; maxClockSkewMs?: number } = {},
): Promise<IdentityVerificationVerdict> {
  const credential = value as SignedIdentityVerification;
  const subject = credential?.credentialSubject;
  if (
    !Array.isArray(credential?.type) ||
    !credential.type.includes(IDENTITY_VERIFICATION_TYPE) ||
    typeof subject?.id !== 'string' ||
    !VERIFICATION_LEVELS.includes(subject.verificationLevel)
  ) {
    return { ok: false, reason: 'schema_invalid', message: 'not an IdentityVerificationCredential with a verification level' };
  }
  if (options.subjectDid !== undefined && subject.id !== options.subjectDid) {
    return { ok: false, reason: 'subject_mismatch', message: 'credentialSubject.id is not the expected party' };
  }
  const window = windowVerdict(credential.validFrom, credential.validUntil, options.now ?? Date.now(), options.maxClockSkewMs);
  if (window !== 'inside') {
    return { ok: false, reason: `credential_${window}`, message: `credential is ${window.replace(/_/g, ' ')}` };
  }
  const proof = await verifyDataIntegrity(credential as unknown as Record<string, unknown>, resolveDid);
  if (!proof.ok) return proof;
  return { ok: true, credential, verificationLevel: subject.verificationLevel };
}
