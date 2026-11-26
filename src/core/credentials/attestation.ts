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
 * Capability attestations (story F-1 point 2, story C-B): one
 * `CapabilityAttestationCredential` per scope. `credentialSubject.id` is the
 * agent DID (the card id), `capability` the scope name, `validUntil` bounds
 * it and a Bitstring status entry revokes it. The owner signs them through
 * the SDK; the Helix issuer signs when the owner has no key.
 */

import { randomUUID } from 'node:crypto';
import type { Signer } from '../crypto/signer.js';
import { getBit } from '../status-list/index.js';
import { signDataIntegrity, verifyDataIntegrity, type DidResolver } from './data-integrity.js';
import { requireDid, type CredentialRefusal } from './identity.js';
import { credentialSchemaViolations, describeViolations, windowVerdict } from './validation.js';
import {
  CAPABILITY_ATTESTATION_TYPE,
  HELIX_CONTEXT,
  VC_V2_CONTEXT,
  type BitstringStatusEntry,
  type CapabilityAttestationCredential,
  type SignedCapabilityAttestation,
  type TrustedIssuers,
} from './types.js';

export interface BuildCapabilityAttestationInput {
  subjectDid: string;
  capability: string;
  validUntil: string;
  statusEntry: BitstringStatusEntry;
  id?: string;
  validFrom?: string;
  proofCreated?: string;
}

/** Scope names follow the Helix scope rule: no whitespace, non-empty. */
export function requireCapability(capability: string): void {
  if (typeof capability !== 'string' || capability.trim() === '' || /\s/.test(capability)) {
    throw new Error('capability must be a non-empty string without whitespace');
  }
}

export async function buildCapabilityAttestation(
  input: BuildCapabilityAttestationInput,
  signer: Signer,
): Promise<SignedCapabilityAttestation> {
  requireDid(input.subjectDid, 'subjectDid');
  requireCapability(input.capability);
  if (typeof input.validUntil !== 'string') throw new Error('validUntil is required');
  const credential: CapabilityAttestationCredential = {
    '@context': [VC_V2_CONTEXT, HELIX_CONTEXT],
    id: input.id ?? `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', CAPABILITY_ATTESTATION_TYPE],
    issuer: signer.did,
    validFrom: input.validFrom ?? new Date().toISOString(),
    validUntil: input.validUntil,
    credentialSubject: { id: input.subjectDid, capability: input.capability },
    credentialStatus: input.statusEntry,
  };
  const signed = await signDataIntegrity(
    credential as unknown as Record<string, unknown>,
    signer,
    input.proofCreated === undefined ? {} : { created: input.proofCreated },
  );
  return signed as unknown as SignedCapabilityAttestation;
}

/** `'*'` trusts every issuer; a list trusts exactly those DIDs (stories rule 9, story C-B point 4). */
export function isTrustedIssuer(issuerDid: string, trustedIssuers: TrustedIssuers): boolean {
  if (trustedIssuers === '*') return true;
  return Array.isArray(trustedIssuers) && trustedIssuers.includes(issuerDid);
}

/** Reads the credential's bit in an already-fetched status list; true when revoked or unreadable (fail-closed). */
export function isRevokedIn(statusEntry: BitstringStatusEntry, encodedList: string): boolean {
  const index = Number(statusEntry.statusListIndex);
  if (!Number.isInteger(index) || index < 0) return true;
  try {
    return getBit(encodedList, index) === 1;
  } catch {
    return true;
  }
}

export type AttestationVerification =
  | { ok: true; credential: SignedCapabilityAttestation; capability: string; issuer: string }
  | CredentialRefusal;

export interface VerifyAttestationOptions {
  /** The card id / agent DID the attestation must name. */
  subjectDid?: string;
  /** The capability name it must attest. */
  capability?: string;
  /** Default `'*'`: an unlisted issuer is `issuer_untrusted`. */
  trustedIssuers?: TrustedIssuers;
  now?: number;
  maxClockSkewMs?: number;
  /**
   * The status list the credential's entry points at, already fetched over
   * HTTPS by the caller (a verifier never asks a Helix database). Omitted:
   * revocation is not checked here.
   */
  statusList?: { credentialSubject: { encodedList: string } };
}

/**
 * Schema, subject, capability name, trusted issuer, window, proof and
 * (given the list) revocation of a capability attestation, in that order.
 */
export async function verifyCapabilityAttestation(
  value: unknown,
  resolveDid: DidResolver,
  options: VerifyAttestationOptions = {},
): Promise<AttestationVerification> {
  const violations = credentialSchemaViolations('attestation', value);
  if (violations.length > 0) {
    return { ok: false, reason: 'schema_invalid', message: describeViolations(violations) };
  }
  const credential = value as SignedCapabilityAttestation;
  const subject = credential.credentialSubject;
  if (options.subjectDid !== undefined && subject.id !== options.subjectDid) {
    return { ok: false, reason: 'subject_mismatch', message: 'credentialSubject.id is not the card id' };
  }
  if (options.capability !== undefined && subject.capability !== options.capability) {
    return { ok: false, reason: 'capability_mismatch', message: 'credentialSubject.capability is not the declared capability' };
  }
  if (!isTrustedIssuer(credential.issuer, options.trustedIssuers ?? '*')) {
    return { ok: false, reason: 'issuer_untrusted', message: `${credential.issuer} is not a trusted issuer` };
  }
  const window = windowVerdict(credential.validFrom, credential.validUntil, options.now ?? Date.now(), options.maxClockSkewMs);
  if (window !== 'inside') {
    return { ok: false, reason: `credential_${window}`, message: `credential is ${window.replace(/_/g, ' ')}` };
  }
  const proof = await verifyDataIntegrity(credential as unknown as Record<string, unknown>, resolveDid);
  if (!proof.ok) return proof;
  if (options.statusList !== undefined && isRevokedIn(credential.credentialStatus, options.statusList.credentialSubject.encodedList)) {
    return { ok: false, reason: 'credential_revoked', message: 'the status list marks this credential revoked' };
  }
  return { ok: true, credential, capability: subject.capability, issuer: credential.issuer };
}
