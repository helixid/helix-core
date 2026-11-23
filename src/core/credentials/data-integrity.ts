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
 * W3C Data Integrity `eddsa-jcs-2022`, as the KYA-OS reference signs and
 * verifies delegation hops and status lists (SPEC.md §6.10):
 *
 * - proof options = the proof without `proofValue`, carrying the document's
 *   `@context`; the unsecured document = the document without `proof`;
 * - hash data = SHA-256(RFC 8785 canonical proof options) followed by
 *   SHA-256(RFC 8785 canonical unsecured document);
 * - signature = Ed25519 over the hash data; `proofValue` = `z` + base58btc.
 *
 * Signing takes a {@link Signer} (story L1-C), so no private key reaches this
 * module. Verifying reads the issuer's DID document through an injected
 * resolver and picks the verification method `proof.verificationMethod`
 * names only when the document lists it under `assertionMethod` exactly once
 * and the issuer controls it (CID §3.3, the same rule the JWS verifier applies).
 * Cross-border rule (stories rule 4): nothing here reads a Helix database.
 */

import * as ed25519 from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../crypto/jcs.js';
import {
  JwsReasons,
  base64UrlDecodeStrict,
  selectAssertionMethod,
  verificationMethodToJwk,
  type DidResolver,
} from '../crypto/jws.js';
import { InvalidJWSError } from '../errors/HelixError.js';
import type { Signer } from '../crypto/signer.js';
import { base58btcDecode, base58btcEncode } from '../crypto/vp.js';
import type { DataIntegrityProof } from './types.js';
import { keyValidityProblem, proofTime } from '../did/key-validity.js';

export type { DidResolver } from '../crypto/jws.js';

/** Why a proof was refused; the same strings helix-sdk-py uses. */
export const ProofReasons = {
  PROOF_MISSING: 'proof_missing',
  PROOF_UNSUPPORTED: 'proof_unsupported',
  PROOF_PURPOSE_MISMATCH: 'proof_purpose_mismatch',
  PROOF_VALUE_MALFORMED: 'proof_value_malformed',
  PROOF_METHOD_MALFORMED: 'proof_method_malformed',
  PROOF_ISSUER_MISMATCH: 'proof_issuer_mismatch',
  PROOF_CONTEXT_MISMATCH: 'proof_context_mismatch',
  DOCUMENT_NOT_CANONICAL: 'document_not_canonical',
  DID_UNRESOLVED: 'did_unresolved',
  KEY_REJECTED: 'key_rejected',
  SIGNATURE_INVALID: 'signature_invalid',
  /** Story C-E: the key carries `revoked`; nothing it signed is accepted. */
  KEY_REVOKED: 'key_revoked',
  /** Story C-E: the proof's `created` is outside the key's validity. */
  KEY_SUPERSEDED: 'key_superseded',
  /** Story C-E: the key's validity members are not RFC 3339 instants. */
  KEY_VALIDITY_MALFORMED: 'key_validity_malformed',
} as const;

export type ProofReason = (typeof ProofReasons)[keyof typeof ProofReasons];

export type ProofVerification =
  | { ok: true; issuer: string; verificationMethod: string }
  | { ok: false; reason: ProofReason; message: string };

export interface SignDataIntegrityOptions {
  /** Only `assertionMethod` proofs are made or accepted in this profile. */
  proofPurpose?: 'assertionMethod';
  /** The proof's `created`; default the current time. Injected for deterministic fixtures. */
  created?: string;
}

export interface VerifyDataIntegrityOptions {
  proofPurpose?: 'assertionMethod';
  /** Epoch ms for a proof that states no `created`; default `Date.now()`. */
  now?: number;
}

const ED25519_SIGNATURE_LENGTH = 64;

/** The DID a document names as its issuer: a string or an `{ id }` object. */
export function issuerOf(issuer: unknown): string | undefined {
  if (typeof issuer === 'string' && issuer.startsWith('did:')) return issuer;
  if (issuer !== null && typeof issuer === 'object') {
    const id = (issuer as { id?: unknown }).id;
    if (typeof id === 'string' && id.startsWith('did:')) return id;
  }
  return undefined;
}

function digest(value: unknown): Uint8Array {
  return sha256(utf8ToBytes(canonicalize(value)));
}

/** SHA-256(canonical proof options) || SHA-256(canonical unsecured document). */
export function hashData(proofOptions: Record<string, unknown>, unsecured: Record<string, unknown>): Uint8Array {
  const proofHash = digest(proofOptions);
  const documentHash = digest(unsecured);
  const data = new Uint8Array(proofHash.length + documentHash.length);
  data.set(proofHash, 0);
  data.set(documentHash, proofHash.length);
  return data;
}

/**
 * Adds an `eddsa-jcs-2022` proof to `document`, signed by `signer`, whose
 * DID must be the document's `issuer` (a proof a verifier would reject is
 * refused here instead). The document must not carry a proof already.
 */
export async function signDataIntegrity<T extends Record<string, unknown>>(
  document: T,
  signer: Signer,
  options: SignDataIntegrityOptions = {},
): Promise<T & { proof: DataIntegrityProof }> {
  if (document['proof'] !== undefined) {
    throw new Error('signDataIntegrity: document already carries a proof');
  }
  const issuer = issuerOf(document['issuer']);
  if (issuer === undefined || issuer !== signer.did) {
    throw new Error(`signDataIntegrity: signer ${signer.did} is not the issuer of the document`);
  }
  const fragment = signer.kid.replace(/^#/, '');
  if (fragment.length === 0 || fragment.includes('#')) {
    throw new Error('signDataIntegrity: signer kid must be a verification-method fragment');
  }
  const proof: Omit<DataIntegrityProof, 'proofValue'> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: options.created ?? new Date().toISOString(),
    verificationMethod: `${signer.did}#${fragment}`,
    proofPurpose: options.proofPurpose ?? 'assertionMethod',
  };
  const config: Record<string, unknown> = { ...proof };
  if (document['@context'] !== undefined) config['@context'] = document['@context'];
  const signature = await signer.sign(hashData(config, document));
  if (!(signature instanceof Uint8Array) || signature.length !== ED25519_SIGNATURE_LENGTH) {
    throw new Error('signDataIntegrity: signer did not return a 64-byte Ed25519 signature');
  }
  return { ...document, proof: { ...proof, proofValue: `z${base58btcEncode(signature)}` } };
}

function refused(reason: ProofReason, message: string): ProofVerification {
  return { ok: false, reason, message };
}

/**
 * Verifies the one `eddsa-jcs-2022` proof on `document` against the key its
 * issuer's DID document lists for `assertionMethod`. Never throws for a bad
 * document or proof: every refusal is a `{ ok: false, reason }` the caller
 * can relay. A resolver that throws is `did_unresolved`.
 */
export async function verifyDataIntegrity(
  document: Record<string, unknown>,
  resolveDid: DidResolver,
  options: VerifyDataIntegrityOptions = {},
): Promise<ProofVerification> {
  const purpose = options.proofPurpose ?? 'assertionMethod';
  const proof = document['proof'];
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) {
    return refused(ProofReasons.PROOF_MISSING, 'document carries no single proof object');
  }
  const members = proof as Record<string, unknown>;
  if (members['type'] !== 'DataIntegrityProof' || members['cryptosuite'] !== 'eddsa-jcs-2022') {
    return refused(ProofReasons.PROOF_UNSUPPORTED, 'proof is not DataIntegrityProof / eddsa-jcs-2022');
  }
  if (members['proofPurpose'] !== purpose) {
    return refused(ProofReasons.PROOF_PURPOSE_MISMATCH, `proofPurpose is not ${purpose}`);
  }
  const proofValue = members['proofValue'];
  if (typeof proofValue !== 'string' || !proofValue.startsWith('z') || proofValue.length < 2) {
    return refused(ProofReasons.PROOF_VALUE_MALFORMED, 'proofValue is not a base58btc multibase string');
  }
  let signature: Uint8Array;
  try {
    signature = base58btcDecode(proofValue.slice(1));
  } catch {
    return refused(ProofReasons.PROOF_VALUE_MALFORMED, 'proofValue is not base58btc');
  }
  if (signature.length !== ED25519_SIGNATURE_LENGTH) {
    return refused(ProofReasons.PROOF_VALUE_MALFORMED, 'proofValue is not a 64-byte Ed25519 signature');
  }
  const verificationMethod = members['verificationMethod'];
  if (typeof verificationMethod !== 'string' || !verificationMethod.includes('#')) {
    return refused(ProofReasons.PROOF_METHOD_MALFORMED, 'verificationMethod is not a DID URL');
  }
  const issuer = issuerOf(document['issuer']);
  const did = verificationMethod.slice(0, verificationMethod.indexOf('#'));
  if (issuer === undefined || did !== issuer) {
    return refused(ProofReasons.PROOF_ISSUER_MISMATCH, 'verificationMethod does not belong to the issuer');
  }

  const unsecured: Record<string, unknown> = { ...document };
  delete unsecured['proof'];
  const config: Record<string, unknown> = { ...members };
  delete config['proofValue'];
  if (config['@context'] !== undefined) {
    // The proof may name its own @context only as a prefix of the document's.
    if (!isPrefix(contexts(document['@context']), contexts(config['@context']))) {
      return refused(ProofReasons.PROOF_CONTEXT_MISMATCH, 'proof @context is not a prefix of the document @context');
    }
    unsecured['@context'] = config['@context'];
  }
  if (unsecured['@context'] !== undefined) config['@context'] = unsecured['@context'];

  let resolved: Awaited<ReturnType<DidResolver>>;
  try {
    resolved = await resolveDid(did);
  } catch (error) {
    return refused(ProofReasons.DID_UNRESOLVED, `could not resolve ${did}: ${(error as Error).message}`);
  }
  if (resolved === null || resolved === undefined) {
    return refused(ProofReasons.DID_UNRESOLVED, `could not resolve ${did}`);
  }
  let publicKey: Uint8Array;
  let method: ReturnType<typeof selectAssertionMethod>;
  try {
    method = selectAssertionMethod(resolved, did, verificationMethod);
    publicKey = base64UrlDecodeStrict(verificationMethodToJwk(method).x)!;
  } catch (error: unknown) {
    const reason = error instanceof InvalidJWSError ? error.reason : JwsReasons.KEY_UNSUPPORTED;
    return refused(ProofReasons.KEY_REJECTED, `${reason}: ${(error as Error).message}`);
  }
  // Story C-E point 3: the key `kid` names must have been valid at `created`.
  const validity = keyValidityProblem(method, proofTime(members['created']), options.now);
  if (validity) return refused(validity.reason, validity.message);
  let data: Uint8Array;
  try {
    data = hashData(config, unsecured);
  } catch (error) {
    return refused(ProofReasons.DOCUMENT_NOT_CANONICAL, (error as Error).message);
  }
  // noble answers false, never throws, for a signature or key that is no point.
  if (!ed25519.verify(signature, data, publicKey)) {
    return refused(ProofReasons.SIGNATURE_INVALID, 'proofValue does not verify');
  }
  return { ok: true, issuer, verificationMethod };
}

function contexts(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function isPrefix(whole: unknown[], prefix: unknown[]): boolean {
  return prefix.length <= whole.length && prefix.every((entry, index) => canonicalize(entry) === canonicalize(whole[index]));
}
