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
 * Proof of possession for a client-held key (KYA-OS story F-3 points 2
 * and 6). Registering a public key proves nothing by itself, so the SDK
 * signs a short message with the new key and Helix checks it against the
 * public JWK in the same request. The private key never leaves the Signer.
 *
 * - enrollment (`helix init`): `helix-enroll:v1:<did>:<kid>:<nonce>`, the
 *   nonce from the enrollment challenge Helix issued for the token;
 * - custody change to self (a rotation): `helix-rotate:v1:<did>:<kid>:<issuedAt>`,
 *   `issuedAt` an ISO-8601 instant within the accepted window.
 *
 * The signature is the raw 64-byte Ed25519 signature, base64url without
 * padding. The JS and Python SDKs build the same bytes
 * (`fixtures/kya-os-helix/custody.json`).
 */

import * as ed25519 from '@noble/ed25519';
import '../crypto/keys.js';
import { base64UrlDecodeStrict } from '../crypto/jws.js';

export const ENROLLMENT_PROOF_PREFIX = 'helix-enroll:v1';
export const ROTATION_PROOF_PREFIX = 'helix-rotate:v1';
/** How far a rotation proof's `issuedAt` may be from now. */
export const ROTATION_PROOF_WINDOW_MS = 5 * 60 * 1000;

export interface EnrollmentProofInput {
  did: string;
  /** Full verification-method id, `<did>#<fragment>`. */
  kid: string;
  nonce: string;
}

export interface RotationProofInput {
  did: string;
  kid: string;
  issuedAt: string;
}

function messageOf(parts: string[]): Uint8Array {
  for (const part of parts) {
    if (typeof part !== 'string' || part.length === 0 || /[\s]/.test(part)) {
      throw new Error('proof message parts must be non-empty strings without whitespace');
    }
  }
  return new TextEncoder().encode(parts.join(':'));
}

export function enrollmentProofMessage(input: EnrollmentProofInput): Uint8Array {
  return messageOf([ENROLLMENT_PROOF_PREFIX, input.did, input.kid, input.nonce]);
}

export function rotationProofMessage(input: RotationProofInput): Uint8Array {
  return messageOf([ROTATION_PROOF_PREFIX, input.did, input.kid, input.issuedAt]);
}

/** Whether `signature` (base64url, 64 bytes) is `publicKey`'s Ed25519 signature over `message`. Never throws. */
export function verifyProofOfPossession(message: Uint8Array, signature: unknown, publicKey: Uint8Array): boolean {
  if (typeof signature !== 'string') return false;
  const bytes = base64UrlDecodeStrict(signature);
  if (bytes === undefined || bytes.length !== 64) return false;
  try {
    return ed25519.verify(bytes, message, publicKey);
  } catch {
    return false;
  }
}

/** Whether a rotation proof's `issuedAt` is a valid instant inside the window around `now`. */
export function rotationProofFresh(issuedAt: unknown, now: number = Date.now()): boolean {
  if (typeof issuedAt !== 'string') return false;
  const at = Date.parse(issuedAt);
  if (Number.isNaN(at)) return false;
  return Math.abs(now - at) <= ROTATION_PROOF_WINDOW_MS;
}
