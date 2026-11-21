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
 * Cross-language custody fixtures (KYA-OS story F-3, stories rule 6):
 * generated once from helix-core's own implementation, checked in at
 * fixtures/kya-os-helix/custody.json, and consumed by helix-core,
 * helix-sdk-js, helix-sdk-py and e2e-playwright, so `helix init` and
 * `HelixCustodialSigner` build the same bytes in both SDKs:
 *
 * - the enrollment and rotation proof-of-possession messages and their
 *   signatures with a TEST-ONLY key (Ed25519 is deterministic);
 * - the custodial signing endpoint's request and response for a payload;
 * - the custody labels and the member names refused as private material.
 *
 * Run: pnpm generate:custody-fixtures
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as ed25519 from '@noble/ed25519';
import {
  CUSTODY_LABEL_HELIX,
  CUSTODY_LABEL_SELF,
  ENROLLMENT_PROOF_PREFIX,
  PRIVATE_KEY_MATERIAL_MEMBERS,
  ROTATION_PROOF_PREFIX,
  base64UrlEncode,
  enrollmentProofMessage,
  publicKeyBytesToJwk,
  rotationProofMessage,
} from '../src/core/index.js';

const SEED_HEX = '9f'.repeat(32); // TEST ONLY
const seed = Buffer.from(SEED_HEX, 'hex');
const publicKey = ed25519.getPublicKey(seed);
const DID = 'did:web:helix.example:acme:fixture-agent';
const KID = `${DID}#key-1`;
const NEW_KID = `${DID}#key-2`;
const NONCE = '0f'.repeat(32);
const ISSUED_AT = '2026-11-21T12:00:00.000Z';
const PAYLOAD = new TextEncoder().encode('{"kyaos":"request-proof","nonce":"n-1"}');

function signed(message: Uint8Array): string {
  return base64UrlEncode(ed25519.sign(message, seed));
}

const enrollmentMessage = enrollmentProofMessage({ did: DID, kid: KID, nonce: NONCE });
const rotationMessage = rotationProofMessage({ did: DID, kid: NEW_KID, issuedAt: ISSUED_AT });

const fixture = {
  description:
    'KYA-OS story F-3 custody fixtures. TEST-ONLY key. enrollment/rotation: the proof-of-possession message (UTF-8) and the raw Ed25519 signature, base64url without padding. sign: POST /v1/{agents|services|owners}/{did}/sign request and response.',
  key: { seedHex: SEED_HEX, publicKeyHex: Buffer.from(publicKey).toString('hex'), publicKeyJwk: publicKeyBytesToJwk(publicKey) },
  enrollment: {
    prefix: ENROLLMENT_PROOF_PREFIX,
    did: DID,
    kid: KID,
    nonce: NONCE,
    message: new TextDecoder().decode(enrollmentMessage),
    signature: signed(enrollmentMessage),
    request: { enrollmentToken: 'enroll:fixture', publicKeyJwk: publicKeyBytesToJwk(publicKey), signature: signed(enrollmentMessage) },
  },
  rotation: {
    prefix: ROTATION_PROOF_PREFIX,
    did: DID,
    kid: NEW_KID,
    issuedAt: ISSUED_AT,
    message: new TextDecoder().decode(rotationMessage),
    signature: signed(rotationMessage),
  },
  sign: {
    did: DID,
    kid: KID,
    payloadUtf8: new TextDecoder().decode(PAYLOAD),
    request: { payload: base64UrlEncode(PAYLOAD) },
    response: { did: DID, kid: KID, alg: 'EdDSA', signature: signed(PAYLOAD) },
  },
  labels: { helix: CUSTODY_LABEL_HELIX, self: CUSTODY_LABEL_SELF },
  privateMaterialMembers: [...PRIVATE_KEY_MATERIAL_MEMBERS].sort(),
};

const out = fileURLToPath(new URL('../fixtures/kya-os-helix/custody.json', import.meta.url));
mkdirSync(fileURLToPath(new URL('../fixtures/kya-os-helix/', import.meta.url)), { recursive: true });
writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`wrote ${out}`);
