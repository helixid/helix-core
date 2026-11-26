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
 * The Ed25519 key a DID names, as raw bytes and as a JWK (KYA-OS story
 * L1-A, conformance Core L1.6 to L1.8).
 *
 * - did:key is decoded locally: multibase `z`, base58btc, multicodec
 *   `0xed01`, 32 bytes. Its document has the shape the KYA-OS reference
 *   implementation builds (`resolveDidKeySync`): one verification method
 *   `<did>#<multibase>` with both key forms.
 * - did:web is fetched over HTTPS by the existing resolver
 *   (`did-resolver.ts`), which checks the served document's id.
 *
 * Cross-border rule (stories, rule 4): this module reads the DID, the
 * document the network serves, and nothing else. It never asks a Helix
 * database anything; `fetch` is its only seam.
 */

import { UnsupportedDIDMethodError, ValidationError } from '../errors/HelixError.js';
import { resolveDID } from '../did-resolver.js';
import {
  base64UrlDecodeStrict,
  selectAssertionMethod,
  verificationMethodToJwk,
  type Ed25519PublicJwk,
  type JwsDidDocument,
  type JwsVerificationMethod,
} from '../crypto/jws.js';
import {
  DID_WEB_CONTEXTS,
  publicKeyBytesToJwk,
  publicKeyFromDidKey,
  publicKeyToMultibaseOf,
  type AgentDidDocument,
} from './document.js';
import { RotationSequenceGuard } from './rotation.js';

export interface ResolvedKey {
  did: string;
  /** Verification-method id, `<did>#<fragment>`: the `kid` a JWS from this key carries. */
  kid: string;
  /** The 32 raw bytes of the Ed25519 public key. */
  rawKey: Uint8Array;
  /** The same key as `{kty: "OKP", crv: "Ed25519", x, kid}`. */
  jwk: Ed25519PublicJwk & { kid: string };
  /** The document the key was read from. */
  document: JwsDidDocument;
}

export interface ResolveDidOptions {
  /** The verification method wanted, as fragment or full id. Default: the first assertion method. */
  kid?: string;
  /**
   * Story C-E point 2: refuses (throws `StaleDidDocumentError`) a did:web
   * document whose `rotationSequence` is lower than one already seen.
   * Default one guard for this process.
   */
  sequenceGuard?: RotationSequenceGuard;
}

const processGuard = new RotationSequenceGuard();

/** The document a did:key resolves to (conformance L1.6); throws for anything but an Ed25519 did:key. */
export function didKeyDocument(did: string): AgentDidDocument {
  if (!did.startsWith('did:key:')) {
    throw new UnsupportedDIDMethodError(did);
  }
  const publicKey = publicKeyFromDidKey(did);
  if (publicKey === undefined) {
    throw new ValidationError(`${did} is not an Ed25519 did:key whose public key decodes`);
  }
  const multibase = did.slice('did:key:'.length);
  const id = `${did}#${multibase}`;
  return {
    '@context': [...DID_WEB_CONTEXTS],
    id: did,
    verificationMethod: [
      {
        id,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyJwk: publicKeyBytesToJwk(publicKey),
        publicKeyMultibase: publicKeyToMultibaseOf(publicKey),
      },
    ],
    authentication: [id],
    assertionMethod: [id],
  };
}

function firstAssertionMethodId(document: JwsDidDocument): string | undefined {
  const first = Array.isArray(document.assertionMethod) ? document.assertionMethod[0] : undefined;
  if (typeof first === 'string') return first.startsWith('#') ? `${document.id}${first}` : first;
  if (typeof first === 'object' && first !== null && typeof first.id === 'string') {
    return first.id.startsWith('#') ? `${document.id}${first.id}` : first.id;
  }
  return undefined;
}

/** The key `kid` (or the first assertion method) names in `document`, in both forms. */
export function keyFromDocument(document: JwsDidDocument, did: string, kid?: string): ResolvedKey {
  const wanted =
    kid === undefined
      ? firstAssertionMethodId(document)
      : kid.startsWith('#')
        ? `${did}${kid}`
        : kid.includes('#')
          ? kid
          : `${did}#${kid}`;
  if (wanted === undefined) {
    throw new ValidationError(`DID document ${did} lists no assertion method`);
  }
  const method: JwsVerificationMethod = selectAssertionMethod(document, did, wanted);
  const jwk = verificationMethodToJwk(method);
  // verificationMethodToJwk only returns strict base64url of 32 bytes.
  const rawKey = base64UrlDecodeStrict(jwk.x) as Uint8Array;
  return { did, kid: wanted, rawKey, jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x, kid: wanted }, document };
}

/** did:key, decoded locally. */
export function resolveDidKey(did: string, options: ResolveDidOptions = {}): ResolvedKey {
  return keyFromDocument(didKeyDocument(did) as unknown as JwsDidDocument, did, options.kid);
}

/** did:web, fetched over HTTPS (plain HTTP for a loopback host) by `did-resolver.ts`. */
export async function resolveDidWeb(did: string, options: ResolveDidOptions = {}): Promise<ResolvedKey> {
  if (!did.startsWith('did:web:')) {
    throw new UnsupportedDIDMethodError(did);
  }
  const document = (await resolveDID(did)) as unknown as JwsDidDocument;
  await (options.sequenceGuard ?? processGuard).assertCurrent(did, document);
  return keyFromDocument(document, did, options.kid);
}

/**
 * `{rawKey, jwk, kid}` of the key `did` names: did:key decoded locally,
 * did:web fetched over HTTPS. No database is consulted.
 */
export async function resolveDid(did: string, options: ResolveDidOptions = {}): Promise<ResolvedKey> {
  if (typeof did !== 'string') {
    throw new ValidationError('did must be a string');
  }
  if (did.startsWith('did:key:')) return resolveDidKey(did, options);
  if (did.startsWith('did:web:')) return resolveDidWeb(did, options);
  throw new UnsupportedDIDMethodError(did);
}
