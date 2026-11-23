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
 * The did:web document of a client-held agent key (KYA-OS story L1-A).
 *
 * The agent generates its Ed25519 key in the SDK and sends Helix only the
 * public half, as an OKP JWK. Helix publishes it in the agent's did:web
 * document as one verification method whose id, `<did>#<key-id>`, is the
 * `kid` every JWS the agent emits carries. The document has the shape the
 * KYA-OS reference implementation builds and reads (`buildDidWebDocument`
 * at the pinned commit): both key forms, `publicKeyJwk` and
 * `publicKeyMultibase`, listed under `authentication` and `assertionMethod`.
 *
 * Nothing here touches private material: a JWK carrying `d` is refused.
 */

import { ValidationError } from '../errors/HelixError.js';
import { decodeBase58btc, encodeBase58btc } from '../crypto/base58.js';
import { base64UrlDecodeStrict, base64UrlEncode } from '../crypto/jws.js';
import { didWebCardUrl } from './web.js';

/** The one DID-document service type KYA-OS owns (SPEC-ENTITY-CARD §5.3, §14.4). */
export const KYA_OS_CARD_SERVICE_TYPE = 'KyaOsEntityCard';
export const KYA_OS_CARD_SERVICE_ID = '#kya-os-card';

export interface KyaOsCardService {
  id: typeof KYA_OS_CARD_SERVICE_ID;
  type: typeof KYA_OS_CARD_SERVICE_TYPE;
  serviceEndpoint: string;
}

export const DID_WEB_CONTEXTS: readonly string[] = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1',
];

export const DEFAULT_AGENT_KEY_ID = 'key-1';

const ED25519_MULTICODEC_PREFIX = [0xed, 0x01] as const;
const ED25519_PUBLIC_KEY_LENGTH = 32;
/** JWK members a public Ed25519 key may carry. Anything else, `d` above all, is refused. */
const PUBLIC_JWK_MEMBERS = new Set(['kty', 'crv', 'x', 'kid']);

/** An Ed25519 public key as RFC 8037 writes it. */
export type PublicKeyJwk = {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid?: string;
};

export type AgentVerificationMethod = {
  id: string;
  type: 'Ed25519VerificationKey2020';
  controller: string;
  publicKeyJwk: PublicKeyJwk;
  publicKeyMultibase: string;
};

export type AgentDidDocument = {
  '@context': string[];
  id: string;
  alsoKnownAs?: string[];
  verificationMethod: AgentVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  service?: unknown[];
};

export interface BuildDidDocumentOptions {
  /** The agent's did:web DID. */
  did: string;
  /** Public JWK only: `{kty: "OKP", crv: "Ed25519", x}`. */
  publicKeyJwk: unknown;
  /** Verification-method fragment (`key-1`) or full id (`<did>#key-1`). Default `key-1`. */
  kid?: string;
  /** Other DIDs of the same subject, the did:key form of this key for one. */
  alsoKnownAs?: readonly string[];
  /** Service endpoints to keep on the document, as the DID core spec lists them. */
  service?: readonly unknown[];
  /**
   * KYA-OS story C-A: anchor the entity's card. `true` derives the card URL
   * from the DID (`https://host/a/b/card.json`, or the well-known path for a
   * bare host); a string names it. The entry replaces any `#kya-os-card`
   * already in `service`.
   */
  cardServiceEndpoint?: string | true | undefined;
}

/** The `{id: "#kya-os-card", type: "KyaOsEntityCard", serviceEndpoint}` entry anchoring a card. */
export function kyaOsCardServiceEntry(serviceEndpoint: string): KyaOsCardService {
  let url: URL;
  try {
    url = new URL(serviceEndpoint);
  } catch {
    throw new ValidationError('cardServiceEndpoint must be an https URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new ValidationError('cardServiceEndpoint must be an https URL');
  }
  return { id: KYA_OS_CARD_SERVICE_ID, type: KYA_OS_CARD_SERVICE_TYPE, serviceEndpoint };
}

/** The `KyaOsEntityCard` service endpoint a DID document anchors, or undefined. */
export function cardEndpointOf(document: unknown): string | undefined {
  const services = (document as { service?: unknown })?.service;
  if (!Array.isArray(services)) return undefined;
  for (const entry of services) {
    if (typeof entry === 'object' && entry !== null && (entry as { type?: unknown }).type === KYA_OS_CARD_SERVICE_TYPE) {
      const endpoint = (entry as { serviceEndpoint?: unknown }).serviceEndpoint;
      if (typeof endpoint === 'string') return endpoint;
    }
  }
  return undefined;
}

/** `service` with the card entry for `did` in place of any earlier `#kya-os-card` / `KyaOsEntityCard` entry. */
export function withKyaOsCardService(service: readonly unknown[] | undefined, did: string, endpoint: string | true = true): unknown[] {
  const entry = kyaOsCardServiceEntry(endpoint === true ? didWebCardUrl(did) : endpoint);
  const kept = (service ?? []).filter((existing) => {
    if (typeof existing !== 'object' || existing === null) return true;
    const { id, type } = existing as { id?: unknown; type?: unknown };
    return id !== KYA_OS_CARD_SERVICE_ID && type !== KYA_OS_CARD_SERVICE_TYPE;
  });
  return [...kept, entry];
}

export function isDidWeb(did: unknown): did is string {
  return typeof did === 'string' && did.startsWith('did:web:') && did.length > 'did:web:'.length;
}

/**
 * The 32 raw bytes of a public Ed25519 JWK. Refuses anything that is not
 * exactly a public OKP/Ed25519 JWK: a `d` member (private material), any
 * other member, a wrong `kty` or `crv`, an `x` that is not strict base64url
 * of 32 bytes.
 */
export function publicKeyJwkBytes(jwk: unknown): Uint8Array {
  if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
    throw new ValidationError('publicKeyJwk must be a JSON object');
  }
  const members = jwk as Record<string, unknown>;
  if ('d' in members) {
    throw new ValidationError(
      'publicKeyJwk carries private material (d); only the public key (kty, crv, x) is accepted',
    );
  }
  const foreign = Object.keys(members).filter((name) => !PUBLIC_JWK_MEMBERS.has(name));
  if (foreign.length > 0) {
    throw new ValidationError(
      `publicKeyJwk carries unexpected members (${foreign.join(', ')}); only kty, crv, x and kid are accepted`,
    );
  }
  if (members['kty'] !== 'OKP' || members['crv'] !== 'Ed25519') {
    throw new ValidationError('publicKeyJwk must be an OKP key on the Ed25519 curve');
  }
  if (members['kid'] !== undefined && typeof members['kid'] !== 'string') {
    throw new ValidationError('publicKeyJwk kid must be a string');
  }
  const x = members['x'];
  const bytes = typeof x === 'string' ? base64UrlDecodeStrict(x) : undefined;
  if (bytes === undefined || bytes.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new ValidationError('publicKeyJwk x must be the strict base64url of a 32-byte Ed25519 public key');
  }
  return bytes;
}

/** `{kty: "OKP", crv: "Ed25519", x}` of raw public key bytes (conformance L1.8). */
export function publicKeyBytesToJwk(publicKey: Uint8Array, kid?: string): PublicKeyJwk {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new ValidationError('An Ed25519 public key is 32 bytes');
  }
  const x = base64UrlEncode(publicKey);
  return kid === undefined ? { kty: 'OKP', crv: 'Ed25519', x } : { kty: 'OKP', crv: 'Ed25519', x, kid };
}

/** `z6Mk…`: multicodec `0xed01` plus the key, base58btc, multibase `z` (conformance L1.9). */
export function publicKeyToMultibaseOf(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new ValidationError('An Ed25519 public key is 32 bytes');
  }
  return `z${encodeBase58btc(new Uint8Array([...ED25519_MULTICODEC_PREFIX, ...publicKey]))}`;
}

/** `did:key:z6Mk…` of raw public key bytes: multicodec `0xed01`, base58btc, multibase `z` (conformance L1.1). */
export function didKeyFromPublicKey(publicKey: Uint8Array): string {
  return `did:key:${publicKeyToMultibaseOf(publicKey)}`;
}

/**
 * The raw public key a did:key names (conformance L1.7), or undefined when
 * the DID is not an Ed25519 did:key whose key decodes: multibase `z`,
 * base58btc, multicodec `0xed01`, then exactly 32 bytes.
 */
export function publicKeyFromDidKey(did: string): Uint8Array | undefined {
  if (!did.startsWith('did:key:z')) return undefined;
  let decoded: Uint8Array;
  try {
    decoded = decodeBase58btc(did.slice('did:key:z'.length));
  } catch {
    return undefined;
  }
  if (
    decoded.length !== ED25519_MULTICODEC_PREFIX.length + ED25519_PUBLIC_KEY_LENGTH ||
    decoded[0] !== ED25519_MULTICODEC_PREFIX[0] ||
    decoded[1] !== ED25519_MULTICODEC_PREFIX[1]
  ) {
    return undefined;
  }
  return decoded.slice(ED25519_MULTICODEC_PREFIX.length);
}

/** `<did>#<fragment>` from a fragment or an already-qualified id; refuses an id of another DID. */
export function verificationMethodId(did: string, kid: string = DEFAULT_AGENT_KEY_ID): string {
  const hash = kid.indexOf('#');
  const fragment = hash === -1 ? kid : kid.slice(hash + 1);
  const owner = hash === -1 ? did : kid.slice(0, hash);
  if (hash !== -1 && hash !== 0 && owner !== did) {
    throw new ValidationError(`kid ${kid} does not belong to ${did}`);
  }
  if (fragment.length === 0 || fragment.includes('#')) {
    throw new ValidationError('kid must name one verification-method fragment');
  }
  return `${did}#${fragment}`;
}

/**
 * The did:web document that publishes one client-held agent key. The
 * verification method id (`<did>#<key-id>`) is the `kid` of every JWS the
 * agent signs; it is both an authentication and an assertion method.
 */
export function buildDidDocument(options: BuildDidDocumentOptions): AgentDidDocument {
  if (!isDidWeb(options.did)) {
    throw new ValidationError('did must be a did:web DID');
  }
  const publicKey = publicKeyJwkBytes(options.publicKeyJwk);
  const id = verificationMethodId(options.did, options.kid);
  const alsoKnownAs = (options.alsoKnownAs ?? []).filter((other) => other !== options.did);
  for (const other of alsoKnownAs) {
    if (typeof other !== 'string' || !other.startsWith('did:')) {
      throw new ValidationError('alsoKnownAs entries must be DIDs');
    }
  }
  const service =
    options.cardServiceEndpoint === undefined
      ? options.service && options.service.length > 0
        ? [...options.service]
        : undefined
      : withKyaOsCardService(options.service, options.did, options.cardServiceEndpoint);
  return {
    '@context': [...DID_WEB_CONTEXTS],
    id: options.did,
    ...(alsoKnownAs.length > 0 ? { alsoKnownAs } : {}),
    verificationMethod: [
      {
        id,
        type: 'Ed25519VerificationKey2020',
        controller: options.did,
        publicKeyJwk: publicKeyBytesToJwk(publicKey),
        publicKeyMultibase: publicKeyToMultibaseOf(publicKey),
      },
    ],
    authentication: [id],
    assertionMethod: [id],
    ...(service ? { service } : {}),
  };
}
