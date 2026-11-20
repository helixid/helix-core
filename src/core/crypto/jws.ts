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
 * EdDSA compact JWS the KYA-OS way (conformance Core L1.3 to L1.5, SPEC §7.4).
 *
 * - `signJws`: `<header>.<payload>.<signature>`, header `{alg: "EdDSA", kid:
 *   "<did>#<fragment>"}`, signature from a {@link Signer}. Core never sees
 *   the private key.
 * - `verifyJws`: verifies against one Ed25519 public JWK. Reads the three
 *   segments and the key's `x` exactly as RFC 7515 §2 writes base64url:
 *   the base64url alphabet only, no padding, no white space, nothing looser.
 * - `verifyJwsByKid`: reads `kid`, resolves the DID through an injected
 *   resolver, picks the one assertion method `kid` names, then `verifyJws`.
 *
 * Refusals: any `alg` but EdDSA, a missing or malformed `kid`, a `kid`
 * naming a key of a DID other than the claimed signer (the `iss` claim, the
 * resolved document, or `expectedDid`), a key or signature that is not
 * strict base64url, a signature that does not verify.
 *
 * Cross-border rule (stories, rule 4): the verify path reads only the JWS,
 * the key it is given or the DID document the resolver returns. It never
 * asks a Helix database anything.
 */

import * as ed25519 from "@noble/ed25519";
import { InvalidJWSError } from "../errors/HelixError.js";
import { base58btcDecode } from "./vp.js";
import { multibaseToPublicKeyHex } from "./keys.js";
import type { Signer } from "./signer.js";

export const JWS_ALG = "EdDSA";

/** Why a JWS was refused; carried as `InvalidJWSError.reason` and mirrored in helix-sdk-py. */
export const JwsReasons = {
  MALFORMED: "jws_malformed",
  HEADER_INVALID: "jws_header_invalid",
  ALG_UNSUPPORTED: "jws_alg_unsupported",
  KID_MISSING: "jws_kid_missing",
  KID_MALFORMED: "jws_kid_malformed",
  KID_MISMATCH: "jws_kid_mismatch",
  KID_DID_MISMATCH: "jws_kid_did_mismatch",
  JWK_INVALID: "jws_jwk_invalid",
  SIGNATURE_INVALID: "jws_signature_invalid",
  DID_UNRESOLVED: "jws_did_unresolved",
  DID_DOCUMENT_MISMATCH: "jws_did_document_mismatch",
  KEY_NOT_FOUND: "jws_key_not_found",
  KEY_NOT_ASSERTION: "jws_key_not_assertion",
  KEY_AMBIGUOUS: "jws_key_ambiguous",
  KEY_FOREIGN_CONTROLLER: "jws_key_foreign_controller",
  KEY_UNSUPPORTED: "jws_key_unsupported",
} as const;

export type JwsReason = (typeof JwsReasons)[keyof typeof JwsReasons];

export interface JwsHeader {
  alg: typeof JWS_ALG;
  kid: string;
  [member: string]: unknown;
}

export interface Ed25519PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid?: string;
}

/** Bytes are signed as given; a string as UTF-8; anything else as `JSON.stringify` of it. */
export type JwsPayload =
  Uint8Array | string | Record<string, unknown> | unknown[];

export interface SignJwsOptions {
  /** Extra protected-header members after `alg` and `kid`, which they cannot override. */
  header?: Record<string, unknown>;
}

export interface VerifyJwsOptions {
  /** The `kid` the header must carry, when the caller knows it. */
  expectedKid?: string;
  /** The DID the `kid` must belong to, when the caller knows it. */
  expectedDid?: string;
}

export interface JwsVerification {
  header: JwsHeader;
  kid: string;
  /** DID part of `kid`. */
  did: string;
  payloadBytes: Uint8Array;
  /** The payload parsed as JSON, or undefined when it is not JSON. */
  payload: unknown;
}

/** A verification method as a DID document lists it; any one Ed25519 key form is enough. */
export interface JwsVerificationMethod {
  id: string;
  type?: string;
  controller?: string;
  publicKeyJwk?: Partial<Ed25519PublicJwk> & Record<string, unknown>;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
  [member: string]: unknown;
}

/** The parts of a DID document `verifyJwsByKid` reads. `buildDIDDocument` output satisfies it. */
export interface JwsDidDocument {
  id: string;
  verificationMethod?: JwsVerificationMethod[];
  assertionMethod?: (string | JwsVerificationMethod)[];
  [member: string]: unknown;
}

/** Resolves a DID to its document, or to nothing. Injected: the verify path never queries a Helix database. */
export type DidResolver = (
  did: string,
) => Promise<JwsDidDocument | null | undefined>;

// ── base64url, strictly ───────────────────────────────────────────────────────

const BASE64URL = /^[A-Za-z0-9_-]*$/;

export function base64UrlEncode(bytes: Uint8Array | string): string {
  const buffer =
    typeof bytes === "string" ? Buffer.from(bytes, "utf8") : Buffer.from(bytes);
  return buffer.toString("base64url");
}

/**
 * Bytes of a base64url string exactly as RFC 7515 §2 writes one: alphabet
 * characters only, no padding, no white space. Undefined for anything else.
 */
export function base64UrlDecodeStrict(value: string): Uint8Array | undefined {
  if (!BASE64URL.test(value) || value.length % 4 === 1) return undefined;
  return new Uint8Array(Buffer.from(value, "base64url"));
}

// ── keys ──────────────────────────────────────────────────────────────────────

export function publicKeyHexToJwk(
  publicKeyHex: string,
  kid?: string,
): Ed25519PublicJwk {
  const x = base64UrlEncode(Buffer.from(publicKeyHex, "hex"));
  return kid === undefined
    ? { kty: "OKP", crv: "Ed25519", x }
    : { kty: "OKP", crv: "Ed25519", x, kid };
}

function jwkPublicKeyBytes(jwk: unknown): Uint8Array {
  const candidate = jwk as Partial<Ed25519PublicJwk> | null;
  if (
    typeof candidate !== "object" ||
    candidate === null ||
    candidate.kty !== "OKP" ||
    candidate.crv !== "Ed25519" ||
    typeof candidate.x !== "string"
  ) {
    throw new InvalidJWSError(
      JwsReasons.JWK_INVALID,
      "Key is not an Ed25519 public JWK",
    );
  }
  const bytes = base64UrlDecodeStrict(candidate.x);
  if (bytes === undefined || bytes.length !== 32) {
    throw new InvalidJWSError(
      JwsReasons.JWK_INVALID,
      "JWK x is not a strict base64url 32-byte key",
    );
  }
  if (candidate.kid !== undefined && typeof candidate.kid !== "string") {
    throw new InvalidJWSError(
      JwsReasons.JWK_INVALID,
      "JWK kid must be a string",
    );
  }
  return bytes;
}

/** The Ed25519 public JWK of a verification method, whichever key form it carries. */
export function verificationMethodToJwk(
  method: JwsVerificationMethod,
): Ed25519PublicJwk {
  if (method.publicKeyJwk !== undefined) {
    const bytes = jwkPublicKeyBytes(method.publicKeyJwk);
    return {
      kty: "OKP",
      crv: "Ed25519",
      x: base64UrlEncode(bytes),
      kid: method.id,
    };
  }
  try {
    if (typeof method.publicKeyMultibase === "string") {
      return publicKeyHexToJwk(
        multibaseToPublicKeyHex(method.publicKeyMultibase),
        method.id,
      );
    }
    if (typeof method.publicKeyBase58 === "string") {
      return publicKeyHexToJwk(
        Buffer.from(base58btcDecode(method.publicKeyBase58)).toString("hex"),
        method.id,
      );
    }
  } catch {
    throw new InvalidJWSError(
      JwsReasons.KEY_UNSUPPORTED,
      `Verification method ${method.id} key is not decodable`,
    );
  }
  throw new InvalidJWSError(
    JwsReasons.KEY_UNSUPPORTED,
    `Verification method ${method.id} carries no Ed25519 public key`,
  );
}

// ── parsing ───────────────────────────────────────────────────────────────────

interface ParsedJws {
  headerSegment: string;
  payloadSegment: string;
  signatureSegment: string;
  header: JwsHeader;
  kid: string;
  did: string;
}

function kidDid(kid: string): string {
  const hash = kid.indexOf("#");
  if (
    !kid.startsWith("did:") ||
    hash <= "did:".length ||
    hash === kid.length - 1
  ) {
    throw new InvalidJWSError(
      JwsReasons.KID_MALFORMED,
      "JWS kid must be <did>#<fragment>",
    );
  }
  return kid.slice(0, hash);
}

function parseJws(jws: unknown): ParsedJws {
  if (typeof jws !== "string") {
    throw new InvalidJWSError(JwsReasons.MALFORMED, "JWS must be a string");
  }
  const segments = jws.split(".");
  if (
    segments.length !== 3 ||
    segments.some((segment) => segment.length === 0)
  ) {
    throw new InvalidJWSError(
      JwsReasons.MALFORMED,
      "Compact JWS must be header.payload.signature",
    );
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments as [
    string,
    string,
    string,
  ];
  for (const segment of segments) {
    if (base64UrlDecodeStrict(segment) === undefined) {
      throw new InvalidJWSError(
        JwsReasons.MALFORMED,
        "JWS segment is not strict base64url",
      );
    }
  }
  let header: unknown;
  try {
    header = JSON.parse(
      Buffer.from(base64UrlDecodeStrict(headerSegment)!).toString("utf8"),
    );
  } catch {
    throw new InvalidJWSError(
      JwsReasons.HEADER_INVALID,
      "JWS header is not JSON",
    );
  }
  if (typeof header !== "object" || header === null || Array.isArray(header)) {
    throw new InvalidJWSError(
      JwsReasons.HEADER_INVALID,
      "JWS header is not a JSON object",
    );
  }
  const members = header as Record<string, unknown>;
  if (members["alg"] !== JWS_ALG) {
    throw new InvalidJWSError(
      JwsReasons.ALG_UNSUPPORTED,
      `JWS alg must be ${JWS_ALG}`,
    );
  }
  const kid = members["kid"];
  if (kid === undefined || kid === null) {
    throw new InvalidJWSError(JwsReasons.KID_MISSING, "JWS header has no kid");
  }
  if (typeof kid !== "string") {
    throw new InvalidJWSError(
      JwsReasons.KID_MALFORMED,
      "JWS kid must be a string",
    );
  }
  return {
    headerSegment,
    payloadSegment,
    signatureSegment,
    header: members as JwsHeader,
    kid,
    did: kidDid(kid),
  };
}

/** The protected header of a compact JWS, read strictly, without verifying anything else. */
export function readJwsHeader(jws: string): JwsHeader {
  return parseJws(jws).header;
}

// ── sign ──────────────────────────────────────────────────────────────────────

function payloadToBytes(payload: JwsPayload): Uint8Array {
  if (payload instanceof Uint8Array) return payload;
  if (typeof payload === "string")
    return new Uint8Array(Buffer.from(payload, "utf8"));
  return new Uint8Array(Buffer.from(JSON.stringify(payload), "utf8"));
}

/**
 * Compact JWS over `payload`, header `{alg: "EdDSA", kid: "<did>#<fragment>"}`
 * (then any `options.header` members), signed by `signer`.
 */
export async function signJws(
  payload: JwsPayload,
  signer: Signer,
  options: SignJwsOptions = {},
): Promise<string> {
  const fragment = signer.kid.replace(/^#/, "");
  if (
    !signer.did.startsWith("did:") ||
    fragment.length === 0 ||
    fragment.includes("#")
  ) {
    throw new InvalidJWSError(
      JwsReasons.KID_MALFORMED,
      "Signer must have a DID and a fragment kid",
    );
  }
  const extra: Record<string, unknown> = { ...(options.header ?? {}) };
  delete extra["alg"];
  delete extra["kid"];
  const header: JwsHeader = {
    alg: JWS_ALG,
    kid: `${signer.did}#${fragment}`,
    ...extra,
  };
  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(payloadToBytes(payload))}`;
  const signature = await signer.sign(
    new Uint8Array(Buffer.from(signingInput, "utf8")),
  );
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new InvalidJWSError(
      JwsReasons.SIGNATURE_INVALID,
      "Signer did not return a 64-byte Ed25519 signature",
    );
  }
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

// ── verify ────────────────────────────────────────────────────────────────────

function claimedIssuer(payload: unknown): string | undefined {
  if (
    typeof payload === "object" &&
    payload !== null &&
    !Array.isArray(payload)
  ) {
    const iss = (payload as Record<string, unknown>)["iss"];
    if (typeof iss === "string") return iss;
  }
  return undefined;
}

/**
 * Verifies a compact EdDSA JWS against one Ed25519 public JWK. Throws
 * {@link InvalidJWSError} (with a {@link JwsReason}) on any refusal.
 */
export function verifyJws(
  jws: string,
  jwk: Ed25519PublicJwk,
  options: VerifyJwsOptions = {},
): JwsVerification {
  const parsed = parseJws(jws);
  const publicKey = jwkPublicKeyBytes(jwk);

  if (jwk.kid !== undefined && jwk.kid !== parsed.kid) {
    throw new InvalidJWSError(
      JwsReasons.KID_MISMATCH,
      "JWS kid does not name the given key",
    );
  }
  if (options.expectedKid !== undefined && options.expectedKid !== parsed.kid) {
    throw new InvalidJWSError(
      JwsReasons.KID_MISMATCH,
      "JWS kid is not the expected kid",
    );
  }
  if (options.expectedDid !== undefined && options.expectedDid !== parsed.did) {
    throw new InvalidJWSError(
      JwsReasons.KID_DID_MISMATCH,
      "JWS kid belongs to a DID other than the expected signer",
    );
  }

  const payloadBytes = base64UrlDecodeStrict(parsed.payloadSegment)!;
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(payloadBytes).toString("utf8"));
  } catch {
    payload = undefined;
  }
  const issuer = claimedIssuer(payload);
  if (issuer !== undefined && issuer !== parsed.did) {
    throw new InvalidJWSError(
      JwsReasons.KID_DID_MISMATCH,
      "JWS kid belongs to a DID other than the iss claim",
    );
  }

  const signature = base64UrlDecodeStrict(parsed.signatureSegment)!;
  const signingInput = new Uint8Array(
    Buffer.from(`${parsed.headerSegment}.${parsed.payloadSegment}`, "utf8"),
  );
  // noble answers false, never throws, for a signature or key that is no point.
  if (
    signature.length !== 64 ||
    !ed25519.verify(signature, signingInput, publicKey)
  ) {
    throw new InvalidJWSError(
      JwsReasons.SIGNATURE_INVALID,
      "JWS signature does not verify",
    );
  }
  return {
    header: parsed.header,
    kid: parsed.kid,
    did: parsed.did,
    payloadBytes,
    payload,
  };
}

function absoluteId(id: string, did: string): string {
  return id.startsWith("#") ? `${did}${id}` : id;
}

/**
 * The one verification method `kid` names in `document`, which must be the
 * document of `did`, list the method under `assertionMethod` (by reference
 * or embedded) exactly once, and be controlled by `did`.
 */
export function selectAssertionMethod(
  document: JwsDidDocument,
  did: string,
  kid: string,
): JwsVerificationMethod {
  if (
    typeof document !== "object" ||
    document === null ||
    document.id !== did
  ) {
    throw new InvalidJWSError(
      JwsReasons.DID_DOCUMENT_MISMATCH,
      `Resolved document is not the document of ${did}`,
    );
  }
  const published = (
    Array.isArray(document.verificationMethod)
      ? document.verificationMethod
      : []
  ).filter(
    (method) =>
      typeof method === "object" &&
      method !== null &&
      absoluteId(String(method.id), did) === kid,
  );
  const assertion = Array.isArray(document.assertionMethod)
    ? document.assertionMethod
    : [];
  const referenced = assertion.some(
    (entry) => typeof entry === "string" && absoluteId(entry, did) === kid,
  );
  const embedded = assertion.filter(
    (entry): entry is JwsVerificationMethod =>
      typeof entry === "object" &&
      entry !== null &&
      absoluteId(String(entry.id), did) === kid,
  );
  const definitions = [...published, ...embedded];
  if (definitions.length === 0) {
    throw new InvalidJWSError(
      JwsReasons.KEY_NOT_FOUND,
      `DID document ${did} does not define ${kid}`,
    );
  }
  if (definitions.length > 1) {
    throw new InvalidJWSError(
      JwsReasons.KEY_AMBIGUOUS,
      `DID document ${did} defines ${kid} more than once`,
    );
  }
  if (!referenced && embedded.length === 0) {
    throw new InvalidJWSError(
      JwsReasons.KEY_NOT_ASSERTION,
      `${kid} is not an assertion method of ${did}`,
    );
  }
  const method = definitions[0]!;
  if (method.controller !== did) {
    throw new InvalidJWSError(
      JwsReasons.KEY_FOREIGN_CONTROLLER,
      `${kid} is not controlled by ${did}`,
    );
  }
  return method;
}

/**
 * Reads `kid`, resolves its DID through `resolveDid`, picks the assertion
 * method `kid` names, then verifies as {@link verifyJws} does against it.
 */
export async function verifyJwsByKid(
  jws: string,
  resolveDid: DidResolver,
  options: VerifyJwsOptions = {},
): Promise<JwsVerification> {
  const { kid, did } = parseJws(jws);
  if (options.expectedDid !== undefined && options.expectedDid !== did) {
    throw new InvalidJWSError(
      JwsReasons.KID_DID_MISMATCH,
      "JWS kid belongs to a DID other than the expected signer",
    );
  }
  const document = await resolveDid(did);
  if (document === null || document === undefined) {
    throw new InvalidJWSError(
      JwsReasons.DID_UNRESOLVED,
      `DID ${did} did not resolve`,
    );
  }
  const method = selectAssertionMethod(document, did, kid);
  const jwk = verificationMethodToJwk(method);
  return verifyJws(jws, { ...jwk, kid }, { ...options, expectedDid: did });
}
