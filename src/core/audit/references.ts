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
 * Caller-presented references and delegation evidence.
 *
 * A reference a caller presents (a credential id, a grant, consent, scope or
 * policy reference, a correlation id, a tool name) is untrusted. One that is
 * empty, over the schema bound, not well-formed UTF-16, or that holds a
 * character that does not print is recorded as the `sha256:` digest of its
 * bytes (AUDITABILITY.md, Event and privacy model): the digest always fits,
 * prints as itself in a log line, and, unlike cutting, keeps two long ids
 * with one beginning apart.
 *
 * A delegation credential is recorded by the `delegationRef` SPEC section 7.8
 * defines and digested over its signed form, so an event and a proof that name
 * the credential carry one string, and an auditor holding the per-credential
 * digests recomputes the chain digest without the credentials.
 */

import { CanonicalJsonError } from '../crypto/jcs.js';
import { auditDigest, digestText } from './digest.js';
import { DIGEST_PATTERN } from './schema.js';
import { AUDIT_DIGEST_DOMAINS, type Digest } from './types.js';

/** The schema bound on a reference, in UTF-16 code units. */
export const MAX_REFERENCE_LENGTH = 256;
/** SPEC section 7.8: a chain of more than this many credentials is not listed. */
export const MAX_CHAIN_DIGESTS = 256;
/** SPEC section 7.8: a credential whose arrays and objects nest deeper has no signed form. */
export const MAX_CREDENTIAL_NESTING = 64;

/**
 * The code points a reader does not see (SPEC section 7.8; vendored at
 * `fixtures/kya-os/conformance/unseen-code-points.json`): Unicode 16.0/17.0
 * general categories Cc, Cf, Zl, Zp and Default_Ignorable_Code_Point. Frozen
 * here, not taken from the runtime's Unicode tables, so every implementation
 * hashes the same ids.
 */
export const UNSEEN_CODE_POINT_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f],
  [0x007f, 0x009f],
  [0x00ad, 0x00ad],
  [0x034f, 0x034f],
  [0x0600, 0x0605],
  [0x061c, 0x061c],
  [0x06dd, 0x06dd],
  [0x070f, 0x070f],
  [0x0890, 0x0891],
  [0x08e2, 0x08e2],
  [0x115f, 0x1160],
  [0x17b4, 0x17b5],
  [0x180b, 0x180f],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0x3164, 0x3164],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0xfff0, 0xfffb],
  [0x110bd, 0x110bd],
  [0x110cd, 0x110cd],
  [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3],
  [0x1d173, 0x1d17a],
  [0xe0000, 0xe0fff],
];

function isUnseenCodePoint(code: number): boolean {
  for (const [first, last] of UNSEEN_CODE_POINT_RANGES) {
    if (code < first) return false;
    if (code <= last) return true;
  }
  return false;
}

/** True when `text` holds a character that does not print, or a surrogate without its pair. */
export function hasUnprintableCharacter(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return true;
      const code = 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00);
      if (isUnseenCodePoint(code)) return true;
      i += 1;
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return true;
    if (isUnseenCodePoint(unit)) return true;
  }
  return false;
}

/**
 * A caller-presented reference as the event records it: verbatim when it is
 * non-empty, within `maxLength` UTF-16 code units and prints as itself,
 * otherwise the `sha256:` digest of its UTF-8 (WTF-8) bytes.
 */
export function sanitizeReference(value: string, maxLength: number = MAX_REFERENCE_LENGTH): string {
  if (value.length > 0 && value.length <= maxLength && !hasUnprintableCharacter(value)) return value;
  return digestText(value);
}

/**
 * SPEC section 7.8 step 2: the reference for a credential id. The id itself,
 * unless it is overlong, holds a character that does not print or a lone
 * surrogate, already reads as a `sha256:` digest, or is the word `unknown`:
 * then the digest of its bytes, so a reference of digest form always stands
 * for the digest of an id and `unknown` never stands for a credential.
 */
export function delegationReference(id: string): string {
  if (id.length === 0 || id.length > MAX_REFERENCE_LENGTH || hasUnprintableCharacter(id) || DIGEST_PATTERN.test(id) || id === 'unknown') {
    return digestText(id);
  }
  return id;
}

/** What a delegation event names a credential that shows no id (AUDITABILITY.md). */
export const UNKNOWN_DELEGATION_REF = 'unknown';

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * The nesting depth of a JSON text's arrays and objects, counted before it is
 * parsed (a depth past `limit` returns `limit + 1` at once), so a value nested
 * to any depth is answered without recursion.
 */
export function jsonTextNestingDepth(text: string, limit: number = MAX_CREDENTIAL_NESTING): number {
  let depth = 0;
  let deepest = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{' || ch === '[') {
      depth += 1;
      if (depth > deepest) deepest = depth;
      if (deepest > limit) return limit + 1;
    } else if (ch === '}' || ch === ']') depth -= 1;
  }
  return deepest;
}

/** The nesting depth of a parsed value, iteratively: the value itself is level 1. */
export function valueNestingDepth(value: unknown, limit: number = MAX_CREDENTIAL_NESTING): number {
  if (typeof value !== 'object' || value === null) return 0;
  let deepest = 0;
  const stack: Array<{ value: object; depth: number }> = [{ value, depth: 1 }];
  while (stack.length > 0) {
    const { value: current, depth } = stack.pop()!;
    if (depth > deepest) deepest = depth;
    if (deepest > limit) return limit + 1;
    const children = Array.isArray(current) ? current : Object.values(current);
    for (const child of children) {
      if (typeof child === 'object' && child !== null) stack.push({ value: child, depth: depth + 1 });
    }
  }
  return deepest;
}

const JWS_SEGMENT = /^[A-Za-z0-9_-]+$/;

function base64UrlNoPad(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

const BASE64_VALUE: Record<string, number> = {};
'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.split('').forEach((ch, index) => {
  BASE64_VALUE[ch] = index;
});
BASE64_VALUE['+'] = 62;
BASE64_VALUE['-'] = 62;
BASE64_VALUE['/'] = 63;
BASE64_VALUE['_'] = 63;
const ASCII_WHITESPACE = new Set([' ', '\t', '\n', '\r', '\f']);

/**
 * Base64 bytes read as SPEC section 7.8 step 1 reads them. `urlOnly` is the
 * JWS reading (base64url alphabet, `=` completing the last group only);
 * otherwise the looser `proofValue` reading (either alphabet, `=` in any
 * number after the last character). Undefined when the string is not a
 * signature under that reading.
 */
export function readSignatureBase64(text: string, urlOnly: boolean): Uint8Array | undefined {
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  let count = 0;
  let padding = 0;
  for (const ch of text) {
    if (ASCII_WHITESPACE.has(ch)) continue;
    if (ch === '=') {
      padding += 1;
      continue;
    }
    if (padding > 0) return undefined;
    if (urlOnly && !(ch === '-' || ch === '_' || /^[A-Za-z0-9]$/.test(ch))) return undefined;
    const value = BASE64_VALUE[ch];
    if (value === undefined) return undefined;
    count += 1;
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  if (count === 0 || count % 4 === 1) return undefined;
  if (urlOnly && padding > 0) {
    const expected = (4 - (count % 4)) % 4;
    if (padding !== expected) return undefined;
  }
  return Uint8Array.from(bytes);
}

function signatureFromProofValue(proof: JsonObject): Uint8Array | undefined {
  const proofValue = nonEmptyString(proof['proofValue']);
  // The SPEC's loose reading, whatever `proof.type` says: a multibase or
  // base58 value is read by the same rule, so every implementation digests
  // one string to one value.
  return proofValue === undefined ? undefined : readSignatureBase64(proofValue, false);
}

/**
 * SPEC section 7.8 step 1: the signed form of a credential, `{jwt, signature}`
 * for a compact VC-JWT and `{credential, signature}` for a credential object,
 * or undefined when the value has none.
 */
export function credentialSignedForm(credential: unknown): JsonObject | undefined {
  if (typeof credential === 'string') {
    const segments = credential.split('.');
    if (segments.length !== 3) return undefined;
    const [header, payload, signature] = segments as [string, string, string];
    if (header.length === 0 || payload.length === 0) return undefined;
    if (!JWS_SEGMENT.test(header) || !JWS_SEGMENT.test(payload)) return undefined;
    const bytes = readSignatureBase64(signature, true);
    if (bytes === undefined || bytes.length === 0) return undefined;
    return { jwt: `${header}.${payload}`, signature: base64UrlNoPad(bytes) };
  }
  if (!isObject(credential)) return undefined;
  if (valueNestingDepth(credential) > MAX_CREDENTIAL_NESTING) return undefined;
  const proof = credential['proof'];
  if (!isObject(proof)) return undefined;
  const bytes = signatureFromProofValue(proof);
  if (bytes === undefined || bytes.length === 0) return undefined;
  const rest: JsonObject = { ...credential };
  delete rest['proof'];
  return { credential: rest, signature: base64UrlNoPad(bytes) };
}

/** SPEC section 7.8 step 2: the digest over a credential's signed form, or undefined when it has none. */
export function credentialDigest(credential: unknown): Digest | undefined {
  const signedForm = credentialSignedForm(credential);
  if (signedForm === undefined) return undefined;
  try {
    return auditDigest(AUDIT_DIGEST_DOMAINS.delegationCredential, signedForm);
  } catch (error) {
    if (error instanceof CanonicalJsonError) return undefined;
    throw error;
  }
}

function readJwtPayload(jwt: string): JsonObject | undefined {
  const segments = jwt.split('.');
  if (segments.length !== 3) return undefined;
  const payload = segments[1]!;
  if (payload.length === 0 || !JWS_SEGMENT.test(payload)) return undefined;
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.from(payload, 'base64url'));
  } catch {
    return undefined;
  }
  if (text.charCodeAt(0) === 0xfeff) return undefined;
  if (jsonTextNestingDepth(text) > MAX_CREDENTIAL_NESTING) return undefined;
  try {
    const parsed: unknown = JSON.parse(text);
    return isObject(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function delegationIdOf(object: JsonObject): string | undefined {
  const subject = object['credentialSubject'];
  if (!isObject(subject)) return undefined;
  const delegation = subject['delegation'];
  return isObject(delegation) ? nonEmptyString(delegation['id']) : undefined;
}

/** SPEC section 7.8 step 1: the id a credential shows in the form it was presented in, or undefined. */
export function credentialShownId(credential: unknown): string | undefined {
  if (typeof credential === 'string') {
    const payload = readJwtPayload(credential);
    if (payload === undefined) return undefined;
    const vc = payload['vc'];
    if (!isObject(vc)) return undefined;
    return nonEmptyString(vc['id']) ?? nonEmptyString(payload['jti']) ?? delegationIdOf(vc);
  }
  if (!isObject(credential)) return undefined;
  return nonEmptyString(credential['id']) ?? delegationIdOf(credential);
}

/** SPEC section 7.8: the `delegationRef` of a credential, or undefined when it shows no id. */
export function delegationRef(credential: unknown): string | undefined {
  const id = credentialShownId(credential);
  return id === undefined ? undefined : delegationReference(id);
}

/**
 * One digest per credential of a chain, root first, as `delegationChainDigests`
 * lists them; undefined when a credential has no signed form or the chain is
 * longer than 256 (SPEC section 7.8: the events then carry the presented
 * credential's digest only).
 */
export function delegationChainDigests(chainRootFirst: readonly unknown[]): Digest[] | undefined {
  if (chainRootFirst.length === 0 || chainRootFirst.length > MAX_CHAIN_DIGESTS) return undefined;
  const digests: Digest[] = [];
  for (const credential of chainRootFirst) {
    const digest = credentialDigest(credential);
    if (digest === undefined) return undefined;
    digests.push(digest);
  }
  return digests;
}

/** SPEC section 7.8 step 3: the chain digest over the array of credential digests, root first. */
export function delegationChainDigest(digests: readonly Digest[]): Digest {
  return auditDigest(AUDIT_DIGEST_DOMAINS.delegationChain, digests);
}
