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
 * Domain-separated digests (AUDITABILITY.md, Cryptographic suites): the
 * SHA-256 of `UTF8(<domain>) || 0x00 || UTF8(JCS(value))`, written in the
 * `sha256:<hex>` form of SPEC section 7.3. JCS is L1-B's `canonicalize`; the
 * audit-integrity vectors fix the event digest, and
 * `fixtures/kya-os-helix/audit-events.json` fixes the rest for the Python port.
 */

import { createHmac } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../crypto/jcs.js';
import { AUDIT_DIGEST_DOMAINS, type AuditProducerEvent, type Digest } from './types.js';

/** `sha256:<hex>` of raw bytes (evidence ciphertext, authenticated data). */
export function digestBytes(bytes: Uint8Array): Digest {
  return `sha256:${bytesToHex(sha256(bytes))}`;
}

/**
 * The bytes of a UTF-16 string as UTF-8, or WTF-8 when it is not well-formed:
 * a surrogate without its pair is written in three bytes as a code point of
 * the same value (SPEC section 7.8), so every string has bytes to digest.
 */
export function wtf8Bytes(text: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < text.length; i += 1) {
    let code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i += 1;
      }
    }
    if (code < 0x80) out.push(code);
    else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    else if (code < 0x10000) out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    else out.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
  }
  return Uint8Array.from(out);
}

/** `sha256:<hex>` of a string's UTF-8 (WTF-8 for a lone surrogate) bytes: how an overlong or malformed reference is recorded. */
export function digestText(text: string): Digest {
  return digestBytes(wtf8Bytes(text));
}

/** The domain-separated digest of a JSON value. Throws `CanonicalJsonError` for a value with no RFC 8785 form. */
export function auditDigest(domain: string, value: unknown): Digest {
  if (domain.length === 0 || domain.includes('\0')) {
    throw new TypeError('Audit digest domain must be non-empty and cannot contain NUL');
  }
  const prefix = utf8ToBytes(`${domain}\0`);
  const body = utf8ToBytes(canonicalize(value));
  const input = new Uint8Array(prefix.length + body.length);
  input.set(prefix);
  input.set(body, prefix.length);
  return digestBytes(input);
}

/** The event digest: domain `org.kya-os.audit.event.v1` over the event's canonical form. */
export function auditEventDigest(event: AuditProducerEvent): Digest {
  return auditDigest(AUDIT_DIGEST_DOMAINS.event, event);
}

/**
 * A keyed commitment value: HMAC-SHA256 under a tenant key over the JCS of
 * `value`, so an index over low-entropy identifiers (an account id, an email)
 * cannot be reversed by dictionary without the key.
 */
export function keyedCommitmentValue(key: Uint8Array, value: unknown): Digest {
  return `sha256:${createHmac('sha256', key).update(canonicalize(value), 'utf8').digest('hex')}`;
}

/**
 * `sha256:` of the JCS of a value's JSON wire form, the one `JSON.stringify`
 * sends (members set to `undefined` dropped). For an in-memory document or
 * credential that still carries optional members as `undefined`, which JCS
 * itself refuses (a non-finite number becomes `null` on the wire); a string that
 * is not well-formed Unicode still throws `CanonicalJsonError`.
 */
export function jsonDigest(value: unknown): Digest {
  return auditDigestOfWire(value);
}

function auditDigestOfWire(value: unknown): Digest {
  return digestBytes(utf8ToBytes(canonicalize(JSON.parse(JSON.stringify(value)))));
}
