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
 * RFC 8785 (JSON Canonicalization Scheme) and the KYA-OS hash format.
 *
 * `canonicalize(value)` writes a JSON value the one way RFC 8785 allows:
 * object members sorted by the UTF-16 code units of their names, no
 * whitespace, numbers as ECMAScript `Number::toString` writes them, strings
 * escaped as `JSON.stringify` escapes them. `hashJson(value)` is the SHA-256
 * of the UTF-8 bytes of that text, written `sha256:<64 lowercase hex>`, the
 * form KYA-OS compares everywhere a hash travels (SPEC §7.3, CONFORMANCE
 * L1.2).
 *
 * The serializer is strict rather than lenient: a value that has no single
 * JSON form (`undefined`, a function, a bigint, a non-finite number, an
 * integer beyond 2^53 - 1, a lone surrogate, a cycle, a Date or any other
 * non-plain object) is refused with a `CanonicalJsonError` instead of being
 * coerced, so two distinguishable inputs never hash alike by accident.
 * `toJSON` is never consulted. The Python SDK's `helix_sdk.crypto.jcs`
 * implements the same rules; `fixtures/kya-os-helix/jcs.json` is the
 * byte-for-byte contract between the two.
 */

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

/** Thrown for a value that has no RFC 8785 canonical form. */
export class CanonicalJsonError extends TypeError {
  constructor(problem: string, path: string) {
    super(`Cannot canonicalize ${problem} at ${path}`);
    this.name = 'CanonicalJsonError';
  }
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

/** A UTF-16 code unit sequence with a high surrogate not followed by a low one, or a low one not preceded by a high one. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function writeString(text: string, path: string): string {
  if (LONE_SURROGATE.test(text)) throw new CanonicalJsonError('a string with a lone surrogate', path);
  return JSON.stringify(text);
}

function writeNumber(value: number, path: string): string {
  if (!Number.isFinite(value)) throw new CanonicalJsonError(`a non-finite number (${String(value)})`, path);
  if (Number.isInteger(value) && Math.abs(value) > MAX_SAFE) {
    throw new CanonicalJsonError(`an integer outside the safe range (${String(value)})`, path);
  }
  // ECMAScript Number::toString is the RFC 8785 §3.2.2.3 rule; it writes -0 as 0.
  return String(value);
}

function write(value: unknown, path: string, ancestors: Set<object>): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return writeString(value, path);
    case 'number':
      return writeNumber(value, path);
    case 'object':
      break;
    default:
      throw new CanonicalJsonError(`a ${typeof value}`, path);
  }
  const container = value as object;
  if (ancestors.has(container)) throw new CanonicalJsonError('a cyclic reference', path);
  ancestors.add(container);
  try {
    if (Array.isArray(container)) return writeArray(container, path, ancestors);
    if (!isPlainObject(container)) throw new CanonicalJsonError('a non-plain object', path);
    return writeObject(container as Record<string, unknown>, path, ancestors);
  } finally {
    ancestors.delete(container);
  }
}

function writeArray(array: readonly unknown[], path: string, ancestors: Set<object>): string {
  const parts: string[] = [];
  for (let index = 0; index < array.length; index += 1) {
    const elementPath = `${path}[${index}]`;
    if (!Object.hasOwn(array, index)) throw new CanonicalJsonError('a sparse array element', elementPath);
    parts.push(write(array[index], elementPath, ancestors));
  }
  return `[${parts.join(',')}]`;
}

function writeObject(object: Record<string, unknown>, path: string, ancestors: Set<object>): string {
  if (Object.getOwnPropertySymbols(object).length > 0) throw new CanonicalJsonError('a symbol-keyed member', path);
  // RFC 8785 §3.2.3: member names sorted by UTF-16 code units, which is how
  // JavaScript's default string comparison orders them.
  // Own property names are distinct, so two never compare equal.
  const keys = Object.keys(object).sort((a, b) => (a < b ? -1 : 1));
  const parts: string[] = [];
  for (const key of keys) {
    const memberPath = `${path}.${key}`;
    parts.push(`${writeString(key, memberPath)}:${write(object[key], memberPath, ancestors)}`);
  }
  return `{${parts.join(',')}}`;
}

/** The RFC 8785 canonical JSON text of `value`. Throws `CanonicalJsonError` for a value that has none. */
export function canonicalize(value: unknown): string {
  return write(value, '$', new Set<object>());
}

/** SHA-256 over the UTF-8 bytes of `canonicalize(value)`, as `sha256:<64 lowercase hex>` (KYA-OS SPEC §7.3). */
export function hashJson(value: unknown): string {
  return `sha256:${bytesToHex(sha256(utf8ToBytes(canonicalize(value))))}`;
}
