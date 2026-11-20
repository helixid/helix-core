// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { canonicalize } from '../../../src/core/crypto/jcs.js';
import { auditEventDigest, parseAuditEvent, validateAuditEvent } from '../../../src/core/audit/index.js';

/**
 * A-1 against the vendored KYA-OS `audit-integrity` vectors (fixtures/kya-os,
 * pinned in PIN.md): the producer event of every vector must validate under
 * the strict schema, canonicalize to `eventCanonical` (event JCS) and digest
 * to `eventDigest` (the domain-separated event digest). The RFC 9162 root,
 * inclusion and consistency parts of the same vectors belong to story A-2.
 */

const FIXTURES = fileURLToPath(new URL('../../../fixtures/', import.meta.url));

interface AuditIntegrityVector {
  id: string;
  expected: 'pass' | 'fail';
  input: { event: unknown; eventCanonical: string; eventDigest: string; canonicalization?: { value: unknown; canonical: string } };
}

const vectors = (JSON.parse(readFileSync(join(FIXTURES, 'kya-os/conformance/vectors/audit-integrity.json'), 'utf8')) as { version: string; vectors: AuditIntegrityVector[] }).vectors;

describe('KYA-OS audit-integrity vectors: event JCS and domain-separated digest', () => {
  it('ships the three pinned vectors', () => {
    expect(vectors.map((vector) => vector.id)).toEqual([
      'audit-integrity/rfc9162-three-leaf',
      'audit-integrity/mutated-root',
      'audit-integrity/code-point-sorted-keys',
    ]);
  });

  for (const vector of vectors) {
    it(`${vector.id}: the event validates, canonicalizes and digests as recorded`, () => {
      expect(validateAuditEvent(vector.input.event).ok).toBe(true);
      const event = parseAuditEvent(vector.input.event);
      expect(canonicalize(event)).toBe(vector.input.eventCanonical);
      expect(auditEventDigest(event)).toBe(vector.input.eventDigest);
    });
  }

  it('refuses an event with an unknown member even when everything else matches the vector', () => {
    const event = vectors[0]!.input.event as Record<string, unknown>;
    expect(validateAuditEvent({ ...event, arguments: { orderId: 'ORD-1' } }).ok).toBe(false);
    expect(validateAuditEvent({ ...event, details: { ...(event['details'] as object), toolName: 'x' } }).ok).toBe(false);
  });

  it('orders keys by UTF-16 code units, which the code-point-sorted vector must not match', () => {
    const sorted = vectors.find((vector) => vector.id === 'audit-integrity/code-point-sorted-keys')!;
    const { value, canonical } = sorted.input.canonicalization!;
    expect(canonicalize(value)).not.toBe(canonical);
    const correct = vectors.find((vector) => vector.id === 'audit-integrity/rfc9162-three-leaf')!.input.canonicalization!;
    expect(canonicalize(correct.value)).toBe(correct.canonical);
  });
});
