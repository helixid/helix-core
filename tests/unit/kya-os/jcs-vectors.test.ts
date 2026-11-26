// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { canonicalize, hashJson } from '../../../src/core/crypto/jcs.js';

/**
 * L1-B against the vendored KYA-OS conformance suite (fixtures/kya-os, pinned
 * in PIN.md) and the Helix fixture set it generates (fixtures/kya-os-helix).
 *
 * Upstream has no standalone JCS vector file; its JCS vectors are spread over
 * the audit-integrity vectors (`input.canonicalization`, `eventCanonical`),
 * SPEC.md appendix C.1, and the signed-proof vectors, whose `expected.request`
 * / `expected.response` must hash to the proof's `requestHash` /
 * `responseHash` (SPEC section 7.3). All of them run here.
 */

const FIXTURES = fileURLToPath(new URL('../../../fixtures/', import.meta.url));
const VECTORS = join(FIXTURES, 'kya-os/conformance/vectors');

interface Vector {
  id: string;
  expected: 'pass' | 'fail';
  input: Record<string, any>;
}

function loadJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function vectors(file: string): Vector[] {
  return loadJson<{ version: string; vectors: Vector[] }>(join(VECTORS, file)).vectors;
}

/** The covered request of SPEC section 7.3: method and params minus `_meta`, arguments minus `_kyaos*`. */
function coveredRequest(request: { method: string; params?: Record<string, unknown> }): Record<string, unknown> {
  const covered: Record<string, unknown> = { method: request.method };
  if (request.params) {
    const params: Record<string, unknown> = { ...request.params };
    delete params['_meta'];
    if (request.method === 'tools/call') {
      const args = (params['arguments'] ?? {}) as Record<string, unknown>;
      params['arguments'] = Object.fromEntries(Object.entries(args).filter(([name]) => !name.startsWith('_kyaos')));
    }
    covered['params'] = params;
  }
  return covered;
}

/** The response hash of SPEC section 7.3: `data` (body profile) or `data` minus `_meta` (envelope profile). */
function responseHash(data: unknown, profile: string | undefined): string {
  if (profile === 'org.kya-os/response-proof.envelope') {
    const rest: Record<string, unknown> = { ...(data as Record<string, unknown>) };
    delete rest['_meta'];
    return hashJson(rest);
  }
  return hashJson(data);
}

function jwsPayload(jws: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jws.split('.')[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
}

describe('vendored suite pin (fixtures/kya-os)', () => {
  it('holds suite 1.10.0 at the pinned vector set hash, file for file', () => {
    const manifest = loadJson<{ suiteVersion: string; vectorSetHash: string; vectorCount: number; files: [string, string][] }>(
      join(FIXTURES, 'kya-os/conformance/SUITE-MANIFEST.json'),
    );
    const names = readdirSync(VECTORS).filter((name) => name.endsWith('.json')).sort();
    let count = 0;
    const files = names.map((name) => {
      const bytes = readFileSync(join(VECTORS, name));
      count += (JSON.parse(bytes.toString('utf8')) as { vectors: unknown[] }).vectors.length;
      return [name, createHash('sha256').update(bytes).digest('hex')];
    });
    expect(files).toEqual(manifest.files);
    expect(count).toBe(manifest.vectorCount);
    expect(manifest.suiteVersion).toBe('1.10.0');
    const vectorSetHash = `sha256:${createHash('sha256').update(canonicalize(files), 'utf8').digest('hex')}`;
    expect(vectorSetHash).toBe('sha256:6dd5e3dd0526b0fb7e7e3ea9e76b63a3acd0651aeb36ee03ea1f820bb15ebed0');
    expect(vectorSetHash).toBe(manifest.vectorSetHash);
    const pin = readFileSync(join(FIXTURES, 'kya-os/PIN.md'), 'utf8');
    expect(pin).toContain('a4d7f61');
    expect(pin).toContain(vectorSetHash);
  });
});

describe('JCS vectors from the suite', () => {
  it('canonicalizes the audit-integrity canonicalization vectors (UTF-16 key order, float layout)', () => {
    const checked = vectors('audit-integrity.json').filter((vector) => vector.input['canonicalization']);
    expect(checked.length).toBeGreaterThan(0);
    for (const vector of checked) {
      const { value, canonical } = vector.input['canonicalization'] as { value: unknown; canonical: string };
      // A `fail` vector supplies a canonical form a conformant implementation must not produce.
      expect(canonicalize(value) === canonical, vector.id).toBe(vector.expected === 'pass');
    }
  });

  it('writes every audit event as its eventCanonical', () => {
    for (const vector of vectors('audit-integrity.json')) {
      expect(canonicalize(vector.input['event']), vector.id).toBe(vector.input['eventCanonical']);
    }
  });

  it('matches SPEC appendix C.1, including the covered-request reductions', () => {
    const emptyArgs = 'sha256:5057521f310b536837b619f0ac040ef8064f8c597da8ec22a56801b435744033';
    const msgHi = 'sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7';
    const input = { method: 'tools/call', params: { name: 'echo', arguments: {} } };
    expect(canonicalize(input)).toBe('{"method":"tools/call","params":{"arguments":{},"name":"echo"}}');
    expect(hashJson(input)).toBe(emptyArgs);
    expect(
      hashJson(
        coveredRequest({
          method: 'tools/call',
          params: {
            name: 'echo',
            arguments: { _kyaos_proof: { jws: '...', meta: {} } },
            _meta: { traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' },
          },
        }),
      ),
    ).toBe(emptyArgs);
    expect(hashJson(coveredRequest({ method: 'tools/call', params: { name: 'echo' } }))).toBe(emptyArgs);
    const business = coveredRequest({
      method: 'tools/call',
      params: { name: 'echo', arguments: { msg: 'hi', _kyaos_delegation: { id: 'urn:uuid:1111-aaaa' } }, _meta: { progressToken: 7 } },
    });
    expect(canonicalize(business)).toBe('{"method":"tools/call","params":{"arguments":{"msg":"hi"},"name":"echo"}}');
    expect(hashJson(business)).toBe(msgHi);
    expect(hashJson(coveredRequest({ method: 'tools/call' }))).toBe(hashJson({ method: 'tools/call' }));
  });
});

describe('signed-proof vector category, hash part', () => {
  /** The vectors whose refusal is the hash part itself: the request or response no longer hashes to the proof. */
  const HASH_FAILURES = [
    'signed-proof/envelope-tampered-structured-content',
    'signed-proof/delegation-proof-request-hash-altered',
    'signed-proof/delegation-proof-request-substituted',
  ];

  it('recomputes requestHash and responseHash from the expected request and response', () => {
    const checked = vectors('signed-proof.json').filter((vector) => vector.input['expected']?.request);
    expect(checked.length).toBeGreaterThan(30);
    const disagreeing: string[] = [];
    for (const vector of checked) {
      const { proof, expected } = vector.input as {
        proof: { jws: string; meta: { requestHash: string; responseHash?: string } };
        expected: { request: { method: string; params?: Record<string, unknown> }; response?: { data: unknown } };
      };
      const profile = jwsPayload(proof.jws)['prf'] as string | undefined;
      let agree = hashJson(coveredRequest(expected.request)) === proof.meta.requestHash;
      if (expected.response) agree &&= responseHash(expected.response.data, profile) === proof.meta.responseHash;
      else expect(proof.meta.responseHash, vector.id).toBeUndefined();
      if (!agree) disagreeing.push(vector.id);
      if (vector.expected === 'pass') expect(agree, `${vector.id}: hashes must agree on a pass vector`).toBe(true);
    }
    expect(disagreeing.sort()).toEqual([...HASH_FAILURES].sort());
  });

  it('hashes the valid-basic proof request as SPEC C.1 (covered request, not the legacy shape)', () => {
    const basic = vectors('signed-proof.json').find((vector) => vector.id === 'signed-proof/valid-basic')!;
    const request = { method: 'tools/call', params: { name: 'echo', arguments: { msg: 'hi' } } };
    expect(basic.input['proof'].meta.requestHash).toBe(hashJson(request));
    expect(basic.input['proof'].meta.requestHash).not.toBe(hashJson({ method: 'echo', params: { msg: 'hi' } }));
  });
});

describe('fixtures/kya-os-helix/jcs.json', () => {
  it('re-derives every vector from the current implementation (regenerate with pnpm generate:kya-os-helix)', () => {
    const file = loadJson<{ vectors: { name: string; input: unknown; canonical: string; hash: string }[] }>(
      join(FIXTURES, 'kya-os-helix/jcs.json'),
    );
    expect(file.vectors.length).toBeGreaterThanOrEqual(14);
    for (const vector of file.vectors) {
      expect(canonicalize(vector.input), vector.name).toBe(vector.canonical);
      expect(hashJson(vector.input), vector.name).toBe(vector.hash);
      expect(vector.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
  });
});
