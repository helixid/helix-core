// Copyright 2026 DgVerse LLP
// KYA-OS story F-1 against the vendored suite (fixtures/kya-os, pinned in PIN.md).
//
// The upstream `delegation-chain` vectors are written in the legacy §6.2 shape
// (`credentialSubject.delegation`, Ed25519Signature2020). Their chain rules are
// the ones the §6.10 evaluator enforces (linkage, scope subset, audience), so
// each local-rule vector is re-expressed as §6.10 hops and must come to the
// same verdict. `tampered-signature` is a proof of the legacy shape, outside
// this evaluator. The `entity-card` vectors give the card-level floor cases.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { checkCapabilities, deriveConformanceLevel, evaluateDelegationChain } from '../../../src/core/index.js';

const VECTORS = fileURLToPath(new URL('../../../fixtures/kya-os/conformance/vectors/', import.meta.url));

interface LegacyDelegation {
  id: string;
  issuerDid: string;
  subjectDid: string;
  scopes?: string[];
  parentId?: string;
  constraints?: { scopes?: string[]; audience?: string };
}
interface LegacyCredential {
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: { id: string; delegation: LegacyDelegation };
}
interface ChainVector {
  id: string;
  expected: 'pass' | 'fail';
  input: { leaf: LegacyCredential; ancestors?: LegacyCredential[]; serverDid: string };
}
interface CardVector {
  id: string;
  expected: 'pass' | 'fail';
  reason: string;
  input: { card: { id: string; capabilities?: (string | { name: string; attestations: { vc: unknown }[] })[] } };
}

function load<T>(file: string): T[] {
  return (JSON.parse(readFileSync(join(VECTORS, file), 'utf8')) as { vectors: T[] }).vectors;
}

/** The §6.10 hop a legacy delegation describes: issuer, delegate, scopes, audience as the resource. */
function asHop(credential: LegacyCredential, parent: LegacyCredential | undefined): Record<string, unknown> {
  const delegation = credential.credentialSubject.delegation;
  const target = delegation.constraints?.audience ?? 'did:web:server.example.com';
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/zcap/v1', 'https://kya-os.org/ns/delegation/v1'],
    id: `urn:zcap:${delegation.id}`,
    type: ['VerifiableCredential', 'DelegationCredential'],
    issuer: credential.issuer,
    validFrom: credential.issuanceDate,
    validUntil: credential.expirationDate ?? '2030-01-01T00:00:00Z',
    credentialSubject: {
      id: `urn:zcap:${delegation.id}`,
      invoker: credential.credentialSubject.id,
      parentCapability: parent ? `urn:zcap:${parent.credentialSubject.delegation.id}` : target,
      invocationTarget: target,
      allowedAction: delegation.scopes ?? delegation.constraints?.scopes ?? [],
    },
    credentialStatus: { type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: '0', statusListCredential: 'https://server.example.com/status/1' },
    proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created: credential.issuanceDate, verificationMethod: `${credential.issuer}#key-1`, proofPurpose: 'assertionMethod', proofValue: 'z1' },
  };
}

describe('delegation-chain vectors re-expressed as §6.10 hops', () => {
  const vectors = load<ChainVector>('delegation-chain.json');
  const localRuleVectors = vectors.filter((vector) => vector.id !== 'delegation-chain/tampered-signature');

  it('covers every vector but the legacy-shape signature one', () => {
    expect(vectors.map((vector) => vector.id)).toEqual([
      'delegation-chain/valid-single-hop',
      'delegation-chain/valid-two-hop-attenuated',
      'delegation-chain/broken-linkage',
      'delegation-chain/scope-widening',
      'delegation-chain/scopeless-parent-widening',
      'delegation-chain/tampered-signature',
      'delegation-chain/audience-mismatch',
    ]);
  });

  for (const vector of localRuleVectors) {
    it(`${vector.id}: ${vector.expected}`, () => {
      // Ancestors are listed leaf-wards; the chain runs root to leaf.
      const ordered = [...(vector.input.ancestors ?? [])].reverse();
      const credentials = [...ordered, vector.input.leaf];
      const hops = credentials.map((credential, index) => asHop(credential, credentials[index - 1]));
      const evaluation = evaluateDelegationChain(hops, { resource: vector.input.serverDid, now: Date.parse('2026-01-02T00:00:00Z') });
      expect(evaluation.ok, evaluation.reasons.join('; ')).toBe(vector.expected === 'pass');
    });
  }
});

describe('entity-card vectors: the capability floor', () => {
  const vectors = load<CardVector>('entity-card.json');
  const resolve = async (): Promise<undefined> => undefined;

  it('a card of bare capabilities is L1; the attested capability of the accountable agent card carries no credential and so is unverified', async () => {
    for (const vector of vectors.filter((candidate) => candidate.expected === 'pass')) {
      const capabilities = vector.input.card.capabilities ?? [];
      const check = await checkCapabilities(capabilities, resolve, { subjectDid: vector.input.card.id });
      expect(check.verified, vector.id).toEqual([]);
      expect(deriveConformanceLevel(check), vector.id).toBe('L1');
    }
    const accountable = vectors.find((vector) => vector.id === 'entity-card/agent-accountable')!;
    const check = await checkCapabilities(accountable.input.card.capabilities!, resolve, { subjectDid: accountable.input.card.id });
    expect(check).toEqual({ verified: [], unverified: ['handshake', 'payments.transfer'] });
  });
});
