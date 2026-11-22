// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: the three credential JSON schemas, their TS mirror and what they refuse.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  CAPABILITY_ATTESTATION_SCHEMA,
  DELEGATION_HOP_SCHEMA,
  IDENTITY_CREDENTIAL_SCHEMA,
} from '../../../../src/core/schemas/credential-schemas.js';
import {
  credentialSchemaViolations,
  describeViolations,
  isCapabilityAttestation,
  isDelegationHop,
  isIdentityCredential,
} from '../../../../src/core/credentials/validation.js';
import { assertSupportedSchema } from '../../../../src/core/credentials/json-schema.js';

function omit<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

const SCHEMA_DIR = fileURLToPath(new URL('../../../../src/core/schemas/', import.meta.url));
const FIXTURE = fileURLToPath(new URL('../../../../fixtures/kya-os-helix/credentials.json', import.meta.url));

interface Fixtures {
  identity: { credential: unknown };
  attestations: { credential: unknown }[];
  chains: { name: string; hops: unknown[] }[];
  schema_rejections: { name: string; kind: 'identity' | 'attestation' | 'hop'; document: unknown; violation_path: string }[];
}
const fixtures = JSON.parse(readFileSync(FIXTURE, 'utf8')) as Fixtures;
const validChain = fixtures.chains.find((chain) => chain.name === 'three_hop_valid')!;

describe('src/core/schemas/*.schema.json', () => {
  it.each([
    ['identity-credential', IDENTITY_CREDENTIAL_SCHEMA],
    ['capability-attestation', CAPABILITY_ATTESTATION_SCHEMA],
    ['delegation-hop', DELEGATION_HOP_SCHEMA],
  ])('%s.schema.json is what credential-schemas.ts mirrors (regenerate with node scripts/sync-credential-schemas.mjs)', (file, mirrored) => {
    const published = JSON.parse(readFileSync(`${SCHEMA_DIR}${file}.schema.json`, 'utf8'));
    expect(mirrored).toEqual(published);
    expect(() => assertSupportedSchema(published)).not.toThrow();
  });

  it('accepts the fixture identity, attestations and hops', () => {
    expect(isIdentityCredential(fixtures.identity.credential)).toBe(true);
    for (const attestation of fixtures.attestations) expect(isCapabilityAttestation(attestation.credential)).toBe(true);
    for (const hop of validChain.hops) expect(isDelegationHop(hop)).toBe(true);
  });

  it('never accepts one kind as another', () => {
    expect(isIdentityCredential(fixtures.attestations[0]!.credential)).toBe(false);
    expect(isCapabilityAttestation(fixtures.identity.credential)).toBe(false);
    expect(isDelegationHop(fixtures.identity.credential)).toBe(false);
    expect(isIdentityCredential(validChain.hops[0])).toBe(false);
  });

  it('refuses every checked-in rejection at the recorded path', () => {
    for (const rejection of fixtures.schema_rejections) {
      const violations = credentialSchemaViolations(rejection.kind, rejection.document);
      expect(violations.length, rejection.name).toBeGreaterThan(0);
      expect(violations.map((violation) => violation.path), rejection.name).toContain(rejection.violation_path);
      expect(describeViolations(violations)).toContain(rejection.violation_path);
    }
  });

  it('identity: no scopes, a name, a responsible party, and nothing unknown at the top level', () => {
    const identity = fixtures.identity.credential as Record<string, unknown>;
    const subject = identity['credentialSubject'] as Record<string, unknown>;
    expect(subject).toEqual({ id: expect.any(String), name: 'orders-agent', responsibleParty: expect.stringMatching(/^did:/) });
    expect(credentialSchemaViolations('identity', { ...identity, extra: 1 }).map((v) => v.path)).toEqual(['$.extra']);
    expect(credentialSchemaViolations('identity', { ...identity, credentialSubject: { ...subject, responsibleParty: 'owner' } }).map((v) => v.path)).toEqual([
      '$.credentialSubject.responsibleParty',
    ]);
  });

  it('attestation: the subject is the agent DID and a capability, nothing more', () => {
    const attestation = fixtures.attestations[0]!.credential as Record<string, unknown>;
    const subject = attestation['credentialSubject'] as Record<string, unknown>;
    expect(credentialSchemaViolations('attestation', { ...attestation, credentialSubject: { ...subject, privilegeScopes: [] } }).map((v) => v.path)).toEqual([
      '$.credentialSubject.privilegeScopes',
    ]);
    expect(credentialSchemaViolations('attestation', { ...attestation, credentialSubject: { id: subject['id'] } }).map((v) => v.message)).toEqual([
      'missing required member "capability"',
    ]);
  });

  it('hop: the §6.10 shape with a closed subject (Core L3.5a), a Bitstring status entry and an eddsa-jcs-2022 proof', () => {
    const hop = validChain.hops[0] as Record<string, unknown>;
    expect(hop['@context']).toEqual([
      'https://www.w3.org/ns/credentials/v2',
      'https://w3id.org/security/zcap/v1',
      'https://kya-os.org/ns/delegation/v1',
    ]);
    expect(hop['type']).toEqual(['VerifiableCredential', 'DelegationCredential']);
    const paths = (changed: Record<string, unknown>): string[] => credentialSchemaViolations('hop', { ...hop, ...changed }).map((v) => v.path);
    expect(paths({ '@context': ['https://www.w3.org/ns/credentials/v2'] })).toEqual(['$.@context', '$.@context', '$.@context']);
    expect(paths({ credentialStatus: { ...(hop['credentialStatus'] as object), type: 'StatusList2021Entry' } })).toEqual(['$.credentialStatus.type']);
    expect(paths({ proof: { ...(hop['proof'] as object), cryptosuite: 'eddsa-rdfc-2022' } })).toEqual(['$.proof.cryptosuite']);
    expect(paths({ proof: { ...(hop['proof'] as object), proofPurpose: 'authentication' } })).toEqual(['$.proof.proofPurpose']);
    const subject = hop['credentialSubject'] as Record<string, unknown>;
    // A controller may stand in for the invoker, but one of them must be there.
    const noDelegate = omit(subject, 'invoker');
    expect(paths({ credentialSubject: { ...noDelegate, controller: subject['invoker'] } })).toEqual([]);
    expect(paths({ credentialSubject: noDelegate })).toEqual(['$.credentialSubject']);
    expect(paths({ credentialSubject: { ...subject, caveats: [{ type: 'MaxAmount', limit: 'ten' }] } })).toEqual(['$.credentialSubject.caveats[0].limit']);
    expect(paths({ credentialSubject: { ...subject, caveats: [{ type: 'Region', regions: ['EU'] }] } })).toEqual([]);
    expect(paths({ validUntil: undefined })).toEqual(['$.validUntil']);
    const noValidUntil = omit(hop, 'validUntil');
    expect(credentialSchemaViolations('hop', noValidUntil).map((v) => v.message)).toEqual(['missing required member "validUntil"']);
  });
});
