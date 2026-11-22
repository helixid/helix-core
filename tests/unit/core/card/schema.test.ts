// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: the card schema (strict, as vendored), parseCard, and buildEntityCard.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  EntityCardInvalidError,
  KYA_OS_CARD_SCHEMA,
  buildEntityCard,
  capabilityName,
  parseEntityCard,
  publicKeyBytesToJwk,
  validateCardJsonSchema as validateJsonSchema,
  validateEntityCard,
} from '../../../../src/core/index.js';

const VENDORED = fileURLToPath(new URL('../../../../fixtures/kya-os/schemas/kya-os-card.schema.json', import.meta.url));
const schema = JSON.parse(readFileSync(VENDORED, 'utf8')) as { examples: unknown[] };
const JWK = publicKeyBytesToJwk(new Uint8Array(32).fill(9));
const DID = 'did:web:helix.test:acme:ledger-agent';

describe('the embedded card schema', () => {
  it('is the vendored kya-os-card.schema.json, value for value', () => {
    expect(JSON.parse(JSON.stringify(KYA_OS_CARD_SCHEMA))).toEqual(schema);
  });

  it('admits every example the schema ships and refuses an unknown top-level field in each', () => {
    for (const example of schema.examples) {
      expect(validateEntityCard(example)).toEqual([]);
      expect(validateEntityCard({ ...(example as object), bogusField: true })).toEqual([{ path: '/bogusField', message: 'must NOT have additional properties' }]);
    }
  });

  it('refuses, with the path, a wrong type, a missing required member, a bad DID, an empty name, a non-decimal index, a non-1 statusSize, an unknown nested member', () => {
    const issues = (value: unknown): string[] => validateEntityCard(value).map((issue) => `${issue.path}: ${issue.message}`);
    expect(issues('card')).toEqual([': must be of type object']);
    expect(issues({ id: DID })).toEqual([": must have required property 'entityType'", ": must have required property 'name'"]);
    expect(issues({ id: 'did:hedera:testnet:x', entityType: 'agent', name: 'A' })[0]).toMatch(/^\/id: must match/);
    expect(issues({ id: `${DID}#key-1`, entityType: 'agent', name: 'A' })[0]).toMatch(/^\/id: must match/);
    expect(issues({ id: DID, entityType: 'tool', name: 'A' })).toEqual(['/entityType: must be one of ["mcp","agent","client","verifier","human"]']);
    expect(issues({ id: DID, entityType: 'agent', name: '' })).toEqual(['/name: must be at least 1 characters']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', revocation: { statusListCredential: 'https://x', statusListIndex: '0x7' } })).toEqual(['/revocation/statusListIndex: must match ^[0-9]+$']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', revocation: { statusListCredential: 'https://x', statusListIndex: '7', statusSize: 0 } })).toEqual(['/revocation/statusSize: must be at least 1']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', publicKeyJwk: { ...JWK, d: 'secret' } })).toEqual(['/publicKeyJwk/d: must NOT have additional properties']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'a' } })).toEqual(['/publicKeyJwk/kty: must equal "OKP"', '/publicKeyJwk/crv: must equal "Ed25519"']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', capabilities: [''] })[0]).toMatch(/^\/capabilities\/0: must match exactly one schema in oneOf/);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', capabilities: [{ name: 'x', attestations: [] }] })[0]).toMatch(/^\/capabilities\/0: must match exactly one/);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', createdAt: 'yesterday' })).toEqual(['/createdAt: must be an RFC 3339 date-time']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', didDocument: 'not a uri' })).toEqual(['/didDocument: must be a URI']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', proofProfile: 'org.kya-os/proof.v2' })).toEqual(['/proofProfile: must be one of ["org.kya-os/proof.v1","org.kya-os/proof@1"]']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', attestations: [{ type: 'KYC', vc: 'x' }] })).toEqual(['/attestations/0/type: must be one of ["IdentityVerification","CapabilityAttestation"]']);
    expect(issues({ id: DID, entityType: 'agent', name: 'A', cimd: { clientId: 'https://x' } })).toEqual(["/cimd: must have required property 'jwksUri'"]);
  });

  it('the lite evaluator refuses a keyword or $ref outside the subset it implements', () => {
    expect(() => validateJsonSchema({ anyOf: [] }, 1)).toThrow(/unsupported keyword anyOf/);
    expect(() => validateJsonSchema({ $ref: '#/definitions/x' }, 1)).toThrow(/unsupported \$ref/);
    expect(() => validateJsonSchema({ $ref: '#/$defs/Missing', $defs: {} }, 1)).toThrow(/not defined/);
    expect(validateJsonSchema({ type: ['string', 'null'] }, null)).toEqual([]);
    expect(validateJsonSchema({ type: 'number' }, 1.5)).toEqual([]);
    expect(validateJsonSchema({ type: 'integer' }, 1.5)).toEqual([{ path: '', message: 'must be of type integer' }]);
    expect(validateJsonSchema({ minItems: 2 }, [1])).toEqual([{ path: '', message: 'must have at least 2 items' }]);
  });
});

describe('parseEntityCard', () => {
  it('returns the card unchanged and throws EntityCardInvalidError with every issue otherwise', () => {
    const card = { id: DID, entityType: 'agent', name: 'Ledger', capabilities: ['handshake', { name: 'ledger.post', attestations: [{ vc: 'jwt', extra: 1 }] }], conformanceLevel: 'L2' };
    expect(parseEntityCard(card)).toBe(card);
    expect(card.capabilities.map((capability) => capabilityName(capability as never))).toEqual(['handshake', 'ledger.post']);
    try {
      parseEntityCard({ ...card, bogusField: true, name: '' });
      throw new Error('unreachable');
    } catch (error) {
      expect(error).toBeInstanceOf(EntityCardInvalidError);
      const refusal = error as EntityCardInvalidError;
      expect(refusal.code).toBe('ENTITY_CARD_INVALID');
      expect(refusal.httpStatus).toBe(400);
      expect(refusal.message).toBe('Entity Card is invalid: /name must be at least 1 characters');
      expect(refusal.details).toEqual({ issues: [{ path: '/name', message: 'must be at least 1 characters' }, { path: '/bogusField', message: 'must NOT have additional properties' }] });
    }
  });
});

describe('buildEntityCard', () => {
  const input = { id: DID, entityType: 'agent' as const, name: 'Acme Ledger Agent', kid: 'key-1', publicKeyJwk: JWK, capabilities: ['handshake'] };

  it('writes the card members in the spec order, the kid in did#fragment form, proofProfile v1, the derived didDocument URL, and never a conformanceLevel', () => {
    const card = buildEntityCard({
      ...input,
      responsibleParty: 'did:web:helix.test:acme',
      principal: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      delegationRef: 'root>del1',
      revocation: { statusListCredential: 'https://helix.test/v1/status-list/cards', statusListIndex: '7' },
      createdAt: '2026-11-21T00:00:00Z',
      conformanceLevel: 'L3',
    });
    expect(Object.keys(card)).toEqual(['id', 'entityType', 'name', 'kid', 'publicKeyJwk', 'createdAt', 'capabilities', 'responsibleParty', 'principal', 'delegationRef', 'didDocument', 'proofProfile', 'revocation']);
    expect(card).toMatchObject({
      kid: `${DID}#key-1`,
      publicKeyJwk: { ...JWK, kid: `${DID}#key-1` },
      didDocument: 'https://helix.test/acme/ledger-agent/did.json',
      proofProfile: 'org.kya-os/proof.v1',
    });
    expect('conformanceLevel' in card).toBe(false);
    expect(validateEntityCard(card)).toEqual([]);
  });

  it('takes a full kid, a named didDocument, attestations and cimd, and leaves out what is not given', () => {
    const card = buildEntityCard({
      id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      entityType: 'human',
      name: 'Alice',
      attestations: [{ type: 'IdentityVerification', vc: 'jwt', issuer: 'did:web:helix.test' }],
      cimd: { clientId: 'https://helix.test/clients/alice', jwksUri: 'https://helix.test/clients/alice/jwks.json' },
    });
    expect(card).toEqual({
      id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      entityType: 'human',
      name: 'Alice',
      attestations: [{ type: 'IdentityVerification', vc: 'jwt', issuer: 'did:web:helix.test' }],
      proofProfile: 'org.kya-os/proof.v1',
      cimd: { clientId: 'https://helix.test/clients/alice', jwksUri: 'https://helix.test/clients/alice/jwks.json' },
    });
    expect(buildEntityCard({ ...input, kid: `${DID}#signing-2026`, didDocument: 'https://cdn.example/did.json' })).toMatchObject({ kid: `${DID}#signing-2026`, didDocument: 'https://cdn.example/did.json' });
    expect(buildEntityCard({ id: DID, entityType: 'mcp', name: 'S', publicKeyJwk: JWK }).publicKeyJwk).toEqual(JWK);
  });

  it('refuses a proof, an unknown member, private key material, a bad DID, a bad entity type, an empty name, a non-DID party, and a kid of another DID', () => {
    expect(() => buildEntityCard({ ...input, proof: { type: 'DataIntegrityProof' } } as never)).toThrow(/unknown members \(proof\)/);
    expect(() => buildEntityCard({ ...input, bogusField: 1 } as never)).toThrow(/unknown members \(bogusField\)/);
    expect(() => buildEntityCard({ ...input, publicKeyJwk: { ...JWK, d: 'secret' } })).toThrow(/private material/);
    expect(() => buildEntityCard({ ...input, id: 'did:hedera:testnet:x' })).toThrow(/did:web or did:key/);
    expect(() => buildEntityCard({ ...input, id: `${DID}#key-1` })).toThrow(/did:web or did:key/);
    expect(() => buildEntityCard({ ...input, entityType: 'tool' as never })).toThrow(/entityType/);
    expect(() => buildEntityCard({ ...input, name: '' })).toThrow(/name/);
    expect(() => buildEntityCard({ ...input, responsibleParty: 'acme' })).toThrow(/responsibleParty/);
    expect(() => buildEntityCard({ ...input, principal: 'did:hedera:testnet:x' })).toThrow(/principal/);
    expect(() => buildEntityCard({ ...input, kid: 'did:web:other.test#key-1' })).toThrow(/does not belong/);
    expect(() => buildEntityCard(null as never)).toThrow(/input object/);
    expect(() => buildEntityCard({ ...input, createdAt: 'yesterday' })).toThrow(EntityCardInvalidError);
  });
});
