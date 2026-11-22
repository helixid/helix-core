// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: the cross-language credential fixture (fixtures/kya-os-helix/credentials.json).
// Regenerates it from source and fails on drift, then holds every recorded verdict.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  checkCapabilities,
  deriveConformanceLevel,
  deriveEffectiveScopes,
  evaluateDelegationChain,
  verifyCapabilityAttestation,
  verifyDelegationChainProofs,
  verifyIdentityCredential,
  verifyIdentityVerificationCredential,
} from '../../../../src/core/index.js';
import { buildCredentialFixtures, serializeCredentialFixtures, type CredentialFixtures } from '../../../../scripts/generate-credential-fixtures.js';
import type { DidResolver } from '../../../../src/core/credentials/index.js';

const FIXTURE_PATH = fileURLToPath(new URL('../../../../fixtures/kya-os-helix/credentials.json', import.meta.url));
const checkedIn = readFileSync(FIXTURE_PATH, 'utf8');
const fixtures = JSON.parse(checkedIn) as CredentialFixtures;
const resolve = (async (did: string) => fixtures.did_documents[did]) as unknown as DidResolver;
const now = Date.parse(fixtures.now);
const statusLists = { [fixtures.status_list_url]: { credentialSubject: { encodedList: fixtures.status_list_encoded } } };

describe('fixtures/kya-os-helix/credentials.json', () => {
  it('is exactly what the generator produces from current source (regenerate with pnpm generate:credential-fixtures)', async () => {
    expect(serializeCredentialFixtures(await buildCredentialFixtures())).toBe(checkedIn);
  });

  it('identity: issued by Helix to the child agent, naming the owner, no scopes, verifies', async () => {
    const verdict = await verifyIdentityCredential(fixtures.identity.credential, resolve, { now, agentDid: fixtures.keys['child']!.did });
    expect(verdict).toMatchObject({ ok: true, responsibleParty: fixtures.keys['owner']!.did });
    expect(Object.keys((fixtures.identity.credential as { credentialSubject: object }).credentialSubject).sort()).toEqual(['id', 'name', 'responsibleParty']);
  });

  it('identity verification: KYB level on the owner, verifies', async () => {
    const verdict = await verifyIdentityVerificationCredential(fixtures.identity_verification.credential, resolve, { now, subjectDid: fixtures.keys['owner']!.did });
    expect(verdict).toMatchObject({ ok: true, verificationLevel: 'enhanced' });
  });

  it('attestations: each verifies under allow-all, and the revoked one reads as revoked against the fixture list', async () => {
    for (const attestation of fixtures.attestations) {
      const verdict = await verifyCapabilityAttestation(attestation.credential, resolve, { now, subjectDid: fixtures.keys['child']!.did });
      expect(verdict, attestation.name).toMatchObject({ ok: true, issuer: fixtures.keys[attestation.signer]!.did });
      const withList = await verifyCapabilityAttestation(attestation.credential, resolve, { now, ...(statusLists[fixtures.status_list_url] ? { statusList: statusLists[fixtures.status_list_url] } : {}) });
      expect(withList.ok, attestation.name).toBe(!attestation.revoked);
    }
  });

  it('chains: every recorded evaluation and proof verdict holds', async () => {
    for (const chain of fixtures.chains) {
      const evaluation = evaluateDelegationChain(chain.hops, {
        ...(chain.options.resource === undefined ? {} : { resource: chain.options.resource }),
        ...(chain.options.resourceOwner === undefined ? {} : { resourceOwner: chain.options.resourceOwner }),
        ...(chain.options.maxChainLength === undefined ? {} : { maxChainLength: chain.options.maxChainLength }),
        now: Date.parse(chain.options.now),
      });
      expect({ ok: evaluation.ok, code: evaluation.code, allowedAction: evaluation.allowedAction, depth: evaluation.depth, responsibleParty: evaluation.responsibleParty, leafInvoker: evaluation.leafInvoker }, chain.name).toEqual({
        ok: chain.expected.ok,
        code: chain.expected.code,
        allowedAction: chain.expected.allowedAction,
        depth: chain.expected.depth,
        responsibleParty: chain.expected.responsibleParty,
        leafInvoker: chain.expected.leafInvoker,
      });
      if (chain.hops.length > 0 && chain.hops.length <= 10 && chain.name !== 'unsigned_leaf' && chain.name !== 'extra_subject_member') {
        expect((await verifyDelegationChainProofs(chain.hops, resolve)).ok, chain.name).toBe(chain.proofs_ok);
      }
    }
    const names = fixtures.chains.map((chain) => chain.name);
    for (const required of ['three_hop_valid', 'broadened_action', 'dropped_caveat', 'extended_valid_until', 'extra_subject_member', 'too_long', 'tampered_proof']) {
      expect(names).toContain(required);
    }
  });

  it('effective scopes: the three-way intersection, equal to the retired formula on the golden-vector cases', () => {
    for (const scopes of fixtures.effective_scopes) {
      expect(deriveEffectiveScopes(scopes.attestations, scopes.leaf_allowed_action, scopes.catalog), scopes.name).toEqual(scopes.expected);
      if (scopes.legacy) {
        // The retired verifier: privilegeScopes.filter(allowed by the grant), or privilegeScopes alone without a grant.
        const legacy = scopes.legacy.grant_scopes === null ? scopes.legacy.privilege_scopes : scopes.legacy.privilege_scopes.filter((scope) => scopes.legacy!.grant_scopes!.includes(scope));
        expect(legacy, scopes.name).toEqual(scopes.legacy.expected);
        expect(scopes.expected, scopes.name).toEqual(legacy);
      }
    }
  });

  it('card levels: capability check and level derive as recorded', async () => {
    for (const card of fixtures.card_levels) {
      const check = await checkCapabilities(card.capabilities, resolve, { subjectDid: card.subject_did, trustedIssuers: card.trusted_issuers, now, statusLists });
      expect(check, card.name).toEqual(card.expected_check);
      expect(deriveConformanceLevel(check, card.proof_floor_ok, card.revocation_fresh), card.name).toBe(card.expected_level);
    }
    const level = (name: string): string => fixtures.card_levels.find((card) => card.name === name)!.expected_level;
    expect(level('fully_attested_allow_all')).toBe('L2');
    expect(level('one_bare_capability')).toBe('L1');
    expect(level('owner_unlisted')).toBe('L1');
    expect(level('owner_listed')).toBe('L2');
    expect(level('revoked_attestation')).toBe('L1');
  });
});
