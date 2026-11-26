// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: fixtures/kya-os-helix/entity-card.json is what the generator produces today,
// and everything it records holds against the implementation: documents and cards validate, every
// DID resolves in two steps over the served map, every refusal refuses for the recorded reason,
// build cases, revocation cases, and the SafeFetch refusals.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  EntityCardInvalidError,
  SafeFetchRefusedError,
  buildEntityCard,
  cardEndpointOf,
  createSafeFetch,
  createStatusListChecker,
  didWebCardUrl,
  entityCardSummary,
  resolveEntityCard,
  resolveEntityCardFromServerMeta,
  serverCardMeta,
  validateEntityCard,
  verifyEntityCard,
  type OutboundFetch,
} from '../../../src/core/index.js';
import { buildEntityCardFixtures, serializeEntityCardFixtures, type EntityCardFixtures } from '../../../scripts/generate-entity-card-fixtures.js';

const PATH = fileURLToPath(new URL('../../../fixtures/kya-os-helix/entity-card.json', import.meta.url));
const checkedIn = readFileSync(PATH, 'utf8');
const fixture = JSON.parse(checkedIn) as EntityCardFixtures;

const serving = (map: Record<string, unknown>): OutboundFetch => async (url) => (map[url] === undefined ? new Response('not found', { status: 404 }) : new Response(JSON.stringify(map[url]), { status: 200 }));

describe('fixtures/kya-os-helix/entity-card.json', () => {
  it('is what the generator produces from current source (regenerate with pnpm generate:entity-card-fixtures)', async () => {
    expect(serializeEntityCardFixtures(await buildEntityCardFixtures())).toBe(checkedIn);
  });

  it('every entity: the document anchors the card, lists did:key and did:hedera, and the card validates and names the key', () => {
    for (const [kind, e] of Object.entries(fixture.entities)) {
      expect(e.kind).toBe(kind);
      expect(e.did_document.id).toBe(e.did);
      expect(e.did_document.alsoKnownAs).toEqual([e.did_key, e.did_hedera]);
      expect(cardEndpointOf(e.did_document)).toBe(e.card_url);
      expect(e.card_url).toBe(didWebCardUrl(e.did));
      expect(validateEntityCard(e.card)).toEqual([]);
      expect(e.card).toMatchObject({ id: e.did, entityType: e.entity_type, name: e.name, kid: e.kid, publicKeyJwk: { ...e.public_key_jwk, kid: e.kid }, didDocument: e.did_document_url, proofProfile: 'org.kya-os/proof.v1' });
      expect(e.card.kid).toBe(e.did_document.verificationMethod[0]!.id);
      expect(e.card.publicKeyJwk!.x).toBe(e.did_document.verificationMethod[0]!.publicKeyJwk.x);
      expect('conformanceLevel' in e.card).toBe(false);
      expect('proof' in e.card).toBe(false);
      expect(e.summary).toEqual(entityCardSummary(e.card));
      expect(e.server_meta).toEqual(serverCardMeta(e.card));
    }
    expect(fixture.entities.org_root.did).toBe(`did:web:${fixture.host}`);
    expect(fixture.entities.org_root.card_url).toBe(`https://${fixture.host}/.well-known/kya-os-card.json`);
  });

  it('the org-owned agent names the org as responsibleParty and the user as principal, and its revocation entry', () => {
    const agent = fixture.entities.agent.card;
    expect(agent.responsibleParty).toBe(fixture.entities.org.did);
    expect(agent.principal).toBe(fixture.user_did_key);
    expect(agent.delegationRef).toBeDefined();
    expect(agent.revocation).toEqual({ statusListCredential: `https://${fixture.host}/v1/status-list/cards`, statusListIndex: '7' });
    expect(fixture.entities.service.card.responsibleParty).toBe(fixture.entities.org.did);
    expect(fixture.entities.service.card.principal).toBeUndefined();
  });

  it('every DID resolves in two steps over the served map to a card that validates', async () => {
    for (const step of fixture.resolution) {
      const urls: string[] = [];
      const fetchLike: OutboundFetch = async (url) => {
        urls.push(url);
        return serving(fixture.served)(url);
      };
      const resolved = await resolveEntityCard(step.did, { fetch: fetchLike });
      expect(urls, step.did).toEqual(step.steps);
      expect(resolved.card.id).toBe(step.card_id);
      expect(validateEntityCard(resolved.card)).toEqual([]);
      const viaMeta = await resolveEntityCardFromServerMeta({ serverMeta: serverCardMeta(resolved.card) }, { fetch: serving(fixture.served) });
      expect(viaMeta.card).toEqual(resolved.card);
    }
  });

  it('every refusal refuses for the recorded reason', async () => {
    for (const refusal of fixture.refusals) {
      let got: string | undefined;
      try {
        if (refusal.card !== undefined) validateEntityCard(refusal.card).length > 0 ? (got = validateEntityCard(refusal.card)[0]!.message) : (got = 'accepted');
        else await resolveEntityCard(refusal.did!, { fetch: serving(refusal.served ?? fixture.served) }), (got = 'resolved');
      } catch (error) {
        got = error instanceof EntityCardInvalidError ? (error.details as { reason?: string }).reason ?? error.code : String(error);
      }
      expect(got, refusal.name).toContain(refusal.reason === 'additionalProperties' ? 'additional properties' : refusal.reason);
    }
  });

  it('build cases: conformanceLevel ignored, a proof, an unknown member and private material refused', () => {
    for (const build of fixture.build_cases) {
      if (build.expected === 'card') {
        const card = buildEntityCard(build.input as never);
        expect(card, build.name).toEqual(build.card);
        for (const member of build.absent ?? []) expect(member in card, `${build.name}: ${member}`).toBe(false);
      } else {
        expect(() => buildEntityCard(build.input as never), build.name).toThrow();
      }
    }
  });

  it('revocation cases: no checker collapses the card, a clear list passes, a set bit collapses to L1 with ok false', async () => {
    const lists = fixture.status_lists as { clear: unknown; revoked: unknown };
    const url = fixture.entities.agent.card.revocation!.statusListCredential;
    for (const c of fixture.revocation_cases) {
      // Lists are signed by the org (story L3-C): read with its DID document, at a time inside their window.
      // The org keeps the URL for its agent's card only because the configuration binds it (SPEC-ENTITY-CARD §10.3).
      const resolveDid = async (did: string) => (did === fixture.entities.org.did ? (fixture.entities.org.did_document as never) : null);
      const clock = () => Date.parse(fixture.status_list_now);
      const statusListIssuers = { [fixture.entities.org.did]: [url] };
      const deps = c.name === 'no_checker' ? {} : { statusListChecker: createStatusListChecker({ resolveDid, clock, statusListIssuers, fetch: serving({ [url]: c.name === 'revoked' ? lists.revoked : lists.clear }) }) };
      const accountable = c.card.responsibleParty === undefined ? deps : { ...deps, accountabilityVerifier: async () => true };
      const result = await verifyEntityCard(c.card, accountable);
      expect({ ok: result.ok, conformanceLevel: result.conformanceLevel, revoked: result.revocation?.revoked ?? false, ...(result.revocation?.code ? { code: result.revocation.code } : {}) }, c.name).toEqual(c.expected);
    }
  });

  it('SafeFetch refuses every recorded URL for the recorded reason', async () => {
    const safeFetch = createSafeFetch({ lookup: async () => ['93.184.216.34'], transport: async () => ({ status: 200, headers: {}, body: new Uint8Array() }) });
    for (const { url, reason } of fixture.safe_fetch_refusals) {
      await expect(safeFetch(url), url).rejects.toSatisfy((error: unknown) => error instanceof SafeFetchRefusedError && error.reason === reason);
    }
  });
});
