// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: two-step card discovery (did.json → KyaOsEntityCard → card.json), the
// bare-host fallback, the server.json projection, and every refusal.
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  EntityCardInvalidError,
  buildDidDocument,
  buildEntityCard,
  entityCardSummary,
  fetchEntityCard,
  publicKeyBytesToJwk,
  resolveEntityCard,
  resolveEntityCardFromServerMeta,
  serverCardMeta,
  setOutboundFetch,
  type OutboundFetch,
} from '../../../../src/core/index.js';

const JWK = publicKeyBytesToJwk(new Uint8Array(32).fill(3));
const AGENT = 'did:web:helix.test:acme:ledger-agent';
const ORG = 'did:web:helix.test';
const agentCard = buildEntityCard({ id: AGENT, entityType: 'agent', name: 'Ledger', kid: 'key-1', publicKeyJwk: JWK, capabilities: ['handshake'] });
const orgCard = buildEntityCard({ id: ORG, entityType: 'verifier', name: 'Helix', kid: 'key-1', publicKeyJwk: JWK });
const agentDocument = buildDidDocument({ did: AGENT, publicKeyJwk: JWK, cardServiceEndpoint: true });
const orgDocument = buildDidDocument({ did: ORG, publicKeyJwk: JWK });

function serving(map: Record<string, unknown>) {
  return vi.fn(async (url: string) => {
    const body = map[url];
    return body === undefined ? new Response('not found', { status: 404 }) : new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  });
}

async function refusal(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof EntityCardInvalidError) return (error.details as { reason: string }).reason;
    throw error;
  }
  throw new Error('expected a refusal');
}

afterEach(() => setOutboundFetch(undefined));

describe('resolveEntityCard', () => {
  it('resolves a path did:web in two steps through the service entry and binds the card to the DID', async () => {
    const fetchLike = serving({ 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': agentCard });
    const resolved = await resolveEntityCard(AGENT, { fetch: fetchLike });
    expect(resolved).toEqual({ did: AGENT, card: agentCard, cardUrl: 'https://helix.test/acme/ledger-agent/card.json', didDocument: agentDocument });
    expect(fetchLike.mock.calls.map((call) => call[0])).toEqual(['https://helix.test/acme/ledger-agent/did.json', 'https://helix.test/acme/ledger-agent/card.json']);
  });

  it('uses the process-wide outbound seam when no fetch is given', async () => {
    setOutboundFetch(serving({ 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': agentCard }));
    expect((await resolveEntityCard(AGENT)).card).toEqual(agentCard);
  });

  it('falls back to /.well-known/kya-os-card.json for a bare host without a service entry, and the service entry wins when both exist', async () => {
    const fallback = serving({ 'https://helix.test/.well-known/did.json': orgDocument, 'https://helix.test/.well-known/kya-os-card.json': orgCard });
    expect((await resolveEntityCard(ORG, { fetch: fallback })).cardUrl).toBe('https://helix.test/.well-known/kya-os-card.json');

    const anchored = buildDidDocument({ did: ORG, publicKeyJwk: JWK, cardServiceEndpoint: 'https://helix.test/cards/org.json' });
    const both = serving({ 'https://helix.test/.well-known/did.json': anchored, 'https://helix.test/cards/org.json': orgCard, 'https://helix.test/.well-known/kya-os-card.json': { ...orgCard, name: 'stale' } });
    const resolved = await resolveEntityCard(ORG, { fetch: both });
    expect(resolved.cardUrl).toBe('https://helix.test/cards/org.json');
    expect(resolved.card.name).toBe('Helix');
    expect(both).toHaveBeenCalledTimes(2);
  });

  it('refuses a did:key, a malformed did:web, a DID URL, and a non-string, before any fetch', async () => {
    const fetchLike = serving({});
    expect(await refusal(() => resolveEntityCard('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', { fetch: fetchLike }))).toBe('did_key_not_resolvable');
    expect(await refusal(() => resolveEntityCard(`${AGENT}#key-1`, { fetch: fetchLike }))).toBe('malformed_did');
    expect(await refusal(() => resolveEntityCard('did:hedera:testnet:x', { fetch: fetchLike }))).toBe('malformed_did');
    expect(await refusal(() => resolveEntityCard(42 as never, { fetch: fetchLike }))).toBe('malformed_did');
    expect(fetchLike).not.toHaveBeenCalled();
  });

  it('fails closed on a missing or foreign DID document, a path DID without a service entry, a missing, non-JSON, invalid or foreign card', async () => {
    const other = buildEntityCard({ id: 'did:web:helix.test:acme:other', entityType: 'agent', name: 'Other' });
    const otherDocument = buildDidDocument({ did: 'did:web:helix.test:acme:other', publicKeyJwk: JWK });
    const cases: [string, Record<string, unknown>, string][] = [
      ['did_document_unavailable', {}, 'did_document_unavailable'],
      ['did_document_mismatch', { 'https://helix.test/acme/ledger-agent/did.json': otherDocument }, 'did_document_mismatch'],
      ['no_card_service', { 'https://helix.test/acme/ledger-agent/did.json': { ...agentDocument, service: [{ id: '#home', type: 'LinkedDomains', serviceEndpoint: 'https://x' }] } }, 'no_card_service'],
      ['card_unavailable', { 'https://helix.test/acme/ledger-agent/did.json': agentDocument }, 'card_unavailable'],
      ['card_mismatch', { 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': other }, 'card_mismatch'],
      ['card_invalid', { 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': { ...agentCard, bogusField: true } }, 'ENTITY_CARD_INVALID'],
    ];
    for (const [name, map, expected] of cases) {
      let got: string;
      try {
        await resolveEntityCard(AGENT, { fetch: serving(map) });
        got = 'resolved';
      } catch (error) {
        const refused = error as EntityCardInvalidError;
        got = (refused.details as { reason?: string } | undefined)?.reason ?? refused.code;
      }
      expect(got, name).toBe(expected);
    }
    const notJson: OutboundFetch = async () => new Response('<html>', { status: 200 });
    expect(await refusal(() => resolveEntityCard(AGENT, { fetch: notJson }))).toBe('did_document_unavailable');
    const throwing: OutboundFetch = async () => {
      throw new Error('refused by SafeFetch');
    };
    await expect(resolveEntityCard(AGENT, { fetch: throwing })).rejects.toThrow(/refused by SafeFetch/);
    expect(await refusal(() => fetchEntityCard('https://helix.test/x.json', { fetch: notJson }))).toBe('card_unavailable');
  });
});

describe('the server.json projection', () => {
  it('projects the claim-minimal summary with the cardRef, or the cardRef alone by-ref', () => {
    const card = buildEntityCard({ id: AGENT, entityType: 'agent', name: 'Ledger', capabilities: ['handshake', { name: 'ledger.post', attestations: [{ vc: 'jwt' }] }], responsibleParty: 'did:web:helix.test:acme', delegationRef: 'r>d', revocation: { statusListCredential: 'https://helix.test/s', statusListIndex: '1' }, createdAt: '2026-11-21T00:00:00Z' });
    expect(entityCardSummary(card)).toEqual({ id: AGENT, entityType: 'agent', name: 'Ledger', capabilities: ['handshake', 'ledger.post'], responsibleParty: 'did:web:helix.test:acme', delegationRef: 'r>d', proofProfile: 'org.kya-os/proof.v1', revocation: { statusListCredential: 'https://helix.test/s', statusListIndex: '1' } });
    expect(serverCardMeta(card)).toEqual({ 'org.kya-os/card': { ...entityCardSummary(card), 'org.kya-os/cardRef': 'https://helix.test/acme/ledger-agent/card.json' } });
    expect(serverCardMeta(card, { byRef: true, cardUrl: 'https://cdn.example/card.json' })).toEqual({ 'org.kya-os/card': { 'org.kya-os/cardRef': 'https://cdn.example/card.json' } });
    const keyCard = buildEntityCard({ id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', entityType: 'human', name: 'Alice' });
    expect(() => serverCardMeta(keyCard)).toThrow(/did:key/);
    expect(entityCardSummary(keyCard)).toEqual({ id: keyCard.id, entityType: 'human', name: 'Alice', proofProfile: 'org.kya-os/proof.v1' });
  });

  it('resolves from a projection: cardRef fetched and bound to the summary id, inline did:web dereferenced, inline did:key parsed, stripped meta falls back to the DID', async () => {
    const fetchLike = serving({ 'https://helix.test/acme/ledger-agent/did.json': agentDocument, 'https://helix.test/acme/ledger-agent/card.json': agentCard, 'https://cdn.example/card.json': agentCard });
    expect((await resolveEntityCardFromServerMeta({ serverMeta: serverCardMeta(agentCard) }, { fetch: fetchLike })).cardUrl).toBe('https://helix.test/acme/ledger-agent/card.json');
    expect((await resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { 'org.kya-os/cardRef': 'https://cdn.example/card.json' } } }, { fetch: fetchLike })).card).toEqual(agentCard);
    expect((await resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': entityCardSummary(agentCard) } }, { fetch: fetchLike })).cardUrl).toBe('https://helix.test/acme/ledger-agent/card.json');
    const keyCard = buildEntityCard({ id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', entityType: 'human', name: 'Alice' });
    expect(await resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': entityCardSummary(keyCard) } }, { fetch: fetchLike })).toEqual({ did: keyCard.id, card: entityCardSummary(keyCard), cardUrl: '' });
    const stripped = await resolveEntityCardFromServerMeta({ serverMeta: { 'modelcontextprotocol/mcp': {} }, did: AGENT }, { fetch: fetchLike });
    expect(stripped.cardUrl).toBe('https://helix.test/acme/ledger-agent/card.json');
    expect(fetchLike.mock.calls.filter((call) => String(call[0]).endsWith('did.json'))).toHaveLength(1);
  });

  it('refuses a stripped projection with no DID, a summary without id, a malformed inline did:web, and a cardRef for another DID', async () => {
    const fetchLike = serving({ 'https://cdn.example/card.json': agentCard });
    expect(await refusal(() => resolveEntityCardFromServerMeta({ serverMeta: {} }, { fetch: fetchLike }))).toBe('no_projection');
    expect(await refusal(() => resolveEntityCardFromServerMeta({ serverMeta: null }, { fetch: fetchLike }))).toBe('no_projection');
    expect(await refusal(() => resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { name: 'x' } } }, { fetch: fetchLike }))).toBe('no_projection');
    expect(await refusal(() => resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { id: 'did:web:helix.test:a#b' } } }, { fetch: fetchLike }))).toBe('malformed_did');
    expect(await refusal(() => resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { id: ORG, 'org.kya-os/cardRef': 'https://cdn.example/card.json' } } }, { fetch: fetchLike }))).toBe('card_mismatch');
    expect(await refusal(() => resolveEntityCardFromServerMeta({ serverMeta: { 'org.kya-os/card': { id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', bogus: 1 } } }, { fetch: fetchLike }).catch((error: EntityCardInvalidError) => { throw Object.assign(error, { details: { reason: error.code } }); }))).toBe('ENTITY_CARD_INVALID');
  });
});
