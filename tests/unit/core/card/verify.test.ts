// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: verifyEntityCard (SPEC-ENTITY-CARD §11.1) recomputes claims through seams,
// fails closed, and derives the level; the status-list checker reads one bit through SafeFetch.
import { describe, expect, it, vi } from 'vitest';
import {
  EnvSigner,
  buildDIDDocument,
  buildEntityCard,
  buildStatusListCredential,
  createStatusList,
  derivePublicKey,
  createStatusListChecker,
  makeAccountabilityVerifier,
  setBit,
  validateDelegationChain,
  verifyEntityCard,
  type BitstringStatusListEntry,
  type DIDDocument,
  type DelegationHop,
  type EntityCard,
  type OutboundFetch,
} from '../../../../src/core/index.js';

const AGENT = 'did:web:helix.test:acme:ledger-agent';
const ORG = 'did:web:helix.test:acme';
const LIST_URL = 'https://helix.test/v1/status-list/cards';
const NOW = Date.parse('2026-11-21T00:00:00Z');

const hop = (overrides: Partial<DelegationHop> & { subject?: Partial<DelegationHop['credentialSubject']> }): DelegationHop => ({
  '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/zcap/v1', 'https://kya-os.org/ns/delegation/v1'],
  id: 'urn:zcap:root',
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: ORG,
  validUntil: '2027-01-01T00:00:00Z',
  ...overrides,
  credentialSubject: {
    id: 'urn:zcap:root',
    invoker: AGENT,
    parentCapability: 'did:web:helix.test:acme:ledger',
    invocationTarget: 'did:web:helix.test:acme:ledger',
    allowedAction: ['ledger.read', 'ledger.post'],
    caveats: [{ type: 'MaxAmount', limit: '1000.00', currency: 'USD' }, { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' }],
    ...overrides.subject,
  },
});

const root = hop({});
const leaf = hop({
  id: 'urn:zcap:del1',
  issuer: AGENT,
  validUntil: '2026-12-01T00:00:00Z',
  subject: { id: 'urn:zcap:del1', invoker: 'did:web:helix.test:acme:sub-agent', parentCapability: 'urn:zcap:root', allowedAction: ['ledger.read'], caveats: [{ type: 'MaxAmount', limit: '500.00', currency: 'USD' }, { type: 'ValidUntil', date: '2026-12-01T00:00:00Z' }] },
});

// The org signs its own list (story L3-C): a Bitstring Status List v1.0 credential with its window and proof.
const ORG_KEY = '5'.repeat(64);
const orgSigner = new EnvSigner({ did: ORG, envVar: 'K', env: { K: ORG_KEY } });
const orgDocument: DIDDocument = buildDIDDocument(ORG, derivePublicKey(ORG_KEY));
const resolveDid = async (did: string): Promise<DIDDocument | null> => (did === ORG ? orgDocument : null);
const signedList = (encoded: string, window: { validFrom?: string; validUntil?: string } = {}): Promise<unknown> =>
  buildStatusListCredential({ id: LIST_URL, issuer: ORG, encodedList: encoded, validFrom: window.validFrom ?? '2026-11-20T23:00:00Z', validUntil: window.validUntil ?? '2026-11-21T01:00:00Z' }, orgSigner);
const clear = createStatusList(64);
const revoked = setBit(clear, 7, 1);
const card = (extra: Partial<EntityCard> = {}): EntityCard => buildEntityCard({ id: AGENT, entityType: 'agent', name: 'Ledger', capabilities: ['handshake', 'ledger.read'], ...extra });
const serving = (map: Record<string, unknown>): OutboundFetch => async (url) => (map[url] === undefined ? new Response('no', { status: 404 }) : new Response(JSON.stringify(map[url]), { status: 200 }));

describe('validateDelegationChain', () => {
  it('accepts an attenuating chain and reports the root issuer, the leaf invoker and the leaf actions', () => {
    expect(validateDelegationChain([root, leaf], { resourceOwner: ORG, resource: 'did:web:helix.test:acme:ledger', now: NOW })).toEqual({
      ok: true,
      reasons: [],
      responsibleParty: ORG,
      leafInvoker: 'did:web:helix.test:acme:sub-agent',
      invocationTarget: 'did:web:helix.test:acme:ledger',
      allowedAction: ['ledger.read'],
      depth: 2,
    });
    expect(validateDelegationChain([{ ...root, issuer: { id: ORG } }], { now: NOW }).responsibleParty).toBe(ORG);
    const { invoker: _invoker, ...byController } = hop({ subject: { controller: AGENT } }).credentialSubject;
    expect(validateDelegationChain([{ ...root, credentialSubject: byController }], { now: NOW }).leafInvoker).toBe(AGENT);
  });

  it('refuses, with every reason, an empty chain, a bad root, each broadening hop, a continuity break, drift, a window, and depth', () => {
    expect(validateDelegationChain([]).reasons).toEqual(['empty delegation chain']);
    const reasons = (chain: DelegationHop[], ctx = {}): string[] => validateDelegationChain(chain, { now: NOW, ...ctx }).reasons;
    expect(reasons([hop({ subject: { parentCapability: 'other' } })])).toEqual(['root delegation: parentCapability must equal invocationTarget']);
    expect(reasons([root], { resource: 'did:web:x' })).toEqual(['root invocationTarget is not the expected resource']);
    expect(reasons([root], { resourceOwner: 'did:web:x' })).toEqual(['root issuer is not the resource owner']);
    expect(reasons([root, leaf], { maxChainLength: 1 })).toEqual(['delegation chain depth 2 exceeds the maximum of 1']);
    expect(reasons([root, { ...leaf, credentialSubject: { ...leaf.credentialSubject, allowedAction: ['ledger.post', 'ledger.delete'] } }])).toEqual(['allowedAction escalation: [ledger.delete] not in parent']);
    expect(reasons([root, { ...leaf, credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'MaxAmount', limit: '1000.01', currency: 'USD' }] } }])).toEqual(['caveat "MaxAmount" broadened or dropped by child', 'caveat "ValidUntil" broadened or dropped by child']);
    expect(reasons([root, { ...leaf, credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'MaxAmount', limit: '500', currency: 'EUR' }, { type: 'ValidUntil', date: '2026-12-01T00:00:00Z' }] } }])).toEqual(['caveat "MaxAmount" broadened or dropped by child']);
    expect(reasons([root, { ...leaf, validUntil: '2027-06-01T00:00:00Z' }])).toEqual(['validUntil broadened: child must expire no later than its parent']);
    const { validUntil: _validUntil, ...openEnded } = leaf;
    expect(reasons([root, openEnded])).toEqual(['validUntil broadened: child must expire no later than its parent']);
    expect(reasons([root, { ...leaf, issuer: 'did:web:helix.test:acme:stranger' }])).toEqual(['broken continuity: parent invoker is not the child issuer']);
    expect(reasons([root, { ...leaf, credentialSubject: { ...leaf.credentialSubject, parentCapability: 'urn:zcap:other' } }])).toEqual(['broken continuity: child.parentCapability is not the parent capability id']);
    expect(reasons([root, { ...leaf, credentialSubject: { ...leaf.credentialSubject, invocationTarget: 'did:web:other' } }])).toEqual(['invocationTarget drift along the chain']);
    expect(reasons([root], { now: Date.parse('2027-02-01T00:00:00Z') })).toEqual(['hop 0: expired (validUntil)', 'hop 0: expired (ValidUntil caveat)']);
    expect(reasons([{ ...root, validFrom: '2026-12-01T00:00:00Z' }])).toEqual(['hop 0: not yet valid (validFrom)']);
    expect(reasons([{ ...root, validUntil: '2027-01-01' }])).toEqual(['hop 0: validUntil is not an RFC 3339 date-time with its offset']);
    expect(reasons([root], { now: Date.parse('2027-01-01T00:01:00Z') })).toEqual([]);
    expect(reasons([root], { now: Date.parse('2027-01-01T00:01:00Z'), maxClockSkewMs: 0 })).toHaveLength(2);
    const unknownCaveat = hop({ subject: { caveats: [{ type: 'Region', region: 'EU' }] } });
    expect(reasons([unknownCaveat, { ...leaf, credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'Region', region: 'EU' }] } }])).toEqual([]);
    expect(reasons([unknownCaveat, { ...leaf, credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'Region', region: 'US' }] } }])).toEqual(['caveat "Region" broadened or dropped by child']);
    expect(reasons([hop({ subject: { caveats: [{ type: 'MaxAmount', limit: 'ten' }] } }), { ...leaf, credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'MaxAmount', limit: '1' }] } }])).toContain('caveat "MaxAmount" broadened or dropped by child');
  });
});

describe('verifyEntityCard', () => {
  it('a card with only self-declared capabilities and no trust claims is ok at L1', async () => {
    expect(await verifyEntityCard(card())).toEqual({ ok: true, conformanceLevel: 'L1', reasons: [], verifiedCapabilities: [], attestations: [] });
  });

  it('accountability: no verifier is configuration_error, a false or throwing verifier fails, a literal verified lifts nothing by itself', async () => {
    const accountable = card({ responsibleParty: ORG, principal: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', delegationRef: 'urn:zcap:root' });
    expect(await verifyEntityCard(accountable)).toMatchObject({ ok: false, code: 'configuration_error', accountability: { responsibleParty: ORG, principal: accountable.principal, verified: false } });
    expect(await verifyEntityCard(accountable, { accountabilityVerifier: async () => false })).toMatchObject({ ok: false, code: 'accountability_failed' });
    expect(await verifyEntityCard(accountable, { accountabilityVerifier: async () => ({ verified: 'yes' as never }) })).toMatchObject({ ok: false, code: 'accountability_failed' });
    expect(await verifyEntityCard(accountable, { accountabilityVerifier: async () => { throw new Error('boom'); } })).toMatchObject({ ok: false, code: 'accountability_unverifiable', reasons: ['accountability verifier threw: boom'] });
    expect(await verifyEntityCard(accountable, { accountabilityVerifier: async () => true })).toMatchObject({ ok: true, conformanceLevel: 'L1', accountability: { verified: true } });
    expect(await verifyEntityCard(accountable, { accountabilityVerifier: async () => ({ verified: true, fresh: false }) })).toMatchObject({ ok: true, accountability: { verified: true, fresh: false } });
  });

  it('makeAccountabilityVerifier joins the chain to the card and to the live proof DID', async () => {
    const accountable = card({ responsibleParty: ORG, delegationRef: 'urn:zcap:root' });
    const verifier = makeAccountabilityVerifier({ chain: [root], resourceOwner: ORG, now: NOW });
    expect(await verifier(accountable, { trustedIssuers: '*' })).toEqual({ verified: true, fresh: true });
    expect(await verifier(accountable, { trustedIssuers: '*', proofDid: AGENT })).toEqual({ verified: true, fresh: true });
    expect(await verifier(accountable, { trustedIssuers: '*', proofDid: 'did:web:attacker.example' })).toEqual({ verified: false, fresh: true });
    expect(await verifier(card({ responsibleParty: 'did:web:other' }), { trustedIssuers: '*' })).toEqual({ verified: false, fresh: true });
    expect(await makeAccountabilityVerifier({ chain: [root], now: Date.parse('2028-01-01T00:00:00Z') })(accountable, { trustedIssuers: '*' })).toEqual({ verified: false, fresh: false });
    expect(await makeAccountabilityVerifier({ chain: [root], now: NOW, proofDid: 'did:web:attacker.example' })(accountable, { trustedIssuers: '*', proofDid: AGENT })).toEqual({ verified: false, fresh: true });
    expect(await verifyEntityCard(accountable, { accountabilityVerifier: verifier, proofDid: AGENT })).toMatchObject({ ok: true, accountability: { verified: true, fresh: true } });
  });

  it('revocation: no checker reads as revoked with configuration_error and collapses to L1 with ok false; a checker decides; a throwing checker is status_unavailable', async () => {
    const revocable = card({ revocation: { statusListCredential: LIST_URL, statusListIndex: '7' } });
    expect(await verifyEntityCard(revocable)).toMatchObject({ ok: false, conformanceLevel: 'L1', code: 'configuration_error', revocation: { checked: false, revoked: true, fresh: false, code: 'configuration_error' } });
    const checker = vi.fn(async () => ({ revoked: false, fresh: true }));
    expect(await verifyEntityCard(revocable, { statusListChecker: checker })).toMatchObject({ ok: true, revocation: { checked: true, revoked: false, fresh: true } });
    expect(checker).toHaveBeenCalledWith(revocable.revocation, { credentialIssuer: AGENT });
    expect(await verifyEntityCard(revocable, { statusListChecker: async () => ({ revoked: true, fresh: true, code: 'card_revoked', reason: 'bit set' }) })).toMatchObject({ ok: false, code: 'card_revoked', reasons: ['bit set'], revocation: { revoked: true, code: 'card_revoked', reason: 'bit set' } });
    expect(await verifyEntityCard(revocable, { statusListChecker: async () => ({ revoked: 'no' as never, fresh: true }) })).toMatchObject({ ok: false, code: 'card_revoked' });
    expect(await verifyEntityCard(revocable, { statusListChecker: async () => { throw new Error('offline'); } })).toMatchObject({ ok: false, code: 'status_unavailable', revocation: { revoked: true, fresh: false, reason: 'offline' } });
  });

  it('level: every capability attested is L2, a live proof of the card DID read fresh lifts to L3, stale or foreign demotes, revoked collapses', async () => {
    const attested = card({ capabilities: [{ name: 'ledger.read', attestations: [{ vc: 'jwt' }] }, { name: 'ledger.post', attestations: [{ vc: 'jwt' }] }], revocation: { statusListCredential: LIST_URL, statusListIndex: '7' } });
    const capabilityVerifier = vi.fn(async (capabilities: unknown[]) => ({ verified: ['ledger.read', 'ledger.post'], unverified: [], fresh: capabilities.length === 2 }));
    const live = { statusListChecker: async () => ({ revoked: false, fresh: true }), capabilityVerifier };
    expect(await verifyEntityCard(attested, live)).toMatchObject({ ok: true, conformanceLevel: 'L2', verifiedCapabilities: ['ledger.read', 'ledger.post'] });
    expect(capabilityVerifier).toHaveBeenCalledWith(attested.capabilities, { subjectDid: AGENT, trustedIssuers: '*' });
    expect(await verifyEntityCard(attested, { ...live, proofDid: AGENT })).toMatchObject({ conformanceLevel: 'L3' });
    expect(await verifyEntityCard(attested, { ...live, proofDid: 'did:web:other', trustedIssuers: ['did:web:helix.test'] })).toMatchObject({ conformanceLevel: 'L2' });
    expect(await verifyEntityCard(attested, { ...live, proofDid: AGENT, statusListChecker: async () => ({ revoked: false, fresh: false }) })).toMatchObject({ conformanceLevel: 'L2' });
    expect(await verifyEntityCard(attested, { ...live, proofDid: AGENT, capabilityVerifier: async () => ({ verified: ['ledger.read', 'ledger.post'], unverified: [], fresh: false }) })).toMatchObject({ conformanceLevel: 'L2' });
    expect(await verifyEntityCard(attested, { ...live, proofDid: AGENT, capabilityVerifier: async () => ({ verified: ['ledger.read'], unverified: ['ledger.post'] }) })).toMatchObject({ conformanceLevel: 'L1', verifiedCapabilities: ['ledger.read'] });
    expect(await verifyEntityCard(attested, { ...live, proofDid: AGENT, capabilityVerifier: async () => { throw new Error('x'); } })).toMatchObject({ ok: true, conformanceLevel: 'L1' });
    expect(await verifyEntityCard(attested, { ...live, proofDid: AGENT, statusListChecker: async () => ({ revoked: true, fresh: true }) })).toMatchObject({ ok: false, conformanceLevel: 'L1', verifiedCapabilities: [] });
    const accountable = card({ capabilities: attested.capabilities!, revocation: attested.revocation!, responsibleParty: ORG, delegationRef: 'urn:zcap:root' });
    expect(await verifyEntityCard(accountable, { ...live, proofDid: AGENT, accountabilityVerifier: async () => ({ verified: true, fresh: false }) })).toMatchObject({ ok: true, conformanceLevel: 'L2' });
    expect(await verifyEntityCard(accountable, { ...live, proofDid: AGENT, accountabilityVerifier: async () => ({ verified: true, fresh: true }) })).toMatchObject({ ok: true, conformanceLevel: 'L3' });
  });

  it('attestations: unverified without a verifier (configuration_error), each asked with the subject, a throwing verifier fails that one', async () => {
    const attested = card({ attestations: [{ type: 'IdentityVerification', vc: 'jwt', subject: ORG }, { type: 'CapabilityAttestation', vc: { id: 'x' } }] });
    expect(await verifyEntityCard(attested)).toMatchObject({ ok: false, code: 'configuration_error', attestations: [{ type: 'IdentityVerification', subject: ORG, verified: false }, { type: 'CapabilityAttestation', verified: false }] });
    const verifier = vi.fn(async (attestation: { type: string }) => attestation.type === 'IdentityVerification');
    expect(await verifyEntityCard(attested, { attestationVerifier: verifier })).toMatchObject({ ok: false, code: 'attestation_failed', attestations: [{ verified: true }, { verified: false }] });
    expect(verifier).toHaveBeenCalledWith(attested.attestations![0], { subjectDid: AGENT, trustedIssuers: '*' });
    expect(await verifyEntityCard(attested, { attestationVerifier: async () => true })).toMatchObject({ ok: true });
    expect(await verifyEntityCard(attested, { attestationVerifier: async () => { throw new Error('x'); } })).toMatchObject({ ok: false, code: 'attestation_failed' });
  });
});

describe('createStatusListChecker', () => {
  const entry: BitstringStatusListEntry = { statusListCredential: LIST_URL, statusListIndex: '7' };
  const seams = { resolveDid: resolveDid as never, clock: () => NOW };

  it('reads the bit of a signed list live through the outbound fetch, fresh, and from a list in hand, not fresh', async () => {
    const [clearList, revokedList] = [await signedList(clear), await signedList(revoked)];
    expect(await createStatusListChecker({ ...seams, fetch: serving({ [LIST_URL]: clearList }) })(entry, { credentialIssuer: AGENT })).toEqual({ revoked: false, fresh: true });
    expect(await createStatusListChecker({ ...seams, fetch: serving({ [LIST_URL]: revokedList }) })(entry, { credentialIssuer: AGENT })).toEqual({ revoked: true, fresh: true, code: 'card_revoked', reason: 'the card credential is revoked' });
    expect(await createStatusListChecker({ ...seams, lists: { [LIST_URL]: clearList } })(entry, { credentialIssuer: AGENT })).toEqual({ revoked: false, fresh: false });
  });

  it('verifies the list before any bit (story L3-C): no resolver, an unsigned, a tampered or a foreign-signed list is unavailable', async () => {
    const clearList = (await signedList(clear)) as Record<string, unknown> & { credentialSubject: Record<string, unknown> };
    const read = async (checker: ReturnType<typeof createStatusListChecker>) => checker(entry, { credentialIssuer: AGENT });
    expect(await read(createStatusListChecker({ clock: () => NOW, lists: { [LIST_URL]: clearList } }))).toMatchObject({ revoked: true, fresh: false, code: 'status_unavailable', reason: 'no resolveDid seam to verify the status list proof' });
    const unsigned: Record<string, unknown> = { ...clearList };
    delete unsigned['proof'];
    expect(await read(createStatusListChecker({ ...seams, lists: { [LIST_URL]: unsigned } }))).toMatchObject({ code: 'status_unavailable', reason: 'status list failed schema validation' });
    // The revoked bit swapped into a list signed over the clear one.
    const tampered = { ...clearList, credentialSubject: { ...clearList.credentialSubject, encodedList: `u${revoked}` } };
    expect(await read(createStatusListChecker({ ...seams, lists: { [LIST_URL]: tampered } }))).toMatchObject({ code: 'status_unavailable', reason: expect.stringMatching(/^status list proof invalid/) });
    expect(await read(createStatusListChecker({ resolveDid: async () => null, clock: () => NOW, lists: { [LIST_URL]: clearList } }))).toMatchObject({ code: 'status_unavailable', reason: expect.stringMatching(/^status list proof invalid/) });
  });

  it('a list past its validUntil is read but never fresh; one whose validFrom lies ahead is unavailable', async () => {
    const stale = await signedList(clear, { validFrom: '2026-11-20T00:00:00Z', validUntil: '2026-11-20T12:00:00Z' });
    expect(await createStatusListChecker({ ...seams, fetch: serving({ [LIST_URL]: stale }) })(entry, { credentialIssuer: AGENT })).toEqual({ revoked: false, fresh: false });
    const staleRevoked = await signedList(revoked, { validFrom: '2026-11-20T00:00:00Z', validUntil: '2026-11-20T12:00:00Z' });
    expect(await createStatusListChecker({ ...seams, fetch: serving({ [LIST_URL]: staleRevoked }) })(entry, { credentialIssuer: AGENT })).toEqual({ revoked: true, fresh: false, code: 'card_revoked', reason: 'the card credential is revoked' });
    const early = await signedList(clear, { validFrom: '2026-11-21T00:05:00Z', validUntil: '2026-11-21T02:00:00Z' });
    expect(await createStatusListChecker({ ...seams, fetch: serving({ [LIST_URL]: early }) })(entry, { credentialIssuer: AGENT })).toMatchObject({ code: 'status_unavailable', reason: 'status list is not valid yet' });
    expect(await createStatusListChecker({ ...seams, clockSkewMs: 600_000, fetch: serving({ [LIST_URL]: early }) })(entry, { credentialIssuer: AGENT })).toEqual({ revoked: false, fresh: true });
    // Without an injected clock the checker reads the real one.
    const wide = await signedList(clear, { validFrom: '2020-01-01T00:00:00Z', validUntil: '2100-01-01T00:00:00Z' });
    expect(await createStatusListChecker({ resolveDid: resolveDid as never, fetch: serving({ [LIST_URL]: wide }) })(entry, { credentialIssuer: AGENT })).toEqual({ revoked: false, fresh: true });
    // A window that is not a pair of date-times, signed as it stands.
    const undated = await buildStatusListCredential({ id: LIST_URL, issuer: ORG, encodedList: clear, validFrom: 'soon', validUntil: '2026-11-21T01:00:00Z' }, orgSigner);
    expect(await createStatusListChecker({ ...seams, lists: { [LIST_URL]: undated } })(entry, { credentialIssuer: AGENT })).toMatchObject({ code: 'status_unavailable', reason: 'status list window is not a pair of date-times' });
  });

  it('fails closed as status_unavailable on an unreachable, non-2xx, non-JSON, malformed or unreadable list, a wide entry, a bad index', async () => {
    const clearList = await signedList(clear);
    const code = async (checker: ReturnType<typeof createStatusListChecker>, candidate = entry): Promise<string | undefined> => (await checker(candidate, { credentialIssuer: AGENT })).code;
    expect(await code(createStatusListChecker({ ...seams, fetch: serving({}) }))).toBe('status_unavailable');
    expect(await code(createStatusListChecker({ ...seams, fetch: async () => { throw new Error('refused'); } }))).toBe('status_unavailable');
    expect(await code(createStatusListChecker({ ...seams, fetch: async () => new Response('<html>', { status: 200 }) }))).toBe('status_unavailable');
    expect(await code(createStatusListChecker({ ...seams, lists: { [LIST_URL]: { not: 'a list' } } }))).toBe('status_unavailable');
    // Signed over bits that do not decode.
    expect(await code(createStatusListChecker({ ...seams, lists: { [LIST_URL]: await signedList('!!') } }))).toBe('status_unavailable');
    expect(await code(createStatusListChecker({ ...seams, lists: { [LIST_URL]: clearList } }), { ...entry, statusListIndex: '999999' })).toBe('status_unavailable');
    expect(await code(createStatusListChecker({ ...seams, lists: { [LIST_URL]: clearList } }), { ...entry, statusSize: 2 })).toBe('status_unavailable');
    expect(await code(createStatusListChecker({ ...seams, lists: { [LIST_URL]: clearList } }), { ...entry, statusListIndex: '7.5' })).toBe('status_unavailable');
    expect(await code(createStatusListChecker({ ...seams, lists: { [LIST_URL]: clearList } }), { ...entry, statusListIndex: '99999999999999999999' })).toBe('status_unavailable');
    expect(await code(createStatusListChecker({ ...seams, lists: { [LIST_URL]: clearList } }), { ...entry, statusSize: 1 })).toBeUndefined();
  });
});
