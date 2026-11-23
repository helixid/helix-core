// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: custody preference at onboarding, every point, against in-memory tables and a real DbKeyStore.
import * as ed25519 from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import {
  CustodialSigningRefusedError,
  CustodyStateInvalidError,
  CustodySubjectNotFoundError,
  DidDocumentUnresolvedError,
  EnrollmentProofInvalidError,
  KeyStoreKeyShreddedError,
  KeyStoreSigner,
  base64UrlDecodeStrict,
  base64UrlEncode,
  buildConformanceReport,
  jsonDigest,
  publicKeyJwkBytes,
  signJws,
  verifyJws,
  type AgentDidDocument,
  type PublicKeyJwk,
} from '../../../../src/core/index.js';
import { pendingHopReissuer } from '../../../../src/services/custody/hop-reissue.js';
import { HOST, clientKey, enrollmentSignature, CustodyEvents, events, harness, rotationProof, type ClientKey, type Harness } from './harness.js';

async function documentOf(h: Harness, did: string): Promise<AgentDidDocument> {
  return (await h.dids.findDidById(did))!.didDocument as AgentDidDocument;
}

function keyIn(document: AgentDidDocument, kid: string): PublicKeyJwk | undefined {
  return document.verificationMethod.find((method) => method.id === kid)?.publicKeyJwk;
}

/** Self-custody onboarding as `helix init` drives it: create, challenge, enroll with a proof of possession. */
async function onboardSelf(h: Harness, input: Record<string, unknown> = {}, key: ClientKey = clientKey()) {
  const created = await h.service.createAgent({ name: 'Self bot', scopes: ['read:orders'], keyCustody: 'self', ...input }, h.context());
  const challenge = await h.service.enrollmentChallenge(created.enrollmentToken);
  const enrolled = await h.service.enroll(
    { enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, challenge.nonce) },
    h.context({ actor: 'enrollment-token' }),
  );
  return { created, challenge, enrolled, key };
}

/** Everything Helix stored, as one string, to look for private material in. */
function everythingStored(h: Harness): Promise<string> {
  return (async () =>
    JSON.stringify({
      wrapped: h.wrapped.dump(),
      records: await h.records.listRecords(),
      keys: await Promise.all((await h.records.listRecords()).map((row) => h.records.listKeys(row.did))),
      dids: await Promise.all((await h.records.listRecords()).map((row) => h.dids.findDidById(row.did))),
      audit: h.audit.events,
      issued: h.issued,
    }))();
}

function publishOwnDomain(h: Harness, documents: { didDocument: unknown; card: unknown; didDocumentUrl: string; cardUrl: string }): void {
  h.web.set(documents.didDocumentUrl, documents.didDocument);
  h.web.set(documents.cardUrl, documents.card);
}

describe('custody facts beside the audit digest (F-4 point 6)', () => {
  it('hands the facts of each custody event to auditFacts, matching the digest the event carries', async () => {
    const kept = new Map<string, Readonly<Record<string, unknown>>>();
    const h = harness({ auditFacts: (digest, facts) => void kept.set(digest, facts) });
    const result = await h.service.createAgent({ name: 'Facts Bot', scopes: [], keyCustody: 'helix', didHosting: 'helix' }, h.context({ org: 'acme' }));
    await h.audit.trail.flush();
    const digests = h.audit.trail.events
      .filter((event) => event.action.category === 'custody')
      .map((event) => (event.details as { configurationDigest?: string }).configurationDigest);
    expect(digests.length).toBeGreaterThan(0);
    for (const digest of digests) {
      expect(kept.get(digest!)).toMatchObject({ did: result.did, subjectType: 'agent' });
      expect(jsonDigest(kept.get(digest!))).toBe(digest);
    }
  });
});

describe('full custodial onboarding (point 3)', () => {
  it('creates the agent in one call: key in the KeyStore, did:web under the Helix domain, active, identity credential and one attestation per scope (F-1)', async () => {
    const h = harness();
    const result = await h.service.createAgent({ name: 'Serverless Bot', scopes: ['read:orders'], keyCustody: 'helix', didHosting: 'helix' }, h.context({ org: 'acme' }));
    expect(result.did).toMatch(/^did:web:helix\.example:acme:serverless-bot-[0-9a-f]{8}$/);
    expect(result).toMatchObject({ subjectType: 'agent', keyCustody: 'helix', didHosting: 'helix', label: 'custody: helix', conformant: false, status: 'active', kid: `${result.did}#key-1`, vcId: 'vc:test:1' });
    expect(result.enrollmentToken).toBeUndefined();
    expect(result.keys).toEqual([expect.objectContaining({ kid: `${result.did}#key-1`, location: 'helix', status: 'active' })]);
    const [held] = await h.keyStore.list(result.did);
    expect(held!.kid).toBe(`${result.did}#key-1`);
    const document = await documentOf(h, result.did);
    expect(keyIn(document, `${result.did}#key-1`)).toEqual(held!.publicKeyJwk);
    expect(document.service).toEqual([{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: `https://${HOST}/acme/${result.did.split(':').pop()}/card.json` }]);
    expect(result.documents!.card).toMatchObject({ id: result.did, entityType: 'agent', name: 'Serverless Bot', kid: `${result.did}#key-1` });
    expect(result.documents!.didDocumentUrl).toBe(`https://${HOST}/acme/${result.did.split(':').pop()}/did.json`);
    // Story F-1's credentials: the identity credential (no custody claims: those stay in the custody record) and one attestation per scope.
    expect(h.issued[0]!.input).toEqual({ agentDid: result.did, name: 'Serverless Bot', ownerDid: 'did:web:helix.example' });
    expect(h.attested).toEqual([{ agentDid: result.did, capability: 'read:orders', vcId: 'att:test:1' }]);
    expect(await h.records.findRecord(result.did)).toMatchObject({ keyCustody: 'helix', didHosting: 'helix', credentialVcId: 'vc:test:1' });
    expect(events(h, CustodyEvents.CUSTODY_CHOSEN)).toEqual([
      expect.objectContaining({ actor: 'admin', did: result.did, subjectType: 'agent', keyCustody: 'helix', didHosting: 'helix', source: { keyCustody: 'override', didHosting: 'override' } }),
    ]);
    expect(events(h, CustodyEvents.CUSTODY_ACTIVATED)).toEqual([expect.objectContaining({ did: result.did, resolution: 'helix-hosted' })]);
  });

  it('signs through the KeyStore, audits each signature by digest, and the signature verifies against the published key', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Signer', keyCustody: 'helix' }, h.context());
    const payload = new TextEncoder().encode('{"tool":"orders.list"}');
    const signed = await h.service.sign(agent.did, { payload: base64UrlEncode(payload) }, h.context({ actor: 'account:acc_1' }), 'agent');
    expect(signed).toMatchObject({ did: agent.did, kid: `${agent.did}#key-1`, alg: 'EdDSA' });
    const published = keyIn(await documentOf(h, agent.did), signed.kid)!;
    expect(await ed25519.verifyAsync(base64UrlDecodeStrict(signed.signature)!, payload, publicKeyJwkBytes(published))).toBe(true);
    await h.service.sign(agent.did, { payload: base64UrlEncode(payload), kid: 'key-1' }, h.context(), 'agent');
    const audited = events(h, CustodyEvents.CUSTODIAL_SIGNATURE);
    expect(audited).toHaveLength(2);
    expect(audited[0]).toMatchObject({ actor: 'account:acc_1', did: agent.did, subjectType: 'agent', kid: signed.kid, payloadBytes: payload.length });
    expect(audited[0]!['payloadDigest']).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(audited)).not.toContain('orders.list');
  });

  it('validates what it signs', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Signer', keyCustody: 'helix' }, h.context());
    await expect(h.service.sign(agent.did, { payload: 42 }, h.context(), 'agent')).rejects.toThrow(/base64url/);
    await expect(h.service.sign(agent.did, { payload: '' }, h.context(), 'agent')).rejects.toThrow(/1 to/);
    await expect(h.service.sign(agent.did, { payload: base64UrlEncode(new Uint8Array(65 * 1024)) }, h.context(), 'agent')).rejects.toThrow(/1 to/);
    await expect(h.service.sign(agent.did, { payload: 'AQ', kid: 'key-7' }, h.context(), 'agent')).rejects.toThrow(CustodialSigningRefusedError);
    await expect(h.service.sign(agent.did, { payload: 'AQ' }, h.context(), 'service')).rejects.toThrow(CustodySubjectNotFoundError);
    await expect(h.service.sign('did:web:helix.example:x:y', { payload: 'AQ' }, h.context(), 'agent')).rejects.toThrow(CustodySubjectNotFoundError);
  });

  it('custodial with own hosting: Helix holds the key, the agent waits for its documents on the owner domain', async () => {
    const h = harness();
    const did = 'did:web:owner.example:agents:hybrid';
    const result = await h.service.createAgent({ name: 'Hybrid', keyCustody: 'helix', didHosting: 'own', did }, h.context());
    expect(result).toMatchObject({ did, status: 'pending_resolution', publishRequired: true, label: 'custody: helix' });
    expect(result.documents!.didDocumentUrl).toBe('https://owner.example/agents/hybrid/did.json');
    await expect(h.service.sign(did, { payload: 'AQ' }, h.context(), 'agent')).rejects.toThrow(CustodyStateInvalidError);
    publishOwnDomain(h, result.documents!);
    const active = await h.service.activate(did, h.context());
    expect(active).toMatchObject({ status: 'active', vcId: 'vc:test:1' });
    expect(h.fetched).toEqual(['https://owner.example/agents/hybrid/did.json', 'https://owner.example/agents/hybrid/card.json']);
  });
});

describe('self-custody onboarding (point 2) and the self-custody invariant', () => {
  it('helix init on Helix hosting: token, challenge, public JWK with proof of possession, active, and no private key anywhere in Helix', async () => {
    const h = harness();
    const { created, challenge, enrolled, key } = await onboardSelf(h);
    expect(created).toMatchObject({ keyCustody: 'self', didHosting: 'helix', status: 'pending_key', label: 'custody: self', conformant: true, kid: null });
    expect(created.enrollmentToken).toMatch(/^enroll:[0-9a-f]{48}$/);
    expect(Date.parse(created.enrollmentExpiresAt!) - h.now.value.getTime()).toBe(24 * 3600 * 1000);
    expect(challenge).toMatchObject({ did: created.did, kid: `${created.did}#key-1`, keyCustody: 'self', didHosting: 'helix', name: 'Self bot' });
    expect(challenge.nonce).toMatch(/^[0-9a-f]{64}$/);
    expect(enrolled).toMatchObject({ did: created.did, status: 'active', kid: `${created.did}#key-1`, vcId: 'vc:test:1' });
    expect(keyIn(await documentOf(h, created.did), enrolled.kid!)).toEqual({ ...key.publicKeyJwk });
    expect(enrolled.documents!.card.publicKeyJwk).toMatchObject({ x: key.publicKeyJwk.x });
    expect(h.issued[0]!.input).toEqual({ agentDid: created.did, name: 'Self bot', ownerDid: 'did:web:helix.example' });
    expect(h.attested.map((entry) => [entry.agentDid, entry.capability])).toEqual([[created.did, 'read:orders']]);
    // The database holds no private key for the self-custody agent.
    expect(await h.keyStore.list(created.did)).toEqual([]);
    expect(h.wrapped.dump()).toEqual([]);
    const stored = await everythingStored(h);
    for (const form of key.forms) expect(stored).not.toContain(form);
    // The token is stored as its hash only.
    expect(stored).not.toContain(created.enrollmentToken);
    expect(events(h, CustodyEvents.CUSTODY_ACTIVATED)).toEqual([expect.objectContaining({ actor: 'enrollment-token', did: created.did })]);
  });

  it('refuses custodial signing for a self-custody agent and audits the refusal', async () => {
    const h = harness();
    const { enrolled } = await onboardSelf(h);
    await expect(h.service.sign(enrolled.did, { payload: 'AQ' }, h.context(), 'agent')).rejects.toThrow(CustodialSigningRefusedError);
    expect(events(h, CustodyEvents.CUSTODIAL_SIGNING_REFUSED)).toEqual([expect.objectContaining({ did: enrolled.did, code: 'custody_self' })]);
    expect(events(h, CustodyEvents.CUSTODIAL_SIGNATURE)).toEqual([]);
  });

  it('helix init on the owner domain: pending until the documents resolve from there, then active', async () => {
    const h = harness();
    const did = 'did:web:owner.example:agents:self';
    const { enrolled, key } = await onboardSelf(h, { didHosting: 'own', did });
    expect(enrolled).toMatchObject({ did, status: 'pending_resolution', publishRequired: true });
    expect(enrolled.documents!.cardUrl).toBe('https://owner.example/agents/self/card.json');
    expect(enrolled.documents!.didDocument.service).toEqual([expect.objectContaining({ serviceEndpoint: 'https://owner.example/agents/self/card.json' })]);
    await expect(h.service.activate(did, h.context())).rejects.toThrow(/answered HTTP 404/);
    publishOwnDomain(h, enrolled.documents!);
    const active = await h.service.activate(did, h.context());
    expect(active.status).toBe('active');
    expect(events(h, CustodyEvents.CUSTODY_ACTIVATED)).toEqual([expect.objectContaining({ did, resolution: 'verified' })]);
    await expect(h.service.activate(did, h.context())).rejects.toThrow(CustodyStateInvalidError);
    expect(h.wrapped.dump()).toEqual([]);
    for (const form of key.forms) expect(await everythingStored(h)).not.toContain(form);
  });

  it('does not activate when the owner domain serves the wrong documents', async () => {
    const did = 'did:web:owner.example:agents:wrong';
    const cases: [string, (h: Harness, docs: { didDocument: AgentDidDocument; card: Record<string, unknown>; didDocumentUrl: string; cardUrl: string }) => void, RegExp][] = [
      ['an unreachable domain', (h, docs) => h.web.set(docs.didDocumentUrl, new Error('ECONNREFUSED')), /could not be read/],
      ['a non-JSON document', (h, docs) => h.web.set(docs.didDocumentUrl, 'not-json'), /not JSON/],
      ['another DID\'s document', (h, docs) => h.web.set(docs.didDocumentUrl, { ...docs.didDocument, id: 'did:web:owner.example:other' }), /not the document/],
      ['a document without the registered key', (h, docs) => h.web.set(docs.didDocumentUrl, { ...docs.didDocument, verificationMethod: [] }), /does not list the registered key/],
      ['an invalid card', (h, docs) => { publishOwnDomain(h, docs); h.web.set(docs.cardUrl, { ...docs.card, unexpected: true }); }, /not a valid Entity Card/],
      ['another DID\'s card', (h, docs) => { publishOwnDomain(h, docs); h.web.set(docs.cardUrl, { ...docs.card, id: 'did:web:owner.example:other' }); }, /not the card/],
      ['a card with another key', (h, docs) => { publishOwnDomain(h, docs); h.web.set(docs.cardUrl, { ...docs.card, publicKeyJwk: { ...(docs.card['publicKeyJwk'] as object), x: clientKey().publicKeyJwk.x } }); }, /another key/],
      ['a card that is not served', (h, docs) => { publishOwnDomain(h, docs); h.web.set(docs.cardUrl, 500); }, /HTTP 500/],
    ];
    for (const [name, serve, expected] of cases) {
      const h = harness();
      const { enrolled } = await onboardSelf(h, { didHosting: 'own', did });
      serve(h, enrolled.documents as never);
      await expect(h.service.activate(did, h.context()), name).rejects.toThrow(DidDocumentUnresolvedError);
      await expect(h.service.activate(did, h.context()), name).rejects.toThrow(expected);
      expect((await h.service.getCustody(did)).status, name).toBe('pending_resolution');
    }
  });

  it('checks the enrollment token, the challenge and the proof of possession', async () => {
    const h = harness();
    const key = clientKey();
    const created = await h.service.createAgent({ name: 'Bot', keyCustody: 'self', expiry: 2 }, h.context());
    expect(Date.parse(created.enrollmentExpiresAt!) - h.now.value.getTime()).toBe(2 * 86_400_000);
    await expect(h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: 'x' }, h.context())).rejects.toThrow(/challenge first/);
    const challenge = await h.service.enrollmentChallenge(created.enrollmentToken);
    await expect(
      h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, 'other') }, h.context()),
    ).rejects.toThrow(EnrollmentProofInvalidError);
    await expect(
      h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: clientKey().publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, challenge.nonce) }, h.context()),
    ).rejects.toThrow(EnrollmentProofInvalidError);
    await expect(h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: { ...key.publicKeyJwk, d: 'x' }, signature: 'x' }, h.context())).rejects.toThrow(/private material/);
    await expect(h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, kid: 3, signature: 'x' }, h.context())).rejects.toThrow(/kid must be a string/);
    const enrolled = await h.service.enroll(
      { enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, kid: 'agent-key', signature: enrollmentSignature(key, challenge.did, `${challenge.did}#agent-key`, challenge.nonce) },
      h.context(),
    );
    expect(enrolled.kid).toBe(`${created.did}#agent-key`);
    await expect(h.service.enrollmentChallenge(created.enrollmentToken)).rejects.toThrow(/already used/);
    await expect(h.service.enrollmentChallenge('enroll:nope')).rejects.toThrow(/not found/);
    await expect(h.service.enrollmentChallenge(undefined)).rejects.toThrow(/required/);
    const late = await h.service.createAgent({ name: 'Late', keyCustody: 'self' }, h.context());
    h.now.value = new Date(h.now.value.getTime() + 25 * 3600 * 1000);
    await expect(h.service.enrollmentChallenge(late.enrollmentToken)).rejects.toThrow(/expired/);
  });

  it('refuses a token used concurrently', async () => {
    const h = harness();
    const key = clientKey();
    const created = await h.service.createAgent({ name: 'Bot', keyCustody: 'self' }, h.context());
    const challenge = await h.service.enrollmentChallenge(created.enrollmentToken);
    await h.records.claimEnrollment(created.did, new Date());
    await h.records.updateRecord(created.did, { enrollmentUsedAt: null });
    const original = h.records.claimEnrollment.bind(h.records);
    h.records.claimEnrollment = async () => false;
    await expect(
      h.service.enroll({ enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, challenge.nonce) }, h.context()),
    ).rejects.toThrow(/already used/);
    h.records.claimEnrollment = original;
  });

  it('matches the enrollment token for activation by the CLI', async () => {
    const h = harness();
    const created = await h.service.createAgent({ name: 'Bot', keyCustody: 'self' }, h.context());
    expect(await h.service.enrollmentTokenMatches(created.did, created.enrollmentToken)).toBe(true);
    expect(await h.service.enrollmentTokenMatches(created.did, 'enroll:other')).toBe(false);
    expect(await h.service.enrollmentTokenMatches(created.did, undefined)).toBe(false);
    expect(await h.service.enrollmentTokenMatches('did:web:none', 'x')).toBe(false);
  });
});

describe('mixed custody per agent (point 4)', () => {
  it('an account defaulting to self creates a custodial agent, and an account defaulting to helix a self-custody agent', async () => {
    const h = harness();
    const selfAccount = h.context({ defaults: { defaultKeyCustody: 'self', defaultDidHosting: 'helix' } });
    const helixAccount = h.context({ defaults: { defaultKeyCustody: 'helix', defaultDidHosting: 'helix' } });
    const followsSelf = await h.service.createAgent({ name: 'Default self' }, selfAccount);
    const serverless = await h.service.createAgent({ name: 'Serverless', keyCustody: 'helix' }, selfAccount);
    const followsHelix = await h.service.createAgent({ name: 'Default helix' }, helixAccount);
    const ownKeys = await h.service.createAgent({ name: 'Own keys', keyCustody: 'self' }, helixAccount);
    expect([followsSelf, serverless, followsHelix, ownKeys].map((agent) => [agent.keyCustody, agent.label, agent.status])).toEqual([
      ['self', 'custody: self', 'pending_key'],
      ['helix', 'custody: helix', 'active'],
      ['helix', 'custody: helix', 'active'],
      ['self', 'custody: self', 'pending_key'],
    ]);
    expect(events(h, CustodyEvents.CUSTODY_CHOSEN).map((event) => event['source'])).toEqual([
      { keyCustody: 'account', didHosting: 'account' },
      { keyCustody: 'override', didHosting: 'account' },
      { keyCustody: 'account', didHosting: 'account' },
      { keyCustody: 'override', didHosting: 'account' },
    ]);
    const views = await h.service.custodyOf([serverless.did, ownKeys.did, 'did:web:unknown']);
    expect(views.map((view) => [view.did, view.label]).sort()).toEqual(
      [
        [serverless.did, 'custody: helix'],
        [ownKeys.did, 'custody: self'],
      ].sort(),
    );
  });

  it('conformance: the self-custody agent is in the claim set, the custodial one excluded with custody: helix (point 5)', async () => {
    const h = harness();
    const { enrolled } = await onboardSelf(h);
    const custodial = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    const report = buildConformanceReport({ implementation: { name: 'Helix ID', version: '3', claims: [{ profile: 'core', level: 'L1' }] }, subjects: await h.service.conformanceSubjects() });
    expect(report.claimSet.map((entry) => entry.did)).toEqual([enrolled.did]);
    expect(report.excluded.map((entry) => [entry.did, entry.label])).toEqual([[custodial.did, 'custody: helix']]);
  });
});

describe('requestedDomains and maxDelegationDepth on POST /v1/agents', () => {
  it('a custodial agent: domains as #domain-N LinkedDomains entries before the card entry, depth on the agent record, not in the credential', async () => {
    const h = harness();
    const agent = await h.service.createAgent(
      { name: 'Router', scopes: ['read:orders'], keyCustody: 'helix', requestedDomains: ['orders.example', 'https://api.example/v1'], maxDelegationDepth: 2 },
      h.context(),
    );
    const services = (await documentOf(h, agent.did)).service as { id: string; type: string; serviceEndpoint: string }[];
    expect(services).toEqual([
      { id: '#domain-1', type: 'LinkedDomains', serviceEndpoint: 'https://orders.example' },
      { id: '#domain-2', type: 'LinkedDomains', serviceEndpoint: 'https://api.example/v1' },
      expect.objectContaining({ id: '#kya-os-card', type: 'KyaOsEntityCard' }),
    ]);
    expect(agent.documents!.didDocument.service).toEqual(services);
    expect(h.issued[0]!.input).not.toHaveProperty('maxDelegationDepth');
    expect(await h.records.findRecord(agent.did)).toMatchObject({ requestedDomains: ['https://orders.example', 'https://api.example/v1'], maxDelegationDepth: 2 });
  });

  it('a self-custody agent gets them at enrollment, and a custody change keeps them', async () => {
    const h = harness();
    const { enrolled } = await onboardSelf(h, { requestedDomains: ['http://tools.example'], maxDelegationDepth: 5 });
    expect(enrolled.documents!.didDocument.service).toEqual([
      { id: '#domain-1', type: 'LinkedDomains', serviceEndpoint: 'http://tools.example' },
      expect.objectContaining({ type: 'KyaOsEntityCard' }),
    ]);
    expect(await h.records.findRecord(enrolled.did)).toMatchObject({ maxDelegationDepth: 5 });
    const changed = await h.service.changeCustody(enrolled.did, { keyCustody: 'helix' }, h.context());
    expect(changed.documents.didDocument.service).toEqual(enrolled.documents!.didDocument.service);
    expect(await h.records.findRecord(enrolled.did)).toMatchObject({ keyCustody: 'helix', maxDelegationDepth: 5, requestedDomains: ['http://tools.example'] });
  });

  it('defaults to no domains and depth 0', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Plain', keyCustody: 'helix', requestedDomains: [] }, h.context());
    expect((await documentOf(h, agent.did)).service).toEqual([expect.objectContaining({ type: 'KyaOsEntityCard' })]);
    expect(await h.records.findRecord(agent.did)).toMatchObject({ requestedDomains: null, maxDelegationDepth: 0 });
  });

  it('refuses what the agent-create route refused, before anything is created', async () => {
    const h = harness();
    const c = h.context();
    await expect(h.service.createAgent({ name: 'x', requestedDomains: 'orders.example' as never }, c)).rejects.toThrow(/requestedDomains must be an array/);
    await expect(h.service.createAgent({ name: 'x', requestedDomains: ['ftp://orders.example'] }, c)).rejects.toMatchObject({ code: 'INVALID_SERVICE_ENDPOINT_URL', httpStatus: 400 });
    await expect(h.service.createAgent({ name: 'x', requestedDomains: ['  '] }, c)).rejects.toMatchObject({ code: 'INVALID_SERVICE_ENDPOINT_URL' });
    await expect(h.service.createAgent({ name: 'x', requestedDomains: [42 as never] }, c)).rejects.toMatchObject({ code: 'INVALID_SERVICE_ENDPOINT_URL' });
    for (const depth of [-1, 6, 1.5, '2', null]) {
      await expect(h.service.createAgent({ name: 'x', maxDelegationDepth: depth as never }, c), String(depth)).rejects.toThrow(/maxDelegationDepth must be a whole number from 0 to 5/);
    }
    expect(await h.records.listRecords()).toEqual([]);
  });
});

describe('input checks', () => {
  it('validates names, scopes, owners, the choice and the DID', async () => {
    const h = harness();
    const c = h.context();
    await expect(h.service.createAgent({ name: ' ' }, c)).rejects.toThrow(/name is required/);
    await expect(h.service.createAgent({ name: 'x', scopes: 'read' as never }, c)).rejects.toThrow(/scopes must be an array/);
    await expect(h.service.createAgent({ name: 'x', scopes: ['s'.repeat(300)] }, c)).rejects.toThrow(/Invalid scopes/);
    await expect(h.service.createAgent({ name: 'x', ownerDid: 'acme' }, c)).rejects.toThrow(/ownerDid/);
    await expect(h.service.createAgent({ name: 'x', expiry: 0 }, c)).rejects.toThrow(/expiry/);
    await expect(h.service.createAgent({ name: 'x', keyCustody: 'custodial' }, c)).rejects.toThrow(/keyCustody/);
    await expect(h.service.createAgent({ name: 'x', didHosting: 'own' }, c)).rejects.toThrow(/did:web on your own domain/);
    await expect(h.service.createAgent({ name: 'x', didHosting: 'own', did: 'did:key:z6Mk' }, c)).rejects.toThrow(/did:web on your own domain/);
    await expect(h.service.createAgent({ name: 'x', didHosting: 'own', did: `did:web:${HOST}:mine` }, c)).rejects.toThrow(/under the Helix domain/);
    await expect(h.service.createAgent({ name: 'x', didHosting: 'helix', did: 'did:web:owner.example' }, c)).rejects.toThrow(/send no did/);
    const owned = await h.service.createAgent({ name: 'x', didHosting: 'own', did: 'did:web:owner.example:a', ownerDid: 'did:web:owner.example' }, c);
    await expect(h.service.createAgent({ name: 'y', didHosting: 'own', did: owned.did }, c)).rejects.toThrow(/already registered/);
    const noHost = harness({ host: '' });
    await expect(noHost.service.createAgent({ name: 'x', keyCustody: 'helix' }, noHost.context())).rejects.toThrow(/DID_DOMAIN/);
    await expect(h.service.getCustody(owned.did, 'service')).rejects.toThrow(CustodySubjectNotFoundError);
    expect((await h.service.getCustody(owned.did)).subjectType).toBe('agent');
    expect(await h.service.cardDetails(owned.did)).toEqual({ name: 'x' });
    expect(await h.service.cardDetails('did:web:none')).toBeUndefined();
  });
});

describe('services and owners (points 1 and 7)', () => {
  it('a custodial service: key in the KeyStore, service record, Helix hosting', async () => {
    const h = harness();
    const result = await h.service.createService({ name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'], keyCustody: 'helix', description: ' Orders ' }, h.context());
    expect(result).toMatchObject({ subjectType: 'service', keyCustody: 'helix', label: 'custody: helix', status: 'active' });
    expect(result.vcId).toBeUndefined();
    expect(result.service).toMatchObject({ did: result.did, name: 'orders', domain: 'orders.example', requiredScopes: ['read:orders'], description: 'Orders', framework: null });
    expect(result.documents!.card.entityType).toBe('mcp');
    expect(await h.keyStore.list(result.did)).toHaveLength(1);
    const signed = await h.service.sign(result.did, { payload: 'AQ' }, h.context(), 'service');
    expect(signed.did).toBe(result.did);
    expect(h.issued).toEqual([]);
  });

  it('a self-custody service registers only its public key; Helix holds nothing and will not sign', async () => {
    const h = harness();
    const key = clientKey();
    const result = await h.service.createService({ name: 'billing', domain: 'billing.example', requiredScopes: ['pay'], keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, framework: 'express' }, h.context());
    expect(result).toMatchObject({ keyCustody: 'self', label: 'custody: self', status: 'active' });
    expect(result.service?.framework).toBe('express');
    expect(await h.keyStore.list(result.did)).toEqual([]);
    await expect(h.service.sign(result.did, { payload: 'AQ' }, h.context(), 'service')).rejects.toThrow(CustodialSigningRefusedError);
    for (const form of key.forms) expect(await everythingStored(h)).not.toContain(form);
  });

  it('validates service input and the key for each custody', async () => {
    const h = harness();
    const c = h.context();
    await expect(h.service.createService({ name: '', domain: 'd', requiredScopes: ['a'] }, c)).rejects.toThrow(/required/);
    await expect(h.service.createService({ name: 'n', domain: 'd', requiredScopes: ['s'.repeat(300)] }, c)).rejects.toThrow(/requiredScopes/);
    await expect(h.service.createService({ name: 'n', domain: 'd', requiredScopes: ['a'], keyCustody: 'self' }, c)).rejects.toThrow(/publicKeyJwk/);
    await expect(h.service.createService({ name: 'n', domain: 'd', requiredScopes: ['a'], keyCustody: 'helix', publicKeyJwk: clientKey().publicKeyJwk }, c)).rejects.toThrow(/send no publicKeyJwk/);
    await h.service.createService({ name: 'n', domain: 'd', requiredScopes: ['a'], keyCustody: 'helix' }, c);
    await expect(h.service.createService({ name: 'n', domain: 'd', requiredScopes: ['a'], keyCustody: 'helix' }, c)).rejects.toThrow(/already enrolled/);
    const noServices = harness({ services: undefined });
    await expect(noServices.service.createService({ name: 'n', domain: 'd', requiredScopes: ['a'] }, noServices.context())).rejects.toThrow(/not configured/);
  });

  it('owner self signs attestations in the SDK, owner helix has Helix sign them; both verify against the published keys (point 7)', async () => {
    const h = harness();
    const ownerKey = clientKey();
    const selfOwner = await h.service.createOwner({ name: 'Acme (self)', keyCustody: 'self', publicKeyJwk: ownerKey.publicKeyJwk, entityType: 'human' }, h.context());
    const helixOwner = await h.service.createOwner({ name: 'Acme (helix)', keyCustody: 'helix' }, h.context());
    expect(selfOwner.documents!.card.entityType).toBe('human');
    expect(helixOwner.documents!.card.entityType).toBe('verifier');
    const attestation = (issuer: string) => ({ iss: issuer, sub: 'did:web:helix.example:acme:bot', capability: 'read:orders' });

    // Owner self: the owner's own signer (in the SDK) makes the proof; Helix refuses to.
    await expect(h.service.sign(selfOwner.did, { payload: 'AQ' }, h.context(), 'owner')).rejects.toThrow(CustodialSigningRefusedError);
    const selfJws = await signJws(attestation(selfOwner.did), {
      did: selfOwner.did,
      kid: 'key-1',
      sign: async (data: Uint8Array) => ed25519.sign(data, ownerKey.seed),
    });
    // Owner helix: Helix signs through the KeyStore, either in process or through the signing endpoint.
    const helixJws = await signJws(attestation(helixOwner.did), new KeyStoreSigner(h.keyStore, helixOwner.did, helixOwner.kid!));
    const remoteJws = await signJws(attestation(helixOwner.did), {
      did: helixOwner.did,
      kid: 'key-1',
      sign: async (data: Uint8Array) => base64UrlDecodeStrict((await h.service.sign(helixOwner.did, { payload: base64UrlEncode(data) }, h.context(), 'owner')).signature)!,
    });
    for (const [jws, owner] of [[selfJws, selfOwner], [helixJws, helixOwner], [remoteJws, helixOwner]] as const) {
      const published = keyIn(await documentOf(h, owner.did), owner.kid!)!;
      expect(verifyJws(jws, published, { expectedKid: owner.kid! }).payload).toMatchObject({ iss: owner.did, capability: 'read:orders' });
    }
    expect(events(h, CustodyEvents.CUSTODIAL_SIGNATURE).map((event) => event['subjectType'])).toEqual(['owner']);
  });

  it('validates owner input', async () => {
    const h = harness();
    await expect(h.service.createOwner({ name: '' }, h.context())).rejects.toThrow(/name is required/);
    await expect(h.service.createOwner({ name: 'o', keyCustody: 'self' }, h.context())).rejects.toThrow(/publicKeyJwk/);
  });
});

describe('changing custody is a rotation (point 6)', () => {
  it('helix to self: new key client side, both keys listed during the overlap, old proofs verify, old key shredded, hop seam called, identity credential kept', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Mover', scopes: ['read:orders'], keyCustody: 'helix' }, h.context());
    const oldKid = agent.kid!;
    const before = new TextEncoder().encode('signed before the change');
    const oldSignature = base64UrlDecodeStrict((await h.service.sign(agent.did, { payload: base64UrlEncode(before) }, h.context(), 'agent')).signature)!;
    const oldPublic = keyIn(await documentOf(h, agent.did), oldKid)!;

    const newKey = clientKey();
    const newKid = `${agent.did}#key-2`;
    const changed = await h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: newKey.publicKeyJwk, proof: rotationProof(newKey, agent.did, newKid, h.now.value.toISOString()) }, h.context({ actor: 'account:acc_1' }));
    expect(changed).toMatchObject({ keyCustody: 'self', label: 'custody: self', conformant: true, kid: newKid, previousKid: oldKid, previousKeyShredded: true, publishRequired: false, credentialVcId: 'vc:test:1' });
    expect(changed.retiresAt).toBe(new Date(h.now.value.getTime() + 86_400_000).toISOString());
    expect(changed.hopReissue).toEqual({ reissued: 0, pending: true, note: expect.stringMatching(/C-E/) });
    expect(changed.keys.map((key) => [key.kid, key.location, key.status])).toEqual([
      [oldKid, 'helix', 'retiring'],
      [newKid, 'self', 'active'],
    ]);

    // Both keys in the DID document during the overlap, the new one first.
    const document = await documentOf(h, agent.did);
    expect(document.assertionMethod).toEqual([newKid, oldKid]);
    expect(keyIn(document, newKid)).toEqual({ ...newKey.publicKeyJwk });
    // A proof made before the change still verifies against the published old key.
    expect(await ed25519.verifyAsync(oldSignature, before, publicKeyJwkBytes(keyIn(document, oldKid)!))).toBe(true);
    expect(keyIn(document, oldKid)).toEqual(oldPublic);
    // The old Helix-held key is shredded and the new key is absent from Helix.
    await expect(h.keyStore.sign({ did: agent.did, kid: oldKid }, before)).rejects.toThrow(KeyStoreKeyShreddedError);
    expect((await h.keyStore.list(agent.did)).map((key) => [key.kid, key.shreddedAt !== null])).toEqual([[oldKid, true]]);
    expect(h.wrapped.dump().every((row) => row.ciphertext === '')).toBe(true);
    for (const form of newKey.forms) expect(await everythingStored(h)).not.toContain(form);
    // Helix will not sign for it any more.
    await expect(h.service.sign(agent.did, { payload: 'AQ' }, h.context(), 'agent')).rejects.toThrow(CustodialSigningRefusedError);
    // The identity credential carries no custody facts (F-1), so it is kept; nothing is reissued.
    expect(h.issued).toHaveLength(1);
    expect(changed).not.toHaveProperty('vcId');
    expect(events(h, CustodyEvents.CUSTODY_CHANGED)).toEqual([
      expect.objectContaining({ actor: 'account:acc_1', did: agent.did, from: 'helix', to: 'self', oldKid, newKid, hopReissue: expect.objectContaining({ pending: true }) }),
    ]);
    expect(events(h, CustodyEvents.CUSTODY_KEY_SHREDDED)).toEqual([expect.objectContaining({ did: agent.did, kid: oldKid })]);
    expect(h.didCacheDeleted).toContain(agent.did);

    // The overlap ends: the old key is revoked and leaves the document.
    h.now.value = new Date(h.now.value.getTime() + 86_400_001);
    const finalized = await h.service.finalizeRotation(agent.did, h.context());
    expect(finalized.revoked).toEqual([oldKid]);
    expect(finalized.keys.find((key) => key.kid === oldKid)).toMatchObject({ status: 'revoked', revokedAt: h.now.value.toISOString() });
    expect((await documentOf(h, agent.did)).verificationMethod.map((method) => method.id)).toEqual([newKid]);
    expect(events(h, CustodyEvents.CUSTODY_KEY_REVOKED)).toEqual([expect.objectContaining({ kid: oldKid, location: 'helix' })]);
    expect((await h.service.finalizeRotation(agent.did, h.context())).revoked).toEqual([]);
  });

  it('self to helix: Helix generates the new key; the client key retires; the overlap can be ended at once', async () => {
    const h = harness();
    const { enrolled } = await onboardSelf(h);
    const changed = await h.service.changeCustody(enrolled.did, { keyCustody: 'helix', overlapSeconds: 0 }, h.context());
    expect(changed).toMatchObject({ keyCustody: 'helix', label: 'custody: helix', kid: `${enrolled.did}#key-2`, previousKeyShredded: false });
    expect(changed.keys.map((key) => [key.location, key.status])).toEqual([['self', 'revoked'], ['helix', 'active']]);
    expect((await documentOf(h, enrolled.did)).verificationMethod.map((method) => method.id)).toEqual([`${enrolled.did}#key-2`]);
    expect((await h.service.sign(enrolled.did, { payload: 'AQ' }, h.context(), 'agent')).kid).toBe(`${enrolled.did}#key-2`);
    expect(events(h, CustodyEvents.CUSTODY_KEY_REVOKED)).toEqual([expect.objectContaining({ location: 'self' })]);
    expect(events(h, CustodyEvents.CUSTODY_KEY_SHREDDED)).toEqual([]);
  });

  it('a due overlap ends on the next signature, and finalize can force it', async () => {
    const h = harness();
    const { enrolled } = await onboardSelf(h);
    await h.service.changeCustody(enrolled.did, { keyCustody: 'helix', overlapSeconds: 60 }, h.context());
    h.now.value = new Date(h.now.value.getTime() + 61_000);
    await h.service.sign(enrolled.did, { payload: 'AQ' }, h.context(), 'agent');
    expect((await h.service.getCustody(enrolled.did)).keys[0]!.status).toBe('revoked');

    const second = harness();
    const agent = await second.service.createAgent({ name: 'Mover', keyCustody: 'helix' }, second.context());
    const key = clientKey();
    await second.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, kid: 'client', proof: rotationProof(key, agent.did, `${agent.did}#client`, second.now.value.toISOString()) }, second.context());
    const forced = await second.service.finalizeRotation(agent.did, second.context(), { force: true }, 'agent');
    expect(forced.revoked).toEqual([`${agent.did}#key-1`]);
    expect(forced.kid).toBe(`${agent.did}#client`);
  });

  it('own hosting: the rotated documents must be republished on the owner domain', async () => {
    const h = harness();
    const result = await h.service.createAgent({ name: 'Own', keyCustody: 'helix', didHosting: 'own', did: 'did:web:owner.example:agents:own' }, h.context());
    publishOwnDomain(h, result.documents!);
    await h.service.activate(result.did, h.context(), 'agent');
    const key = clientKey();
    const changed = await h.service.changeCustody(result.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: rotationProof(key, result.did, `${result.did}#key-2`, h.now.value.toISOString()) }, h.context());
    expect(changed.publishRequired).toBe(true);
    expect(changed.documents.didDocumentUrl).toBe('https://owner.example/agents/own/did.json');
  });

  it('refuses a change that does not fit', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Mover', keyCustody: 'helix' }, h.context());
    const key = clientKey();
    const kid2 = `${agent.did}#key-2`;
    await expect(h.service.changeCustody(agent.did, { keyCustody: 'custodial' }, h.context())).rejects.toThrow(/self or helix/);
    await expect(h.service.changeCustody(agent.did, { keyCustody: 'helix' }, h.context())).rejects.toThrow(/already has key custody helix/);
    await expect(h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, overlapSeconds: -1 }, h.context())).rejects.toThrow(/overlapSeconds/);
    await expect(h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk }, h.context())).rejects.toThrow(/issuedAt/);
    await expect(
      h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: rotationProof(key, agent.did, kid2, '2020-01-01T00:00:00Z') }, h.context()),
    ).rejects.toThrow(/five minutes/);
    await expect(
      h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: { issuedAt: h.now.value.toISOString(), signature: 'AAAA' } }, h.context()),
    ).rejects.toThrow(EnrollmentProofInvalidError);
    await expect(
      h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, kid: 'key-1', proof: rotationProof(key, agent.did, agent.kid!, h.now.value.toISOString()) }, h.context()),
    ).rejects.toThrow(/already used/);
    const pending = await h.service.createAgent({ name: 'Pending', keyCustody: 'self' }, h.context());
    await expect(h.service.changeCustody(pending.did, { keyCustody: 'helix' }, h.context())).rejects.toThrow(/custody changes on an active subject/);
    await expect(h.service.activate(pending.did, h.context())).rejects.toThrow(CustodyStateInvalidError);
    const self = await onboardSelf(h);
    await expect(h.service.changeCustody(self.enrolled.did, { keyCustody: 'helix', publicKeyJwk: key.publicKeyJwk }, h.context())).rejects.toThrow(/send no publicKeyJwk/);
  });

  it('the hop reissue seam is replaceable (C-E)', async () => {
    const calls: unknown[] = [];
    const h = harness({ hopReissuer: { reissueHopsForKid: async (input) => { calls.push(input); return { reissued: 2, pending: false }; } } });
    const agent = await h.service.createAgent({ name: 'Mover', keyCustody: 'helix' }, h.context());
    const key = clientKey();
    const changed = await h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: rotationProof(key, agent.did, `${agent.did}#key-2`, h.now.value.toISOString()) }, h.context());
    expect(changed.hopReissue).toEqual({ reissued: 2, pending: false });
    expect(calls).toEqual([{ did: agent.did, oldKid: `${agent.did}#key-1`, newKid: `${agent.did}#key-2`, requestId: 'req_test' }]);
    expect(await pendingHopReissuer.reissueHopsForKid({ did: 'd', oldKid: 'a', newKid: 'b', requestId: 'r' })).toMatchObject({ pending: true });
  });

  it('a service changes custody too, with no credential to reissue', async () => {
    const h = harness();
    const created = await h.service.createService({ name: 'svc', domain: 'svc.example', requiredScopes: ['a'], keyCustody: 'helix' }, h.context());
    const key = clientKey();
    const changed = await h.service.changeCustody(created.did, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: rotationProof(key, created.did, `${created.did}#key-2`, h.now.value.toISOString()) }, h.context(), 'service');
    expect(changed).not.toHaveProperty('vcId');
    expect(h.issued).toEqual([]);
  });
});
