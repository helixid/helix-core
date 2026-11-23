// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: the custody routes over HTTP, the self-custody invariant on the wire, and Helix-hosted documents.
import { Readable } from 'node:stream';
import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';
import { base64UrlEncode } from '../../../src/core/index.js';
import { errorHandler } from '../../../src/middleware/errorHandler.js';
import custodyRoutes, { type CustodyRouteOptions } from '../../../src/routes/custody/index.js';
import entityCardRoutes from '../../../src/routes/entity-card/index.js';
import serviceProviderRoutes from '../../../src/routes/service-provider/index.js';
import { createEntityCardSource } from '../../../src/services/entity-card/entity-card.source.js';
import { HOST, clientKey, enrollmentSignature, harness, rotationProof, type Harness } from '../services/custody/harness.js';

const ADMIN = 'test-admin-key-0123456789';

interface App {
  app: FastifyInstance;
  h: Harness;
  bodies: string[];
  legacyEnroll: ReturnType<typeof vi.fn>;
}

async function app(options: Partial<CustodyRouteOptions> = {}, serviceDefaults?: () => unknown): Promise<App> {
  const h = harness();
  const bodies: string[] = [];
  const legacyEnroll = vi.fn(async () => ({ id: 'svc:legacy', did: 'did:hedera:testnet:legacy', name: 'legacy' }));
  const instance = Fastify({ logger: false });
  instance.setErrorHandler(errorHandler);
  instance.addHook('preParsing', async (_request, _reply, payload) => {
    const chunks: Buffer[] = [];
    for await (const chunk of payload) chunks.push(Buffer.from(chunk));
    bodies.push(Buffer.concat(chunks).toString('utf8'));
    return Readable.from([Buffer.concat(chunks)]);
  });
  await instance.register(custodyRoutes, { prefix: '/v1', custodyService: h.service, adminApiKey: ADMIN, ...options });
  await instance.register(serviceProviderRoutes, {
    prefix: '/v1',
    adminApiKey: ADMIN,
    serviceProviderService: { enroll: legacyEnroll } as never,
    custody: { service: h.service, ...(serviceDefaults ? { defaultsOf: serviceDefaults as never } : {}) },
  });
  await instance.register(entityCardRoutes, {
    source: createEntityCardSource({ host: HOST, didRepository: h.dids, details: (did) => h.service.cardDetails(did) }),
  });
  await instance.ready();
  return { app: instance, h, bodies, legacyEnroll };
}

const admin = { 'x-admin-api-key': ADMIN };

function post(a: App, url: string, payload: unknown, headers: Record<string, string> = admin) {
  return a.app.inject({ method: 'POST', url, headers, payload: payload as Record<string, unknown> });
}

function enc(did: string): string {
  return encodeURIComponent(did);
}

describe('custody routes', () => {
  it('self-custody over HTTP: the token and the public JWK are all that travel, and Helix stores no private key', async () => {
    const a = await app();
    const key = clientKey();
    const created = await post(a, '/v1/agents', { name: 'Self bot', scopes: ['read:orders'], keyCustody: 'self' });
    expect(created.statusCode, created.body).toBe(201);
    const { did, enrollmentToken } = created.json() as { did: string; enrollmentToken: string };
    const challenge = await post(a, '/v1/agents/enroll/challenge', { enrollmentToken }, {});
    expect(challenge.statusCode, challenge.body).toBe(200);
    const { kid, nonce } = challenge.json() as { kid: string; nonce: string };
    const enrolled = await post(a, '/v1/agents/enroll', { enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, did, kid, nonce) }, {});
    expect(enrolled.statusCode, enrolled.body).toBe(201);
    expect(enrolled.json()).toMatchObject({ did, status: 'active', label: 'custody: self' });
    for (const raw of a.bodies) {
      for (const form of key.forms) expect(raw).not.toContain(form);
      expect(JSON.parse(raw || '{}')).not.toHaveProperty('publicKeyJwk.d');
    }
    expect(a.h.wrapped.dump()).toEqual([]);
    const signed = await post(a, `/v1/agents/${enc(did)}/sign`, { payload: 'AQ' });
    expect(signed.statusCode).toBe(409);
    expect(signed.json()).toMatchObject({ error: { code: 'CUSTODIAL_SIGNING_REFUSED' } });
  });

  it('refuses private key material anywhere in a body, before anything is stored', async () => {
    const a = await app();
    const key = clientKey();
    const created = (await post(a, '/v1/agents', { name: 'Bot', keyCustody: 'self' })).json() as { did: string; enrollmentToken: string };
    const d = Buffer.from(key.seed).toString('base64url');
    for (const [url, payload, headers] of [
      ['/v1/agents/enroll', { enrollmentToken: created.enrollmentToken, publicKeyJwk: { ...key.publicKeyJwk, d }, signature: 'x' }, {}],
      ['/v1/agents/enroll', { enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, privateKeyHex: 'aa', signature: 'x' }, {}],
      ['/v1/agents/enroll/challenge', { enrollmentToken: created.enrollmentToken, seed: 'aa' }, {}],
      ['/v1/agents', { name: 'x', keyCustody: 'self', privateKey: 'aa' }, admin],
      ['/v1/owners', { name: 'x', keyCustody: 'self', publicKeyJwk: { ...key.publicKeyJwk, d } }, admin],
      [`/v1/agents/${enc(created.did)}/custody`, { keyCustody: 'helix', secret: 'x' }, admin],
      [`/v1/agents/${enc(created.did)}/activate`, { privateKeyJwk: {} }, admin],
      ['/v1/services', { name: 's', domain: 'd', requiredScopes: ['a'], keyCustody: 'self', publicKeyJwk: { ...key.publicKeyJwk, d } }, admin],
    ] as const) {
      const response = await post(a, url, payload, headers as Record<string, string>);
      expect(response.statusCode, `${url} ${response.body}`).toBe(400);
      expect(response.body).toMatch(/private key material/);
    }
    expect((await a.h.service.getCustody(created.did)).status).toBe('pending_key');
    expect(await a.h.records.listKeys(created.did)).toEqual([]);
    const foreign = await post(a, '/v1/agents/enroll', { enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: 'x', extra: 1 }, {});
    expect(foreign.statusCode).toBe(400);
    expect(foreign.body).toMatch(/unexpected members \(extra\)/);
    expect((await post(a, '/v1/agents/enroll', ['array'], {})).statusCode).toBe(400);
  });

  it('gates creation, signing, reading and changing on the admin key by default', async () => {
    const a = await app();
    const custodial = (await post(a, '/v1/agents', { name: 'C', keyCustody: 'helix' })).json() as { did: string };
    for (const [method, url] of [
      ['POST', '/v1/agents'],
      ['POST', '/v1/owners'],
      ['POST', `/v1/agents/${enc(custodial.did)}/sign`],
      ['GET', `/v1/agents/${enc(custodial.did)}/custody`],
      ['POST', `/v1/agents/${enc(custodial.did)}/custody`],
      ['POST', `/v1/agents/${enc(custodial.did)}/custody/finalize`],
      ['POST', `/v1/agents/${enc(custodial.did)}/activate`],
      ['GET', '/v1/custody/defaults'],
      ['GET', '/v1/conformance/report'],
      ['POST', '/v1/services'],
    ] as const) {
      const response = await a.app.inject({ method, url, headers: { 'x-admin-api-key': 'wrong' }, ...(method === 'POST' ? { payload: {} } : {}) });
      expect(response.statusCode, `${method} ${url}`).toBe(403);
    }
  });

  it('custodial over HTTP: one call, signing, reading, changing custody and finalizing', async () => {
    const a = await app();
    const created = await post(a, '/v1/agents', { name: 'Custodial', scopes: ['read:orders'], keyCustody: 'helix', didHosting: 'helix' });
    expect(created.statusCode, created.body).toBe(201);
    const { did, kid } = created.json() as { did: string; kid: string };
    const signed = await post(a, `/v1/agents/${enc(did)}/sign`, { payload: base64UrlEncode(new Uint8Array([1, 2, 3])) });
    expect(signed.statusCode, signed.body).toBe(200);
    expect(signed.json()).toMatchObject({ did, kid, alg: 'EdDSA' });
    const read = await a.app.inject({ method: 'GET', url: `/v1/agents/${enc(did)}/custody`, headers: admin });
    expect(read.json()).toMatchObject({ did, keyCustody: 'helix', label: 'custody: helix', conformant: false });
    const key = clientKey();
    const changed = await post(a, `/v1/agents/${enc(did)}/custody`, { keyCustody: 'self', publicKeyJwk: key.publicKeyJwk, proof: rotationProof(key, did, `${did}#key-2`, a.h.now.value.toISOString()) });
    expect(changed.statusCode, changed.body).toBe(200);
    expect(changed.json()).toMatchObject({ keyCustody: 'self', previousKeyShredded: true, hopReissue: { pending: true } });
    const finalized = await post(a, `/v1/agents/${enc(did)}/custody/finalize`, { force: true });
    expect(finalized.json()).toMatchObject({ revoked: [kid] });
    const wrongType = await post(a, `/v1/services/${enc(did)}/sign`, { payload: 'AQ' });
    expect(wrongType.statusCode).toBe(404);
    expect(wrongType.json()).toMatchObject({ error: { code: 'CUSTODY_SUBJECT_NOT_FOUND' } });
    const bad = await post(a, '/v1/agents', { name: 'x', keyCustody: 'nope' });
    expect(bad.statusCode).toBe(400);
    expect(bad.json()).toMatchObject({ error: { code: 'CUSTODY_CHOICE_INVALID' } });
  });

  it('POST /v1/agents with an enrollmentToken goes unchanged to story F-1 token onboarding, without the custody authorization', async () => {
    const onboardWithCustody = vi.fn(async () => ({ agentDid: 'did:web:h:agents:t', vcId: 'vc:1', identity: { id: 'vc:1' }, attestations: [{ id: 'att:1' }] }));
    const { enrollmentOnboardingHandler } = await import('../../../src/routes/agent/index.js');
    const a = await app({ enrollmentOnboarding: enrollmentOnboardingHandler({ onboardWithCustody } as never) });
    const onboarded = await post(a, '/v1/agents', { enrollmentToken: 'tok', domains: ['orders.example'], ownerDid: 'did:web:owner.example' }, {});
    expect(onboarded.statusCode, onboarded.body).toBe(201);
    expect(onboarded.json()).toEqual({ agentDid: 'did:web:h:agents:t', identity: { id: 'vc:1' }, attestations: [{ id: 'att:1' }] });
    expect(onboardWithCustody).toHaveBeenCalledWith({ enrollmentToken: 'tok', domains: ['orders.example'], ownerDid: 'did:web:owner.example' }, expect.any(String));
    // A custody create still needs the admin key, and never reaches the token onboarding.
    expect((await post(a, '/v1/agents', { name: 'NoKey', keyCustody: 'helix' }, {})).statusCode).toBe(403);
    expect((await post(a, '/v1/agents', { name: 'Custodial', keyCustody: 'helix' })).statusCode).toBe(201);
    expect(onboardWithCustody).toHaveBeenCalledTimes(1);
    // Without the handler, an enrollmentToken body is a custody create like any other (and needs a name).
    const plain = await app();
    expect((await post(plain, '/v1/agents', { enrollmentToken: 'tok' })).statusCode).toBe(400);
  });

  it('the package exports the token onboarding handler, so a consuming server (helixid) wires POST /v1/agents as core does', async () => {
    const pkg = await import('../../../src/index.js');
    const { enrollmentOnboardingHandler } = await import('../../../src/routes/agent/index.js');
    expect(pkg.enrollmentOnboardingHandler).toBe(enrollmentOnboardingHandler);
  });

  it('the agent routes register POST /agents only when the custody routes do not own it', async () => {
    const { default: agentRoutes } = await import('../../../src/routes/agent/index.js');
    for (const [createAgentRoute, expected] of [[false, 404], [undefined, 201]] as const) {
      const instance = Fastify({ logger: false });
      const agentService = { onboardWithCustody: vi.fn(async () => ({ agentDid: 'd', vcId: 'v', identity: {}, attestations: [] })) };
      await instance.register(agentRoutes, { prefix: '/v1', agentService: agentService as never, ...(createAgentRoute === undefined ? {} : { createAgentRoute }) });
      const res = await instance.inject({ method: 'POST', url: '/v1/agents', payload: { enrollmentToken: 'tok' } });
      expect(res.statusCode, String(createAgentRoute)).toBe(expected);
      await instance.close();
    }
  });

  it('POST /v1/agents takes requestedDomains and maxDelegationDepth and refuses bad values', async () => {
    const a = await app();
    const created = await post(a, '/v1/agents', { name: 'Router', scopes: ['read:orders'], keyCustody: 'helix', requestedDomains: ['orders.example'], maxDelegationDepth: 3 });
    expect(created.statusCode, created.body).toBe(201);
    expect(created.json().documents.didDocument.service[0]).toEqual({ id: '#domain-1', type: 'LinkedDomains', serviceEndpoint: 'https://orders.example' });
    expect(await a.h.records.findRecord(created.json().did)).toMatchObject({ maxDelegationDepth: 3, requestedDomains: ['https://orders.example'] });
    const badDomain = await post(a, '/v1/agents', { name: 'x', requestedDomains: ['not a url'] });
    expect(badDomain.statusCode).toBe(400);
    expect(badDomain.json()).toMatchObject({ error: { code: 'INVALID_SERVICE_ENDPOINT_URL' } });
    const badDepth = await post(a, '/v1/agents', { name: 'x', maxDelegationDepth: 9 });
    expect(badDepth.statusCode).toBe(400);
    expect(badDepth.json()).toMatchObject({ error: { code: 'VALIDATION_ERROR' } });
  });

  it('serves Helix-hosted documents through the C-A routes, named from the custody record', async () => {
    const a = await app();
    const { did } = (await post(a, '/v1/agents', { name: 'Hosted Bot', keyCustody: 'helix' })).json() as { did: string };
    const path = did.split(':').slice(3).join('/');
    const document = await a.app.inject({ method: 'GET', url: `/${path}/did.json` });
    expect(document.statusCode, document.body).toBe(200);
    expect(document.json()).toMatchObject({ id: did, verificationMethod: [{ id: `${did}#key-1` }] });
    const card = await a.app.inject({ method: 'GET', url: `/${path}/card.json` });
    expect(card.json()).toMatchObject({ id: did, entityType: 'agent', name: 'Hosted Bot', kid: `${did}#key-1` });
  });

  it('activates an own-hosted agent with its enrollment token or the admin key, never with neither', async () => {
    const a = await app();
    const key = clientKey();
    const did = 'did:web:owner.example:agents:cli';
    const { enrollmentToken } = (await post(a, '/v1/agents', { name: 'CLI', keyCustody: 'self', didHosting: 'own', did })).json() as { enrollmentToken: string };
    const { kid, nonce } = (await post(a, '/v1/agents/enroll/challenge', { enrollmentToken }, {})).json() as { kid: string; nonce: string };
    const enrolled = (await post(a, '/v1/agents/enroll', { enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, did, kid, nonce) }, {})).json() as {
      documents: { didDocument: unknown; card: unknown; didDocumentUrl: string; cardUrl: string };
    };
    expect((await post(a, `/v1/agents/${enc(did)}/activate`, {}, {})).statusCode).toBe(403);
    const unresolved = await post(a, `/v1/agents/${enc(did)}/activate`, { enrollmentToken }, {});
    expect(unresolved.statusCode).toBe(422);
    expect(unresolved.json()).toMatchObject({ error: { code: 'DID_DOCUMENT_UNRESOLVED', details: { did } } });
    a.h.web.set(enrolled.documents.didDocumentUrl, enrolled.documents.didDocument);
    a.h.web.set(enrolled.documents.cardUrl, enrolled.documents.card);
    const active = await post(a, `/v1/agents/${enc(did)}/activate`, { enrollmentToken }, {});
    expect(active.statusCode, active.body).toBe(200);
    expect(active.json()).toMatchObject({ status: 'active' });
    expect(a.h.audit.events.find((entry) => entry.event.event === 'CUSTODY_ACTIVATED')?.payload).toMatchObject({ actor: 'enrollment-token' });

    const hybrid = (await post(a, '/v1/agents', { name: 'H', keyCustody: 'helix', didHosting: 'own', did: 'did:web:owner.example:agents:h' })).json() as {
      did: string;
      documents: { didDocument: unknown; card: unknown; didDocumentUrl: string; cardUrl: string };
    };
    a.h.web.set(hybrid.documents.didDocumentUrl, hybrid.documents.didDocument);
    a.h.web.set(hybrid.documents.cardUrl, hybrid.documents.card);
    expect((await post(a, `/v1/agents/${enc(hybrid.did)}/activate`, {})).statusCode).toBe(200);
  });

  it('owners: creation and custodial signing', async () => {
    const a = await app();
    const owner = await post(a, '/v1/owners', { name: 'Acme', keyCustody: 'helix' });
    expect(owner.statusCode, owner.body).toBe(201);
    const { did } = owner.json() as { did: string };
    expect((await post(a, `/v1/owners/${enc(did)}/sign`, { payload: 'AQ' })).statusCode).toBe(200);
    expect((await a.app.inject({ method: 'GET', url: `/v1/owners/${enc(did)}/custody`, headers: admin })).json()).toMatchObject({ subjectType: 'owner' });
  });

  it('reports defaults and the conformance claim set', async () => {
    const a = await app();
    const defaults = await a.app.inject({ method: 'GET', url: '/v1/custody/defaults', headers: admin });
    expect(defaults.json()).toEqual({ custody: { defaultKeyCustody: 'self', defaultDidHosting: 'helix' }, source: 'built-in' });
    const custodial = (await post(a, '/v1/agents', { name: 'C', keyCustody: 'helix' })).json() as { did: string };
    const key = clientKey();
    const self = (await post(a, '/v1/services', { name: 'svc', domain: 'svc.example', requiredScopes: ['a'], keyCustody: 'self', publicKeyJwk: key.publicKeyJwk })).json() as { did: string };
    const report = await a.app.inject({ method: 'GET', url: '/v1/conformance/report', headers: admin });
    expect(report.statusCode).toBe(200);
    expect(report.json()).toMatchObject({
      implementation: { name: 'Helix ID', claims: [] },
      claimSet: [{ did: self.did, label: 'custody: self' }],
      excluded: [{ did: custodial.did, label: 'custody: helix' }],
    });
  });

  it('uses the hosted build hooks: authorize, actor, account defaults and onCreated', async () => {
    const created: string[] = [];
    const activated: string[] = [];
    const authorize = vi.fn(async (request: { headers: Record<string, unknown> }) => {
      if (request.headers['authorization'] !== 'Bearer acc') throw Object.assign(new Error('no'), { code: 'ACCESS_TOKEN_INVALID', httpStatus: 401 });
    });
    const a = await app({
      authorize: authorize as never,
      actorOf: () => 'account:acc_1',
      defaultsOf: () => ({ defaultKeyCustody: 'helix', defaultDidHosting: 'helix' }),
      onCreated: (_request, result) => void created.push(result.did),
      onActivated: (_request, result) => void activated.push(`${result.did} ${result.status}`),
      implementation: { name: 'Helix Enterprise', version: '1', claims: [{ profile: 'core', level: 'L1' }] },
      reportSubjects: (_request, subjects) => subjects.filter((subject) => created.includes(subject.did)),
    });
    const headers = { authorization: 'Bearer acc' };
    const agent = await post(a, '/v1/agents', { name: 'Follows account' }, headers);
    expect(agent.statusCode, agent.body).toBe(201);
    expect(agent.json()).toMatchObject({ keyCustody: 'helix', did: expect.stringMatching(/^did:web:helix\.example:agents:[0-9a-f]{32}$/) });
    expect(created).toEqual([agent.json().did]);
    expect(a.h.audit.events.find((entry) => entry.event.event === 'CUSTODY_CHOSEN')?.payload).toMatchObject({ actor: 'account:acc_1', source: { keyCustody: 'account' } });
    const defaults = await a.app.inject({ method: 'GET', url: '/v1/custody/defaults', headers });
    expect(defaults.json()).toEqual({ custody: { defaultKeyCustody: 'helix', defaultDidHosting: 'helix' }, source: 'account' });
    const report = await a.app.inject({ method: 'GET', url: '/v1/conformance/report', headers });
    expect(report.json()).toMatchObject({ implementation: { name: 'Helix Enterprise' }, excluded: [{ label: 'custody: helix' }] });
    await a.h.service.createAgent({ name: 'Another account', keyCustody: 'helix' }, a.h.context());
    const scoped = (await a.app.inject({ method: 'GET', url: '/v1/conformance/report', headers })).json() as { summary: { subjects: number } };
    expect(scoped.summary.subjects).toBe(1);
    expect((await post(a, '/v1/agents', { name: 'x' }, {})).statusCode).toBe(401);
    expect(authorize).toHaveBeenCalledWith(expect.anything(), { action: 'createAgent' });

    // Self-custody: enrolled with the token alone, then onActivated tells the hosted build.
    const key = clientKey();
    const self = (await post(a, '/v1/agents', { name: 'Own keys', keyCustody: 'self' }, headers)).json() as { did: string; enrollmentToken: string };
    const { kid, nonce } = (await post(a, '/v1/agents/enroll/challenge', { enrollmentToken: self.enrollmentToken }, {})).json() as { kid: string; nonce: string };
    await post(a, '/v1/agents/enroll', { enrollmentToken: self.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, self.did, kid, nonce) }, {});
    const own = (await post(a, '/v1/agents', { name: 'Own domain', keyCustody: 'helix', didHosting: 'own', did: 'did:web:owner.example:agents:hook' }, headers)).json() as {
      did: string;
      documents: { didDocument: unknown; card: unknown; didDocumentUrl: string; cardUrl: string };
    };
    a.h.web.set(own.documents.didDocumentUrl, own.documents.didDocument);
    a.h.web.set(own.documents.cardUrl, own.documents.card);
    expect((await post(a, `/v1/agents/${enc(own.did)}/activate`, {}, headers)).statusCode).toBe(200);
    expect(activated).toEqual([`${self.did} active`, `${own.did} active`]);
  });

  it('POST /services: a custody choice or an account preference goes to the custody service, anything else to the enrollment as before', async () => {
    const a = await app();
    const legacy = await post(a, '/v1/services', { name: 'legacy', domain: 'legacy.example', requiredScopes: ['a'] });
    expect(legacy.statusCode).toBe(201);
    expect(a.legacyEnroll).toHaveBeenCalledTimes(1);
    const custodial = await post(a, '/v1/services', { name: 'orders', domain: 'orders.example', requiredScopes: ['a'], keyCustody: 'helix' });
    expect(custodial.statusCode, custodial.body).toBe(201);
    expect(custodial.json()).toMatchObject({ name: 'orders', domain: 'orders.example', keyCustody: 'helix', label: 'custody: helix', id: expect.stringMatching(/^svc:/) });
    expect(custodial.json()).not.toHaveProperty('service');
    expect(a.legacyEnroll).toHaveBeenCalledTimes(1);

    const withAccount = await app({}, () => ({ defaultKeyCustody: 'helix', defaultDidHosting: 'helix' }));
    const followed = await post(withAccount, '/v1/services', { name: 'billing', domain: 'billing.example', requiredScopes: ['a'] });
    expect(followed.json()).toMatchObject({ keyCustody: 'helix' });
    expect(withAccount.legacyEnroll).not.toHaveBeenCalled();
  });
});

describe('the account is the agent\'s owner (F-3 follow-up: responsibleParty === issuer(root))', () => {
  it('names the caller\'s account DID as owner of every agent it creates, and refuses another ownerDid', async () => {
    const a = await app({ ownerDidOf: () => 'did:web:helix.example:accounts:acc-1' });
    const custodial = await post(a, '/v1/agents', { name: 'Owned', scopes: ['read:orders'], keyCustody: 'helix' });
    expect(custodial.statusCode, custodial.body).toBe(201);
    expect(a.h.issued.at(-1)!.input).toMatchObject({ agentDid: custodial.json().did, ownerDid: 'did:web:helix.example:accounts:acc-1' });
    // The same DID in the body is fine; any other is refused before anything is created.
    expect((await post(a, '/v1/agents', { name: 'Same', keyCustody: 'helix', ownerDid: 'did:web:helix.example:accounts:acc-1' })).statusCode).toBe(201);
    const refused = await post(a, '/v1/agents', { name: 'Other', keyCustody: 'helix', ownerDid: 'did:web:someone-else.example' });
    expect(refused.statusCode).toBe(400);
    expect(refused.json().error.message).toContain("account's DID");
    expect(a.h.issued).toHaveLength(2);
  });

  it('without accounts the body\'s ownerDid is kept, else the Helix issuer answers for the agent', async () => {
    const a = await app();
    await post(a, '/v1/agents', { name: 'Named', keyCustody: 'helix', ownerDid: 'did:web:owner.example' });
    await post(a, '/v1/agents', { name: 'Unnamed', keyCustody: 'helix' });
    expect(a.h.issued.map((entry) => entry.input['ownerDid'])).toEqual(['did:web:owner.example', 'did:web:helix.example']);
  });
});
