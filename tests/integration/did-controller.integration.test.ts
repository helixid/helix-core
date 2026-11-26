// Copyright 2026 DgVerse LLP
// A DID document's top-level controller is optional (Harish, 2026-11-24): stored as null when a
// document has none, and the DID lookup route leaves it out.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify from 'fastify';
import { afterAll, describe, expect, it } from 'vitest';
import { buildDIDDocument } from '../../src/core/index.js';
import { errorHandler } from '../../src/middleware/errorHandler.js';
import didRoutes from '../../src/routes/did/index.js';
import type { IDIDService } from '../../src/services/did/did.service.js';
import { DidRepository } from '../../src/repositories/did.repository.js';
import { SqliteStore } from '../../src/storage/sqlite.js';

const AGENT = 'did:web:127.0.0.1%3A3200:agents:a';
const ACCOUNT = 'did:web:127.0.0.1%3A3880:accounts:a0';
const dir = mkdtempSync(join(tmpdir(), 'helix-did-controller-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const params = (did: string, controller?: string) => ({
  id: did,
  subjectType: 'agent',
  ...(controller === undefined ? {} : { controller }),
  publicKey: did.slice(-1).repeat(64),
  hederaTransactionId: 'not-anchored',
  didDocument: { id: did, ...(controller === undefined ? {} : { controller }) },
});

describe.each([
  ['in memory', () => new DidRepository()],
  ['SQLite (controller column nullable)', () => new DidRepository(undefined, new SqliteStore(join(dir, `${Math.random().toString(16).slice(2)}.sqlite`)))],
])('DidRepository %s', (_name, make) => {
  it('stores a DID without a controller, and one with', async () => {
    const repo = make();
    const without = await repo.createDid(params(`${AGENT}1`));
    expect(without).not.toHaveProperty('controller');
    expect(await repo.findDidById(`${AGENT}1`)).not.toHaveProperty('controller');
    await repo.createDid(params(`${AGENT}2`, ACCOUNT));
    expect((await repo.findDidById(`${AGENT}2`))?.controller).toBe(ACCOUNT);
  });
});

describe('GET /v1/dids/:did', () => {
  it('leaves controller out when the document has none, and returns it when it has one', async () => {
    const documents: Record<string, unknown> = {
      [`${AGENT}1`]: (({ controller: _c, ...rest }) => rest)(buildDIDDocument(`${AGENT}1`, 'a'.repeat(64)) as unknown as Record<string, unknown>),
      [`${AGENT}2`]: { ...(buildDIDDocument(`${AGENT}2`, 'b'.repeat(64)) as unknown as Record<string, unknown>), controller: ACCOUNT },
    };
    const didService = { resolveDID: async (did: string) => ({ document: documents[did], deactivated: false }) } as unknown as IDIDService;
    const app = Fastify({ logger: false });
    app.addSchema({ $id: 'Error', type: 'object', properties: { error: { type: 'object', additionalProperties: true } } });
    for (const id of ['NotFound', 'BadRequest', 'Conflict']) app.addSchema({ $id: id, type: 'object', $ref: 'Error#' });
    app.setErrorHandler(errorHandler);
    await app.register(didRoutes, { didService });
    const without = await app.inject({ url: `/v1/dids/${encodeURIComponent(`${AGENT}1`)}` });
    expect(without.statusCode).toBe(200);
    expect(without.json()).not.toHaveProperty('controller');
    expect(without.json().id).toBe(`${AGENT}1`);
    expect((await app.inject({ url: `/v1/dids/${encodeURIComponent(`${AGENT}2`)}` })).json().controller).toBe(ACCOUNT);
    await app.close();
  });
});
