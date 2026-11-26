// Copyright 2026 DgVerse LLP
// Registry v3 (2026-11-24): the Helix agent registry's routes -- GET /agent/registry, POST /mcp,
// publish and withdraw -- and, on any other deployment, only GET /agent/registry/:did.
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';
import registryRoutes, { REGISTRY_MCP_TOOLS } from '../../src/routes/registry/index.js';
import { RegistryService, type RegistrySource } from '../../src/services/registry/registry.service.js';
import { HelixError } from '../../src/core/index.js';
import type { AgentRegistryEntry } from '../../src/services/registry/registry.js';

const NOW = '2026-11-24T12:00:00.000Z';
const B: AgentRegistryEntry = { agentDid: 'did:web:h:agents:b', name: 'Agent B', status: 'active', owner: { did: null, name: 'Client B' }, publishedAt: NOW, deployment: 'http://h' };
const C2: AgentRegistryEntry = { ...B, agentDid: 'did:web:c:agents:c2', name: 'Agent C2', owner: { did: null, name: 'Client C' }, deployment: 'http://c' };

const source: RegistrySource = { agents: async () => [B] };
const published = { entries: async () => [C2] };

const inbox = () => ({
  publish: vi.fn(async () => ({ did: C2.agentDid, deployment: 'http://c', entry: C2, registeredAt: new Date(NOW) })),
  withdraw: vi.fn(async () => ({ removed: true })),
});

let app: FastifyInstance | undefined;
afterEach(async () => {
  await app?.close();
  app = undefined;
});

/** With an inbox: the Helix registry. Without: any other deployment. */
async function build(withInbox: ReturnType<typeof inbox> | null = inbox()): Promise<FastifyInstance> {
  app = Fastify();
  await app.register(registryRoutes, { registry: new RegistryService(source, withInbox ? published : undefined), inbox: withInbox ?? undefined, rateLimitMax: 1000, version: '9.9.9' });
  return app;
}

const rpc = (server: FastifyInstance, body: unknown) => server.inject({ method: 'POST', url: '/mcp', payload: body as never });

describe('GET /agent/registry on the Helix registry', () => {
  it('lists discoverable agents, its own and those other deployments registered, open', async () => {
    const server = await build();
    const open = await server.inject({ url: '/agent/registry' });
    expect(open.statusCode).toBe(200);
    expect(open.headers['cache-control']).toBe('no-store');
    expect(open.json()).toEqual({ agents: [B, C2], nextCursor: null });
    expect((await server.inject({ url: '/agent/registry?q=c2' })).json().agents).toEqual([C2]);
    expect((await server.inject({ url: `/agent/registry/${encodeURIComponent(C2.agentDid)}` })).json()).toEqual({ agent: C2 });
  });

  it('answers errors with their status, and has no service registry', async () => {
    const server = await build();
    const notListed = await server.inject({ url: `/agent/registry/${encodeURIComponent('did:web:h:agents:hidden')}` });
    expect(notListed.statusCode).toBe(404);
    expect(notListed.json().error).toMatchObject({ code: 'DID_NOT_FOUND', message: 'Agent is not listed' });
    expect((await server.inject({ url: '/agent/registry?limit=99' })).statusCode).toBe(400);
    expect((await server.inject({ url: '/service/registry' })).statusCode).toBe(404);
    expect((await server.inject({ url: '/service/registry?url=https://air.example' })).statusCode).toBe(404);
  });

  it('answers an unexpected failure with 500', async () => {
    app = Fastify();
    await app.register(registryRoutes, { registry: { searchAgents: async () => { throw 'x'; }, getAgent: vi.fn(), getOwnAgent: vi.fn() } as never, inbox: inbox() });
    const internal = await app.inject({ url: '/agent/registry' });
    expect(internal.statusCode).toBe(500);
    expect(internal.json().error.code).toBe('INTERNAL_ERROR');
  });
});

describe('any other deployment', () => {
  it('answers GET /agent/registry/:did for its own discoverable agents only, and nothing else', async () => {
    const server = await build(null);
    expect((await server.inject({ url: `/agent/registry/${encodeURIComponent(B.agentDid)}` })).json()).toEqual({ agent: B });
    expect((await server.inject({ url: `/agent/registry/${encodeURIComponent(C2.agentDid)}` })).statusCode).toBe(404);
    expect((await server.inject({ url: '/agent/registry' })).statusCode).toBe(404);
    expect((await server.inject({ method: 'POST', url: '/agent/registry', payload: { registration: 'x' } })).statusCode).toBe(404);
    expect((await rpc(server, { jsonrpc: '2.0', id: 1, method: 'tools/list' })).statusCode).toBe(404);
  });
});

describe('POST /mcp: the Helix registry as MCP tools', () => {
  it('initializes, pings and lists its two tools', async () => {
    const server = await build();
    const init = (await rpc(server, { jsonrpc: '2.0', id: 1, method: 'initialize' })).json();
    expect(init.result).toMatchObject({ serverInfo: { name: 'helix-registry', version: '9.9.9' }, capabilities: { tools: { listChanged: false } } });
    expect((await rpc(server, { jsonrpc: '2.0', id: 'p', method: 'ping' })).json()).toEqual({ jsonrpc: '2.0', id: 'p', result: {} });
    const tools = (await rpc(server, { jsonrpc: '2.0', id: 2, method: 'tools/list' })).json().result.tools.map((t: { name: string }) => t.name);
    expect(tools).toEqual(['search_agents', 'get_agent']);
    expect(REGISTRY_MCP_TOOLS.map((t) => t.name)).toEqual(tools);
  });

  it('runs each tool', async () => {
    const server = await build();
    const call = async (name: string, args: unknown) => (await rpc(server, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name, arguments: args } })).json().result;
    expect((await call('search_agents', {})).structuredContent.agents).toEqual([B, C2]);
    expect((await call('get_agent', { did: B.agentDid })).structuredContent).toEqual({ agent: B });
    const notListed = await call('get_agent', {});
    expect(notListed).toMatchObject({ isError: true, structuredContent: { error: { code: 'DID_NOT_FOUND' } } });
    expect(JSON.parse(notListed.content[0].text).error.message).toBe('Agent is not listed');
    expect((await call('search_agents', { limit: 0 })).structuredContent.error.code).toBe('VALIDATION_ERROR');
  });

  it('answers protocol errors, and the removed service tools, as JSON-RPC errors', async () => {
    const server = await build();
    for (const name of ['search_services', 'get_service']) {
      expect((await rpc(server, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name } })).json().error).toEqual({ code: -32602, message: `Unknown tool: ${name}` });
    }
    expect((await rpc(server, { jsonrpc: '2.0', id: 5, method: 'resources/list' })).json().error.code).toBe(-32601);
    expect((await rpc(server, { jsonrpc: '1.0', id: 6, method: 'ping' })).json()).toMatchObject({ id: 6, error: { code: -32600 } });
    expect((await rpc(server, { id: { odd: true }, method: 5 })).json()).toMatchObject({ id: null, error: { code: -32600 } });
    expect((await rpc(server, [{ jsonrpc: '2.0', id: 1, method: 'ping' }])).statusCode).toBe(400);
    expect((await rpc(server, { jsonrpc: '2.0', method: 'notifications/initialized' })).statusCode).toBe(202);
    const get = await server.inject({ url: '/mcp' });
    expect(get.statusCode).toBe(405);
    expect(get.headers['allow']).toBe('POST');
  });

  it('turns a thrown non-Error into an internal error tool result', async () => {
    app = Fastify();
    await app.register(registryRoutes, { registry: { searchAgents: async () => { throw 'x'; }, getAgent: vi.fn(), getOwnAgent: vi.fn() } as never, inbox: inbox() });
    const result = (await rpc(app, { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'search_agents' } })).json().result;
    expect(result.structuredContent.error).toEqual({ code: 'INTERNAL_ERROR', message: 'Internal error' });
  });
});

describe('the Helix registry: publish and withdraw', () => {
  it('takes registrations and withdrawals', async () => {
    const box = inbox();
    const server = await build(box);
    const response = await server.inject({ method: 'POST', url: '/agent/registry', payload: { registration: 'a.b.c' } });
    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({ agent: C2, registeredAt: NOW });
    expect(box.publish).toHaveBeenCalledWith('a.b.c');
    expect((await server.inject({ method: 'POST', url: '/agent/registry', payload: 'not json object', headers: { 'content-type': 'text/plain' } })).statusCode).toBe(201);
    expect(box.publish).toHaveBeenLastCalledWith(undefined);
    expect((await server.inject({ method: 'DELETE', url: `/agent/registry/${encodeURIComponent(C2.agentDid)}` })).json()).toEqual({ removed: true });
    expect(box.withdraw).toHaveBeenCalledWith(C2.agentDid);
    box.publish.mockRejectedValueOnce(new HelixError('REGISTRATION_NOT_LISTED', 'not listed', 403));
    expect((await server.inject({ method: 'POST', url: '/agent/registry', payload: { registration: 'x' } })).statusCode).toBe(403);
    expect((await server.inject({ method: 'POST', url: '/service/registry', payload: { registration: 'x' } })).statusCode).toBe(404);
  });
});
