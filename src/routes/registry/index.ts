// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Registry v3 (2026-11-24): the Helix agent registry, at fixed paths.
//
// On the Helix registry (the Helix-hosted deployment, given an inbox):
//   GET    /agent/registry?q=&limit=&cursor=   discoverable agents
//   GET    /agent/registry/:did                one agent -> { agent }
//   POST   /mcp                                the same as MCP tools (JSON-RPC 2.0,
//                                              Streamable HTTP with plain JSON answers):
//                                              search_agents, get_agent
//   POST   /agent/registry  { registration }   publish (HelixRegistryInbox)
//   DELETE /agent/registry/:did                withdraw (re-checked with the deployment)
//
// On every other deployment, only GET /agent/registry/:did, for its own
// discoverable agents: what the Helix registry checks a registration against.
//
// All open: a discoverable agent is listed for anyone. "Not listed" is one
// 404 for unknown, not discoverable, revoked and deactivated.

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { HelixError } from '../../core/index.js';
import type { HelixRegistryInbox } from '../../services/registry/helix-registry.inbox.js';
import type { RegistryService } from '../../services/registry/registry.service.js';
import {
  AGENT_REGISTRY_PATH,
  REGISTRY_MCP_PATH,
  REGISTRY_MAX_PAGE,
  REGISTRY_QUERY_MAX_LENGTH,
  parseRegistrySearch,
} from '../../services/registry/registry.js';

export const REGISTRY_MCP_PROTOCOL_VERSION = '2025-06-18';
export const REGISTRY_RATE_LIMIT_DEFAULT = 30;

export interface RegistryRouteOptions {
  registry: Pick<RegistryService, 'searchAgents' | 'getAgent' | 'getOwnAgent'>;
  /** Only on the Helix registry: accepts registrations and withdrawals, and turns on search and MCP. */
  inbox?: Pick<HelixRegistryInbox, 'publish' | 'withdraw'> | undefined;
  /** Requests per minute per IP (when @fastify/rate-limit is registered). */
  rateLimitMax?: number | undefined;
  /** serverInfo.version of the MCP server. */
  version?: string | undefined;
}

const QUERY_SCHEMA = {
  type: 'object',
  properties: {
    q: { type: 'string', maxLength: REGISTRY_QUERY_MAX_LENGTH, description: 'Words to match (any word) in the name or owner, or an exact DID' },
    limit: { type: 'integer', minimum: 1, maximum: REGISTRY_MAX_PAGE },
    cursor: { type: 'string' },
  },
  additionalProperties: false,
} as const;

const READ_ONLY = { readOnlyHint: true, openWorldHint: false } as const;

export const REGISTRY_MCP_TOOLS = [
  {
    name: 'search_agents',
    title: 'Search the Helix agent registry',
    description: 'Discoverable agents: each with its DID, name, owner and the deployment it is onboarded on.',
    inputSchema: QUERY_SCHEMA,
    annotations: READ_ONLY,
  },
  {
    name: 'get_agent',
    title: 'Get one agent',
    description: 'One discoverable agent, by DID.',
    inputSchema: { type: 'object', properties: { did: { type: 'string' } }, required: ['did'], additionalProperties: false },
    annotations: READ_ONLY,
  },
] as const;

class RpcError extends Error {
  constructor(
    readonly rpcCode: number,
    message: string,
  ) {
    super(message);
  }
}

function asObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function errorBody(error: unknown, requestId: string): { status: number; body: unknown } {
  if (error && typeof error === 'object' && 'code' in error && 'httpStatus' in error) {
    const typed = error as HelixError;
    return { status: typed.httpStatus, body: { error: { code: typed.code, message: typed.message, requestId } } };
  }
  return { status: 500, body: { error: { code: 'INTERNAL_ERROR', message: 'Internal server error', requestId } } };
}

async function answer(request: FastifyRequest, reply: FastifyReply, run: () => Promise<unknown>, status = 200): Promise<FastifyReply> {
  try {
    const value = await run();
    // Un-publishing must take effect at once, so nothing may cache a page.
    return reply.code(status).header('Cache-Control', 'no-store').send(value);
  } catch (error) {
    const mapped = errorBody(error, request.id);
    return reply.code(mapped.status).header('Cache-Control', 'no-store').send(mapped.body);
  }
}

/** A tool's answer: the JSON as text (for any client) and as structuredContent. */
function toolResult(value: unknown, isError = false): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value, isError };
}

const registryRoutes: FastifyPluginAsync<RegistryRouteOptions> = async (fastify, options) => {
  const { registry, inbox } = options;
  const config = { rateLimit: { max: options.rateLimitMax ?? REGISTRY_RATE_LIMIT_DEFAULT, timeWindow: '1 minute' } };
  const didOf = (request: FastifyRequest): string => (request.params as { did: string }).did;

  if (!inbox) {
    // Not the Helix registry: only its own discoverable agents, one at a time, for the Helix registry's check.
    fastify.get(`${AGENT_REGISTRY_PATH}/:did`, { config }, (request, reply) =>
      answer(request, reply, async () => ({ agent: await registry.getOwnAgent(didOf(request)) })),
    );
    return;
  }

  fastify.get(AGENT_REGISTRY_PATH, { config }, (request, reply) => answer(request, reply, async () => registry.searchAgents(parseRegistrySearch(request.query))));
  fastify.get(`${AGENT_REGISTRY_PATH}/:did`, { config }, (request, reply) =>
    answer(request, reply, async () => ({ agent: await registry.getAgent(didOf(request)) })),
  );
  fastify.post(AGENT_REGISTRY_PATH, { config }, (request, reply) =>
    answer(
      request,
      reply,
      async () => {
        const published = await inbox.publish(asObject(request.body)['registration']);
        return { agent: published.entry, registeredAt: published.registeredAt.toISOString() };
      },
      201,
    ),
  );
  fastify.delete(`${AGENT_REGISTRY_PATH}/:did`, { config }, (request, reply) => answer(request, reply, () => inbox.withdraw(didOf(request))));

  async function callTool(name: unknown, rawArgs: unknown): Promise<Record<string, unknown>> {
    const args = asObject(rawArgs);
    try {
      switch (name) {
        case 'search_agents':
          return toolResult(await registry.searchAgents(parseRegistrySearch(args)));
        case 'get_agent':
          return toolResult({ agent: await registry.getAgent(typeof args['did'] === 'string' ? args['did'] : '') });
        default:
          throw new RpcError(-32602, `Unknown tool: ${String(name)}`);
      }
    } catch (error) {
      if (error instanceof RpcError) throw error;
      // A tool that ran and answered "no" (not listed, a bad query) is a tool result, not a protocol error.
      const code = error && typeof error === 'object' && 'code' in error ? String((error as { code: unknown }).code) : 'INTERNAL_ERROR';
      return toolResult({ error: { code, message: error instanceof Error ? error.message : 'Internal error' } }, true);
    }
  }

  async function handle(message: Record<string, unknown>): Promise<unknown> {
    if (message['jsonrpc'] !== '2.0' || typeof message['method'] !== 'string') throw new RpcError(-32600, 'Invalid Request');
    const params = asObject(message['params']);
    switch (message['method']) {
      case 'initialize':
        return {
          protocolVersion: REGISTRY_MCP_PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'helix-registry', title: 'Helix agent registry', version: options.version ?? '0.1.0' },
          instructions: 'Read-only. Find discoverable agents with search_agents; read one with get_agent.',
        };
      case 'ping':
        return {};
      case 'tools/list':
        return { tools: REGISTRY_MCP_TOOLS };
      case 'tools/call':
        return callTool(params['name'], params['arguments']);
      default:
        throw new RpcError(-32601, `Method not found: ${message['method']}`);
    }
  }

  fastify.post(REGISTRY_MCP_PATH, { config }, async (request, reply) => {
    if (Array.isArray(request.body)) {
      return reply.code(400).send({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Batches are not supported' } });
    }
    const message = asObject(request.body);
    const rawId = message['id'];
    const id = typeof rawId === 'string' || typeof rawId === 'number' ? rawId : null;
    if (rawId === undefined && typeof message['method'] === 'string' && message['jsonrpc'] === '2.0') return reply.code(202).send();
    try {
      return reply.code(200).header('Cache-Control', 'no-store').send({ jsonrpc: '2.0', id, result: await handle(message) });
    } catch (error) {
      const rpcCode = error instanceof RpcError ? error.rpcCode : -32603;
      return reply.code(200).send({ jsonrpc: '2.0', id, error: { code: rpcCode, message: error instanceof Error ? error.message : 'Internal error' } });
    }
  });
  // Streamable HTTP clients may open a GET stream; this server has nothing to push.
  fastify.get(REGISTRY_MCP_PATH, async (_request, reply) => reply.code(405).header('Allow', 'POST').send());
};

export default registryRoutes;
