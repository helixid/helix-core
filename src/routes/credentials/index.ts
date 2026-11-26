// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * KYA-OS story F-1, the credential split, over HTTP: the Helix copy of an
 * agent's credentials, its capability attestations, and delegation hops.
 * Identity, attestations and hops are three credentials; changing one never
 * reissues or revokes another.
 *
 * Every route asks `authorize` first, with what it is about to do. The
 * default is the admin key (`x-admin-api-key`), as in the open-source build;
 * a build with accounts passes its own (helix-server-enterprise lets an
 * account act on the agents, services and hops it owns). The same routes
 * serve every agent, whoever holds its key (story F-3): a hop is signed by
 * its issuer, which Helix can do for the Helix issuer, a did_keys key or a
 * custodial (KeyStore) subject; a self-custody agent signs its own hops.
 *
 * `agentRoutes` registers this plugin unless told not to, so the paths are
 * unchanged for the servers that already serve them.
 */

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { AdminAuthRequiredError, ErrorCode, HelixError, type Caveat, type SignedDelegationHop } from '../../core/index.js';
import { mapAgentError } from '../../services/agent/agent.service.js';
import type { CredentialService } from '../../services/credentials/credential.service.js';

/** What a request is about to do, for `authorize`. A hop action carries the stored chain it touches, root first. */
export type CredentialRouteAction =
  | { action: 'readCredentials'; agentDid: string }
  | { action: 'attest'; agentDid: string }
  | { action: 'revokeAttestation'; agentDid: string; capability: string }
  | { action: 'issueRootHop'; issuer: string; invoker: string; invocationTarget: string }
  | { action: 'issueHop'; parentId: string; delegator: string; invoker: string; chain: SignedDelegationHop[] }
  | { action: 'readChain'; hopId: string; chain: SignedDelegationHop[] }
  | { action: 'revokeHop'; hopId: string; chain: SignedDelegationHop[] };

export interface CredentialRouteOptions {
  /** Issues and revokes the split credentials. Without it every route answers 503. */
  credentialService?: CredentialService | undefined;
  /** The admin key the default `authorize` checks. */
  adminApiKey?: string | undefined;
  /** Throws when the caller may not perform `action`. Default: `x-admin-api-key` must equal `adminApiKey`. */
  authorize?: ((request: FastifyRequest, action: CredentialRouteAction) => Promise<void> | void) | undefined;
}

function sendError(request: FastifyRequest, reply: FastifyReply, error: unknown): FastifyReply {
  const mapped = mapAgentError(error);
  return reply
    .code(mapped.statusCode)
    .send({ error: { code: mapped.code, message: mapped.message, requestId: request.id } });
}

function requireStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || item === '')) {
    throw new HelixError(ErrorCode.VALIDATION_ERROR, `${name} must be an array of non-empty strings`, 400);
  }
  return value as string[];
}

function optionalCaveats(value: unknown): Caveat[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'object' || item === null || typeof item.type !== 'string')) {
    throw new HelixError(ErrorCode.VALIDATION_ERROR, 'caveats must be an array of objects with a type', 400);
  }
  return value as Caveat[];
}

function requireString(body: Record<string, unknown>, name: string): string {
  if (typeof body[name] !== 'string' || body[name] === '') {
    throw new HelixError(ErrorCode.VALIDATION_ERROR, `${name} is required`, 400);
  }
  return body[name] as string;
}

/** Who a hop delegates to: its invoker, or its controller in the older form. */
export function hopDelegate(hop: SignedDelegationHop): string {
  return hop.credentialSubject.invoker ?? hop.credentialSubject.controller!;
}

const credentialRoutes: FastifyPluginAsync<CredentialRouteOptions> = async (fastify, options) => {
  /** The default gate, checked before anything else is read, exactly as before the hook existed. */
  function requireAdmin(request: FastifyRequest): void {
    const submitted = request.headers['x-admin-api-key'];
    const submittedKey = Array.isArray(submitted) ? submitted[0] : submitted;
    if (!options.adminApiKey || submittedKey !== options.adminApiKey) {
      throw new AdminAuthRequiredError();
    }
  }
  /** A host's own gate, asked once the request says what it would do. */
  const hook = options.authorize;
  const gate = async (request: FastifyRequest, action: CredentialRouteAction): Promise<void> => {
    if (hook) await hook(request, action);
  };
  const adminFirst = (request: FastifyRequest): void => {
    if (!hook) requireAdmin(request);
  };

  function credentials(): CredentialService {
    if (!options.credentialService) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'Credential issuance is not configured on this server', 503);
    }
    return options.credentialService;
  }

  /** The stored chain that ends at `id`, or VC_NOT_FOUND. */
  async function storedChain(id: string): Promise<SignedDelegationHop[]> {
    const chain = await credentials().chainOf(id);
    if (chain.length === 0) {
      throw new HelixError(ErrorCode.VC_NOT_FOUND, `No delegation hop ${id}`, 404);
    }
    return chain;
  }

  /** The parent hop to re-delegate under, or the same not-found `issueHop` answers. */
  async function parentChain(id: string): Promise<SignedDelegationHop[]> {
    const chain = await credentials().chainOf(id);
    if (chain.length === 0) {
      throw new HelixError(ErrorCode.DELEGATION_PARENT_VC_NOT_FOUND, `No delegation hop ${id}`, 404);
    }
    return chain;
  }

  // GET /agents/:did/credentials - the Helix copy of everything issued to the agent.
  fastify.get('/agents/:did/credentials', async (request, reply) => {
    try {
      adminFirst(request);
      const params = request.params as { did: string };
      await gate(request, { action: 'readCredentials', agentDid: params.did });
      return reply.code(200).send(await credentials().listAgentCredentials(params.did));
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // POST /agents/:did/attestations - issue one attestation. Body is either
  // `{ capability }` (Helix issuer signs) or `{ attestation }` (an owner
  // signed it through the SDK; verified, then kept).
  fastify.post('/agents/:did/attestations', async (request, reply) => {
    try {
      adminFirst(request);
      const params = request.params as { did: string };
      await gate(request, { action: 'attest', agentDid: params.did });
      const body = (request.body ?? {}) as { capability?: unknown; attestation?: unknown; validUntil?: unknown };
      if (body.attestation !== undefined) {
        const attestation = await credentials().registerAttestation(params.did, body.attestation, request.id);
        return reply.code(201).send({ attestation });
      }
      if (typeof body.capability !== 'string' || body.capability === '') {
        throw new HelixError(ErrorCode.VALIDATION_ERROR, 'capability or attestation is required', 400);
      }
      const validUntil = typeof body.validUntil === 'string' ? new Date(body.validUntil) : undefined;
      if (validUntil !== undefined && Number.isNaN(validUntil.getTime())) {
        throw new HelixError(ErrorCode.VALIDATION_ERROR, 'validUntil must be a date-time', 400);
      }
      const [attestation] = await credentials().issueAttestations(
        { agentDid: params.did, capabilities: [body.capability], ...(validUntil ? { validUntil } : {}) },
        request.id,
      );
      return reply.code(201).send({ attestation });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // DELETE /agents/:did/attestations/:capability - revoke that one scope through the status list.
  fastify.delete('/agents/:did/attestations/:capability', async (request, reply) => {
    try {
      adminFirst(request);
      const params = request.params as { did: string; capability: string };
      const capability = decodeURIComponent(params.capability);
      await gate(request, { action: 'revokeAttestation', agentDid: params.did, capability });
      const revokedVcIds = await credentials().revokeAttestation(params.did, capability, request.id);
      return reply.code(200).send({ agentDid: params.did, capability, revokedVcIds });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // POST /grants - a root delegation hop: parentCapability is the resource
  // itself. Signed by `issuer` (the Helix issuer, or a DID whose key Helix
  // holds: did_keys, or a custodial subject's KeyStore key); the user-signed
  // root of story L3-H takes this place at consent.
  fastify.post('/grants', async (request, reply) => {
    try {
      adminFirst(request);
      const body = (request.body ?? {}) as Record<string, unknown>;
      const issuer = requireString(body, 'issuer');
      const invoker = requireString(body, 'invoker');
      const invocationTarget = requireString(body, 'invocationTarget');
      const allowedAction = requireStringArray(body['allowedAction'], 'allowedAction');
      const caveats = optionalCaveats(body['caveats']);
      await gate(request, { action: 'issueRootHop', issuer, invoker, invocationTarget });
      const hop = await credentials().issueRootHop(
        {
          issuer,
          invoker,
          invocationTarget,
          allowedAction,
          ...(caveats === undefined ? {} : { caveats }),
          ...(typeof body['validUntil'] === 'string' ? { validUntil: body['validUntil'] } : {}),
        },
        request.id,
      );
      return reply.code(201).send({ hop });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // POST /grants/:id/hops - re-delegate under the stored hop :id to another
  // DID; signed by the parent's invoker, refused when it would broaden.
  fastify.post('/grants/:id/hops', async (request, reply) => {
    try {
      adminFirst(request);
      const params = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;
      const invoker = requireString(body, 'invoker');
      const allowedAction = requireStringArray(body['allowedAction'], 'allowedAction');
      const caveats = optionalCaveats(body['caveats']);
      const chain = await parentChain(params.id);
      await gate(request, { action: 'issueHop', parentId: params.id, delegator: hopDelegate(chain[chain.length - 1]!), invoker, chain });
      const result = await credentials().issueHop(
        params.id,
        {
          invoker,
          allowedAction,
          ...(caveats === undefined ? {} : { caveats }),
          ...(typeof body['validUntil'] === 'string' ? { validUntil: body['validUntil'] } : {}),
        },
        request.id,
      );
      return reply.code(201).send(result);
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // GET /grants/:id/chain - the stored chain root to leaf that ends at :id.
  fastify.get('/grants/:id/chain', async (request, reply) => {
    try {
      adminFirst(request);
      const params = request.params as { id: string };
      const chain = await storedChain(params.id);
      await gate(request, { action: 'readChain', hopId: params.id, chain });
      return reply.code(200).send({ chain });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // DELETE /grants/:id - revoke a hop and every hop below it (cascading, SPEC.md §6.5).
  fastify.delete('/grants/:id', async (request, reply) => {
    try {
      adminFirst(request);
      const params = request.params as { id: string };
      const chain = await storedChain(params.id);
      await gate(request, { action: 'revokeHop', hopId: params.id, chain });
      const revokedVcIds = await credentials().revokeHop(params.id, request.id);
      return reply.code(200).send({ revokedVcIds });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });
};

export default credentialRoutes;
