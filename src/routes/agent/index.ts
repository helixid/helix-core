// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import { AdminAuthRequiredError, ErrorCode, HelixError, type Caveat } from '../../core/index.js';
import type { IAgentService } from '../../services/agent/IAgentService.js';
import { mapAgentError } from '../../services/agent/agent.service.js';
import type { CredentialService } from '../../services/credentials/credential.service.js';

export interface AgentRouteOptions {
  agentService: IAgentService;
  /**
   * Issues and revokes the split credentials of KYA-OS story F-1 (identity,
   * capability attestations, delegation hops). Required for the /agents/:did
   * credential routes and /grants; without it those routes answer 503.
   */
  credentialService?: CredentialService | undefined;
  /** Required to call POST /agents/:did/vp — see that route's comment for why. */
  adminApiKey?: string | undefined;
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

const agentRoutes: FastifyPluginAsync<AgentRouteOptions> = async (fastify, options) => {
  function requireAdmin(request: { headers: Record<string, string | string[] | undefined> }): void {
    const submitted = request.headers['x-admin-api-key'];
    const submittedKey = Array.isArray(submitted) ? submitted[0] : submitted;
    if (!options.adminApiKey || submittedKey !== options.adminApiKey) {
      throw new AdminAuthRequiredError();
    }
  }

  fastify.post('/enrollment-tokens', async (request, reply) => {
    try {
      const body = request.body as {
        agentName: string;
        requestedScopes: string[];
        requestedDomains?: string[];
        expiry?: number;
      };
      const result = await options.agentService.generateEnrollmentToken(body, request.id);
      return reply.code(201).send(result);
    } catch (error) {
      const mapped = mapAgentError(error);
      return reply
        .code(mapped.statusCode)
        .send({ error: { code: mapped.code, message: mapped.message, requestId: request.id } });
    }
  });

  // POST /onboard - single-call, server-custody onboarding. Agent
  // self-custody has been retired: the agent no longer generates a keypair
  // or submits a public key here — the server does, internally, and stores
  // the resulting private key encrypted (see AgentService.onboardWithCustody).
  // Only { agentDid, vcId } comes back; no key material ever does.
  fastify.post('/onboard', async (request, reply) => {
    try {
      const result = await options.agentService.onboardWithCustody(
        request.body as { enrollmentToken: string; domains?: string[] },
        request.id,
      );
      return reply.code(201).send({ agentDid: result.agentDid, vcId: result.vcId });
    } catch (error) {
      const mapped = mapAgentError(error);
      return reply
        .code(mapped.statusCode)
        .send({ error: { code: mapped.code, message: mapped.message, requestId: request.id } });
    }
  });

  // POST /agents/:did/vp - sign a VP on behalf of a server-custody agent.
  // The caller never has the agent's private key, so this has to be an API
  // call rather than local VPBuilder.sign(). Gated by the admin key: OSS has
  // no per-tenant credential narrower than that (unlike the hosted/
  // enterprise build's per-account bearer token), so this is deliberately
  // the same all-or-nothing trust already placed in the admin key for VC
  // issuance/revocation — a known scoping reduction versus self-custody,
  // where only the agent's own key could ever sign for itself.
  fastify.post('/agents/:did/vp', async (request, reply) => {
    try {
      requireAdmin(request);
      const params = request.params as { did: string };
      const body = request.body as { targetService: string; userDid?: string };
      const result = await options.agentService.signVP(
        {
          did: params.did,
          targetService: body.targetService,
          ...(body.userDid ? { userDid: body.userDid } : {}),
        },
        request.id,
      );
      return reply.code(200).send(result);
    } catch (error) {
      const mapped = mapAgentError(error);
      return reply
        .code(mapped.statusCode)
        .send({ error: { code: mapped.code, message: mapped.message, requestId: request.id } });
    }
  });

  fastify.post('/challenges', async (request, reply) => {
    try {
      const result = await options.agentService.issueUserChallenge(
        request.body as { did: string; purpose: 'user_verification' },
        request.id,
      );
      return reply.code(201).send(result);
    } catch (error) {
      const mapped = mapAgentError(error);
      return reply
        .code(mapped.statusCode)
        .send({ error: { code: mapped.code, message: mapped.message, requestId: request.id } });
    }
  });

  fastify.post('/challenges/:challengeId/verify', async (request, reply) => {
    try {
      const params = request.params as { challengeId: string };
      const body = request.body as { signature: string };
      const result = await options.agentService.verifyUserChallenge(
        params.challengeId,
        body,
        request.id,
      );
      return reply.code(200).send(result);
    } catch (error) {
      const mapped = mapAgentError(error);
      return reply
        .code(mapped.statusCode)
        .send({ error: { code: mapped.code, message: mapped.message, requestId: request.id } });
    }
  });


  // ── KYA-OS story F-1: the credential split ────────────────────────────────
  // Identity, capability attestations and delegation hops are three
  // credentials; changing one never reissues or revokes another. Every
  // route below is admin-gated for the same reason POST /agents/:did/vp is.

  function credentials(): CredentialService {
    if (!options.credentialService) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'Credential issuance is not configured on this server', 503);
    }
    return options.credentialService;
  }

  // POST /agents - onboard a custodial agent and return its identity
  // credential plus one capability attestation per requested scope. The
  // request may carry `ownerDid`, the party that answers for the agent
  // (default: the Helix issuer DID).
  fastify.post('/agents', async (request, reply) => {
    try {
      const body = request.body as { enrollmentToken: string; domains?: string[]; ownerDid?: string };
      const result = await options.agentService.onboardWithCustody(
        {
          enrollmentToken: body.enrollmentToken,
          ...(body.domains ? { domains: body.domains } : {}),
          ...(body.ownerDid ? { ownerDid: body.ownerDid } : {}),
        },
        request.id,
      );
      return reply.code(201).send({
        agentDid: result.agentDid,
        identity: result.identity,
        attestations: result.attestations,
      });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // GET /agents/:did/credentials - the Helix copy of everything issued to the agent.
  fastify.get('/agents/:did/credentials', async (request, reply) => {
    try {
      requireAdmin(request);
      const params = request.params as { did: string };
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
      requireAdmin(request);
      const params = request.params as { did: string };
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
      requireAdmin(request);
      const params = request.params as { did: string; capability: string };
      const revokedVcIds = await credentials().revokeAttestation(params.did, decodeURIComponent(params.capability), request.id);
      return reply.code(200).send({ agentDid: params.did, capability: decodeURIComponent(params.capability), revokedVcIds });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // POST /grants - a root delegation hop: parentCapability is the resource
  // itself. Signed by `issuer` (the Helix issuer, or a DID whose key Helix
  // holds in custody); the user-signed root of story L3-H takes this place
  // at consent.
  fastify.post('/grants', async (request, reply) => {
    try {
      requireAdmin(request);
      const body = (request.body ?? {}) as Record<string, unknown>;
      for (const name of ['issuer', 'invoker', 'invocationTarget'] as const) {
        if (typeof body[name] !== 'string' || body[name] === '') {
          throw new HelixError(ErrorCode.VALIDATION_ERROR, `${name} is required`, 400);
        }
      }
      const hop = await credentials().issueRootHop(
        {
          issuer: body['issuer'] as string,
          invoker: body['invoker'] as string,
          invocationTarget: body['invocationTarget'] as string,
          allowedAction: requireStringArray(body['allowedAction'], 'allowedAction'),
          ...(optionalCaveats(body['caveats']) === undefined ? {} : { caveats: optionalCaveats(body['caveats'])! }),
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
      requireAdmin(request);
      const params = request.params as { id: string };
      const body = (request.body ?? {}) as Record<string, unknown>;
      if (typeof body['invoker'] !== 'string' || body['invoker'] === '') {
        throw new HelixError(ErrorCode.VALIDATION_ERROR, 'invoker is required', 400);
      }
      const result = await credentials().issueHop(
        params.id,
        {
          invoker: body['invoker'],
          allowedAction: requireStringArray(body['allowedAction'], 'allowedAction'),
          ...(optionalCaveats(body['caveats']) === undefined ? {} : { caveats: optionalCaveats(body['caveats'])! }),
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
      requireAdmin(request);
      const params = request.params as { id: string };
      const chain = await credentials().chainOf(params.id);
      if (chain.length === 0) {
        throw new HelixError(ErrorCode.VC_NOT_FOUND, `No delegation hop ${params.id}`, 404);
      }
      return reply.code(200).send({ chain });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

  // DELETE /grants/:id - revoke a hop and every hop below it (cascading, SPEC.md §6.5).
  fastify.delete('/grants/:id', async (request, reply) => {
    try {
      requireAdmin(request);
      const params = request.params as { id: string };
      const revokedVcIds = await credentials().revokeHop(params.id, request.id);
      return reply.code(200).send({ revokedVcIds });
    } catch (error) {
      return sendError(request, reply, error);
    }
  });

};

export default agentRoutes;
