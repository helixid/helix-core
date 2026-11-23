// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import type { IAgentService } from '../../services/agent/IAgentService.js';
import { mapAgentError } from '../../services/agent/agent.service.js';
import type { CredentialService } from '../../services/credentials/credential.service.js';
import credentialRoutes from '../credentials/index.js';

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
  /**
   * Whether this plugin registers POST /agents. False when the custody routes
   * (KYA-OS story F-3) own the path: they hand a body carrying
   * `enrollmentToken` to `enrollmentOnboardingHandler`, unchanged.
   */
  createAgentRoute?: boolean | undefined;
  /**
   * Whether this plugin registers the F-1 credential routes (`credentialRoutes`:
   * /agents/:did/credentials, attestations, /grants) behind the admin key.
   * False when the host registers them itself with its own `authorize`.
   */
  credentialRoutes?: boolean | undefined;
}

function sendError(request: FastifyRequest, reply: FastifyReply, error: unknown): FastifyReply {
  const mapped = mapAgentError(error);
  return reply
    .code(mapped.statusCode)
    .send({ error: { code: mapped.code, message: mapped.message, requestId: request.id } });
}

/**
 * POST /agents with an enrollment token (story F-1): onboard a custodial agent
 * and return its identity credential plus one capability attestation per
 * requested scope. The request may carry `ownerDid`, the party that answers
 * for the agent (default: the Helix issuer DID).
 */
export function enrollmentOnboardingHandler(
  agentService: Pick<IAgentService, 'onboardWithCustody'>,
): (request: FastifyRequest, reply: FastifyReply) => Promise<FastifyReply> {
  return async (request, reply) => {
    try {
      const body = request.body as { enrollmentToken: string; domains?: string[]; ownerDid?: string };
      const result = await agentService.onboardWithCustody(
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
  };
}

const agentRoutes: FastifyPluginAsync<AgentRouteOptions> = async (fastify, options) => {
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



  // POST /agents - see enrollmentOnboardingHandler. Not registered here when
  // the custody routes own the path (createAgentRoute: false).
  if (options.createAgentRoute !== false) {
    fastify.post('/agents', enrollmentOnboardingHandler(options.agentService));
  }

  // The F-1 credential routes (credentials, attestations, grants and hops),
  // admin-gated here; a build with accounts registers credentialRoutes itself
  // with its own authorize hook and sets credentialRoutes: false.
  if (options.credentialRoutes !== false) {
    await fastify.register(credentialRoutes, { credentialService: options.credentialService, adminApiKey: options.adminApiKey });
  }
};

export default agentRoutes;
