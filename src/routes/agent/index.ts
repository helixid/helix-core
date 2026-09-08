// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

import type { FastifyPluginAsync } from 'fastify';
import { AdminAuthRequiredError, type SignedVC } from '../../core/index.js';
import type { IAgentService } from '../../services/agent/IAgentService.js';
import { mapAgentError } from '../../services/agent/agent.service.js';

interface AgentRouteOptions {
  agentService: IAgentService;
  /** Required to call POST /agents/:did/vp — see that route's comment for why. */
  adminApiKey?: string | undefined;
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
        maxDelegationDepth?: number;
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
      return reply.code(201).send(result);
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
      const body = request.body as {
        targetService: string;
        userDid?: string;
        grantVC?: SignedVC;
        vcId?: string;
      };
      const result = await options.agentService.signVP(
        {
          did: params.did,
          targetService: body.targetService,
          ...(body.userDid ? { userDid: body.userDid } : {}),
          ...(body.grantVC ? { grantVC: body.grantVC } : {}),
          ...(body.vcId ? { vcId: body.vcId } : {}),
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

  // POST /agents/:did/delegate - delegate a slice of a server-custody
  // agent's authority to another DID. Same trust boundary and gating as
  // POST /agents/:did/vp above: the delegator's private key is what
  // authorizes this, and OSS has no per-tenant credential narrower than the
  // admin key.
  fastify.post('/agents/:did/delegate', async (request, reply) => {
    try {
      requireAdmin(request);
      const params = request.params as { did: string };
      const body = request.body as {
        to: string;
        scopes: string[];
        expiresIn: number;
        vcId?: string;
      };
      const result = await options.agentService.delegateAuthority(
        {
          did: params.did,
          to: body.to,
          scopes: body.scopes,
          expiresIn: body.expiresIn,
          ...(body.vcId ? { vcId: body.vcId } : {}),
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

};

export default agentRoutes;
