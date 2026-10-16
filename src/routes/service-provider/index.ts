// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Service Providers: enrollment and consent grants, both signed with the
// service's custody-held key. Who may call is the one thing that differs
// between a self-hosted instance (admin key) and a hosted one (the account
// that owns the service), so it is injected as `authorize` rather than
// decided here.

import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import { AdminAuthRequiredError } from '../../core/index.js';
import { mapAgentError } from '../../services/agent/agent.service.js';
import type {
  EnrollServiceInput,
  IServiceProviderService,
  IssueDelegationGrantInput,
} from '../../services/service-provider/service-provider.service.js';

export type ServiceProviderAction =
  | { action: 'enroll' }
  | { action: 'grant'; serviceDid: string; agentDid: string };

export interface ServiceProviderRouteOptions {
  serviceProviderService: IServiceProviderService;
  /**
   * Throws when the caller may not perform `action`. Defaults to requiring
   * `x-admin-api-key` to equal `adminApiKey` (the self-hosted rule).
   */
  authorize?: (request: FastifyRequest, action: ServiceProviderAction) => Promise<void> | void;
  adminApiKey?: string | undefined;
}

const serviceProviderRoutes: FastifyPluginAsync<ServiceProviderRouteOptions> = async (fastify, options) => {
  const authorize =
    options.authorize ??
    ((request: FastifyRequest) => {
      const submitted = request.headers['x-admin-api-key'];
      const submittedKey = Array.isArray(submitted) ? submitted[0] : submitted;
      if (!options.adminApiKey || submittedKey !== options.adminApiKey) {
        throw new AdminAuthRequiredError();
      }
    });

  // POST /v1/services — enroll a service: the platform mints its DID and
  // holds its key.
  fastify.post('/services', async (request, reply) => {
    try {
      await authorize(request, { action: 'enroll' });
      const result = await options.serviceProviderService.enroll(
        request.body as EnrollServiceInput,
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

  // POST /v1/service-delegation-grants — a user, through a service, grants
  // an agent scoped authority. The service signs; the user is recorded as
  // `credentialSubject.userDid`.
  fastify.post('/service-delegation-grants', async (request, reply) => {
    try {
      const body = (request.body ?? {}) as IssueDelegationGrantInput;
      await authorize(request, { action: 'grant', serviceDid: body.serviceDid, agentDid: body.agentDid });
      const result = await options.serviceProviderService.issueDelegationGrant(body, request.id);
      return reply.code(201).send(result);
    } catch (error) {
      const mapped = mapAgentError(error);
      return reply
        .code(mapped.statusCode)
        .send({ error: { code: mapped.code, message: mapped.message, requestId: request.id } });
    }
  });
};

export default serviceProviderRoutes;
