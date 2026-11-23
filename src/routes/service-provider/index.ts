// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Service Providers: enrollment. (Consent grants a service signed for its
// user are retired: since KYA-OS story L3-H the user's own did:key signs the
// root hop at consent, routes/consent/.) Who may call is the one thing that differs
// between a self-hosted instance (admin key) and a hosted one (the account
// that owns the service), so it is injected as `authorize` rather than
// decided here.

import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import { AdminAuthRequiredError, ValidationError, findPrivateKeyMaterial, type CustodyDefaults } from '../../core/index.js';
import type { CustodyService } from '../../services/custody/custody.service.js';
import { mapAgentError } from '../../services/agent/agent.service.js';
import type { EnrollServiceInput, IServiceProviderService } from '../../services/service-provider/service-provider.service.js';

export type ServiceProviderAction = { action: 'enroll' };

export interface ServiceProviderRouteOptions {
  serviceProviderService: IServiceProviderService;
  /**
   * Throws when the caller may not perform `action`. Defaults to requiring
   * `x-admin-api-key` to equal `adminApiKey` (the self-hosted rule).
   */
  authorize?: (request: FastifyRequest, action: ServiceProviderAction) => Promise<void> | void;
  adminApiKey?: string | undefined;
  /**
   * KYA-OS story F-3: the per-service custody choice. When given, a
   * `POST /services` that names `keyCustody` or `didHosting`, or whose caller
   * has an account preference, is created by the custody service (its key in
   * the KeyStore or held by the service itself, its did:web on Helix or its
   * own domain); any other keeps the enrollment below.
   */
  custody?: {
    service: Pick<CustodyService, 'createService'>;
    defaultsOf?: ((request: FastifyRequest) => Promise<CustodyDefaults | undefined> | CustodyDefaults | undefined) | undefined;
    actorOf?: ((request: FastifyRequest) => string) | undefined;
  } | undefined;
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
      const custody = options.custody;
      const input = (request.body ?? {}) as Record<string, unknown>;
      const defaults = await custody?.defaultsOf?.(request);
      if (custody && (input['keyCustody'] !== undefined || input['didHosting'] !== undefined || defaults)) {
        const found = findPrivateKeyMaterial(input);
        if (found !== undefined) throw new ValidationError(`Request carries private key material (${found}); only the public JWK is accepted`);
        const { service, ...custodyResult } = await custody.service.createService(input as never, {
          requestId: request.id,
          actor: custody.actorOf?.(request) ?? 'admin',
          defaults,
        });
        return reply.code(201).send({ ...service, ...custodyResult });
      }
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
};

export default serviceProviderRoutes;
