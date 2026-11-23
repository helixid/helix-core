// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { FastifyPluginAsync } from 'fastify';
import { AdminAuthRequiredError } from '../../core/index.js';
import type { StatusListService } from '../../services/status-lists/status-list.service.js';

export interface StatusListRouteOptions {
  statusLists: StatusListService;
  adminApiKey?: string | undefined;
}

/**
 * Public status lists (KYA-OS story L3-C): one W3C Bitstring Status List
 * v1.0 credential per issuer DID, signed by that issuer.
 *
 * - `GET /v1/status-list/:listId`: the signed list. `no-cache` with an ETag,
 *   so a verifier that refetches on a revocation signal is never handed a
 *   shared cache's copy from before the revocation; 503 while a self-custody
 *   issuer has not signed the current bits (fail closed).
 * - `GET /v1/status-list/:listId/unsigned`: the list as it stands, with a
 *   fresh window, for a self-custody issuer to sign.
 * - `PUT /v1/status-list/:listId`: the list its issuer signed; accepted only
 *   with the stored bits and a proof by that issuer's assertion key.
 * - `POST /v1/status-list` (admin): creates a list for a list id.
 * - `POST /v1/status-list/entries` (admin): an entry on an issuer's own list,
 *   for a credential that issuer signs itself (self-custody): the issuer
 *   puts the entry in the credential, then signs the list when it changes.
 */
const statusListRoutes: FastifyPluginAsync<StatusListRouteOptions> = async (fastify, options) => {
  const { statusLists, adminApiKey } = options;

  function requireAdmin(request: { headers: Record<string, string | string[] | undefined> }): void {
    const submitted = request.headers['x-admin-api-key'];
    const submittedKey = Array.isArray(submitted) ? submitted[0] : submitted;
    if (!adminApiKey || submittedKey !== adminApiKey) {
      throw new AdminAuthRequiredError();
    }
  }

  fastify.get('/:listId', async (request, reply) => {
    const { listId } = request.params as { listId: string };
    const list = await statusLists.getSigned(listId);
    const etag = `"${list.proof.proofValue.slice(1, 33)}"`;
    if (request.headers['if-none-match'] === etag) return reply.code(304).header('ETag', etag).send();
    return reply
      .header('Cache-Control', 'no-cache')
      .header('ETag', etag)
      .header('Content-Type', 'application/vc+json; charset=utf-8')
      .send(list);
  });

  fastify.get('/:listId/unsigned', async (request, reply) => {
    const { listId } = request.params as { listId: string };
    return reply.header('Cache-Control', 'no-store').send(await statusLists.publisher.unsignedList(listId));
  });

  fastify.put('/:listId', async (request, reply) => {
    const { listId } = request.params as { listId: string };
    return reply.code(200).send(await statusLists.publisher.submitSigned(listId, request.body));
  });

  fastify.post(
    '/entries',
    { schema: { body: { type: 'object', required: ['issuer'], properties: { issuer: { type: 'string', pattern: '^did:' } }, additionalProperties: false } } },
    async (request, reply) => {
      requireAdmin(request);
      return reply.code(201).send(await statusLists.statusEntryFor((request.body as { issuer: string }).issuer));
    },
  );

  fastify.post('', async (request, reply) => {
    requireAdmin(request);
    const body = (request.body as { listId?: string } | undefined) ?? {};
    const listId = body.listId ?? statusLists.publisher.listIdFor(statusLists.publisher.helixIssuerDid);
    await statusLists.publisher.ensureList(listId);
    return reply.code(201).send(await statusLists.getSigned(listId));
  });
};

export default statusListRoutes;
