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

/**
 * `POST /v1/revocations` (KYA-OS story L3-C point 5).
 *
 * Body, either:
 * - `{ request }`: a revocation request the revoker signed itself (compact
 *   JWS, `typ: "kya-os-revocation+jwt"`, claims `{iss, credentialId, iat,
 *   jti, aud}`). No API key: the signature is the authority, checked against
 *   the revoker's public DID document and then against the chain;
 * - `{ credentialId, revoker }` with the admin API key: a revoker whose key
 *   Helix holds (custodial); Helix signs the same request with that key,
 *   through the KeyStore, and judges it the same way.
 *
 * 200 `{ credentialId, revoker, revoked: [target, ...descendants] }`; 400
 * malformed request, 401 signature refused, 403 not an allowed revoker (the
 * subject never is), 404 no such credential, 409 already revoked.
 */

import type { FastifyPluginAsync } from 'fastify';
import { AdminAuthRequiredError, ErrorCode, HelixError, type Signer } from '../../core/index.js';
import type { RevocationService } from '../../services/revocation/revocation.service.js';

export interface RevocationRouteOptions {
  revocations: RevocationService;
  /** The Signer of a revoker DID whose key Helix holds (custodial); for the admin form. */
  signerFor?: ((did: string) => Promise<Signer>) | undefined;
  adminApiKey?: string | undefined;
}

const revocationRoutes: FastifyPluginAsync<RevocationRouteOptions> = async (fastify, options) => {
  fastify.post(
    '/',
    {
      schema: {
        body: {
          type: 'object',
          properties: {
            request: { type: 'string', minLength: 1, maxLength: 16384 },
            credentialId: { type: 'string', minLength: 1 },
            revoker: { type: 'string', pattern: '^did:' },
          },
          additionalProperties: false,
        },
      },
    },
    async (request, reply) => {
      const body = request.body as { request?: string; credentialId?: string; revoker?: string };
      if (body.request !== undefined) {
        if (body.credentialId !== undefined || body.revoker !== undefined) {
          throw new HelixError(ErrorCode.REVOCATION_REQUEST_INVALID, 'send either a signed request or credentialId and revoker, not both', 400);
        }
        return reply.code(200).send(await options.revocations.revokeSigned(body.request, request.id));
      }
      if (body.credentialId === undefined || body.revoker === undefined) {
        throw new HelixError(ErrorCode.REVOCATION_REQUEST_INVALID, 'a signed request, or credentialId and revoker, is required', 400);
      }
      const submitted = request.headers['x-admin-api-key'];
      const key = Array.isArray(submitted) ? submitted[0] : submitted;
      if (!options.adminApiKey || key !== options.adminApiKey) throw new AdminAuthRequiredError();
      if (options.signerFor === undefined) {
        throw new HelixError(ErrorCode.REVOCATION_REQUEST_INVALID, 'this server signs for no revoker; send a request the revoker signed', 400);
      }
      const signer = await options.signerFor(body.revoker);
      return reply.code(200).send(await options.revocations.revoke(body.credentialId, signer, request.id));
    },
  );
};

export default revocationRoutes;
