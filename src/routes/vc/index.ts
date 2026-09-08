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
import { AdminAuthRequiredError, ErrorCode, HelixError } from '../../core/index.js';
import type { SignedVC } from '../../core/index.js';
import type { IVCService, IssueVCParams, RenewVCOptions } from '../../services/vc/vc.service.js';

const VC_STATUSES = ['active', 'revoked', 'expired'] as const;
type VCStatus = (typeof VC_STATUSES)[number];

export interface VcRouteOptions {
  vcService: IVCService;
  adminApiKey?: string | undefined;
}

interface VCParams {
  vcId: string;
}

interface ListVCQuery {
  subjectDid?: string;
  status?: string;
  limit?: string;
}

/**
 * VC API Route Definitions (Boundary 2).
 */
const vcRoutes: FastifyPluginAsync<VcRouteOptions> = async (fastify, options) => {
  const { vcService, adminApiKey } = options;

  function requireAdmin(request: { headers: Record<string, string | string[] | undefined> }): void {
    const submitted = request.headers['x-admin-api-key'];
    const submittedKey = Array.isArray(submitted) ? submitted[0] : submitted;
    if (!adminApiKey || submittedKey !== adminApiKey) {
      throw new AdminAuthRequiredError();
    }
  }

  // GET /v1/vcs - List VC summaries
  fastify.get('', async (request, reply) => {
    requireAdmin(request);

    const query = request.query as { subjectDid?: string; status?: string; limit?: string };
    if (query.status && !(VC_STATUSES as readonly string[]).includes(query.status)) {
      throw new HelixError(
        ErrorCode.VALIDATION_ERROR,
        `Invalid status filter: ${query.status}`,
        400,
      );
    }
    const limit = query.limit === undefined ? undefined : Number.parseInt(query.limit, 10);
    if (limit !== undefined && (Number.isNaN(limit) || limit < 1)) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, `Invalid limit: ${query.limit}`, 400);
    }
    const result = await vcService.listVCs({
      subjectDid: query.subjectDid,
      status: query.status as VCStatus | undefined,
      limit,
    });
    return reply.send(result);
  });

  // POST /v1/vcs - Issue a VC
  fastify.post('', async (request, reply) => {
    requireAdmin(request);
    const params = request.body as IssueVCParams;
    const result = await vcService.issueVC(params, request.id);
    return reply.status(201).send(result);
  });

  // POST /v1/vcs/register - Register a VC signed outside this platform, so
  // the platform holds it rather than the agent carrying it. The consent
  // path: a Service Provider issues a DelegationGrantCredential with its own
  // key, then registers it here. Distinct from POST /v1/vcs, which *issues* a
  // VC signed by the platform issuer -- the wrong signature for a grant,
  // whose whole point is that the SP attested to it.
  //
  // Admin-gated like every other write here. OSS has no per-tenant credential
  // narrower than the admin key, so an SP registering a grant presents the
  // same key an agent presents to sign a VP. The submitted proof is verified
  // regardless, so the key gates who may write, not what may be claimed.
  fastify.post('/register', async (request, reply) => {
    requireAdmin(request);
    const body = request.body as { vc?: SignedVC } | undefined;
    if (!body?.vc) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'Body must include a `vc`', 400);
    }
    const result = await vcService.registerExternalVC(body.vc, request.id);
    return reply.status(result.alreadyRegistered ? 200 : 201).send(result);
  });

  // GET /v1/vcs/:vcId - Get VC details
  fastify.get('/:vcId', async (request, reply) => {
    const { vcId } = request.params as VCParams;
    const result = await vcService.getVC(vcId, request.id);
    return reply.send(result);
  });

  // GET /v1/vcs/:vcId/status - Get VC status only (active/revoked/expired)
  fastify.get('/:vcId/status', async (request, reply) => {
    const { vcId } = request.params as VCParams;
    const status = await vcService.getVCStatus(vcId);
    return reply.send({ vcId, status });
  });

  // POST /v1/vcs/:vcId/revoke - Revoke a VC
  fastify.post('/:vcId/revoke', async (request, reply) => {
    requireAdmin(request);
    const { vcId } = request.params as VCParams;
    const result = await vcService.revokeVC(vcId, request.id);
    return reply.send(result);
  });

  // POST /v1/vcs/:vcId/renew - Renew a VC
  fastify.post('/:vcId/renew', async (request, reply) => {
    requireAdmin(request);
    const { vcId } = request.params as VCParams;
    const overrides = request.body as RenewVCOptions;
    const result = await vcService.renewVC(vcId, overrides, request.id);
    return reply.status(201).send(result);
  });
};

export default vcRoutes;
