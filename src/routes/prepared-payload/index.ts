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
//
// See docs/proposal-sdk-api-only.md. These endpoints let an SDK build a
// delegation or grant VC without reimplementing helix-core's payload
// construction locally. The private key never leaves the caller: prepare()
// returns an unsigned payload + hash to sign, finalize() attaches the
// resulting signature.

import type { FastifyPluginAsync } from 'fastify';
import { HelixError, ErrorCode } from '../../core/index.js';
import type { IPreparedPayloadService } from '../../services/prepared-payload/IPreparedPayloadService.js';
import type { IVCService } from '../../services/vc/IVCService.js';

export interface PreparedPayloadRouteOptions {
  preparedPayloadService: IPreparedPayloadService;
  vcService: IVCService;
}

interface DelegationPrepareBody {
  delegatorDid: string;
  fromVC: Record<string, unknown>;
  to: string;
  scopes: string[];
  expiresIn: number;
}

interface GrantPrepareBody {
  issuerDid: string;
  agentDid: string;
  userDid: string;
  scopes: string[];
  durability: 'standing' | 'session';
  serviceDid?: string;
  statusList: { credentialSubject: { encodedList: string } };
  statusListCredentialUrl: string;
}

interface AgentRenewalPrepareBody {
  currentVC: Record<string, unknown>;
  statusList: { credentialSubject: { encodedList: string } };
  statusListCredentialUrl: string;
  expiresIn: number;
  scopes?: string[];
}

interface FinalizeBody {
  token: string;
  verificationMethod: string;
  signatureHex: string;
  proofCreatedAt?: string;
}

function requireFields(body: Record<string, unknown>, fields: string[]): void {
  const missing = fields.filter((field) => body[field] === undefined || body[field] === null);
  if (missing.length > 0) {
    throw new HelixError(
      ErrorCode.VALIDATION_ERROR,
      `Missing required field(s): ${missing.join(', ')}`,
      400,
    );
  }
}

const preparedPayloadRoutes: FastifyPluginAsync<PreparedPayloadRouteOptions> = async (
  fastify,
  { preparedPayloadService, vcService },
) => {
  // POST /v1/vcs/delegation/prepare
  fastify.post('/delegation/prepare', async (request, reply) => {
    const body = request.body as DelegationPrepareBody;
    requireFields(body as unknown as Record<string, unknown>, [
      'delegatorDid',
      'fromVC',
      'to',
      'scopes',
      'expiresIn',
    ]);
    const result = await preparedPayloadService.prepareDelegation({
      delegatorDid: body.delegatorDid,
      fromVC: body.fromVC as never,
      to: body.to,
      scopes: body.scopes,
      expiresIn: body.expiresIn,
    });
    return reply.status(201).send(result);
  });

  // POST /v1/vcs/delegation/finalize
  fastify.post('/delegation/finalize', async (request, reply) => {
    const body = request.body as FinalizeBody;
    requireFields(body as unknown as Record<string, unknown>, [
      'token',
      'verificationMethod',
      'signatureHex',
    ]);
    const result = await preparedPayloadService.finalizeDelegation(body);
    return reply.status(200).send(result);
  });

  // POST /v1/vcs/grant/prepare
  fastify.post('/grant/prepare', async (request, reply) => {
    const body = request.body as GrantPrepareBody;
    requireFields(body as unknown as Record<string, unknown>, [
      'issuerDid',
      'agentDid',
      'userDid',
      'scopes',
      'durability',
      'statusList',
      'statusListCredentialUrl',
    ]);
    const result = await preparedPayloadService.prepareGrant(body);
    return reply.status(201).send(result);
  });

  // POST /v1/vcs/grant/finalize
  fastify.post('/grant/finalize', async (request, reply) => {
    const body = request.body as FinalizeBody;
    requireFields(body as unknown as Record<string, unknown>, [
      'token',
      'verificationMethod',
      'signatureHex',
    ]);
    const result = await preparedPayloadService.finalizeGrant(body);

    // The platform holds the consent credential. finalize() only verifies the
    // SP's signature and marks the token consumed -- it persists nothing --
    // so without this the grant would exist only in whatever the SP and the
    // agent happened to keep. That was survivable while agents had wallets;
    // with self-custody retired there is no agent-side store left to hold it.
    // Mirrors delegateAuthority()'s registerSignedVC() call for delegation VCs.
    //
    // Deliberately not best-effort: if this throws, the caller gets an error
    // rather than a grant the platform silently failed to hold. The finalize
    // token is already consumed at this point, so a retry has to start from a
    // fresh prepare -- registerExternalVC() is idempotent by vcId, so
    // re-registering the same grant is safe if the SP still has it.
    await vcService.registerExternalVC(result, request.id);

    return reply.status(200).send(result);
  });

  // POST /v1/vcs/agent-renewal/prepare
  fastify.post('/agent-renewal/prepare', async (request, reply) => {
    const body = request.body as AgentRenewalPrepareBody;
    requireFields(body as unknown as Record<string, unknown>, [
      'currentVC',
      'statusList',
      'statusListCredentialUrl',
      'expiresIn',
    ]);
    const result = await preparedPayloadService.prepareAgentRenewal({
      currentVC: body.currentVC as never,
      statusList: body.statusList,
      statusListCredentialUrl: body.statusListCredentialUrl,
      expiresIn: body.expiresIn,
      ...(body.scopes !== undefined ? { scopes: body.scopes } : {}),
    });
    return reply.status(201).send(result);
  });

  // POST /v1/vcs/agent-renewal/finalize
  fastify.post('/agent-renewal/finalize', async (request, reply) => {
    const body = request.body as FinalizeBody;
    requireFields(body as unknown as Record<string, unknown>, [
      'token',
      'verificationMethod',
      'signatureHex',
    ]);
    const result = await preparedPayloadService.finalizeAgentRenewal(body);
    return reply.status(200).send(result);
  });
};

export default preparedPayloadRoutes;
