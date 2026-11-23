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
 * Custody preference at onboarding (KYA-OS story F-3), under `/v1`:
 *
 *   POST /agents                         create an agent with its custody choice
 *                                        (custodial: one call; self-custody:
 *                                        returns the enrollment token)
 *   POST /agents/enroll/challenge        `helix init` step 1 (enrollment token)
 *   POST /agents/enroll                  `helix init` step 2: public JWK + proof
 *   POST /owners                         an owner key for attestations (point 7)
 *   POST /{agents|services|owners}/:did/activate        own hosting: check the
 *                                        documents resolve, then activate
 *   POST /{agents|services|owners}/:did/sign            custodial signing
 *   GET  /{agents|services|owners}/:did/custody         the custody record
 *   POST /{agents|services|owners}/:did/custody         change custody (rotation)
 *   POST /{agents|services|owners}/:did/custody/finalize  end a rotation overlap
 *   GET  /custody/defaults               the caller's resolved default choice
 *   GET  /conformance/report             claim set and `custody: helix` exclusions
 *
 * `POST /services` takes the same choice in the service-provider routes.
 *
 * Who may call is injected, as for the service-provider routes: the
 * self-hosted default is the admin key; the hosted build checks the account
 * owns the subject (`authorize`), supplies the account preference
 * (`defaultsOf`), the actor (`actorOf`) and the did:web org segment
 * (`orgOf`), and links new subjects to the account (`onCreated`). The two
 * enrollment calls are authorised by the enrollment token itself, and
 * `activate` also accepts it, so `helix init` needs no admin key.
 *
 * Self-custody invariant: a body carrying private key material anywhere is
 * refused with 400 before it is read.
 */

import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import {
  AdminAuthRequiredError,
  BUILT_IN_CUSTODY_DEFAULTS,
  HelixError,
  ValidationError,
  buildConformanceReport,
  findPrivateKeyMaterial,
  type ConformanceImplementation,
  type ConformanceSubject,
  type CustodyDefaults,
  type CustodySubjectType,
} from '../../core/index.js';
import type { CustodyContext, CustodyService, OnboardingResult } from '../../services/custody/custody.service.js';

export type CustodyAction =
  | { action: 'createAgent' }
  | { action: 'createOwner' }
  | { action: 'read' | 'sign' | 'changeCustody' | 'activate' | 'finalize'; subjectType: CustodySubjectType; did: string }
  | { action: 'defaults' }
  | { action: 'report' };

export interface CustodyRouteOptions {
  custodyService: CustodyService;
  adminApiKey?: string | undefined;
  /** Throws when the caller may not perform `action`. Default: `x-admin-api-key` must equal `adminApiKey`. */
  authorize?: ((request: FastifyRequest, action: CustodyAction) => Promise<void> | void) | undefined;
  /** The account preference of the caller; none in a build without accounts. */
  defaultsOf?: ((request: FastifyRequest) => Promise<CustodyDefaults | undefined> | CustodyDefaults | undefined) | undefined;
  /** Who the audit events name. Default `admin`. */
  actorOf?: ((request: FastifyRequest) => string) | undefined;
  /** The org segment of a Helix-hosted did:web. */
  orgOf?: ((request: FastifyRequest) => Promise<string | undefined> | string | undefined) | undefined;
  /**
   * The DID of the account the caller acts for. An agent it creates names it
   * as owner (its identity credential's and card's `responsibleParty`), and a
   * different `ownerDid` in the body is refused. None in a build without
   * accounts: the body's `ownerDid`, else the Helix issuer.
   */
  ownerDidOf?: ((request: FastifyRequest) => Promise<string | undefined> | string | undefined) | undefined;
  /** Called after a subject is created, e.g. to link it to the caller's account. */
  onCreated?: ((request: FastifyRequest, result: OnboardingResult) => Promise<void> | void) | undefined;
  /**
   * Called when a subject becomes active after creation: a self-custody agent
   * enrolled by `helix init` (Helix hosting) or any own-hosted subject whose
   * documents resolved. These calls carry the enrollment token, not the
   * account, so the hosted build finds the account from its own link.
   */
  onActivated?: ((request: FastifyRequest, result: OnboardingResult) => Promise<void> | void) | undefined;
  /** The subjects the caller's conformance report covers; the hosted build keeps it to the account's own. Default: all. */
  reportSubjects?: ((request: FastifyRequest, subjects: ConformanceSubject[]) => Promise<ConformanceSubject[]> | ConformanceSubject[]) | undefined;
  /** What the conformance report says the implementation claims. Default: no claims. */
  implementation?: ConformanceImplementation | undefined;
  /**
   * POST /agents with an `enrollmentToken` in the body is story F-1's token
   * onboarding (identity credential and attestations): handed to this handler
   * unchanged, without the custody authorization. Without it, such a body is
   * a custody create like any other.
   */
  enrollmentOnboarding?: ((request: FastifyRequest, reply: FastifyReply) => Promise<FastifyReply>) | undefined;
}

const SUBJECT_PATHS: { path: string; subjectType: CustodySubjectType }[] = [
  { path: 'agents', subjectType: 'agent' },
  { path: 'services', subjectType: 'service' },
  { path: 'owners', subjectType: 'owner' },
];

const DEFAULT_IMPLEMENTATION: ConformanceImplementation = { name: 'Helix ID', version: '3.0.0', claims: [] };

function body(request: FastifyRequest): Record<string, unknown> {
  const value = request.body ?? {};
  if (typeof value !== 'object' || Array.isArray(value)) throw new ValidationError('Request body must be a JSON object');
  return value as Record<string, unknown>;
}

/** The self-custody invariant at the door: no private key material anywhere in the body. */
function refusePrivateMaterial(value: unknown): void {
  const found = findPrivateKeyMaterial(value);
  if (found !== undefined) {
    throw new ValidationError(`Request carries private key material (${found}); only the public JWK is accepted`);
  }
}

const custodyRoutes: FastifyPluginAsync<CustodyRouteOptions> = async (fastify, options) => {
  const service = options.custodyService;
  const authorize =
    options.authorize ??
    ((request: FastifyRequest): void => {
      const submitted = request.headers['x-admin-api-key'];
      const submittedKey = Array.isArray(submitted) ? submitted[0] : submitted;
      if (!options.adminApiKey || submittedKey !== options.adminApiKey) throw new AdminAuthRequiredError();
    });
  const actorOf = options.actorOf ?? ((): string => 'admin');

  async function context(request: FastifyRequest, actor?: string): Promise<CustodyContext> {
    return {
      requestId: request.id,
      actor: actor ?? actorOf(request),
      defaults: await options.defaultsOf?.(request),
      org: await options.orgOf?.(request),
      owner: await options.ownerDidOf?.(request),
    };
  }

  function send(reply: FastifyReply, request: FastifyRequest, error: unknown): FastifyReply {
    // A HelixError, or anything shaped like one (the hosted build's guards throw typed errors of their own).
    if (error instanceof HelixError || (error instanceof Error && 'code' in error && 'httpStatus' in error)) {
      const typed = error as HelixError;
      return reply.code(typed.httpStatus).send({ error: { code: typed.code, message: typed.message, requestId: request.id, ...(typed.details ? { details: typed.details } : {}) } });
    }
    throw error;
  }

  fastify.post('/agents', async (request, reply) => {
    const raw = request.body as { enrollmentToken?: unknown } | null | undefined;
    if (options.enrollmentOnboarding && raw && typeof raw === 'object' && 'enrollmentToken' in raw) {
      return options.enrollmentOnboarding(request, reply);
    }
    try {
      await authorize(request, { action: 'createAgent' });
      const input = body(request);
      refusePrivateMaterial(input);
      const result = await service.createAgent(input as never, await context(request));
      await options.onCreated?.(request, result);
      return reply.code(201).send(result);
    } catch (error) {
      return send(reply, request, error);
    }
  });

  fastify.post('/agents/enroll/challenge', async (request, reply) => {
    try {
      const input = body(request);
      refusePrivateMaterial(input);
      return reply.code(200).send(await service.enrollmentChallenge(input['enrollmentToken']));
    } catch (error) {
      return send(reply, request, error);
    }
  });

  fastify.post('/agents/enroll', async (request, reply) => {
    try {
      const input = body(request);
      refusePrivateMaterial(input);
      const foreign = Object.keys(input).filter((name) => !['enrollmentToken', 'publicKeyJwk', 'kid', 'signature'].includes(name));
      if (foreign.length > 0) throw new ValidationError(`Request carries unexpected members (${foreign.join(', ')})`);
      const result = await service.enroll(
        { enrollmentToken: input['enrollmentToken'], publicKeyJwk: input['publicKeyJwk'], kid: input['kid'], signature: input['signature'] },
        await context(request, 'enrollment-token'),
      );
      if (result.status === 'active') await options.onActivated?.(request, result);
      return reply.code(201).send(result);
    } catch (error) {
      return send(reply, request, error);
    }
  });

  fastify.post('/owners', async (request, reply) => {
    try {
      await authorize(request, { action: 'createOwner' });
      const input = body(request);
      refusePrivateMaterial(input);
      const result = await service.createOwner(input as never, await context(request));
      await options.onCreated?.(request, result);
      return reply.code(201).send(result);
    } catch (error) {
      return send(reply, request, error);
    }
  });

  for (const { path, subjectType } of SUBJECT_PATHS) {
    fastify.post<{ Params: { did: string } }>(`/${path}/:did/activate`, async (request, reply) => {
      try {
        const input = body(request);
        refusePrivateMaterial(input);
        const did = request.params.did;
        const byToken = await service.enrollmentTokenMatches(did, input['enrollmentToken']);
        if (!byToken) await authorize(request, { action: 'activate', subjectType, did });
        const result = await service.activate(did, await context(request, byToken ? 'enrollment-token' : undefined), subjectType);
        await options.onActivated?.(request, result);
        return reply.code(200).send(result);
      } catch (error) {
        return send(reply, request, error);
      }
    });

    fastify.post<{ Params: { did: string } }>(`/${path}/:did/sign`, async (request, reply) => {
      try {
        const did = request.params.did;
        await authorize(request, { action: 'sign', subjectType, did });
        const input = body(request);
        return reply.code(200).send(await service.sign(did, { payload: input['payload'], kid: input['kid'] }, await context(request), subjectType));
      } catch (error) {
        return send(reply, request, error);
      }
    });

    fastify.get<{ Params: { did: string } }>(`/${path}/:did/custody`, async (request, reply) => {
      try {
        const did = request.params.did;
        await authorize(request, { action: 'read', subjectType, did });
        return reply.code(200).send(await service.getCustody(did, subjectType));
      } catch (error) {
        return send(reply, request, error);
      }
    });

    fastify.post<{ Params: { did: string } }>(`/${path}/:did/custody`, async (request, reply) => {
      try {
        const did = request.params.did;
        const input = body(request);
        refusePrivateMaterial(input);
        await authorize(request, { action: 'changeCustody', subjectType, did });
        return reply.code(200).send(await service.changeCustody(did, input as never, await context(request), subjectType));
      } catch (error) {
        return send(reply, request, error);
      }
    });

    fastify.post<{ Params: { did: string } }>(`/${path}/:did/custody/finalize`, async (request, reply) => {
      try {
        const did = request.params.did;
        await authorize(request, { action: 'finalize', subjectType, did });
        const input = body(request);
        return reply.code(200).send(await service.finalizeRotation(did, await context(request), { force: input['force'] === true }, subjectType));
      } catch (error) {
        return send(reply, request, error);
      }
    });
  }

  fastify.get('/custody/defaults', async (request, reply) => {
    try {
      await authorize(request, { action: 'defaults' });
      const account = await options.defaultsOf?.(request);
      return reply.code(200).send({ custody: account ?? { ...BUILT_IN_CUSTODY_DEFAULTS }, source: account ? 'account' : 'built-in' });
    } catch (error) {
      return send(reply, request, error);
    }
  });

  fastify.get('/conformance/report', async (request, reply) => {
    try {
      await authorize(request, { action: 'report' });
      const subjects = await service.conformanceSubjects();
      const report = buildConformanceReport({
        implementation: options.implementation ?? DEFAULT_IMPLEMENTATION,
        subjects: options.reportSubjects ? await options.reportSubjects(request, subjects) : subjects,
      });
      return reply.code(200).send(report);
    } catch (error) {
      return send(reply, request, error);
    }
  });
};

export default custodyRoutes;
