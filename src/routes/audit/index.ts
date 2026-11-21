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
 * The recorder API (story A-2), under `/v1/audit`, operator-authenticated
 * (`x-admin-api-key`, or the same key as a bearer token):
 *
 * - `POST /submissions`: one producer submission (`submission.ts`), answered
 *   with the signed entry; a redelivery gets the original entry back.
 * - `GET /ledgers`, `GET /ledgers/:ledgerId/epochs`: ledgers and their epochs.
 * - `GET /ledgers/:ledgerId/epochs/:epochId/entries`: the stored entries of
 *   one epoch, exactly as stored (an export for offline verification).
 * - `GET /ledgers/:ledgerId/verify`: the verify walk, run here.
 * - `POST /ledgers/:ledgerId/epochs`: an epoch transition (`reason`).
 * - `POST /ledgers/:ledgerId/legal-holds`, `POST /legal-holds/:holdId/release`,
 *   `POST /ledgers/:ledgerId/disposals`: retention administration, each recorded.
 *
 * None of this is a verify path of the cross-border rule: the recorder is
 * the ledger's writer, and its verify walk reads the ledger it keeps.
 */

import type { FastifyPluginAsync, FastifyRequest } from 'fastify';
import { z } from 'zod';
import {
  AdminAuthRequiredError,
  AUDIT_EPOCH_TRANSITION_REASONS,
  HelixError,
  verifyAuditLedger,
  type AuditEpochTransitionReason,
  type StoredAuditEntry,
} from '../../core/index.js';
import type { ApiAudit } from '../../audit/api-audit.js';
import { handleAuditSubmission } from '../../audit/submission.js';

export interface AuditRouteOptions {
  audit: ApiAudit;
  adminApiKey?: string | undefined;
}

const OPERATOR = 'admin-api-key';

/** The admin key, as `x-admin-api-key` or as a bearer token. */
export function requireAuditOperator(adminApiKey: string | undefined, request: Pick<FastifyRequest, 'headers'>): void {
  const header = request.headers['x-admin-api-key'];
  const submitted = Array.isArray(header) ? header[0] : header;
  const bearer = /^Bearer\s+(\S+)$/i.exec(request.headers.authorization ?? '')?.[1];
  if (!adminApiKey || (submitted !== adminApiKey && bearer !== adminApiKey)) throw new AdminAuthRequiredError();
}

function body<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value ?? {});
  if (!parsed.success) {
    const issue = parsed.error.issues[0]!;
    throw new HelixError('VALIDATION_ERROR', `${issue.path.join('.') || 'body'}: ${issue.message}`, 400);
  }
  return parsed.data;
}

const sequence = z.string().regex(/^(0|[1-9][0-9]*)$/);
const transitionBody = z.object({ reason: z.enum(AUDIT_EPOCH_TRANSITION_REASONS) }).strict();
const holdTarget = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('ledger') }).strict(),
  z.object({ kind: z.literal('entry'), ledgerEpochId: z.string().min(1).max(256), sequence }).strict(),
  z.object({ kind: z.literal('evidence'), objectId: z.string().min(1).max(256) }).strict(),
]);
const holdBody = z.object({ holdId: z.string().min(1).max(256), target: holdTarget }).strict();
const disposalBody = z
  .object({
    target: z.discriminatedUnion('kind', [
      z.object({ kind: z.literal('entry'), ledgerEpochId: z.string().min(1).max(256), sequence }).strict(),
      z.object({ kind: z.literal('evidence'), objectId: z.string().min(1).max(256) }).strict(),
    ]),
  })
  .strict();

const auditRoutes: FastifyPluginAsync<AuditRouteOptions> = async (fastify, options) => {
  const { recorder, retention, storage } = options.audit;
  fastify.addHook('preHandler', async (request) => requireAuditOperator(options.adminApiKey, request));

  fastify.post('/submissions', async (request, reply) => {
    const result = await handleAuditSubmission(recorder, request.body);
    return reply.status(201).send(result);
  });

  fastify.get('/ledgers', async () => {
    const ledgers = await storage.journal.listLedgers();
    return Promise.all(ledgers.map(async (ledger) => ({ ...ledger, epochs: await storage.journal.listEpochs(ledger.ledgerId) })));
  });

  fastify.get<{ Params: { ledgerId: string } }>('/ledgers/:ledgerId/epochs', async (request) => {
    const ledger = await storage.journal.getLedger(request.params.ledgerId);
    if (ledger === null) throw new HelixError('VALIDATION_ERROR', 'No such audit ledger', 404, { ledgerId: request.params.ledgerId });
    return { ...ledger, epochs: await storage.journal.listEpochs(ledger.ledgerId) };
  });

  fastify.get<{ Params: { ledgerId: string; epochId: string } }>('/ledgers/:ledgerId/epochs/:epochId/entries', async (request, reply) => {
    const ledger = { ledgerId: request.params.ledgerId, ledgerEpochId: request.params.epochId };
    const lines: string[] = [];
    for await (const stored of storage.journal.readStoredRange(ledger)) lines.push(JSON.stringify(stored));
    // One stored row per element, the entry text untouched, so an offline verifier sees exactly what is stored.
    return reply.type('application/json').send(`[${lines.join(',')}]`);
  });

  fastify.get<{ Params: { ledgerId: string }; Querystring: { trustedRecorder?: string | string[] } }>('/ledgers/:ledgerId/verify', async (request) => {
    const { ledgerId } = request.params;
    const epochs = await storage.journal.listEpochs(ledgerId);
    if (epochs.length === 0) throw new HelixError('VALIDATION_ERROR', 'No such audit ledger', 404, { ledgerId });
    const pins = request.query.trustedRecorder;
    return verifyAuditLedger({
      ledgerId,
      epochs: epochs.map((epoch) => ({
        ledgerEpochId: epoch.ledgerEpochId,
        read: (): AsyncIterable<StoredAuditEntry> => storage.journal.readStoredRange(epoch),
        storedHead: { sequence: epoch.head.sequence, entryDigest: epoch.head.entryDigest },
      })),
      ...(pins !== undefined ? { trustedRecorders: Array.isArray(pins) ? pins : [pins] } : {}),
    });
  });

  fastify.post<{ Params: { ledgerId: string } }>('/ledgers/:ledgerId/epochs', async (request, reply) => {
    const { reason } = body(transitionBody, request.body);
    const transition = await recorder.transition(request.params.ledgerId, reason as AuditEpochTransitionReason);
    return reply.status(201).send(transition);
  });

  fastify.post<{ Params: { ledgerId: string } }>('/ledgers/:ledgerId/legal-holds', async (request, reply) => {
    const { holdId, target } = body(holdBody, request.body);
    const entry = await retention.applyLegalHold({ holdId, target: { ...target, ledgerId: request.params.ledgerId }, authorizedBy: OPERATOR });
    return reply.status(201).send({ holdId, entry });
  });

  fastify.post<{ Params: { holdId: string } }>('/legal-holds/:holdId/release', async (request) => {
    const entry = await retention.releaseLegalHold({ holdId: request.params.holdId, authorizedBy: OPERATOR });
    return { holdId: request.params.holdId, released: true, entry };
  });

  fastify.post<{ Params: { ledgerId: string } }>('/ledgers/:ledgerId/disposals', async (request, reply) => {
    const { target } = body(disposalBody, request.body);
    const result = await retention.dispose({ target: { ...target, ledgerId: request.params.ledgerId }, authorizedBy: OPERATOR });
    return reply.status(201).send(result);
  });
};

export default auditRoutes;
