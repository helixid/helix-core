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
 * The audit log API (KYA-OS A-1). Producers that do not run the API's own
 * trail (the middleware, the SDKs) post their typed events here; the store
 * records them as they are, with the producer's own source sequence and
 * predecessor digest. Every event is validated strictly: an unknown member
 * anywhere is a 400, never dropped. Evidence objects travel separately
 * from the events that reference them.
 */

import type { FastifyPluginAsync } from 'fastify';
import {
  AdminAuthRequiredError,
  AUDIT_EVENT_FAMILIES,
  AUDIT_EVENT_TYPES,
  AuditEvidenceError,
  ErrorCode,
  HelixError,
  auditEventDigest,
  canonicalize,
  evidenceRefSchema,
  parseAuditEvent,
  type AuditTrailEntry,
  type EvidenceRef,
} from '../../core/index.js';
import type { AuditEventStore } from '../../audit/store.js';

export interface AuditLogRouteOptions {
  auditStore: AuditEventStore;
  adminApiKey?: string | undefined;
}

interface ListAuditLogQuery {
  eventType?: string;
  family?: string;
  since?: string;
  correlationId?: string;
  limit?: string;
}

function requireAdmin(adminApiKey: string | undefined, request: { headers: Record<string, string | string[] | undefined> }): void {
  const submitted = request.headers['x-admin-api-key'];
  const submittedKey = Array.isArray(submitted) ? submitted[0] : submitted;
  if (!adminApiKey || submittedKey !== adminApiKey) {
    throw new AdminAuthRequiredError();
  }
}

function normalizeLimit(limit: string | undefined): number {
  if (limit === undefined) return 50;
  const parsed = Number(limit);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 500) {
    throw new HelixError(ErrorCode.VALIDATION_ERROR, 'limit must be an integer between 1 and 500', 400);
  }
  return parsed;
}

function normalizeSince(since: string | undefined): Date | undefined {
  if (!since) return undefined;
  const parsed = new Date(since);
  if (Number.isNaN(parsed.getTime())) {
    throw new HelixError(ErrorCode.VALIDATION_ERROR, 'since must be an ISO timestamp', 400);
  }
  return parsed;
}

function normalizeOneOf(name: string, value: string | undefined, allowed: readonly string[]): string | undefined {
  if (value === undefined || value === '') return undefined;
  if (!allowed.includes(value)) {
    throw new HelixError(ErrorCode.VALIDATION_ERROR, `${name} must be one of: ${allowed.join(', ')}`, 400);
  }
  return value;
}

/** A base64url ciphertext as the evidence routes carry it; refused when it is not one. */
function decodeCiphertext(value: unknown): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new AuditEvidenceError('ciphertextBase64url must be a non-empty base64url string');
  }
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

const auditLogRoutes: FastifyPluginAsync<AuditLogRouteOptions> = async (fastify, options) => {
  // A producer's typed event, recorded as presented.
  fastify.post('/events', async (request, reply) => {
    requireAdmin(options.adminApiKey, request);
    const event = parseAuditEvent(request.body);
    const entry: AuditTrailEntry = { event, canonical: canonicalize(event), eventDigest: auditEventDigest(event) };
    await options.auditStore.append(entry);
    return reply.status(201).send({ recorded: true, eventId: event.eventId, eventDigest: entry.eventDigest });
  });

  // An evidence object an event refers to; the bytes must be the ones the reference commits to.
  fastify.post('/evidence', async (request, reply) => {
    requireAdmin(options.adminApiKey, request);
    const body = (request.body ?? {}) as { ref?: unknown; ciphertextBase64url?: unknown };
    const parsedRef = evidenceRefSchema.safeParse(body.ref);
    if (!parsedRef.success) {
      throw new AuditEvidenceError('ref is not an EvidenceRef', { issues: parsedRef.error.issues.map((issue) => issue.message) });
    }
    const ref = parsedRef.data as EvidenceRef;
    const stored = await options.auditStore.putIfAbsent({ ref, ciphertext: decodeCiphertext(body.ciphertextBase64url) });
    return reply.status(201).send({ stored: true, objectId: stored.objectId, ciphertextDigest: stored.ciphertextDigest });
  });

  fastify.get<{ Params: { objectId: string } }>('/evidence/:objectId', async (request, reply) => {
    requireAdmin(options.adminApiKey, request);
    const object = await options.auditStore.get(request.params.objectId);
    if (object === null) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'No evidence object with this id', 404, { objectId: request.params.objectId });
    }
    return reply.send({ ref: object.ref, ciphertextBase64url: Buffer.from(object.ciphertext).toString('base64url') });
  });

  fastify.get('', async (request, reply) => {
    requireAdmin(options.adminApiKey, request);
    const query = request.query as ListAuditLogQuery;
    const records = await options.auditStore.list({
      eventType: normalizeOneOf('eventType', query.eventType, AUDIT_EVENT_TYPES),
      family: normalizeOneOf('family', query.family, AUDIT_EVENT_FAMILIES),
      correlationId: query.correlationId || undefined,
      since: normalizeSince(query.since),
      limit: normalizeLimit(query.limit),
    });
    return reply.send(
      records.map((record) => ({
        id: record.id,
        recordedAt: record.recordedAt.toISOString(),
        eventDigest: record.eventDigest,
        event: record.event,
      })),
    );
  });
};

export default auditLogRoutes;
