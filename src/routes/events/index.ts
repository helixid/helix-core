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
 * Revocation signals (KYA-OS story L3-C point 7).
 *
 * - `GET /v1/events/revocations`: Server-Sent Events. One outbound
 *   connection per middleware instance; each revocation arrives as
 *   `id: <jti>`, `event: revocation`, `data: <SET>`. `Last-Event-ID` replays
 *   what a reconnecting client missed (while this process still holds it).
 *   A comment every `heartbeatMs` keeps proxies from closing an idle stream.
 *   Public: a SET carries only a credential id, signed by the Helix issuer.
 * - `GET|POST|DELETE /v1/events/revocations/webhooks` (admin API key): the
 *   endpoints that receive every SET by push (RFC 8935), for services that
 *   prefer inbound.
 */

import type { FastifyPluginAsync } from 'fastify';
import { AdminAuthRequiredError, ErrorCode, HelixError } from '../../core/index.js';
import type { RevocationEvent, RevocationSignalPublisher } from '../../services/revocation/signal-publisher.js';

export interface EventRouteOptions {
  signals: RevocationSignalPublisher;
  adminApiKey?: string | undefined;
  /** Keep-alive comment interval, ms; default 15,000. */
  heartbeatMs?: number | undefined;
}

const sseEvent = (event: RevocationEvent): string => `id: ${event.id}\nevent: revocation\ndata: ${event.set}\n\n`;

const eventRoutes: FastifyPluginAsync<EventRouteOptions> = async (fastify, options) => {
  const { signals } = options;
  await signals.start();
  // Open streams never go idle, so the server's close would wait on them: end each one when the server closes.
  const streams = new Set<{ end(): void }>();
  fastify.addHook('preClose', async () => {
    for (const stream of streams) stream.end();
  });

  function requireAdmin(headers: Record<string, string | string[] | undefined>): void {
    const submitted = headers['x-admin-api-key'];
    const key = Array.isArray(submitted) ? submitted[0] : submitted;
    if (!options.adminApiKey || key !== options.adminApiKey) throw new AdminAuthRequiredError();
  }

  fastify.get('/revocations', async (request, reply) => {
    const lastEventId = request.headers['last-event-id'];
    reply.hijack();
    const raw = reply.raw;
    raw.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    raw.write(`: helix revocation signals, issuer ${signals.issuer}\nretry: 2000\n\n`);
    const { missed, unsubscribe } = signals.subscribe((event) => raw.write(sseEvent(event)), typeof lastEventId === 'string' ? lastEventId : undefined);
    for (const event of missed) raw.write(sseEvent(event));
    const heartbeat = setInterval(() => raw.write(': keep-alive\n\n'), options.heartbeatMs ?? 15_000);
    heartbeat.unref?.();
    streams.add(raw);
    request.raw.on('close', () => {
      clearInterval(heartbeat);
      unsubscribe();
      streams.delete(raw);
    });
  });

  fastify.get('/revocations/webhooks', async (request) => {
    requireAdmin(request.headers);
    return { webhooks: signals.webhooks };
  });

  fastify.post(
    '/revocations/webhooks',
    { schema: { body: { type: 'object', required: ['url'], properties: { url: { type: 'string', minLength: 1 } }, additionalProperties: false } } },
    async (request, reply) => {
      requireAdmin(request.headers);
      try {
        signals.addWebhook((request.body as { url: string }).url);
      } catch (error) {
        throw new HelixError(ErrorCode.VALIDATION_ERROR, (error as Error).message, 400);
      }
      return reply.code(201).send({ webhooks: signals.webhooks });
    },
  );

  fastify.delete(
    '/revocations/webhooks',
    { schema: { body: { type: 'object', required: ['url'], properties: { url: { type: 'string', minLength: 1 } }, additionalProperties: false } } },
    async (request, reply) => {
      requireAdmin(request.headers);
      if (!signals.removeWebhook((request.body as { url: string }).url)) {
        throw new HelixError(ErrorCode.VALIDATION_ERROR, 'no such webhook', 404);
      }
      return reply.code(200).send({ webhooks: signals.webhooks });
    },
  );
};

export default eventRoutes;
