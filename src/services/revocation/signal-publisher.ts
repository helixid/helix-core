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
 * The revocation signal, emitted (KYA-OS story L3-C point 7).
 *
 * Every revocation emits one Security Event Token (RFC 8417) signed by the
 * Helix issuer, carrying only the credential id (the SET format is the SDK's
 * `kyaos.verifier.signRevocationSignal`, so emitter and receivers share one
 * definition). Delivery:
 *
 * - SSE, `GET /v1/events/revocations`: every subscriber of this process gets
 *   each SET as an event `revocation` with the SET's `jti` as its id; a
 *   reconnecting client sends `Last-Event-ID` and is replayed what it missed
 *   from a bounded buffer;
 * - webhook push (RFC 8935): each registered endpoint gets a `POST` with
 *   `Content-Type: application/secevent+jwt`; 202 is delivery, anything else
 *   is retried with backoff, and a delivery that never succeeds is audited.
 *
 * With several API instances, a `SignalBus` (Redis pub/sub) carries each SET
 * to every instance, so an SSE client connected to any instance receives it.
 * No polling anywhere. The signal is a cache hint: it never revokes anything.
 */

import { kyaos } from '@helixid/sdk-js';
import { AuditEvents } from '../../core/audit/events.js';
import type { IAuditLogger, Signer } from '../../core/index.js';

export interface RevocationEvent {
  /** The SET's `jti`: the SSE event id. */
  id: string;
  credentialId: string;
  set: string;
}

/** Carries each SET to every API instance; the default delivers in this process only. */
export interface SignalBus {
  publish(event: RevocationEvent): Promise<void>;
  subscribe(handler: (event: RevocationEvent) => void): Promise<void> | void;
  close?(): Promise<void> | void;
}

export class InProcessSignalBus implements SignalBus {
  readonly #handlers = new Set<(event: RevocationEvent) => void>();

  async publish(event: RevocationEvent): Promise<void> {
    for (const handler of this.#handlers) handler(event);
  }

  subscribe(handler: (event: RevocationEvent) => void): void {
    this.#handlers.add(handler);
  }
}

/** The ioredis commands the Redis bus needs: one connection publishes, a second one subscribes. */
export interface RedisPubSubLike {
  publish(channel: string, message: string): Promise<unknown>;
  subscribe(channel: string): Promise<unknown>;
  on(event: 'message', listener: (channel: string, message: string) => void): unknown;
  quit?(): Promise<unknown>;
}

/** Every instance publishes to and listens on one Redis channel. */
export class RedisSignalBus implements SignalBus {
  readonly #publisher: RedisPubSubLike;
  readonly #subscriber: RedisPubSubLike;
  readonly #channel: string;

  constructor(options: { publisher: RedisPubSubLike; subscriber: RedisPubSubLike; channel?: string }) {
    this.#publisher = options.publisher;
    this.#subscriber = options.subscriber;
    this.#channel = options.channel ?? 'helix:revocation-signals';
  }

  async publish(event: RevocationEvent): Promise<void> {
    await this.#publisher.publish(this.#channel, JSON.stringify(event));
  }

  async subscribe(handler: (event: RevocationEvent) => void): Promise<void> {
    this.#subscriber.on('message', (channel, message) => {
      if (channel !== this.#channel) return;
      try {
        const event = JSON.parse(message) as RevocationEvent;
        if (typeof event?.id === 'string' && typeof event.set === 'string' && typeof event.credentialId === 'string') handler(event);
      } catch {
        // A message that is not an event is not one of ours.
      }
    });
    await this.#subscriber.subscribe(this.#channel);
  }

  async close(): Promise<void> {
    await this.#subscriber.quit?.();
    await this.#publisher.quit?.();
  }
}

export interface WebhookTarget {
  url: string;
}

export interface RevocationSignalPublisherOptions {
  /** The Helix issuer's Signer: every SET is signed by it. */
  signer: Signer;
  bus?: SignalBus | undefined;
  /** Endpoints that receive every SET by push (RFC 8935). */
  webhooks?: readonly string[] | undefined;
  /** Push transport; default the global `fetch`. */
  fetch?: typeof fetch | undefined;
  /** Delivery attempts per endpoint and SET (default 3), the first retry after `retryDelayMs` (default 500), doubling. */
  maxAttempts?: number | undefined;
  retryDelayMs?: number | undefined;
  /** How many recent events a reconnecting SSE client can be replayed; default 1000. */
  bufferSize?: number | undefined;
  audit?: IAuditLogger | undefined;
  clock?: (() => number) | undefined;
}

export class RevocationSignalPublisher {
  readonly #options: RevocationSignalPublisherOptions;
  readonly #bus: SignalBus;
  readonly #subscribers = new Set<(event: RevocationEvent) => void>();
  readonly #buffer: RevocationEvent[] = [];
  readonly #webhooks = new Set<string>();
  readonly #pending = new Set<Promise<void>>();
  #started: Promise<void> | undefined;

  constructor(options: RevocationSignalPublisherOptions) {
    this.#options = options;
    this.#bus = options.bus ?? new InProcessSignalBus();
    for (const url of options.webhooks ?? []) this.addWebhook(url);
  }

  /** Subscribes to the bus once; every event it carries is buffered and handed to this process's SSE clients. */
  start(): Promise<void> {
    this.#started ??= Promise.resolve(
      this.#bus.subscribe((event) => {
        this.#buffer.push(event);
        if (this.#buffer.length > (this.#options.bufferSize ?? 1000)) this.#buffer.shift();
        for (const subscriber of this.#subscribers) subscriber(event);
      }),
    );
    return this.#started;
  }

  get issuer(): string {
    return this.#options.signer.did;
  }

  /** Signs one SET for `credentialId`, carries it to every instance's SSE clients, and pushes it to every webhook. */
  async publish(credentialId: string): Promise<RevocationEvent> {
    await this.start();
    const iat = Math.floor((this.#options.clock ?? Date.now)() / 1000);
    const set = await kyaos.verifier.signRevocationSignal({ credentialId, iat }, this.#options.signer);
    const claims = JSON.parse(Buffer.from(set.split('.')[1]!, 'base64url').toString('utf8')) as { jti: string };
    const event: RevocationEvent = { id: claims.jti, credentialId, set };
    await this.#bus.publish(event);
    for (const url of this.#webhooks) {
      const delivery = this.#push(url, event).finally(() => this.#pending.delete(delivery));
      this.#pending.add(delivery);
    }
    return event;
  }

  /** Every push still in flight (for tests and graceful shutdown). */
  async drain(): Promise<void> {
    await Promise.all([...this.#pending]);
  }

  async #push(url: string, event: RevocationEvent): Promise<void> {
    const doFetch = this.#options.fetch ?? fetch;
    const attempts = this.#options.maxAttempts ?? 3;
    let delay = this.#options.retryDelayMs ?? 500;
    let last = '';
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        const response = await doFetch(url, {
          method: 'POST',
          headers: { 'content-type': kyaos.verifier.SECEVENT_JWT_MEDIA_TYPE, accept: 'application/json' },
          body: event.set,
          redirect: 'error',
          signal: AbortSignal.timeout(5_000),
        });
        if (response.status === 202) return;
        last = `answered ${response.status}`;
        // RFC 8935 §2.3: a 400 names what was wrong with the SET; sending it again changes nothing.
        if (response.status === 400) break;
      } catch (error) {
        last = (error as Error).message;
      }
      if (attempt < attempts) {
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= 2;
      }
    }
    await this.#options.audit?.log(AuditEvents.VC_REVOCATION_FAILED, {
      requestId: 'revocation-signal',
      vcId: event.credentialId,
      stage: 'webhook_push',
      endpoint: url,
      jti: event.id,
      message: last,
    });
  }

  addWebhook(url: string): void {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(`webhook ${url} is not a URL`);
    }
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname))) {
      throw new Error(`webhook ${url} must be https (http only on loopback, for development)`);
    }
    this.#webhooks.add(parsed.toString());
  }

  removeWebhook(url: string): boolean {
    try {
      return this.#webhooks.delete(new URL(url).toString());
    } catch {
      return false;
    }
  }

  get webhooks(): string[] {
    return [...this.#webhooks];
  }

  /**
   * Adds an SSE subscriber; returns the events after `lastEventId` it
   * missed (all buffered ones are newer when the id is unknown to this
   * process: none are replayed, since they cannot be placed) and an
   * unsubscribe function.
   */
  subscribe(handler: (event: RevocationEvent) => void, lastEventId?: string): { missed: RevocationEvent[]; unsubscribe: () => void } {
    this.#subscribers.add(handler);
    let missed: RevocationEvent[] = [];
    if (lastEventId !== undefined) {
      const at = this.#buffer.findIndex((event) => event.id === lastEventId);
      if (at !== -1) missed = this.#buffer.slice(at + 1);
    }
    return { missed, unsubscribe: () => this.#subscribers.delete(handler) };
  }

  get subscriberCount(): number {
    return this.#subscribers.size;
  }

  async close(): Promise<void> {
    await this.drain();
    await this.#bus.close?.();
  }
}
