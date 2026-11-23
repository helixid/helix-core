// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * `POST /v1/verify` (KYA-OS story F-2): the local verifier of
 * `@helixid/sdk-js` (`kyaos.verifier.verify`) behind an HTTP call, for
 * callers that do not run the SDK. It verifies one shape: a KYA-OS request
 * proof (`org.kya-os/proof.v1`) plus the delegation chain the request
 * carried, and the agent's Entity Card when given. It replaces
 * `/v1/vp/verify`, which is retired with no backward compatibility.
 *
 * Cross-border rule (stories rule 4): this route reads the presented
 * artifacts, public DID documents, status lists and cards over HTTPS, its own
 * in-process nonce store and its configuration. It never asks a Helix
 * database whether it has seen a credential, so a credential issued by any
 * Helix deployment verifies here exactly as it would at a service running the
 * middleware.
 *
 * Body: `{ proof, chain?, request, card?, expectedAudience, resource?,
 * resourceOwner?, trustedRootIssuers?, catalog?, action?, tokenCnfJkt? }`.
 * `expectedAudience` is the caller's own DID: the service the proof was
 * minted for. Answer: 200 with the verifier's result (`ok`, `level`,
 * `effectiveScopes`, `reasons`, `chainSummary`, ...) whether or not the proof
 * verified; 400 for a body that is not one.
 */

import type { FastifyPluginAsync } from 'fastify';
import { kyaos } from '@helixid/sdk-js';

const { verifier } = kyaos;

/** What the replay store needs: the middleware's `NonceStore` shape. */
export interface VerifyNonceStore {
  insert(nonce: string, agentDid: string | undefined, expiresAt: number): Promise<boolean>;
}

export interface VerifyRouteOptions {
  /** `'*'` (default) trusts every attestation issuer; a list trusts those DIDs only (stories rule 9). */
  trustedIssuers?: '*' | readonly string[] | undefined;
  /** The longest carried chain read; default 10, and a request may lower it, never raise it. */
  maxChainLength?: number | undefined;
  /** The replay store; default one in memory for this process. Share a Redis store across API instances. */
  nonceStore?: VerifyNonceStore | undefined;
  /** How DID documents, status lists and cards are fetched; default the global `fetch`, `https:` only. */
  fetch?: ((url: string) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>) | undefined;
  /** Development only: read `http:` on loopback hosts. */
  allowLoopbackHttp?: boolean | undefined;
  /** Seams a deployment or a test supplies in place of the defaults. */
  resolveDid?: kyaos.verifier.DidResolver | undefined;
  resolveDidKeys?: kyaos.verifier.VerifierSeams['resolveDidKeys'];
  fetchStatusList?: kyaos.verifier.FetchStatusList | undefined;
  resolveCard?: ((did: string) => Promise<unknown>) | undefined;
  /**
   * The status cache (story L3-C): lists and verdicts, `statusCacheTtl`,
   * high-privilege scopes at ≤ 60 s; a cached read is `fresh: false`.
   * Default one in memory for this process.
   */
  statusCache?: kyaos.verifier.StatusCache | undefined;
  /** Issuer DID to the status-list URLs or `https:` origins bound to it (SPEC.md §6.6 keeper rules 1 and 2). */
  statusListIssuers?: Record<string, string[]> | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: (() => number) | undefined;
}

interface VerifyBody {
  proof: unknown;
  chain?: unknown;
  request: kyaos.verifier.ProofRequest;
  card?: unknown;
  expectedAudience: string;
  resource?: string;
  resourceOwner?: string;
  trustedRootIssuers?: string[];
  catalog?: string[];
  action?: string;
  tokenCnfJkt?: string;
  maxChainLength?: number;
}

/** A replay store in memory: one key per `(agent, nonce)`, swept of expired entries on each insert. */
export function memoryNonceStore(clock: () => number): VerifyNonceStore {
  const entries = new Map<string, number>();
  return {
    insert: async (nonce, agentDid, expiresAt): Promise<boolean> => {
      const now = clock();
      for (const [key, expiry] of entries) if (expiry <= now) entries.delete(key);
      const key = `${agentDid ?? ''}|${nonce}`;
      if (entries.has(key)) return false;
      entries.set(key, expiresAt);
      return true;
    },
  };
}

/** `https:` URLs as given; `http:` on loopback only when `allowLoopbackHttp` (an `https:` loopback URL is then read over `http:`). */
export function readableUrl(url: string, allowLoopbackHttp: boolean): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
  if (parsed.protocol === 'https:') {
    if (loopback && allowLoopbackHttp) parsed.protocol = 'http:';
    return parsed.toString();
  }
  return parsed.protocol === 'http:' && loopback && allowLoopbackHttp ? parsed.toString() : undefined;
}

const DID_ARRAY = { type: 'array', items: { type: 'string', pattern: '^did:' } } as const;

const verifyRoutes: FastifyPluginAsync<VerifyRouteOptions> = async (fastify, options) => {
  const clock = options.clock ?? Date.now;
  const nonceStore = options.nonceStore ?? memoryNonceStore(clock);
  const allowLoopbackHttp = options.allowLoopbackHttp ?? false;
  const doFetch = options.fetch ?? ((url: string): Promise<Response> => fetch(url));
  const fetchJson = async (url: string): Promise<unknown> => {
    const target = readableUrl(url, allowLoopbackHttp);
    if (target === undefined) throw new Error(`refusing to fetch ${url}: only https: URLs are read`);
    const response = await doFetch(target);
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);
    return response.json();
  };
  const resolveDid =
    options.resolveDid ??
    verifier.createDidResolver({
      fetch: async (url: string) => {
        const target = readableUrl(url, allowLoopbackHttp);
        // A URL that is not read is refused here; the verifier reports the DID unresolved.
        if (target === undefined) throw new Error(`refusing to fetch ${url}: only https: URLs are read`);
        return doFetch(target);
      },
    });
  // Every list's proof is verified, by its issuer's assertionMethod key, before any bit is read (story L3-C).
  const fetchStatusList =
    options.fetchStatusList ??
    verifier.createStatusListFetcher({
      fetch: async (url) => {
        const target = readableUrl(url, allowLoopbackHttp);
        if (target === undefined) throw new Error(`refusing to fetch ${url}: only https: URLs are read`);
        return doFetch(target);
      },
      resolveDid,
    });
  const statusCache = options.statusCache ?? new verifier.StatusCache({ clock });
  const seams: kyaos.verifier.VerifierSeams = {
    resolveDid,
    resolveDidKeys: options.resolveDidKeys ?? verifier.createDidKeysResolver(resolveDid),
    fetchStatusList,
    checkRevocation: verifier.createRevocationChecker({
      fetchStatusList,
      cache: statusCache,
      ...(options.statusListIssuers === undefined ? {} : { statusListIssuers: options.statusListIssuers }),
    }),
    resolveCard:
      options.resolveCard ??
      (async (did): Promise<unknown> => {
        const endpoint = cardEndpointOf(await resolveDid(did));
        return endpoint === undefined ? undefined : fetchJson(endpoint);
      }),
    nonceStore,
    clock,
    trustedIssuers: options.trustedIssuers ?? '*',
  };
  const maxChainLength = options.maxChainLength ?? verifier.MAX_DELEGATION_DEPTH;

  fastify.post(
    '/',
    {
      schema: {
        body: {
          type: 'object',
          required: ['proof', 'request', 'expectedAudience'],
          properties: {
            proof: {},
            chain: {},
            card: {},
            request: { type: 'object', required: ['method'], properties: { method: { type: 'string' }, params: {} } },
            expectedAudience: { type: 'string', pattern: '^did:' },
            resource: { type: 'string', minLength: 1 },
            resourceOwner: { type: 'string', pattern: '^did:' },
            trustedRootIssuers: DID_ARRAY,
            catalog: { type: 'array', items: { type: 'string' } },
            action: { type: 'string' },
            tokenCnfJkt: { type: 'string' },
            maxChainLength: { type: 'integer', minimum: 1 },
          },
          additionalProperties: false,
        },
      },
    },
    async (request, reply) => {
      const body = request.body as VerifyBody;
      const result = await verifier.verify(
        {
          proof: body.proof,
          request: body.request,
          ...(body.chain === undefined ? {} : { chain: body.chain }),
          ...(body.card === undefined ? {} : { card: body.card }),
        },
        seams,
        {
          expectedAudience: body.expectedAudience,
          resource: body.resource ?? body.expectedAudience,
          // A request may lower the bound, never raise it past this deployment's.
          maxChainLength: Math.min(body.maxChainLength ?? maxChainLength, maxChainLength),
          ...(body.resourceOwner === undefined ? {} : { resourceOwner: body.resourceOwner }),
          ...(body.trustedRootIssuers === undefined ? {} : { trustedRootIssuers: body.trustedRootIssuers }),
          ...(body.catalog === undefined ? {} : { catalog: body.catalog }),
          ...(body.action === undefined ? {} : { action: body.action }),
          ...(body.tokenCnfJkt === undefined ? {} : { tokenCnfJkt: body.tokenCnfJkt }),
        },
      );
      return reply.code(200).send(result);
    },
  );
};

/** The URL the `KyaOsEntityCard` service of a DID document names, or undefined. */
export function cardEndpointOf(document: unknown): string | undefined {
  if (document === null || typeof document !== 'object') return undefined;
  const services = (document as { service?: unknown }).service;
  if (!Array.isArray(services)) return undefined;
  for (const service of services) {
    if (service === null || typeof service !== 'object') continue;
    const { type, serviceEndpoint } = service as { type?: unknown; serviceEndpoint?: unknown };
    const types = Array.isArray(type) ? type : [type];
    if (types.includes('KyaOsEntityCard') && typeof serviceEndpoint === 'string') return serviceEndpoint;
  }
  return undefined;
}

export default verifyRoutes;
