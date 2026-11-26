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

import type { FastifyPluginAsync } from 'fastify';
import {
  DIDDeactivatedError,
  DIDNotFoundError,
  HelixError,
  buildEntityCard,
  didWebFromPath,
  isLoopbackHost,
  parseDidWeb,
  projectJwks,
  withKyaOsCardService,
  type BuildEntityCardInput,
  type EntityCard,
} from '../../core/index.js';

/**
 * Helix-hosted did:web documents and Entity Cards (KYA-OS story C-A):
 *
 *   GET /{path}/did.json                  the DID document of did:web:<host>:{path}
 *   GET /{path}/card.json                 its card
 *   GET /{path}/jwks.json                 story C-E: its keys as a JWK Set, the
 *                                        mechanical projection of the document's
 *                                        verificationMethod[] (kid preserved),
 *                                        with each key's validity and the
 *                                        document's rotationSequence and updated
 *   GET /.well-known/kya-os-card.json     the bare-host org's card (did:web:<host>)
 *
 * `{path}` is any depth. Helix builds `<kind>/<hex>` (`agents/<hex>`,
 * `services/<hex>`, `accounts/<hex>`: `did:web:<host>:<kind>:<hex>`), and the
 * lookup is by DID, so any path a stored DID has is served. The served document always anchors the card with the
 * `KyaOsEntityCard` service entry (SPEC-ENTITY-CARD §5.3), so a document
 * stored before this story resolves in two steps too. The card is built on
 * every read from what the source knows (`buildEntityCard`): never a
 * `conformanceLevel`, never a proof.
 *
 * Registered after the static routes: Fastify's wildcard has the lowest
 * priority, so the issuer's `/.well-known/did.json` and every `/v1/...` route stay with their own plugins; anything else that is not a
 * `did.json` or `card.json` path falls through to the usual 404.
 */

export interface EntityCardRecord {
  didDocument: unknown;
  deactivatedAt?: Date | null | undefined;
  /** What the card says; `id` is the DID and `didDocument` is filled by the route. */
  card: Omit<BuildEntityCardInput, 'id' | 'didDocument'>;
}

export interface EntityCardSource {
  /** The did:web host these documents are served for: the raw `DID_DOMAIN` (`host[:port]`, not percent-encoded). */
  host: string;
  find(did: string): Promise<EntityCardRecord | null>;
}

export interface EntityCardRouteOptions {
  source: EntityCardSource;
  /**
   * The origin the documents are reachable at, when it is not `https://<host>`
   * (a local stack on plain http). The card's service endpoint and
   * `didDocument` URL are built on it.
   */
  publicOrigin?: string | undefined;
}

/** The URLs the route serves `did` at. */
export function hostedUrls(did: string, publicOrigin: string | undefined): { didDocument: string; card: string } {
  const parsed = parseDidWeb(did);
  if (parsed === undefined) throw new DIDNotFoundError(did);
  const origin = (publicOrigin ?? `${isLoopbackHost(parsed.host) ? 'http' : 'https'}://${parsed.host}`).replace(/\/$/, '');
  if (parsed.path.length === 0) {
    return { didDocument: `${origin}/.well-known/did.json`, card: `${origin}/.well-known/kya-os-card.json` };
  }
  const path = parsed.path.map(encodeURIComponent).join('/');
  return { didDocument: `${origin}/${path}/did.json`, card: `${origin}/${path}/card.json` };
}

const entityCardRoutes: FastifyPluginAsync<EntityCardRouteOptions> = async (fastify, options) => {
  const host = options.source.host;

  async function lookup(did: string): Promise<EntityCardRecord> {
    const record = await options.source.find(did);
    if (!record) throw new DIDNotFoundError(did);
    if (record.deactivatedAt) throw new DIDDeactivatedError(did);
    return record;
  }

  async function serve(did: string, document: 'did' | 'card'): Promise<unknown> {
    const record = await lookup(did);
    const urls = hostedUrls(did, options.publicOrigin);
    if (document === 'did') {
      const stored = (record.didDocument ?? {}) as { service?: unknown[] };
      return { ...stored, service: withKyaOsCardService(Array.isArray(stored.service) ? stored.service : undefined, did, urls.card) };
    }
    const card: EntityCard = buildEntityCard({ ...record.card, id: did, didDocument: urls.didDocument });
    return card;
  }

  fastify.get('/*', async (request, reply) => {
    let pathname = new URL(request.url, 'http://placeholder').pathname;
    const jwks = pathname.endsWith('/jwks.json');
    if (jwks) pathname = `${pathname.slice(0, -'jwks.json'.length)}did.json`;
    const target = didWebFromPath(host, pathname);
    if (target === undefined || (jwks && target.document !== 'did')) return reply.callNotFound();
    try {
      const served = await serve(target.did, target.document);
      const body = jwks ? projectJwks(served as Parameters<typeof projectJwks>[0]) : served;
      return reply.type('application/json').header('Cache-Control', 'public, max-age=300').send(body);
    } catch (error) {
      if (error instanceof HelixError) {
        return reply.code(error.httpStatus).send({ error: { code: error.code, message: error.message, requestId: request.id } });
      }
      throw error;
    }
  });
};

export default entityCardRoutes;
