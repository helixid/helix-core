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
 * Entity Card discovery (SPEC-ENTITY-CARD §6.5, story C-A): a bare did:web
 * resolves in two steps, `did.json` → the `KyaOsEntityCard` service entry →
 * `card.json`. A bare `did:web:host` with no service entry falls back to
 * `/.well-known/kya-os-card.json`; the service entry wins when both exist.
 * A did:key has no web home, so discovery refuses it: a did:key card is
 * supplied directly. The fetched card's `id` must be the DID it was
 * resolved for. Every read goes through SafeFetch (`net/outbound.ts`).
 *
 * Cross-border rule (stories, rule 4): this reads public documents over
 * HTTPS and nothing else.
 */

import { EntityCardInvalidError } from '../errors/HelixError.js';
import { cardEndpointOf } from '../did/document.js';
import { didWebCardUrl, didWebDocumentUrl, isBareDidWeb, parseDidWeb, sameDid } from '../did/web.js';
import { getOutboundFetch, type OutboundFetch } from '../net/outbound.js';
import { parseEntityCard, type EntityCard } from './schema.js';

export const KYA_OS_CARD_META_KEY = 'org.kya-os/card';
export const KYA_OS_CARD_REF_KEY = 'org.kya-os/cardRef';

export interface ResolveEntityCardOptions {
  /** Replaces the process-wide outbound SafeFetch for this resolution. */
  fetch?: OutboundFetch | undefined;
}

export interface ResolvedEntityCard {
  did: string;
  card: EntityCard;
  cardUrl: string;
  /** The DID document the card was discovered through; absent for a `cardRef` or inline did:key card. */
  didDocument?: unknown;
}

function refused(reason: string, message: string): EntityCardInvalidError {
  return new EntityCardInvalidError(message, { reason });
}

async function readJson(url: string, fetchLike: OutboundFetch, what: string): Promise<unknown> {
  let response: Awaited<ReturnType<OutboundFetch>>;
  try {
    response = await fetchLike(url, { headers: { accept: 'application/json' } });
  } catch (error) {
    throw refused(`${what}_unavailable`, `${what} at ${url} could not be read: ${(error as Error).message}`);
  }
  if (!response.ok) throw refused(`${what}_unavailable`, `${what} at ${url} answered HTTP ${response.status}`);
  try {
    return await response.json();
  } catch {
    throw refused(`${what}_unavailable`, `${what} at ${url} is not JSON`);
  }
}

/** `card.json` at `url`, parsed, and bound to `expectedDid` when one is known. */
export async function fetchEntityCard(url: string, options: ResolveEntityCardOptions & { expectedDid?: string | undefined } = {}): Promise<ResolvedEntityCard> {
  const fetchLike = options.fetch ?? getOutboundFetch();
  const card = parseEntityCard(await readJson(url, fetchLike, 'card'));
  if (options.expectedDid !== undefined && !sameDid(card.id, options.expectedDid)) {
    throw refused('card_mismatch', `card at ${url} is for ${card.id}, not ${options.expectedDid}`);
  }
  return { did: card.id, card, cardUrl: url };
}

/** Two-step resolution of a did:web to its card. */
export async function resolveEntityCard(did: string, options: ResolveEntityCardOptions = {}): Promise<ResolvedEntityCard> {
  if (typeof did !== 'string') throw refused('malformed_did', 'did must be a string');
  if (did.startsWith('did:key:')) {
    throw refused('did_key_not_resolvable', `${did} has no web home: a did:key card is supplied directly, never discovered`);
  }
  if (parseDidWeb(did) === undefined) throw refused('malformed_did', `${did} is not a did:web DID that names a URL`);
  const fetchLike = options.fetch ?? getOutboundFetch();
  const documentUrl = didWebDocumentUrl(did);
  const document = await readJson(documentUrl, fetchLike, 'did_document');
  const servedId = (document as { id?: unknown })?.id;
  if (typeof servedId !== 'string' || !sameDid(servedId, did)) {
    throw refused('did_document_mismatch', `DID document at ${documentUrl} is not for ${did}`);
  }
  const endpoint = cardEndpointOf(document) ?? (isBareDidWeb(did) ? didWebCardUrl(did) : undefined);
  if (endpoint === undefined) {
    throw refused('no_card_service', `DID document for ${did} has no KyaOsEntityCard service entry`);
  }
  const resolved = await fetchEntityCard(endpoint, { fetch: fetchLike, expectedDid: did });
  return { ...resolved, did, didDocument: document };
}

export interface ServerMetaResolution {
  /** The `_meta` of an MCP `server.json` / catalog entry (or the `org.kya-os/card` value itself). */
  serverMeta: unknown;
  /** The server's DID, when known: the fallback when the projection was stripped. */
  did?: string | undefined;
}

/**
 * A card from an MCP `server.json` projection (§6.1): a `org.kya-os/cardRef`
 * is fetched; an inline did:web summary is an index, so its canonical
 * `card.json` is fetched and bound to the summary's id; an inline did:key
 * summary is parsed in place. A stripped projection degrades to the two-step
 * resolution of `did` when one is known, never to a failure of its own.
 */
export async function resolveEntityCardFromServerMeta(input: ServerMetaResolution, options: ResolveEntityCardOptions = {}): Promise<ResolvedEntityCard> {
  const meta = input.serverMeta as Record<string, unknown> | undefined;
  const entry = typeof meta === 'object' && meta !== null ? (meta[KYA_OS_CARD_META_KEY] as unknown) : undefined;
  if (entry === undefined) {
    if (input.did !== undefined) return resolveEntityCard(input.did, options);
    throw refused('no_projection', `server metadata carries no ${KYA_OS_CARD_META_KEY} and no DID is known`);
  }
  const record = typeof entry === 'object' && entry !== null ? (entry as Record<string, unknown>) : {};
  const ref = record[KYA_OS_CARD_REF_KEY];
  if (typeof ref === 'string') {
    const expected = typeof record['id'] === 'string' ? record['id'] : input.did;
    return fetchEntityCard(ref, { fetch: options.fetch, expectedDid: expected });
  }
  const id = record['id'];
  if (typeof id !== 'string') throw refused('no_projection', `${KYA_OS_CARD_META_KEY} summary has no id and no cardRef`);
  if (id.startsWith('did:web:')) {
    if (parseDidWeb(id) === undefined) throw refused('malformed_did', `${id} is not a did:web DID that names a URL`);
    return fetchEntityCard(didWebCardUrl(id), { fetch: options.fetch, expectedDid: id });
  }
  const summary = { ...record };
  delete summary[KYA_OS_CARD_REF_KEY];
  const card = parseEntityCard(summary);
  return { did: card.id, card, cardUrl: '' };
}
