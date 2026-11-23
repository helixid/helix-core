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
 * The claim-minimal projection of a card onto MCP `server.json` /
 * `catalog.json` `_meta["org.kya-os/card"]` (SPEC-ENTITY-CARD §6.1, story
 * C-A): identity, type, name, capability names, the accountability pointers
 * (`responsibleParty`, `delegationRef`, `revocation`) that keep the index
 * honest, `proofProfile`, and `org.kya-os/cardRef`, the canonical
 * `card.json` URL a verifier lands back on. Pure: no I/O, no crypto.
 */

import { didWebCardUrl, parseDidWeb } from '../did/web.js';
import { KYA_OS_CARD_META_KEY, KYA_OS_CARD_REF_KEY } from './resolve.js';
import { capabilityName } from '../credentials/card-level.js';
import type { BitstringStatusListEntry, EntityCard, EntityType } from './schema.js';

export interface EntityCardSummary {
  id: string;
  entityType: EntityType;
  name: string;
  capabilities?: string[];
  responsibleParty?: string;
  delegationRef?: string;
  proofProfile?: string;
  revocation?: BitstringStatusListEntry;
}

export type CardRefValue = { [KYA_OS_CARD_REF_KEY]: string };

export type ServerCardMeta = { [KYA_OS_CARD_META_KEY]: (EntityCardSummary & CardRefValue) | CardRefValue };

export function entityCardSummary(card: EntityCard): EntityCardSummary {
  return {
    id: card.id,
    entityType: card.entityType,
    name: card.name,
    ...(card.capabilities === undefined ? {} : { capabilities: card.capabilities.map(capabilityName) }),
    ...(card.responsibleParty === undefined ? {} : { responsibleParty: card.responsibleParty }),
    ...(card.delegationRef === undefined ? {} : { delegationRef: card.delegationRef }),
    ...(card.proofProfile === undefined ? {} : { proofProfile: card.proofProfile }),
    ...(card.revocation === undefined ? {} : { revocation: card.revocation }),
  };
}

export interface ServerCardMetaOptions {
  /** The canonical `card.json` URL; derived from a did:web id when omitted. */
  cardUrl?: string | undefined;
  /** Emit only the `cardRef` (a catalog index row), no inline summary. */
  byRef?: boolean | undefined;
}

/** `{ "org.kya-os/card": { …summary, "org.kya-os/cardRef": url } }` to spread into `server.json` `_meta`. */
export function serverCardMeta(card: EntityCard, options: ServerCardMetaOptions = {}): ServerCardMeta {
  const cardUrl = options.cardUrl ?? (parseDidWeb(card.id) === undefined ? undefined : didWebCardUrl(card.id));
  if (cardUrl === undefined) {
    throw new Error('serverCardMeta: a did:key card has no card URL; pass cardUrl');
  }
  const ref: CardRefValue = { [KYA_OS_CARD_REF_KEY]: cardUrl };
  return { [KYA_OS_CARD_META_KEY]: options.byRef ? ref : { ...entityCardSummary(card), ...ref } };
}
