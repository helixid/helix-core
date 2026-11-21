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
 * A live W3C Bitstring Status List reader for a card's `revocation` entry
 * (SPEC-ENTITY-CARD §10.3, story C-A): the list is read through SafeFetch
 * (`net/outbound.ts`), must have the shape Helix's own lists have, and the
 * one bit at `statusListIndex` decides. Everything that cannot be shown
 * not-revoked reads as revoked and not fresh: an unreachable or malformed
 * list, an entry wider than one bit, an index out of range. Signature and
 * window checks of the list itself are story L3-C's.
 */

import { getBit } from '../status-list/index.js';
import { StatusListCredentialSchema } from '../status-list/schema.js';
import { getOutboundFetch, type OutboundFetch } from '../net/outbound.js';
import type { RevocationVerdict, StatusListChecker } from './verify.js';

export interface StatusListCheckerOptions {
  fetch?: OutboundFetch | undefined;
  /** Lists already in hand (tests, a cached copy): read without a fetch and reported not fresh. */
  lists?: Record<string, unknown> | undefined;
}

export function createStatusListChecker(options: StatusListCheckerOptions = {}): StatusListChecker {
  return async (entry) => {
    const unavailable = (reason: string): RevocationVerdict => ({ revoked: true, fresh: false, code: 'status_unavailable', reason });
    if (entry.statusSize !== undefined && entry.statusSize !== 1) {
      return unavailable(`statusSize ${entry.statusSize} is not readable as one bit`);
    }
    if (!/^[0-9]+$/.test(entry.statusListIndex)) return unavailable('statusListIndex is not a decimal string');
    const index = Number(entry.statusListIndex);
    if (!Number.isSafeInteger(index)) return unavailable('statusListIndex is out of range');

    let raw: unknown;
    let fresh = false;
    if (options.lists && entry.statusListCredential in options.lists) {
      raw = options.lists[entry.statusListCredential];
    } else {
      try {
        const response = await (options.fetch ?? getOutboundFetch())(entry.statusListCredential, { headers: { accept: 'application/vc+json, application/json' } });
        if (!response.ok) return unavailable(`status list answered HTTP ${response.status}`);
        raw = await response.json();
        fresh = true;
      } catch (error) {
        return unavailable(`status list could not be read: ${(error as Error).message}`);
      }
    }
    const parsed = StatusListCredentialSchema.safeParse(raw);
    if (!parsed.success) return unavailable('status list failed schema validation');
    let bit: 0 | 1;
    try {
      bit = getBit(parsed.data.credentialSubject.encodedList, index);
    } catch {
      return unavailable('status list entry could not be read');
    }
    return bit === 1 ? { revoked: true, fresh, code: 'card_revoked', reason: 'the card credential is revoked' } : { revoked: false, fresh };
  };
}
