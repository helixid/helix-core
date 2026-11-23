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
 * list, an entry wider than one bit, an index out of range.
 *
 * The list itself (story L3-C point 2): its issuer's `DataIntegrityProof`
 * (`eddsa-jcs-2022`) is verified through the `resolveDid` seam before any
 * bit is read, and without that seam nothing is read (fail closed). A list
 * whose `validFrom` lies ahead (beyond the clock skew) is refused; one past
 * its `validUntil` is still read, but never as fresh.
 */

import { bareEncodedList, getBit } from '../status-list/index.js';
import { StatusListCredentialSchema } from '../status-list/schema.js';
import { getOutboundFetch, type OutboundFetch } from '../net/outbound.js';
import { verifyDataIntegrity, type DidResolver } from '../credentials/data-integrity.js';
import type { RevocationVerdict, StatusListChecker } from './verify.js';

export interface StatusListCheckerOptions {
  fetch?: OutboundFetch | undefined;
  /** Lists already in hand (tests, a cached copy): read without a fetch and reported not fresh. */
  lists?: Record<string, unknown> | undefined;
  /** Resolves the list issuer's DID for its proof (story L3-C). Without it every list reads as unavailable. */
  resolveDid?: DidResolver | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: (() => number) | undefined;
  /** Tolerance for a `validFrom` ahead of the clock; default 120 s. */
  clockSkewMs?: number | undefined;
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
    if (options.resolveDid === undefined) return unavailable('no resolveDid seam to verify the status list proof');
    const proof = await verifyDataIntegrity(raw as Record<string, unknown>, options.resolveDid);
    if (!proof.ok) return unavailable(`status list proof invalid: ${proof.reason}`);
    const now = (options.clock ?? Date.now)();
    const validFrom = Date.parse(parsed.data.validFrom);
    const validUntil = Date.parse(parsed.data.validUntil);
    if (Number.isNaN(validFrom) || Number.isNaN(validUntil)) return unavailable('status list window is not a pair of date-times');
    if (validFrom > now + (options.clockSkewMs ?? 120_000)) return unavailable('status list is not valid yet');
    // Past its window the list is still read, but only as a stale copy.
    if (validUntil <= now) fresh = false;
    let bit: 0 | 1;
    try {
      bit = getBit(bareEncodedList(parsed.data.credentialSubject.encodedList), index);
    } catch {
      return unavailable('status list entry could not be read');
    }
    return bit === 1 ? { revoked: true, fresh, code: 'card_revoked', reason: 'the card credential is revoked' } : { revoked: false, fresh };
  };
}
