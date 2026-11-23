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
 *
 * Whose list it is (SPEC-ENTITY-CARD §10.3, SPEC.md §6.6): the list counts
 * only when the issuer its proof verified for is the one keeper of the URL
 * the entry names, decided before the list is read and never from the list:
 * the issuer `statusListIssuers` binds that exact URL, or its `https:`
 * origin, to; otherwise the Entity, the card's `id`. A Helix card's entry
 * points at the agent's identity VC, which Helix issues and lists, so a
 * verifier binds Helix's issuer DID to Helix's list URLs; without that
 * binding a Helix-signed list is not the Entity's and the card reads as
 * revoked (`status_list_mismatch`, fail closed). Every list must state the
 * entry's URL, byte for byte, as its `id` (Helix's list schema requires an
 * `id`, so the §10.3 allowance for an unbound Entity's id-less list is not
 * taken: such a list is refused as malformed). The bindings are
 * read by the SDK's keeper rule (`kyaos.verifier.keeper`), the same bytes-as-
 * written comparison the middleware applies. The §10.3 root rule (a verified
 * `responsibleParty` keeping its root credential's list) is not applied here.
 */

import { bareEncodedList, getBit } from '../status-list/index.js';
import { StatusListCredentialSchema } from '../status-list/schema.js';
import { getOutboundFetch, type OutboundFetch } from '../net/outbound.js';
import { verifyDataIntegrity, type DidResolver } from '../credentials/data-integrity.js';
import { kyaos } from '@helixid/sdk-js';
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
  /**
   * Issuer DID to the exact list URLs and `https:` origins it keeps
   * (SPEC-ENTITY-CARD §10.3), e.g. `{ [helixIssuerDid]: ['https://api.helix.example'] }`.
   * A URL bound to no issuer is kept by the card's own DID. A malformed
   * binding (one URL bound to two issuers, an origin ending in `/`, a host
   * not in lower case) throws a `TypeError` when the checker is created.
   */
  statusListIssuers?: Record<string, string[]> | undefined;
}

export function createStatusListChecker(options: StatusListCheckerOptions = {}): StatusListChecker {
  const configuration = kyaos.verifier.statusConfiguration({ statusListIssuers: options.statusListIssuers });
  return async (entry, ctx) => {
    const unavailable = (reason: string): RevocationVerdict => ({ revoked: true, fresh: false, code: 'status_unavailable', reason });
    const mismatch = (reason: string): RevocationVerdict => ({ revoked: true, fresh: false, code: 'status_list_mismatch', reason });
    const entity = ctx?.entity;
    if (typeof entity !== 'string' || entity === '') return unavailable('no card DID to decide who keeps the status list');
    const url = entry.statusListCredential;
    const keeper = kyaos.verifier.keeper(url, entity, configuration).did;
    if (entry.statusSize !== undefined && entry.statusSize !== 1) {
      return unavailable(`statusSize ${entry.statusSize} is not readable as one bit`);
    }
    if (!/^[0-9]+$/.test(entry.statusListIndex)) return unavailable('statusListIndex is not a decimal string');
    const index = Number(entry.statusListIndex);
    if (!Number.isSafeInteger(index)) return unavailable('statusListIndex is out of range');

    let raw: unknown;
    let fresh = false;
    if (options.lists && url in options.lists) {
      raw = options.lists[url];
    } else {
      try {
        const response = await (options.fetch ?? getOutboundFetch())(url, { headers: { accept: 'application/vc+json, application/json' } });
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
    if (proof.issuer !== keeper) return mismatch(`status list is signed by ${proof.issuer}, not ${keeper}, who keeps ${url}`);
    if (parsed.data.id !== url) return mismatch(`status list id ${parsed.data.id} is not the URL it was read from`);
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
