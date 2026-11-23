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
 * The two custody choices of KYA-OS story F-3 point 1, independent of each
 * other, any combination allowed:
 *
 * - key custody: `self` (the private key is generated and held client side,
 *   the SDK signs through its Signer) or `helix` (Helix generates the key,
 *   holds it in its KeyStore and signs on the account's behalf);
 * - DID hosting: `own` (a did:web on the owner's domain, the DID document and
 *   card served from there) or `helix` (a did:web under the Helix domain,
 *   served by Helix).
 *
 * The account preference (`custody.defaultKeyCustody`,
 * `custody.defaultDidHosting`) lives where accounts exist (the enterprise
 * build); an agent, service or owner may override it at creation. A build
 * without accounts has no account default and falls back to the conformant
 * default, self-custody on Helix hosting.
 *
 * KYA-OS SPEC §4.5: an implementation that holds agent keys is
 * non-conformant, so a `helix` key custody subject is labelled
 * `custody: helix` and kept out of every conformance claim (point 5).
 */

import { CustodyChoiceInvalidError } from './errors.js';

export const KEY_CUSTODY_MODES = ['self', 'helix'] as const;
export type KeyCustodyMode = (typeof KEY_CUSTODY_MODES)[number];

export const DID_HOSTING_MODES = ['own', 'helix'] as const;
export type DidHostingMode = (typeof DID_HOSTING_MODES)[number];

/** What a custody record is about. Owners sign attestations (point 7); the consent did:key of L3-H is always Helix-held. */
export const CUSTODY_SUBJECT_TYPES = ['agent', 'service', 'owner'] as const;
export type CustodySubjectType = (typeof CUSTODY_SUBJECT_TYPES)[number];

export interface CustodyChoice {
  keyCustody: KeyCustodyMode;
  didHosting: DidHostingMode;
}

/** The account preference, as the enterprise account stores it under `custody`. */
export interface CustodyDefaults {
  defaultKeyCustody: KeyCustodyMode;
  defaultDidHosting: DidHostingMode;
}

/** A per-subject override: either member may be left to the default. */
export interface CustodyOverride {
  keyCustody?: unknown;
  didHosting?: unknown;
}

/** Where each member of a resolved choice came from, for the audit event. */
export type CustodyChoiceSource = 'override' | 'account' | 'built-in';

export interface ResolvedCustodyChoice extends CustodyChoice {
  source: { keyCustody: CustodyChoiceSource; didHosting: CustodyChoiceSource };
}

/** The conformant default when there is no account preference: keys with the owner, DID served by Helix. */
export const BUILT_IN_CUSTODY_DEFAULTS: Readonly<CustodyDefaults> = Object.freeze({
  defaultKeyCustody: 'self',
  defaultDidHosting: 'helix',
});

export const CUSTODY_LABEL_HELIX = 'custody: helix';
export const CUSTODY_LABEL_SELF = 'custody: self';
export type CustodyLabel = typeof CUSTODY_LABEL_HELIX | typeof CUSTODY_LABEL_SELF;

export function isKeyCustodyMode(value: unknown): value is KeyCustodyMode {
  return typeof value === 'string' && (KEY_CUSTODY_MODES as readonly string[]).includes(value);
}

export function isDidHostingMode(value: unknown): value is DidHostingMode {
  return typeof value === 'string' && (DID_HOSTING_MODES as readonly string[]).includes(value);
}

export function isCustodySubjectType(value: unknown): value is CustodySubjectType {
  return typeof value === 'string' && (CUSTODY_SUBJECT_TYPES as readonly string[]).includes(value);
}

/** The label Helix's records, the console and the conformance report show (point 5). */
export function custodyLabel(keyCustody: KeyCustodyMode): CustodyLabel {
  return keyCustody === 'helix' ? CUSTODY_LABEL_HELIX : CUSTODY_LABEL_SELF;
}

/** Only a subject whose key Helix does not hold can be in a Core or Card claim (SPEC §4.5). */
export function isConformantCustody(keyCustody: KeyCustodyMode): boolean {
  return keyCustody === 'self';
}

/** Checks an account preference; refuses anything but the two modes of each choice. */
export function parseCustodyDefaults(value: unknown): CustodyDefaults {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new CustodyChoiceInvalidError('custody defaults must be an object with defaultKeyCustody and defaultDidHosting');
  }
  const members = value as Record<string, unknown>;
  const foreign = Object.keys(members).filter((name) => name !== 'defaultKeyCustody' && name !== 'defaultDidHosting');
  if (foreign.length > 0) {
    throw new CustodyChoiceInvalidError(`custody defaults carry unexpected members (${foreign.join(', ')})`);
  }
  if (!isKeyCustodyMode(members['defaultKeyCustody'])) {
    throw new CustodyChoiceInvalidError(`defaultKeyCustody must be one of ${KEY_CUSTODY_MODES.join(', ')}`);
  }
  if (!isDidHostingMode(members['defaultDidHosting'])) {
    throw new CustodyChoiceInvalidError(`defaultDidHosting must be one of ${DID_HOSTING_MODES.join(', ')}`);
  }
  return { defaultKeyCustody: members['defaultKeyCustody'], defaultDidHosting: members['defaultDidHosting'] };
}

/**
 * The choice a new agent, service or owner gets: each member of `override`
 * when given, else the account preference, else the built-in default.
 * An override that is not one of the modes is refused, never ignored.
 */
export function resolveCustodyChoice(
  override: CustodyOverride | undefined,
  accountDefaults?: CustodyDefaults | undefined,
): ResolvedCustodyChoice {
  const given = override ?? {};
  if (given.keyCustody !== undefined && !isKeyCustodyMode(given.keyCustody)) {
    throw new CustodyChoiceInvalidError(`keyCustody must be one of ${KEY_CUSTODY_MODES.join(', ')}`);
  }
  if (given.didHosting !== undefined && !isDidHostingMode(given.didHosting)) {
    throw new CustodyChoiceInvalidError(`didHosting must be one of ${DID_HOSTING_MODES.join(', ')}`);
  }
  const fallbackSource: CustodyChoiceSource = accountDefaults ? 'account' : 'built-in';
  const defaults = accountDefaults ?? BUILT_IN_CUSTODY_DEFAULTS;
  return {
    keyCustody: (given.keyCustody as KeyCustodyMode | undefined) ?? defaults.defaultKeyCustody,
    didHosting: (given.didHosting as DidHostingMode | undefined) ?? defaults.defaultDidHosting,
    source: {
      keyCustody: given.keyCustody !== undefined ? 'override' : fallbackSource,
      didHosting: given.didHosting !== undefined ? 'override' : fallbackSource,
    },
  };
}

/**
 * The custody members Helix writes onto a subject's identity credential and
 * every record it keeps for the subject (point 1). A card never carries
 * them: its schema is closed (SPEC-ENTITY-CARD §4).
 */
export function custodyClaims(choice: CustodyChoice): CustodyChoice {
  return { keyCustody: choice.keyCustody, didHosting: choice.didHosting };
}
