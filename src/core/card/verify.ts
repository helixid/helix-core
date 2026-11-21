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
 * `verifyEntityCard` (SPEC-ENTITY-CARD §11.1, story C-A): recompute what a
 * card claims through injected seams and derive its level, fail-closed.
 *
 * 1. Capabilities: with no verifier, every capability is unverified (L1).
 * 2. Accountability: a card with `responsibleParty` is verified only by an
 *    accountability verifier (`responsibleParty === issuer(rootVC)` and the
 *    leaf invoker is the proof's DID, §10.2); with none, the party is not
 *    verified (`configuration_error`).
 * 3. Attestations: each through the attestation verifier; none supplied,
 *    none verified.
 * 4. Revocation: a card that declares `revocation` is verified only with a
 *    status-list checker to read it; with none, it reads as revoked and not
 *    fresh with `configuration_error` (§10.3). The checker's answer is
 *    read strictly: only a literal `revoked: false` passes.
 * 5. `ok` = accountability ok and attestations ok and not revoked.
 * 6. Level: a revoked card collapses to L1; otherwise L2 when every declared
 *    capability is attested and verified, lifted to L3 by a live proof of
 *    the card's own DID (`proofFloor`) read fresh; else L1. The card's own
 *    `conformanceLevel` is never read.
 */

import { validateDelegationChain, type DelegationChainContext, type DelegationHop } from './chain.js';
import { capabilityName, type BitstringStatusListEntry, type Capability, type CardAttestation, type ConformanceLevel, type EntityCard } from './schema.js';

export type TrustedIssuers = '*' | readonly string[];

export interface CapabilityCheckResult {
  verified: string[];
  unverified: string[];
  fresh?: boolean;
}

export type CapabilityVerifier = (
  capabilities: Capability[],
  ctx: { subjectDid: string; trustedIssuers: TrustedIssuers },
) => Promise<CapabilityCheckResult>;

export interface AccountabilityResult {
  verified: boolean;
  fresh?: boolean;
}

export type AccountabilityVerifier = (
  card: EntityCard,
  ctx: { trustedIssuers: TrustedIssuers; proofDid?: string | undefined },
) => Promise<boolean | AccountabilityResult>;

export type AttestationVerifier = (attestation: CardAttestation, ctx: { subjectDid: string; trustedIssuers: TrustedIssuers }) => Promise<boolean>;

export interface RevocationVerdict {
  revoked: boolean;
  fresh: boolean;
  code?: string;
  reason?: string;
}

/** Reads one Bitstring Status List entry, live or cached; e.g. `createStatusListChecker`. */
export type StatusListChecker = (entry: BitstringStatusListEntry, ctx: { credentialIssuer: string }) => Promise<RevocationVerdict>;

export interface VerifyEntityCardDeps {
  capabilityVerifier?: CapabilityVerifier | undefined;
  accountabilityVerifier?: AccountabilityVerifier | undefined;
  attestationVerifier?: AttestationVerifier | undefined;
  statusListChecker?: StatusListChecker | undefined;
  /** `'*'` (stories: allow all until phase 4) or an allowlist. Default `'*'`. */
  trustedIssuers?: TrustedIssuers | undefined;
  /** The DID a live per-request proof verified, when one accompanied the request (§11.1 step 2). */
  proofDid?: string | undefined;
}

export interface VerifyEntityCardResult {
  ok: boolean;
  conformanceLevel: ConformanceLevel;
  /** Why the card is not ok: the first refusal's code. */
  code?: string;
  reasons: string[];
  verifiedCapabilities: string[];
  accountability?: { responsibleParty: string; principal?: string; verified: boolean; fresh?: boolean };
  attestations: { type: string; subject?: string; verified: boolean }[];
  revocation?: { checked: boolean; revoked: boolean; fresh: boolean; code?: string; reason?: string };
}

export interface AccountabilityInput {
  chain: readonly DelegationHop[];
  resourceOwner?: string | undefined;
  resource?: string | undefined;
  /** Epoch milliseconds the chain is held at. */
  now?: number | undefined;
  /** The live proof's DID; the leaf invoker must equal it when given. */
  proofDid?: string | undefined;
}

/**
 * An accountability verifier over a chain supplied with the card (the
 * vectors' `accountability` input, a request's carried chain): the edge
 * holds iff the chain validates structurally, `card.responsibleParty` is its
 * root issuer and, with a `proofDid`, the leaf invoker is that DID.
 */
export function makeAccountabilityVerifier(input: AccountabilityInput): AccountabilityVerifier {
  return async (card, ctx) => {
    const context: DelegationChainContext = {
      resourceOwner: input.resourceOwner,
      resource: input.resource,
      now: input.now,
    };
    const result = validateDelegationChain(input.chain, context);
    const proofDid = input.proofDid ?? ctx.proofDid;
    const partyOk = card.responsibleParty !== undefined && card.responsibleParty === result.responsibleParty;
    const joinOk = proofDid === undefined || result.leafInvoker === proofDid;
    return { verified: result.ok && partyOk && joinOk, fresh: result.ok };
  };
}

function deriveLevel(capabilities: Capability[] | undefined, verified: Set<string>, proofFloor: boolean, fresh: boolean): ConformanceLevel {
  const declared = (capabilities ?? []).map(capabilityName);
  const allAttested = declared.length > 0 && declared.every((name) => verified.has(name));
  if (!allAttested) return 'L1';
  return proofFloor && fresh ? 'L3' : 'L2';
}

export async function verifyEntityCard(card: EntityCard, deps: VerifyEntityCardDeps = {}): Promise<VerifyEntityCardResult> {
  const trustedIssuers = deps.trustedIssuers ?? '*';
  const reasons: string[] = [];
  let code: string | undefined;
  const refuse = (refusalCode: string, reason: string): void => {
    code ??= refusalCode;
    reasons.push(reason);
  };

  // 1. Capabilities.
  let check: CapabilityCheckResult = { verified: [], unverified: (card.capabilities ?? []).map(capabilityName) };
  if (deps.capabilityVerifier && card.capabilities && card.capabilities.length > 0) {
    try {
      check = await deps.capabilityVerifier(card.capabilities, { subjectDid: card.id, trustedIssuers });
    } catch {
      check = { verified: [], unverified: card.capabilities.map(capabilityName), fresh: false };
    }
  }
  const capabilityFresh = check.fresh === undefined || check.fresh === true;

  // 2. Accountability.
  let accountability: VerifyEntityCardResult['accountability'];
  let accountabilityFresh = true;
  if (card.responsibleParty !== undefined) {
    let verdict: boolean | AccountabilityResult = false;
    if (deps.accountabilityVerifier) {
      try {
        verdict = await deps.accountabilityVerifier(card, { trustedIssuers, proofDid: deps.proofDid });
      } catch (error) {
        refuse('accountability_unverifiable', `accountability verifier threw: ${(error as Error).message}`);
      }
    } else {
      refuse('configuration_error', 'card names a responsibleParty and no accountability verifier was supplied');
    }
    const verified = verdict === true || (typeof verdict === 'object' && verdict !== null && verdict.verified === true);
    const fresh = typeof verdict === 'object' && verdict !== null ? verdict.fresh : undefined;
    if (!verified && code === undefined) refuse('accountability_failed', 'responsibleParty did not verify against the delegation chain');
    if (fresh !== undefined) accountabilityFresh = fresh === true;
    accountability = {
      responsibleParty: card.responsibleParty,
      ...(card.principal === undefined ? {} : { principal: card.principal }),
      verified,
      ...(fresh === undefined ? {} : { fresh: fresh === true }),
    };
  }

  // 3. Attestations.
  const attestations: VerifyEntityCardResult['attestations'] = [];
  for (const attestation of card.attestations ?? []) {
    let verified = false;
    if (deps.attestationVerifier) {
      try {
        verified = (await deps.attestationVerifier(attestation, { subjectDid: card.id, trustedIssuers })) === true;
      } catch {
        verified = false;
      }
    }
    if (!verified) refuse(deps.attestationVerifier ? 'attestation_failed' : 'configuration_error', `${attestation.type} attestation did not verify`);
    attestations.push({ type: attestation.type, ...(attestation.subject === undefined ? {} : { subject: attestation.subject }), verified });
  }

  // 4. Revocation.
  let revocation: VerifyEntityCardResult['revocation'];
  if (card.revocation !== undefined) {
    if (!deps.statusListChecker) {
      revocation = { checked: false, revoked: true, fresh: false, code: 'configuration_error', reason: 'card declares revocation and no status-list checker was supplied' };
    } else {
      try {
        const verdict = await deps.statusListChecker(card.revocation, { credentialIssuer: card.id });
        const revoked = verdict.revoked !== false;
        revocation = {
          checked: true,
          revoked,
          fresh: verdict.fresh === true,
          ...(revoked ? { code: verdict.code ?? 'card_revoked' } : {}),
          ...(verdict.reason === undefined ? {} : { reason: verdict.reason }),
        };
      } catch (error) {
        revocation = { checked: true, revoked: true, fresh: false, code: 'status_unavailable', reason: (error as Error).message };
      }
    }
    if (revocation.revoked) refuse(revocation.code!, revocation.reason ?? 'card credential is revoked');
  }

  const revoked = revocation?.revoked === true;
  const verified = new Set(revoked ? [] : check.verified);
  const proofFloor = deps.proofDid !== undefined && deps.proofDid === card.id;
  const fresh = (revocation === undefined || revocation.fresh) && accountabilityFresh && capabilityFresh;
  return {
    ok: reasons.length === 0,
    conformanceLevel: deriveLevel(card.capabilities, verified, proofFloor, fresh),
    ...(code === undefined ? {} : { code }),
    reasons,
    verifiedCapabilities: [...verified],
    ...(accountability === undefined ? {} : { accountability }),
    attestations,
    ...(revocation === undefined ? {} : { revocation }),
  };
}
