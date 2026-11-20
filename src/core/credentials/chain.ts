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
 * The delegation chain (SPEC.md §6.10, story F-1 points 4 and 5): a list of
 * hops root to leaf, valid only if EVERY hop attenuates its parent. Pure
 * functions: no database, no network, no lookup fallback. Signature checks
 * are the caller's (`verifyDelegationChainProofs` below, or story F-2's
 * verifier); status reads are story L3-C's.
 *
 * Attenuation invariants (fail-closed, every reason reported):
 * - action subset: child `allowedAction` ⊆ parent;
 * - monotone caveats: no parent caveat dropped; `MaxAmount` ≤ parent (same
 *   currency, exact decimals), `ValidUntil` ≤ parent, unknown types verbatim;
 * - `validUntil` narrowing: child ≤ parent, both read as RFC 3339 with offset;
 * - continuity: parent `invoker` = child `issuer`; child `parentCapability`
 *   = parent capability `id`;
 * - constant `invocationTarget`;
 * - root: `parentCapability` = `invocationTarget`; when the caller asserts
 *   `resource` / `resourceOwner`, the root's target / issuer must match.
 *
 * Chain length is bounded (10 hops, `maxChainLength`) before any entry is
 * parsed, so an oversized chain costs nothing to refuse.
 */

import type { DidResolver } from './data-integrity.js';
import { verifyDelegationHop, invokerOf } from './hop.js';
import { parseDateTime } from './json-schema.js';
import { clockSkewMs, credentialSchemaViolations, describeViolations, windowVerdict } from './validation.js';
import type { Caveat, DelegationCredential, SignedDelegationHop } from './types.js';

export const MAX_DELEGATION_DEPTH = 10;

export type ChainRefusalCode =
  | 'chain_invalid'
  | 'delegation_malformed'
  | 'delegation_expired'
  | 'delegation_not_yet_valid'
  | 'untrusted_root'
  | 'configuration_error'
  | 'proof_invalid';

export interface EvaluateDelegationChainOptions {
  /** The resource the verifier is: the root's `invocationTarget` must equal it. */
  resource?: string;
  /** When asserted, the root's `issuer` must be this DID (the accountable resource owner). */
  resourceOwner?: string;
  /** Epoch ms; default `Date.now()`. */
  now?: number;
  /** Default {@link MAX_DELEGATION_DEPTH}; must be a positive integer. */
  maxChainLength?: number;
  /** 0 to 600,000 ms; default 120,000. */
  maxClockSkewMs?: number;
}

export interface DelegationChainEvaluation {
  ok: boolean;
  /** The code of the first rule broken; absent when `ok`. */
  code?: ChainRefusalCode;
  reasons: string[];
  /** `issuer(root)`: the accountable party. */
  responsibleParty?: string;
  /** The leaf delegate, which a verifier joins to the request proof's DID. */
  leafInvoker?: string;
  invocationTarget?: string;
  /** The leaf's `allowedAction`: the authority the chain grants. Empty when refused. */
  allowedAction: string[];
  depth: number;
}

interface BrokenRule {
  code: ChainRefusalCode;
  reason: string;
}

/** A non-negative decimal split into digit strings, or undefined when it is not one. */
function decimalParts(value: string): { whole: string; fraction: string } | undefined {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(value.trim());
  return match?.[1] ? { whole: match[1], fraction: match[2] ?? '' } : undefined;
}

/** `child <= parent` as exact decimals, never rounded; any unparseable value is false. */
export function decimalLte(child: string, parent: string): boolean {
  const c = decimalParts(child);
  const p = decimalParts(parent);
  if (!c || !p) return false;
  const scale = Math.max(c.fraction.length, p.fraction.length);
  const scaled = (part: { whole: string; fraction: string }): bigint => BigInt(part.whole + part.fraction.padEnd(scale, '0'));
  return scaled(c) <= scaled(p);
}

function dateLte(child: unknown, parent: unknown): boolean {
  const c = parseDateTime(child);
  const p = parseDateTime(parent);
  return c !== undefined && p !== undefined && c <= p;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, sortKeys(record[key])]),
    );
  }
  return value;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b));
}

/** True iff `child` is at least as narrow as `parent` for the same caveat type. */
export function caveatNarrows(parent: Caveat, child: Caveat): boolean {
  if (parent.type !== child.type) return false;
  if (parent.type === 'ValidUntil') {
    return typeof parent.date === 'string' && typeof child.date === 'string' && dateLte(child.date, parent.date);
  }
  if (parent.type === 'MaxAmount') {
    // A currency-less parent may be narrowed by a child that pins one; a
    // parent that pins a currency requires the same one.
    const currencyNarrows = parent.currency === undefined || parent.currency === child.currency;
    return (
      currencyNarrows &&
      typeof parent.limit === 'string' &&
      typeof child.limit === 'string' &&
      decimalLte(child.limit, parent.limit)
    );
  }
  return deepEqual(parent, child);
}

/** Every way `child` fails to attenuate `parent`; empty when the hop is a valid narrowing. */
export function attenuationReasons(parent: DelegationCredential, child: DelegationCredential): string[] {
  const p = parent.credentialSubject;
  const c = child.credentialSubject;
  const reasons: string[] = [];
  const parentActions = new Set(p.allowedAction);
  const escalated = c.allowedAction.filter((action) => !parentActions.has(action));
  if (escalated.length > 0) {
    reasons.push(`allowedAction escalation: [${escalated.join(', ')}] not in parent`);
  }
  for (const parentCaveat of p.caveats ?? []) {
    if (!(c.caveats ?? []).some((childCaveat) => caveatNarrows(parentCaveat, childCaveat))) {
      reasons.push(`caveat "${parentCaveat.type}" broadened or dropped by child`);
    }
  }
  if (!dateLte(child.validUntil, parent.validUntil)) {
    reasons.push('validUntil broadened: child must expire no later than its parent');
  }
  const delegate = invokerOf(parent);
  if (delegate === undefined || delegate !== child.issuer) {
    reasons.push('broken continuity: parent invoker is not the child issuer');
  }
  if (c.parentCapability !== p.id) {
    reasons.push('broken continuity: child parentCapability is not the parent capability id');
  }
  if (c.invocationTarget !== p.invocationTarget) {
    reasons.push('invocationTarget drift: the resource must be constant along the chain');
  }
  return reasons;
}

function rootRules(root: DelegationCredential, options: EvaluateDelegationChainOptions): BrokenRule[] {
  const subject = root.credentialSubject;
  const broken: BrokenRule[] = [];
  if (subject.parentCapability !== subject.invocationTarget) {
    broken.push({ code: 'chain_invalid', reason: 'root delegation: parentCapability must equal invocationTarget' });
  }
  if (options.resource !== undefined && subject.invocationTarget !== options.resource) {
    broken.push({ code: 'chain_invalid', reason: 'root invocationTarget is not the expected resource' });
  }
  if (options.resourceOwner !== undefined && root.issuer !== options.resourceOwner) {
    broken.push({ code: 'untrusted_root', reason: 'root issuer is not the resource owner' });
  }
  return broken;
}

function windowRules(chain: readonly DelegationCredential[], nowMs: number, maxClockSkewMs: number | undefined): BrokenRule[] {
  const broken: BrokenRule[] = [];
  chain.forEach((hop, index) => {
    const verdict = windowVerdict(hop.validFrom, hop.validUntil, nowMs, maxClockSkewMs);
    if (verdict === 'malformed') {
      broken.push({ code: 'delegation_malformed', reason: `hop ${index}: validFrom/validUntil is not an RFC 3339 date-time with offset` });
    } else if (verdict === 'expired') {
      broken.push({ code: 'delegation_expired', reason: `hop ${index}: expired (validUntil ${hop.validUntil} is in the past)` });
    } else if (verdict === 'not_yet_valid') {
      broken.push({ code: 'delegation_not_yet_valid', reason: `hop ${index}: not yet valid (validFrom ${hop.validFrom} is in the future)` });
    }
    for (const caveat of hop.credentialSubject.caveats ?? []) {
      if (caveat.type !== 'ValidUntil') continue;
      const caveatVerdict = windowVerdict(undefined, caveat.date, nowMs, maxClockSkewMs);
      if (caveatVerdict === 'malformed') {
        broken.push({ code: 'delegation_malformed', reason: `hop ${index}: ValidUntil caveat date is not an RFC 3339 date-time with offset` });
      } else if (caveatVerdict === 'expired') {
        broken.push({ code: 'delegation_expired', reason: `hop ${index}: expired caveat (ValidUntil ${String(caveat.date)} is in the past)` });
      }
    }
  });
  return broken;
}

const REFUSED: Pick<DelegationChainEvaluation, 'ok' | 'allowedAction'> = { ok: false, allowedAction: [] };

/**
 * Evaluates a chain of hops (root to leaf) against the attenuation, root,
 * continuity and window invariants. Pure: it reads the hops it is given and
 * nothing else. A refused chain reports every rule it breaks and the code
 * of the first; `allowedAction` is then empty, so nothing downstream can
 * read authority out of a refusal.
 */
export function evaluateDelegationChain(
  hops: unknown,
  options: EvaluateDelegationChainOptions = {},
): DelegationChainEvaluation {
  const maxChainLength = options.maxChainLength ?? MAX_DELEGATION_DEPTH;
  if (!Number.isInteger(maxChainLength) || maxChainLength < 1) {
    return { ...REFUSED, code: 'configuration_error', reasons: ['maxChainLength must be a positive integer'], depth: 0 };
  }
  if (clockSkewMs(options.maxClockSkewMs) === undefined) {
    return { ...REFUSED, code: 'configuration_error', reasons: ['maxClockSkewMs must be a number of milliseconds from 0 to 600000'], depth: 0 };
  }
  if (!Array.isArray(hops) || hops.length === 0) {
    return { ...REFUSED, code: 'chain_invalid', reasons: ['empty delegation chain'], depth: 0 };
  }
  // Bounded before any entry is parsed: an oversized chain is refused for its length alone.
  if (hops.length > maxChainLength) {
    return {
      ...REFUSED,
      code: 'chain_invalid',
      reasons: [`delegation chain depth ${hops.length} exceeds the maximum of ${maxChainLength}`],
      depth: hops.length,
    };
  }
  const malformed: BrokenRule[] = [];
  hops.forEach((hop, index) => {
    const violations = credentialSchemaViolations('hop', hop);
    if (violations.length > 0) {
      malformed.push({ code: 'delegation_malformed', reason: `hop ${index}: ${describeViolations(violations)}` });
    }
  });
  if (malformed.length > 0) {
    return { ...REFUSED, code: 'delegation_malformed', reasons: malformed.map((rule) => rule.reason), depth: hops.length };
  }
  const chain = hops as SignedDelegationHop[];
  const root = chain[0]!;
  const leaf = chain[chain.length - 1]!;
  const broken: BrokenRule[] = [...rootRules(root, options)];
  for (let index = 1; index < chain.length; index += 1) {
    for (const reason of attenuationReasons(chain[index - 1]!, chain[index]!)) {
      broken.push({ code: 'chain_invalid', reason: `hop ${index}: ${reason}` });
    }
  }
  broken.push(...windowRules(chain, options.now ?? Date.now(), options.maxClockSkewMs));
  const first = broken[0];
  return {
    ok: first === undefined,
    ...(first === undefined ? {} : { code: first.code }),
    reasons: broken.map((rule) => rule.reason),
    responsibleParty: root.issuer,
    ...(invokerOf(leaf) === undefined ? {} : { leafInvoker: invokerOf(leaf)! }),
    invocationTarget: leaf.credentialSubject.invocationTarget,
    allowedAction: first === undefined ? [...leaf.credentialSubject.allowedAction] : [],
    depth: chain.length,
  };
}

export type ChainProofVerification = { ok: true } | { ok: false; code: 'proof_invalid'; reasons: string[] };

/**
 * Every hop's proof, root to leaf, through the issuer's DID document,
 * stopping at the first refusal (SPEC-ENTITY-CARD.md §11.4: a hop's issuer
 * is its own word only once its proof holds). Reads DID documents through
 * the injected resolver and nothing else.
 */
export async function verifyDelegationChainProofs(
  hops: readonly unknown[],
  resolveDid: DidResolver,
): Promise<ChainProofVerification> {
  for (let index = 0; index < hops.length; index += 1) {
    const verdict = await verifyDelegationHop(hops[index], resolveDid);
    if (!verdict.ok) {
      return { ok: false, code: 'proof_invalid', reasons: [`hop ${index}: ${verdict.reason}: ${verdict.message}`] };
    }
  }
  return { ok: true };
}

/** An attestation as the scope it attests, whether given as a name or as a credential. */
export type AttestedCapability = string | { credentialSubject: { capability: string } };

export function attestedCapabilities(attestations: readonly AttestedCapability[]): string[] {
  const names: string[] = [];
  for (const attestation of attestations) {
    const name = typeof attestation === 'string' ? attestation : attestation.credentialSubject.capability;
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

/**
 * Enforcement scopes (story F-1 point 4): the three-way intersection of what
 * the agent is attested for, what the leaf hop allows and what the service
 * offers. Order follows the attestations; duplicates collapse. With no hops
 * (no delegation presented) `leafAllowedAction` is the caller's choice; an
 * empty array grants nothing.
 */
export function deriveEffectiveScopes(
  attestations: readonly AttestedCapability[],
  leafAllowedAction: readonly string[],
  catalog: readonly string[],
): string[] {
  const allowed = new Set(leafAllowedAction);
  const offered = new Set(catalog);
  return attestedCapabilities(attestations).filter((scope) => allowed.has(scope) && offered.has(scope));
}
