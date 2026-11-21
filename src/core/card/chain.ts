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
 * The structural reading of a DelegationCredential chain that the Entity
 * Card's accountability edge recomputes (SPEC-ENTITY-CARD §10.1, §10.2;
 * SPEC.md §6.10): `responsibleParty === issuer(rootVC)` and `leafInvoker ===
 * proof.did`, over a chain whose every hop attenuates its parent (actions a
 * subset, caveats monotone-narrowing, `validUntil` no later), keeps
 * continuity (parent invoker is child issuer, `parentCapability` names the
 * parent) and a constant `invocationTarget`, and whose every hop is inside
 * its validity window now. No I/O and no crypto: proofs and status are other
 * seams (F-1's `src/core/credentials/` evaluates signed chains in full).
 */

export interface DelegationCaveat {
  type: string;
  date?: string;
  limit?: string;
  currency?: string;
  [member: string]: unknown;
}

export interface DelegationHop {
  '@context'?: unknown;
  id?: string;
  type?: unknown;
  issuer: string | { id: string };
  validFrom?: string;
  validUntil?: string;
  credentialSubject: {
    id?: string;
    controller?: string;
    invoker?: string;
    parentCapability: string;
    invocationTarget: string;
    allowedAction: string[];
    caveats?: DelegationCaveat[];
    [member: string]: unknown;
  };
  [member: string]: unknown;
}

export interface DelegationChainContext {
  /** Asserted issuer of the root hop (the accountable resource owner). */
  resourceOwner?: string | undefined;
  /** Asserted `invocationTarget` of the root hop. */
  resource?: string | undefined;
  /** Epoch milliseconds for the validity window; default `Date.now()`. */
  now?: number | undefined;
  /** Clock tolerance on every window bound, milliseconds; default 120 000. */
  maxClockSkewMs?: number | undefined;
  maxChainLength?: number | undefined;
}

export interface DelegationChainResult {
  ok: boolean;
  reasons: string[];
  responsibleParty?: string;
  leafInvoker?: string;
  invocationTarget?: string;
  allowedAction: string[];
  depth: number;
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

function parseDateTime(value: unknown): number | undefined {
  if (typeof value !== 'string' || !RFC3339.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : ms;
}

function dateLte(child: string, parent: string): boolean {
  const c = parseDateTime(child);
  const p = parseDateTime(parent);
  return c !== undefined && p !== undefined && c <= p;
}

function decimalParts(dec: string): { whole: string; fraction: string } | undefined {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(dec.trim());
  return match?.[1] ? { whole: match[1], fraction: match[2] ?? '' } : undefined;
}

function decimalLte(child: string, parent: string): boolean {
  const c = decimalParts(child);
  const p = decimalParts(parent);
  if (!c || !p) return false;
  const scale = Math.max(c.fraction.length, p.fraction.length);
  const scaled = ({ whole, fraction }: { whole: string; fraction: string }): bigint => BigInt(whole + fraction.padEnd(scale, '0'));
  return scaled(c) <= scaled(p);
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, sortKeys(record[key])]));
  }
  return value;
}

function caveatNarrows(parent: DelegationCaveat, child: DelegationCaveat): boolean {
  if (parent.type !== child.type) return false;
  if (parent.type === 'ValidUntil') {
    return typeof parent.date === 'string' && typeof child.date === 'string' && dateLte(child.date, parent.date);
  }
  if (parent.type === 'MaxAmount') {
    const currencyNarrows = parent.currency === undefined || parent.currency === child.currency;
    return currencyNarrows && typeof parent.limit === 'string' && typeof child.limit === 'string' && decimalLte(child.limit, parent.limit);
  }
  return JSON.stringify(sortKeys(parent)) === JSON.stringify(sortKeys(child));
}

export function issuerDid(hop: DelegationHop): string | undefined {
  return typeof hop.issuer === 'string' ? hop.issuer : typeof hop.issuer?.id === 'string' ? hop.issuer.id : undefined;
}

export function invokerDid(hop: DelegationHop): string | undefined {
  return hop.credentialSubject.invoker ?? hop.credentialSubject.controller;
}

/** Why `child` fails to attenuate `parent` (empty: a valid hop). */
export function attenuates(parent: DelegationHop, child: DelegationHop): string[] {
  const p = parent.credentialSubject;
  const c = child.credentialSubject;
  const reasons: string[] = [];
  const parentActions = new Set(p.allowedAction);
  const escalated = c.allowedAction.filter((action) => !parentActions.has(action));
  if (escalated.length > 0) reasons.push(`allowedAction escalation: [${escalated.join(', ')}] not in parent`);
  for (const caveat of p.caveats ?? []) {
    if (!(c.caveats ?? []).some((candidate) => caveatNarrows(caveat, candidate))) {
      reasons.push(`caveat "${caveat.type}" broadened or dropped by child`);
    }
  }
  if (parent.validUntil !== undefined && (child.validUntil === undefined || !dateLte(child.validUntil, parent.validUntil))) {
    reasons.push('validUntil broadened: child must expire no later than its parent');
  }
  const delegate = invokerDid(parent);
  if (delegate === undefined || delegate !== issuerDid(child)) {
    reasons.push('broken continuity: parent invoker is not the child issuer');
  }
  if (c.parentCapability !== p.id) reasons.push('broken continuity: child.parentCapability is not the parent capability id');
  if (c.invocationTarget !== p.invocationTarget) reasons.push('invocationTarget drift along the chain');
  return reasons;
}

function windowReasons(hop: DelegationHop, position: number, now: number, skewMs: number): string[] {
  const reasons: string[] = [];
  const bounds: [string, unknown, 'from' | 'until'][] = [
    ['validFrom', hop.validFrom, 'from'],
    ['validUntil', hop.validUntil, 'until'],
    ...(hop.credentialSubject.caveats ?? [])
      .filter((caveat) => caveat.type === 'ValidUntil')
      .map((caveat): [string, unknown, 'until'] => ['ValidUntil caveat', caveat.date, 'until']),
  ];
  for (const [name, value, kind] of bounds) {
    if (value === undefined) continue;
    const bound = parseDateTime(value);
    if (bound === undefined) {
      reasons.push(`hop ${position}: ${name} is not an RFC 3339 date-time with its offset`);
    } else if (kind === 'until' && now > bound + skewMs) {
      reasons.push(`hop ${position}: expired (${name})`);
    } else if (kind === 'from' && now < bound - skewMs) {
      reasons.push(`hop ${position}: not yet valid (${name})`);
    }
  }
  return reasons;
}

/** Structural validation of a chain, root first, fail-closed. */
export function validateDelegationChain(chain: readonly DelegationHop[], ctx: DelegationChainContext = {}): DelegationChainResult {
  const depth = chain.length;
  if (depth === 0) return { ok: false, reasons: ['empty delegation chain'], allowedAction: [], depth };
  const root = chain[0]!;
  const leaf = chain[depth - 1]!;
  const reasons: string[] = [];
  if (ctx.maxChainLength !== undefined && depth > ctx.maxChainLength) {
    reasons.push(`delegation chain depth ${depth} exceeds the maximum of ${ctx.maxChainLength}`);
  }
  const subject = root.credentialSubject;
  if (subject.parentCapability !== subject.invocationTarget) {
    reasons.push('root delegation: parentCapability must equal invocationTarget');
  }
  if (ctx.resource !== undefined && subject.invocationTarget !== ctx.resource) {
    reasons.push('root invocationTarget is not the expected resource');
  }
  if (ctx.resourceOwner !== undefined && issuerDid(root) !== ctx.resourceOwner) {
    reasons.push('root issuer is not the resource owner');
  }
  for (let i = 1; i < depth; i += 1) reasons.push(...attenuates(chain[i - 1]!, chain[i]!));
  const now = ctx.now ?? Date.now();
  const skewMs = ctx.maxClockSkewMs ?? 120_000;
  chain.forEach((hop, position) => reasons.push(...windowReasons(hop, position, now, skewMs)));
  return {
    ok: reasons.length === 0,
    reasons,
    ...(issuerDid(root) === undefined ? {} : { responsibleParty: issuerDid(root)! }),
    ...(invokerDid(leaf) === undefined ? {} : { leafInvoker: invokerDid(leaf)! }),
    invocationTarget: leaf.credentialSubject.invocationTarget,
    allowedAction: [...leaf.credentialSubject.allowedAction],
    depth,
  };
}
