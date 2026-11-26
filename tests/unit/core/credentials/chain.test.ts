// Copyright 2026 DgVerse LLP
// KYA-OS story F-1: the delegation chain evaluator, attenuation invariants and the three-way intersection.
import { describe, expect, it } from 'vitest';
import {
  EnvSigner,
  MAX_DELEGATION_DEPTH,
  attenuationReasons,
  attestedCapabilities,
  buildDelegationHop,
  caveatNarrows,
  decimalLte,
  derivePublicKey,
  deriveEffectiveScopes,
  evaluateDelegationChain,
  publicKeyToMultibase,
  rootHopInput,
  verifyDelegationChainProofs,
  type BitstringStatusEntry,
  type DIDDocument,
  type SignedDelegationHop,
} from '../../../../src/core/index.js';
import type { DidResolver } from '../../../../src/core/credentials/index.js';
import { testDidDocument } from '../../../utils/didDocuments.js';

function omit<T extends object, K extends keyof T>(value: T, key: K): Omit<T, K> {
  const copy = { ...value };
  delete copy[key];
  return copy;
}

const NOW = Date.parse('2026-06-01T00:00:00Z');
const RESOURCE = 'did:web:service.example:orders';

function actor(seed: string): { did: string; signer: EnvSigner; document: DIDDocument } {
  const key = seed.repeat(64).slice(0, 64);
  const did = `did:key:${publicKeyToMultibase(derivePublicKey(key))}`;
  return { did, signer: new EnvSigner({ did, envVar: 'K', env: { K: key } }), document: testDidDocument(did, derivePublicKey(key)) };
}
const user = actor('a');
const parent = actor('b');
const child = actor('c');
const documents = Object.fromEntries([user, parent, child].map((a) => [a.did, a.document]));
const resolve = (async (did: string) => documents[did]) as unknown as DidResolver;
const entry = (index: number): BitstringStatusEntry => ({ type: 'BitstringStatusListEntry', statusPurpose: 'revocation', statusListIndex: String(index), statusListCredential: 'https://helix.example/status/1' });

async function chain(): Promise<[SignedDelegationHop, SignedDelegationHop]> {
  const root = await buildDelegationHop(
    rootHopInput({ invoker: parent.did, invocationTarget: RESOURCE, allowedAction: ['read:orders', 'write:orders'], caveats: [{ type: 'MaxAmount', limit: '100', currency: 'USD' }], validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z', statusEntry: entry(1), id: 'urn:zcap:root' }),
    user.signer,
  );
  const leaf = await buildDelegationHop(
    { invoker: child.did, parentCapability: 'urn:zcap:root', invocationTarget: RESOURCE, allowedAction: ['read:orders'], caveats: [{ type: 'MaxAmount', limit: '50', currency: 'USD' }], validUntil: '2026-12-01T00:00:00Z', statusEntry: entry(2), id: 'urn:zcap:leaf' },
    parent.signer,
  );
  return [root, leaf];
}

describe('evaluateDelegationChain', () => {
  it('accepts a chain whose every hop attenuates its parent and reports the join', async () => {
    const hops = await chain();
    const evaluation = evaluateDelegationChain(hops, { resource: RESOURCE, now: NOW });
    expect(evaluation).toEqual({
      ok: true,
      reasons: [],
      responsibleParty: user.did,
      leafInvoker: child.did,
      invocationTarget: RESOURCE,
      allowedAction: ['read:orders'],
      depth: 2,
    });
    expect(evaluateDelegationChain(hops, { resource: RESOURCE, resourceOwner: user.did, now: NOW }).ok).toBe(true);
    expect(evaluateDelegationChain(hops, { now: NOW }).ok).toBe(true);
  });

  it('is bounded before any entry is parsed: an oversized chain of junk is refused for its length alone', () => {
    const junk = Array.from({ length: MAX_DELEGATION_DEPTH + 1 }, () => 'not a hop');
    expect(evaluateDelegationChain(junk, { now: NOW })).toMatchObject({ ok: false, code: 'chain_invalid', depth: 11, allowedAction: [] });
    expect(evaluateDelegationChain(junk, { now: NOW }).reasons).toEqual(['delegation chain depth 11 exceeds the maximum of 10']);
    expect(evaluateDelegationChain(['x', 'y'], { maxChainLength: 1, now: NOW })).toMatchObject({ ok: false, code: 'chain_invalid' });
    expect(evaluateDelegationChain(['x'], { maxChainLength: 0, now: NOW })).toMatchObject({ ok: false, code: 'configuration_error' });
    expect(evaluateDelegationChain(['x'], { maxChainLength: 1.5, now: NOW })).toMatchObject({ ok: false, code: 'configuration_error' });
    expect(evaluateDelegationChain(['x'], { maxClockSkewMs: -1, now: NOW })).toMatchObject({ ok: false, code: 'configuration_error' });
  });

  it('refuses an empty or non-array chain and a malformed hop, naming the hop', async () => {
    expect(evaluateDelegationChain([], { now: NOW })).toMatchObject({ ok: false, code: 'chain_invalid', reasons: ['empty delegation chain'], depth: 0 });
    expect(evaluateDelegationChain('nope', { now: NOW })).toMatchObject({ ok: false, code: 'chain_invalid' });
    const [root, leaf] = await chain();
    const refused = evaluateDelegationChain([root, { ...leaf, credentialSubject: { ...leaf.credentialSubject, scopes: ['x'] } }], { now: NOW });
    expect(refused).toMatchObject({ ok: false, code: 'delegation_malformed', depth: 2, allowedAction: [] });
    expect(refused.reasons[0]).toMatch(/^hop 1: \$\.credentialSubject\.scopes/);
    expect(refused.responsibleParty).toBeUndefined();
  });

  it('refuses every broadening or broken hop with every reason, and the code of the first', async () => {
    const [root, leaf] = await chain();
    const subject = leaf.credentialSubject;
    const at = (hops: unknown[], options = {}) => evaluateDelegationChain(hops, { resource: RESOURCE, now: NOW, ...options });
    const broadened = at([root, { ...leaf, credentialSubject: { ...subject, allowedAction: ['read:orders', 'admin:all'] } }]);
    expect(broadened).toMatchObject({ ok: false, code: 'chain_invalid', allowedAction: [] });
    expect(broadened.reasons).toEqual(['hop 1: allowedAction escalation: [admin:all] not in parent']);
    expect(at([root, { ...leaf, credentialSubject: { ...subject, caveats: [] } }]).reasons).toEqual(['hop 1: caveat "MaxAmount" broadened or dropped by child']);
    expect(at([root, { ...leaf, validUntil: '2027-06-01T00:00:00Z' }]).reasons).toEqual(['hop 1: validUntil broadened: child must expire no later than its parent']);
    expect(at([root, { ...leaf, issuer: child.did }]).reasons).toEqual(['hop 1: broken continuity: parent invoker is not the child issuer']);
    expect(at([root, { ...leaf, credentialSubject: { ...subject, parentCapability: 'urn:zcap:other' } }]).reasons).toEqual(['hop 1: broken continuity: child parentCapability is not the parent capability id']);
    expect(at([root, { ...leaf, credentialSubject: { ...subject, invocationTarget: 'did:web:other' } }]).reasons).toEqual(['hop 1: invocationTarget drift: the resource must be constant along the chain']);
    const everything = at([root, { ...leaf, issuer: child.did, validUntil: '2027-06-01T00:00:00Z', credentialSubject: { ...subject, allowedAction: ['x'], caveats: [], parentCapability: 'p', invocationTarget: 't' } }]);
    expect(everything.reasons).toHaveLength(6);
    // Root rules.
    expect(at([{ ...root, credentialSubject: { ...root.credentialSubject, parentCapability: 'urn:zcap:x' } }]).reasons).toEqual(['root delegation: parentCapability must equal invocationTarget']);
    expect(at([root], { resource: 'did:web:other' }).reasons).toEqual(['root invocationTarget is not the expected resource']);
    expect(at([root], { resourceOwner: parent.did })).toMatchObject({ ok: false, code: 'untrusted_root', reasons: ['root issuer is not the resource owner'] });
    // A parent that names no delegate cannot be continued.
    const rootSubject = omit(root.credentialSubject, 'invoker');
    expect(at([{ ...root, credentialSubject: rootSubject }, leaf]).code).toBe('delegation_malformed');
  });

  it('refuses hops outside their window and malformed dates, holding each bound with the skew', async () => {
    const [root, leaf] = await chain();
    const at = (now: string, hops: unknown[] = [root, leaf], options = {}) => evaluateDelegationChain(hops, { now: Date.parse(now), ...options });
    expect(at('2026-12-01T00:01:59Z').ok).toBe(true);
    expect(at('2026-12-01T00:02:01Z')).toMatchObject({ ok: false, code: 'delegation_expired', reasons: ['hop 1: expired (validUntil 2026-12-01T00:00:00Z is in the past)'] });
    expect(at('2025-12-31T23:57:59Z')).toMatchObject({ ok: false, code: 'delegation_not_yet_valid', reasons: ['hop 0: not yet valid (validFrom 2026-01-01T00:00:00Z is in the future)'] });
    expect(at('2026-12-01T00:00:30Z', [root, leaf], { maxClockSkewMs: 0 })).toMatchObject({ ok: false, code: 'delegation_expired' });
    const withCaveat = { ...leaf, credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'MaxAmount', limit: '50', currency: 'USD' }, { type: 'ValidUntil', date: '2026-03-01T00:00:00Z' }] } };
    expect(at('2026-06-01T00:00:00Z', [root, withCaveat])).toMatchObject({ ok: false, code: 'delegation_expired', reasons: ['hop 1: expired caveat (ValidUntil 2026-03-01T00:00:00Z is in the past)'] });
    const malformedCaveat = { ...leaf, credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'MaxAmount', limit: '50', currency: 'USD' }, { type: 'ValidUntil', date: 'soon' }] } };
    expect(at('2026-06-01T00:00:00Z', [root, malformedCaveat]).code).toBe('delegation_malformed');
    expect(at('2026-06-01T00:00:00Z', [root, { ...leaf, validUntil: '2026-12-01T00:00:00Z', validFrom: '2026-01-01T00:00:00' }]).code).toBe('delegation_malformed');
    // A ValidUntil caveat that states no date bounds nothing and is not a window rule.
    expect(at('2026-06-01T00:00:00Z', [root, { ...leaf, credentialSubject: { ...leaf.credentialSubject, caveats: [{ type: 'MaxAmount', limit: '50', currency: 'USD' }, { type: 'ValidUntil' }] } }]).ok).toBe(true);
  });

  it('reads the clock from the wall when none is injected', async () => {
    const hops = await chain();
    expect(evaluateDelegationChain(hops).ok).toBe(true);
  });
});

describe('attenuation helpers', () => {
  it('decimalLte compares exact decimals, never rounding', () => {
    expect(decimalLte('100', '100')).toBe(true);
    expect(decimalLte('99.999999999', '100')).toBe(true);
    expect(decimalLte('100.0000009', '100')).toBe(false);
    expect(decimalLte('1e2', '100')).toBe(false);
    expect(decimalLte('100', '-1')).toBe(false);
    expect(decimalLte(' 5 ', '5.0')).toBe(true);
  });

  it('caveatNarrows: ValidUntil, MaxAmount with currency rules, unknown types verbatim', () => {
    expect(caveatNarrows({ type: 'ValidUntil', date: '2027-01-01T00:00:00Z' }, { type: 'ValidUntil', date: '2026-01-01T00:00:00Z' })).toBe(true);
    expect(caveatNarrows({ type: 'ValidUntil', date: '2026-01-01T00:00:00Z' }, { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' })).toBe(false);
    expect(caveatNarrows({ type: 'ValidUntil' }, { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' })).toBe(false);
    expect(caveatNarrows({ type: 'ValidUntil', date: '2027-01-01T00:00:00Z' }, { type: 'MaxAmount', limit: '1' })).toBe(false);
    expect(caveatNarrows({ type: 'MaxAmount', limit: '10' }, { type: 'MaxAmount', limit: '5', currency: 'USD' })).toBe(true);
    expect(caveatNarrows({ type: 'MaxAmount', limit: '10', currency: 'USD' }, { type: 'MaxAmount', limit: '5' })).toBe(false);
    expect(caveatNarrows({ type: 'MaxAmount', limit: '10', currency: 'USD' }, { type: 'MaxAmount', limit: '5', currency: 'EUR' })).toBe(false);
    expect(caveatNarrows({ type: 'MaxAmount', currency: 'USD' }, { type: 'MaxAmount', limit: '5', currency: 'USD' })).toBe(false);
    expect(caveatNarrows({ type: 'MaxAmount', limit: '10', currency: 'USD' }, { type: 'MaxAmount', currency: 'USD' })).toBe(false);
    expect(caveatNarrows({ type: 'Region', regions: ['EU'] }, { type: 'Region', regions: ['EU'] })).toBe(true);
    expect(caveatNarrows({ type: 'Region', regions: ['EU'] }, { type: 'Region', regions: ['EU', 'US'] })).toBe(false);
  });

  it('attenuationReasons lists each broken invariant', async () => {
    const [root, leaf] = await chain();
    expect(attenuationReasons(root, leaf)).toEqual([]);
    expect(attenuationReasons(root, { ...leaf, validUntil: 'soon' })).toEqual(['validUntil broadened: child must expire no later than its parent']);
  });
});

describe('verifyDelegationChainProofs', () => {
  it('verifies every hop root to leaf through the resolver and stops at the first refusal', async () => {
    const [root, leaf] = await chain();
    expect(await verifyDelegationChainProofs([root, leaf], resolve)).toEqual({ ok: true });
    const tampered = { ...leaf, credentialSubject: { ...leaf.credentialSubject, allowedAction: ['write:orders'] } };
    const refused = await verifyDelegationChainProofs([root, tampered], resolve);
    expect(refused).toMatchObject({ ok: false, code: 'proof_invalid' });
    expect((refused as { reasons: string[] }).reasons[0]).toMatch(/^hop 1: signature_invalid/);
    expect(await verifyDelegationChainProofs([{ ...root, credentialSubject: { ...root.credentialSubject, extra: 1 } }, leaf], resolve)).toMatchObject({ ok: false });
    expect(await verifyDelegationChainProofs([], resolve)).toEqual({ ok: true });
  });
});

describe('deriveEffectiveScopes', () => {
  it('is attestations ∩ leaf allowedAction ∩ catalog, in attestation order, duplicates collapsed', () => {
    expect(deriveEffectiveScopes(['read:orders', 'write:orders', 'read:catalog'], ['read:orders', 'read:catalog'], ['read:catalog', 'read:orders'])).toEqual(['read:orders', 'read:catalog']);
    expect(deriveEffectiveScopes(['read:orders'], ['read:orders'], ['write:orders'])).toEqual([]);
    expect(deriveEffectiveScopes(['read:orders'], [], ['read:orders'])).toEqual([]);
    expect(deriveEffectiveScopes([], ['read:orders'], ['read:orders'])).toEqual([]);
    expect(deriveEffectiveScopes(['a', 'a', 'b'], ['a', 'b'], ['a', 'b'])).toEqual(['a', 'b']);
    const attestation = { credentialSubject: { capability: 'read:orders' } };
    expect(deriveEffectiveScopes([attestation, 'read:orders', 'x'], ['read:orders', 'x'], ['read:orders', 'x'])).toEqual(['read:orders', 'x']);
    expect(attestedCapabilities([attestation, 'b'])).toEqual(['read:orders', 'b']);
  });
});
