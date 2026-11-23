// Copyright 2026 DgVerse LLP
// KYA-OS conformance vectors for the Entity Card layer (story C-A), vendored from
// decentralized-identity/kya-os-mcp at a4d7f61 (suite 1.10.0) under fixtures/kya-os/.
//
// entity-card.json: every vector's card through parseEntityCard + verifyEntityCard, the
// accountability input (when given) wired through makeAccountabilityVerifier as the upstream
// reference adapter wires it; a malformed card, a card declaring revocation with nothing to
// check it, and a broken leaf/proof join must each fail.
// did-web-resolution.json: every vector's document served under the DID's well-known URL to the
// card resolver's first step; a document of another id, or none, must fail closed before any card
// is read, and the valid one resolves on to its card.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  EntityCardInvalidError,
  HelixError,
  buildEntityCard,
  makeAccountabilityVerifier,
  parseEntityCard,
  resolveEntityCard,
  verifyEntityCard,
  type DelegationHop,
  type OutboundFetch,
  type VerifyEntityCardDeps,
} from '../../../src/core/index.js';

const VENDORED = fileURLToPath(new URL('../../../fixtures/kya-os/', import.meta.url));

interface Vector<I> {
  id: string;
  expected: 'pass' | 'fail';
  reason: string;
  input: I;
}

interface EntityCardInput {
  card: unknown;
  trustedIssuers?: string[];
  cimdKeyProven?: boolean;
  accountability?: { resourceOwner: string; resource?: string; chain: DelegationHop[]; proofDid?: string; now?: number };
}

function load<I>(name: string): { version: string; category: string; vectors: Vector<I>[] } {
  return JSON.parse(readFileSync(`${VENDORED}conformance/vectors/${name}`, 'utf8'));
}

function sha256(name: string): string {
  return createHash('sha256').update(readFileSync(`${VENDORED}conformance/vectors/${name}`)).digest('hex');
}

/** The reference adapter's verifyEntityCard: parse (a throw fails), then verify; ok decides. */
async function verifyVector(input: EntityCardInput): Promise<{ outcome: 'pass' | 'fail'; detail?: string }> {
  try {
    const card = parseEntityCard(input.card);
    const deps: VerifyEntityCardDeps = {
      ...(input.trustedIssuers ? { trustedIssuers: input.trustedIssuers } : {}),
      ...(input.accountability ? { accountabilityVerifier: makeAccountabilityVerifier(input.accountability) } : {}),
    };
    const result = await verifyEntityCard(card, deps);
    return result.ok ? { outcome: 'pass' } : { outcome: 'fail', detail: `card rejected (level ${result.conformanceLevel}, ${result.code})` };
  } catch (error) {
    return { outcome: 'fail', detail: (error as Error).message };
  }
}

describe('vendored vector files are the pinned ones', () => {
  it('match SUITE-MANIFEST.json', () => {
    const manifest = JSON.parse(readFileSync(`${VENDORED}conformance/SUITE-MANIFEST.json`, 'utf8')) as { suiteVersion: string; files: [string, string][] };
    expect(manifest.suiteVersion).toBe('1.10.0');
    for (const name of ['entity-card.json', 'did-web-resolution.json']) {
      expect(sha256(name), name).toBe(manifest.files.find(([file]) => file === name)![1]);
    }
  });
});

describe('entity-card.json (Entity Card parseCard + verifyCard)', () => {
  const file = load<EntityCardInput>('entity-card.json');

  it('has the eight pinned vectors', () => {
    expect(file.category).toBe('entity-card');
    expect(file.vectors.map((v) => v.id)).toEqual([
      'entity-card/mcp-valid',
      'entity-card/client-valid',
      'entity-card/verifier-valid',
      'entity-card/human-valid',
      'entity-card/agent-accountable',
      'entity-card/revocation-unchecked',
      'entity-card/malformed-unknown-field',
      'entity-card/accountability-join-broken',
    ]);
  });

  for (const vector of file.vectors) {
    it(`${vector.id}: ${vector.reason}`, async () => {
      const verdict = await verifyVector(vector.input);
      expect(verdict.outcome, verdict.detail).toBe(vector.expected);
    });
  }

  it('malformed-unknown-field is refused by the strict schema with the field named', () => {
    const malformed = file.vectors.find((v) => v.id === 'entity-card/malformed-unknown-field')!;
    expect(() => parseEntityCard(malformed.input.card)).toThrow(EntityCardInvalidError);
    try {
      parseEntityCard(malformed.input.card);
    } catch (error) {
      expect((error as EntityCardInvalidError).details).toEqual({ issues: [{ path: '/bogusField', message: 'must NOT have additional properties' }] });
    }
  });

  it('revocation-unchecked fails as configuration_error and passes once a checker reads the list clear', async () => {
    const vector = file.vectors.find((v) => v.id === 'entity-card/revocation-unchecked')!;
    const card = parseEntityCard(vector.input.card);
    const accountabilityVerifier = makeAccountabilityVerifier(vector.input.accountability!);
    expect(await verifyEntityCard(card, { accountabilityVerifier })).toMatchObject({ ok: false, code: 'configuration_error', conformanceLevel: 'L1' });
    expect(await verifyEntityCard(card, { accountabilityVerifier, statusListChecker: async () => ({ revoked: false, fresh: true }) })).toMatchObject({ ok: true });
    expect(await verifyEntityCard(card, { accountabilityVerifier, statusListChecker: async () => ({ revoked: true, fresh: true }) })).toMatchObject({ ok: false, conformanceLevel: 'L1' });
  });

  it('a self-declared conformanceLevel is never trusted: the level is recomputed', async () => {
    const agent = file.vectors.find((v) => v.id === 'entity-card/agent-accountable')!;
    const card = parseEntityCard({ ...(agent.input.card as object), conformanceLevel: 'L3' });
    const result = await verifyEntityCard(card, { accountabilityVerifier: makeAccountabilityVerifier(agent.input.accountability!) });
    expect(result).toMatchObject({ ok: true, conformanceLevel: 'L1' });
    const rebuilt = buildEntityCard({ ...(agent.input.card as object), conformanceLevel: 'L3' } as never);
    expect('conformanceLevel' in rebuilt).toBe(false);
  });
});

describe('did-web-resolution.json through the card resolver', () => {
  const file = load<{ did: string; didDocument?: Record<string, unknown> }>('did-web-resolution.json');
  const card = (did: string) => buildEntityCard({ id: did, entityType: 'agent', name: 'Vector agent' });

  it('has the three pinned vectors', () => {
    expect(file.vectors.map((v) => v.id)).toEqual(['did-web/valid', 'did-web/id-mismatch', 'did-web/not-found']);
  });

  for (const vector of file.vectors) {
    it(`${vector.id}: ${vector.reason}`, async () => {
      const urls: string[] = [];
      const fetchLike: OutboundFetch = async (url) => {
        urls.push(url);
        if (url === 'https://agent.example.com/.well-known/did.json') {
          return vector.input.didDocument === undefined ? new Response('not found', { status: 404 }) : new Response(JSON.stringify(vector.input.didDocument), { status: 200 });
        }
        if (url === 'https://agent.example.com/.well-known/kya-os-card.json') return new Response(JSON.stringify(card(vector.input.did)), { status: 200 });
        return new Response('not found', { status: 404 });
      };
      if (vector.expected === 'pass') {
        const resolved = await resolveEntityCard(vector.input.did, { fetch: fetchLike });
        expect(resolved.card.id).toBe(vector.input.did);
        expect(resolved.didDocument).toEqual(vector.input.didDocument);
        expect(urls).toEqual(['https://agent.example.com/.well-known/did.json', 'https://agent.example.com/.well-known/kya-os-card.json']);
      } else {
        await expect(resolveEntityCard(vector.input.did, { fetch: fetchLike })).rejects.toBeInstanceOf(HelixError);
        expect(urls, 'fails closed before any card is read').toEqual(['https://agent.example.com/.well-known/did.json']);
      }
    });
  }
});
