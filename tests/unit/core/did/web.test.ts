// Copyright 2026 DgVerse LLP
// KYA-OS story C-A: did:web issuance, URL derivation, and the card service entry on the DID document.
import { describe, expect, it } from 'vitest';
import {
  KYA_OS_CARD_SERVICE_ID,
  KYA_OS_CARD_SERVICE_TYPE,
  buildDidDocument,
  cardEndpointOf,
  didWebCardUrl,
  didWebDocumentUrl,
  didWebFor,
  didWebFromPath,
  isBareDidWeb,
  isLoopbackHost,
  issueDidWeb,
  kyaOsCardServiceEntry,
  normalizeDid,
  parseDidWeb,
  publicKeyBytesToJwk,
  sameDid,
  withKyaOsCardService,
} from '../../../../src/core/index.js';

const JWK = publicKeyBytesToJwk(new Uint8Array(32).fill(7));

describe('did:web issuance and parsing', () => {
  it('issues did:web:<host>:<org>:<slug>, did:web:<host>:<org> and the bare host, percent-encoding each segment', () => {
    expect(issueDidWeb({ host: 'helix.test', org: 'acme', slug: 'ledger-agent' })).toBe('did:web:helix.test:acme:ledger-agent');
    expect(issueDidWeb({ host: 'Helix.Test', org: 'acme' })).toBe('did:web:helix.test:acme');
    expect(issueDidWeb({ host: 'helix.test' })).toBe('did:web:helix.test');
    expect(issueDidWeb({ host: 'localhost:3000', org: 'acme', slug: 'a b' })).toBe('did:web:localhost%3A3000:acme:a%20b');
    expect(didWebFor('helix.test', ['acme', 'alice:agent'])).toBe('did:web:helix.test:acme:alice%3Aagent');
    expect(() => issueDidWeb({ host: 'helix.test', slug: 'orphan' })).toThrow(/org segment/);
    expect(() => didWebFor('helix.test/path')).toThrow(/host/);
    expect(() => didWebFor('helix.test', [''])).toThrow(/segment/);
    expect(() => didWebFor('helix.test', ['..'])).toThrow(/segment/);
  });

  it('parses what it issues and refuses what names no URL', () => {
    expect(parseDidWeb('did:web:localhost%3A3000:acme:a%20b')).toEqual({ host: 'localhost:3000', path: ['acme', 'a b'] });
    expect(parseDidWeb('did:web:helix.test')).toEqual({ host: 'helix.test', path: [] });
    expect(isBareDidWeb('did:web:helix.test')).toBe(true);
    expect(isBareDidWeb('did:web:helix.test:acme')).toBe(false);
    for (const bad of ['did:key:z6Mk', 'did:web:', 'did:web:helix.test::acme', 'did:web:helix.test:acme:%2E%2E', 'did:web:helix.test:a%2Fb', 'did:web:helix.test%2Fpath', 'did:web:helix.test:%E0%A4%A', 42]) {
      expect(parseDidWeb(bad as string), String(bad)).toBeUndefined();
    }
  });

  it('derives the document and card URLs, with the well-known fallback for a bare host', () => {
    expect(didWebDocumentUrl('did:web:helix.test:acme:ledger-agent')).toBe('https://helix.test/acme/ledger-agent/did.json');
    expect(didWebCardUrl('did:web:helix.test:acme:ledger-agent')).toBe('https://helix.test/acme/ledger-agent/card.json');
    expect(didWebDocumentUrl('did:web:helix.test')).toBe('https://helix.test/.well-known/did.json');
    expect(didWebCardUrl('did:web:helix.test')).toBe('https://helix.test/.well-known/kya-os-card.json');
    expect(didWebCardUrl('did:web:localhost%3A3000:acme:a%20b'), 'a loopback host serves plain http').toBe('http://localhost:3000/acme/a%20b/card.json');
    expect(didWebDocumentUrl('did:web:127.0.0.1%3A3580')).toBe('http://127.0.0.1:3580/.well-known/did.json');
    expect(isLoopbackHost('[::1]:3000')).toBe(true);
    expect(isLoopbackHost('helix.test')).toBe(false);
    expect(() => didWebCardUrl('did:key:z6Mk')).toThrow(/did:web/);
  });

  it('maps a served path back to the DID it names', () => {
    expect(didWebFromPath('helix.test', '/acme/ledger-agent/did.json')).toEqual({ did: 'did:web:helix.test:acme:ledger-agent', document: 'did' });
    expect(didWebFromPath('helix.test', '/acme/card.json')).toEqual({ did: 'did:web:helix.test:acme', document: 'card' });
    expect(didWebFromPath('helix.test', '/.well-known/did.json')).toEqual({ did: 'did:web:helix.test', document: 'did' });
    expect(didWebFromPath('helix.test', '/.well-known/kya-os-card.json')).toEqual({ did: 'did:web:helix.test', document: 'card' });
    expect(didWebFromPath('localhost:3000', '/acme/a%20b/did.json')).toEqual({ did: 'did:web:localhost%3A3000:acme:a%20b', document: 'did' });
    for (const path of ['/v1/agents', '/acme/did.jsonx', '/did.json', '//did.json', '/a/../did.json', '/.well-known/x/did.json', '/a/%E0%A4%A/did.json', '/a//card.json']) {
      expect(didWebFromPath('helix.test', path), path).toBeUndefined();
    }
  });

  it('compares DIDs by one spelling', () => {
    expect(normalizeDid('did:web:Helix.Test:acme:a%20b')).toBe('did:web:helix.test:acme:a%20b');
    expect(normalizeDid('did:web:localhost%3a3000:x')).toBe('did:web:localhost%3A3000:x');
    expect(normalizeDid('did:key:z6MkABC')).toBe('did:key:z6MkABC');
    expect(sameDid('did:web:HELIX.test', 'did:web:helix.test')).toBe(true);
    expect(sameDid('did:web:helix.test:users:alice%3Aagent', 'did:web:helix.test:users:alice:agent')).toBe(false);
    expect(sameDid('did:web:helix.test:%E0%A4%A', 'did:web:helix.test:%E0%A4%A')).toBe(false);
    expect(sameDid('did:key:z6MkABC', 'did:key:z6MkABc')).toBe(false);
  });
});

describe('the KyaOsEntityCard service entry', () => {
  it('builds the entry and refuses a non-URL endpoint', () => {
    expect(kyaOsCardServiceEntry('https://helix.test/acme/card.json')).toEqual({ id: KYA_OS_CARD_SERVICE_ID, type: KYA_OS_CARD_SERVICE_TYPE, serviceEndpoint: 'https://helix.test/acme/card.json' });
    expect(() => kyaOsCardServiceEntry('card.json')).toThrow(/https URL/);
    expect(() => kyaOsCardServiceEntry('ftp://helix.test/card.json')).toThrow(/https URL/);
  });

  it('is added by buildDidDocument, derived from the DID or named, replacing an older entry and keeping other services', () => {
    const did = 'did:web:helix.test:acme:ledger-agent';
    const derived = buildDidDocument({ did, publicKeyJwk: JWK, cardServiceEndpoint: true, alsoKnownAs: ['did:hedera:testnet:z123_0.0.1'] });
    expect(derived.service).toEqual([{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://helix.test/acme/ledger-agent/card.json' }]);
    expect(derived.alsoKnownAs).toEqual(['did:hedera:testnet:z123_0.0.1']);
    expect(cardEndpointOf(derived)).toBe('https://helix.test/acme/ledger-agent/card.json');

    const named = buildDidDocument({
      did,
      publicKeyJwk: JWK,
      service: [{ id: '#home', type: 'LinkedDomains', serviceEndpoint: 'https://acme.example' }, { id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://old.example/card.json' }, 'odd'],
      cardServiceEndpoint: 'http://localhost:3000/acme/ledger-agent/card.json',
    });
    expect(named.service).toEqual([
      { id: '#home', type: 'LinkedDomains', serviceEndpoint: 'https://acme.example' },
      'odd',
      { id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'http://localhost:3000/acme/ledger-agent/card.json' },
    ]);
    expect(buildDidDocument({ did, publicKeyJwk: JWK }).service).toBeUndefined();
    expect(buildDidDocument({ did, publicKeyJwk: JWK, service: [] }).service).toBeUndefined();
    expect(withKyaOsCardService(undefined, 'did:web:helix.test')).toEqual([{ id: '#kya-os-card', type: 'KyaOsEntityCard', serviceEndpoint: 'https://helix.test/.well-known/kya-os-card.json' }]);
  });

  it('reads no endpoint from a document without one', () => {
    expect(cardEndpointOf({ service: [{ type: 'KyaOsEntityCard', serviceEndpoint: 42 }, { type: 'LinkedDomains', serviceEndpoint: 'https://x' }] })).toBeUndefined();
    expect(cardEndpointOf({ service: 'none' })).toBeUndefined();
    expect(cardEndpointOf(null)).toBeUndefined();
  });
});
