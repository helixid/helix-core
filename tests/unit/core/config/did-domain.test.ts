// Copyright 2026 DgVerse LLP
// One did:web shape (2026-11-23): DID_DOMAIN is the raw host[:port] and the
// Helix issuer is didWebFor(DID_DOMAIN), its port percent-encoded once.
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../../../../src/core/config/index.js';

const BASE = { HELIX_SIGNING_KEY: '11deb8f4b8f2e1c0a9d7c6b5a4938271605f4e3d2c1b0a998877665544332211', DATABASE_URL: 'postgresql://x:y@localhost:5432/z', NODE_ENV: 'test', HELIX_ADMIN_API_KEY: 'admin-key-for-tests-0123456789abcdef' };

describe('DID_DOMAIN and the Helix issuer DID', () => {
  it('builds did:web:<domain> through didWebFor, encoding a port', () => {
    expect(loadConfig({ ...BASE, DID_METHOD: 'web', DID_DOMAIN: 'api.helixid.dev' }).HELIX_ISSUER_DID).toBe('did:web:api.helixid.dev');
    expect(loadConfig({ ...BASE, DID_METHOD: 'web', DID_DOMAIN: '127.0.0.1:3680' }).HELIX_ISSUER_DID).toBe('did:web:127.0.0.1%3A3680');
  });

  it('refuses a DID_DOMAIN that is already encoded or is not a bare host', () => {
    for (const domain of ['localhost%3A3000', 'https://api.helixid.dev', 'api.helixid.dev/v1']) {
      expect(() => loadConfig({ ...BASE, DID_METHOD: 'web', DID_DOMAIN: domain }), domain).toThrow(/DID_DOMAIN: the raw host/);
      expect(() => loadConfig({ ...BASE, DID_METHOD: 'key', DID_DOMAIN: domain }), `${domain} with did:key`).toThrow(/DID_DOMAIN: the raw host/);
    }
  });

  it('keeps a did:key issuer with DID_METHOD=key', () => {
    expect(loadConfig({ ...BASE, DID_METHOD: 'key', DID_DOMAIN: 'localhost:3680' }).HELIX_ISSUER_DID).toMatch(/^did:key:z6Mk/);
  });
});
