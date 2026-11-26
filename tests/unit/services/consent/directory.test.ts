// Copyright 2026 DgVerse LLP
// KYA-OS story L3-H: what the consent service asks the deployment: a known service and its name, and the
// scopes an agent onboarded here is attested for.
import { describe, expect, it } from 'vitest';
import { AgentActiveCredentialNotFoundError, DelegateeNotAnAgentError, HelixError } from '../../../../src/core/index.js';
import { consentAgentScopes, consentServiceDirectory } from '../../../../src/services/consent/directory.js';
import { MemoryJtiStore } from '../../../../src/services/consent/signed-request.js';

describe('consentServiceDirectory', () => {
  const services = {
    findByDid: async (did: string) =>
      ({ 'did:web:a': { name: 'Enrolled', revokedAt: null }, 'did:web:revoked': { name: 'Gone', revokedAt: new Date() } })[did] ?? null,
  };
  const custody = {
    custodyOf: async (dids: readonly string[]) =>
      [
        { did: 'did:web:c', subjectType: 'service', status: 'active', name: 'Custodial' },
        { did: 'did:web:n', subjectType: 'service', status: 'active', name: null },
        { did: 'did:web:p', subjectType: 'service', status: 'pending_key', name: 'Pending' },
        { did: 'did:web:g', subjectType: 'agent', status: 'active', name: 'Agent' },
      ].filter((record) => dids.includes(record.did)),
  };

  it('knows enrolled and active custody services, never revoked, pending or other subjects', async () => {
    const serviceOf = consentServiceDirectory({ services, custody });
    expect(await serviceOf('did:web:a')).toEqual({ name: 'Enrolled' });
    expect(await serviceOf('did:web:c')).toEqual({ name: 'Custodial' });
    expect(await serviceOf('did:web:n')).toEqual({});
    for (const did of ['did:web:revoked', 'did:web:p', 'did:web:g', 'did:web:none']) expect(await serviceOf(did)).toBeUndefined();
    expect(await consentServiceDirectory({})('did:web:a')).toBeUndefined();
  });
});

describe('consentAgentScopes', () => {
  it('reads attested scopes, skips agents onboarded elsewhere, and grants nothing to a revoked one', async () => {
    const scopesOf = consentAgentScopes({
      getAgentScopes: async (did: string) => {
        if (did === 'did:web:elsewhere') throw new DelegateeNotAnAgentError(did);
        if (did === 'did:web:revoked') throw new AgentActiveCredentialNotFoundError(did);
        if (did === 'did:web:broken') throw new HelixError('VALIDATION_ERROR', 'bad', 400);
        return { scopes: ['orders:read'] };
      },
    });
    expect(await scopesOf('did:web:agent')).toEqual(['orders:read']);
    expect(await scopesOf('did:web:elsewhere')).toBeUndefined();
    expect(await scopesOf('did:web:revoked')).toEqual([]);
    await expect(scopesOf('did:web:broken')).rejects.toThrow('bad');
  });
});

describe('MemoryJtiStore', () => {
  it('accepts a jti once until it expires', () => {
    let now = 1000;
    const store = new MemoryJtiStore(() => now);
    expect(store.claim('a', 2000)).toBe(true);
    expect(store.claim('a', 2000)).toBe(false);
    now = 2001;
    expect(store.claim('a', 3000)).toBe(true);
    expect(new MemoryJtiStore().claim('b', Date.now() + 1000)).toBe(true);
  });
});
