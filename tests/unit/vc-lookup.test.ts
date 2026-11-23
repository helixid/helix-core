// Copyright 2026 DgVerse LLP
import { describe, expect, it } from 'vitest';
import { normalizeScopes, scopeKey, vcLookupColumns } from '../../src/core/vc-lookup.js';

describe('scope keys', () => {
  it('ignore order and repeats', () => {
    expect(normalizeScopes(['b', 'a', 'b'])).toEqual(['a', 'b']);
    expect(scopeKey(['b', 'a', 'b'])).toBe(scopeKey(['a', 'b']));
    expect(scopeKey(['a'])).not.toBe(scopeKey(['a', 'b']));
    expect(scopeKey([])).toBe('');
  });
});

describe('vcLookupColumns', () => {
  it('reads a consent grant', () => {
    expect(
      vcLookupColumns({
        type: ['VerifiableCredential', 'DelegationGrantCredential'],
        issuer: 'did:web:svc',
        credentialSubject: { id: 'did:key:agent', userDid: 'did:web:u', scopes: ['y', 'x'] },
      }),
    ).toEqual({ vcType: 'DelegationGrantCredential', issuerDid: 'did:web:svc', userDid: 'did:web:u', scopeKey: 'x y' });
  });

  it('reads an identity credential and an attestation, which carry no user and no scope set', () => {
    expect(
      vcLookupColumns({
        type: ['VerifiableCredential', 'AgentIdentityCredential'],
        issuer: 'did:web:issuer',
        credentialSubject: { id: 'did:key:agent', name: 'agent', responsibleParty: 'did:web:owner' },
      }),
    ).toEqual({ vcType: 'AgentIdentityCredential', issuerDid: 'did:web:issuer', userDid: null, scopeKey: null });
    expect(
      vcLookupColumns({
        type: ['VerifiableCredential', 'CapabilityAttestationCredential'],
        issuer: 'did:web:issuer',
        credentialSubject: { id: 'did:key:agent', capability: 'read' },
      }),
    ).toEqual({ vcType: 'CapabilityAttestationCredential', issuerDid: 'did:web:issuer', userDid: null, scopeKey: null });
  });

  it('does not read the retired privilegeScopes member', () => {
    expect(
      vcLookupColumns({ type: ['VerifiableCredential', 'X'], issuer: 'did:web:i', credentialSubject: { privilegeScopes: ['read'] } }).scopeKey,
    ).toBeNull();
  });

  it('yields nulls for anything it cannot read, never throws', () => {
    expect(vcLookupColumns(null)).toEqual({ vcType: null, issuerDid: null, userDid: null, scopeKey: null });
    expect(vcLookupColumns({ type: 'VerifiableCredential', credentialSubject: { scopes: [1] } })).toEqual({
      vcType: null,
      issuerDid: null,
      userDid: null,
      scopeKey: null,
    });
  });
});
