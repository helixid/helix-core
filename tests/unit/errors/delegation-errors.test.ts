// Copyright 2026 DgVerse LLP
import { describe, expect, it } from 'vitest';
import {
  HelixError,
  MaxDelegationDepthExceededError,
  SelfDelegationNotAllowedError,
  DelegationNotPermittedError,
  DelegationChainInvalidError,
  DelegationParentVCNotFoundError,
  DelegationParentVCRevokedError,
  ScopeEscalationDeniedError,
} from '../../../src/core/errors/HelixError.js';

const classes = [
  MaxDelegationDepthExceededError,
  DelegationNotPermittedError,
  DelegationParentVCNotFoundError,
  DelegationParentVCRevokedError,
];

describe('delegation error classes', () => {
  it.each(classes.map((c) => [c.name, c] as const))('%s carries a code, status and default message', (_name, Cls) => {
    const error = new Cls();
    expect(error).toBeInstanceOf(HelixError);
    expect(typeof error.code).toBe('string');
    expect(error.httpStatus).toBeGreaterThanOrEqual(400);
    expect(error.message.length).toBeGreaterThan(0);
  });

  it.each(classes.map((c) => [c.name, c] as const))('%s accepts a custom message', (_name, Cls) => {
    expect(new Cls('custom').message).toBe('custom');
  });

  it('SelfDelegationNotAllowedError and DelegationChainInvalidError embed their argument', () => {
    expect(new SelfDelegationNotAllowedError('did:key:z6MkSelf').message).toContain('did:key:z6MkSelf');
    const chain = new DelegationChainInvalidError('broken link');
    expect(chain.message).toContain('broken link');
    expect(chain.details).toEqual({ reason: 'broken link' });
  });

  it('ScopeEscalationDeniedError names the scope', () => {
    const error = new ScopeEscalationDeniedError('admin');
    expect(error.code).toBe('SCOPE_ESCALATION_DENIED');
    expect(error.message).toContain('admin');
  });
});
