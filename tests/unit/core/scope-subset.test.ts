// Copyright 2026 DgVerse LLP
import { describe, expect, it } from 'vitest';
import { validateScopeSubset } from '../../../src/core/schemas/vc.js';
import { ScopeEscalationDeniedError } from '../../../src/core/errors/HelixError.js';

describe('validateScopeSubset', () => {
  it('accepts a child scope set contained in the parent', () => {
    expect(() => validateScopeSubset(['read', 'write'], ['read'])).not.toThrow();
    expect(() => validateScopeSubset(['read'], [])).not.toThrow();
  });

  it('throws ScopeEscalationDeniedError naming the first escalated scope', () => {
    expect(() => validateScopeSubset(['read'], ['read', 'admin'])).toThrow(ScopeEscalationDeniedError);
    expect(() => validateScopeSubset(['read'], ['admin'])).toThrow(/admin/);
  });
});
