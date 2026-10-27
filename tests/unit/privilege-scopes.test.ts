// Copyright 2026 DgVerse LLP
import { describe, expect, it } from 'vitest';
import { MAX_SCOPES, findScopeProblem, parseScopes } from '../../src/core/schemas/privilegeScopes.js';

describe('parseScopes', () => {
  it('splits on any run of spaces, commas, tabs and newlines', () => {
    expect(parseScopes('a,b, cd')).toEqual(['a', 'b', 'cd']);
    expect(parseScopes('a ,, b\t\ncd\r\n')).toEqual(['a', 'b', 'cd']);
    expect(parseScopes(['a,b', ' c ', ''])).toEqual(['a', 'b', 'c']);
  });

  it('keeps free text as given, drops repeats, keeps first-seen order', () => {
    expect(parseScopes('calendar.events https://www.googleapis.com/auth/gmail.readonly Read:Orders calendar.events')).toEqual([
      'calendar.events',
      'https://www.googleapis.com/auth/gmail.readonly',
      'Read:Orders',
    ]);
    expect(parseScopes(' , ')).toEqual([]);
  });
});

describe('findScopeProblem', () => {
  it('accepts any text without separators', () => {
    expect(findScopeProblem(['read:orders', 'calendar.events', 'orders/read', 'https://x.example/a?b=c'])).toBeNull();
    expect(findScopeProblem([])).toBeNull();
  });

  it('refuses empty scopes, separators inside a scope, overlong scopes and too many scopes', () => {
    expect(findScopeProblem([''])).toMatch(/non-empty/);
    expect(findScopeProblem([42])).toMatch(/non-empty string/);
    expect(findScopeProblem(['read orders'])).toMatch(/whitespace or a comma/);
    expect(findScopeProblem(['a,b'])).toMatch(/whitespace or a comma/);
    expect(findScopeProblem(['x'.repeat(256)])).toMatch(/longer than 255/);
    expect(findScopeProblem(Array.from({ length: MAX_SCOPES + 1 }, (_, i) => `s${i}`))).toMatch(/at most/);
  });
});
