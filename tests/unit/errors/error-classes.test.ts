// Copyright 2026 DgVerse LLP
// Every HelixError subclass carries a code, an HTTP status and a message, whatever
// its constructor takes. Story F-2 retired the VP path whose suites used to build
// most of these; the classes stay for the consumers that still name them.
import { describe, expect, it } from 'vitest';
import * as errors from '../../../src/core/errors/HelixError.js';

const classes = Object.entries(errors).filter(
  (entry): entry is [string, new (...args: unknown[]) => errors.HelixError] =>
    typeof entry[1] === 'function' && entry[1] !== errors.HelixError && entry[1].prototype instanceof errors.HelixError,
);

describe('HelixError subclasses', () => {
  it('finds the classes', () => {
    expect(classes.length).toBeGreaterThan(50);
  });

  /** Constructors that take something other than strings. */
  const special: Record<string, unknown[][]> = { ConsentGrantScopeNotAllowedError: [[['read', 'write']]] };

  it.each(classes)('%s carries a code, a status and a message', (name, Cls) => {
    for (const args of special[name] ?? [[], ['did:web:a', 'did:web:b', 'did:web:c'], ['reason_code', 'a message']]) {
      const error = new Cls(...args);
      expect(error).toBeInstanceOf(errors.HelixError);
      expect(typeof error.code).toBe('string');
      expect(error.httpStatus).toBeGreaterThanOrEqual(400);
      expect(typeof error.message).toBe('string');
    }
  });
});
