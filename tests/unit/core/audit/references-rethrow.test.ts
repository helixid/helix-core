// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/core/audit/digest.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/core/audit/digest.js')>();
  return {
    ...actual,
    auditDigest: () => {
      throw new Error('hash provider failed');
    },
  };
});

describe('credentialDigest', () => {
  it('reports a hash provider failure instead of calling the credential unsigned', async () => {
    const { credentialDigest } = await import('../../../../src/core/audit/references.js');
    expect(() => credentialDigest('h.p.c2ln')).toThrow('hash provider failed');
  });
});
