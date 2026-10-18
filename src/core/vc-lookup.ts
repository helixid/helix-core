// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// The `vcs` lookup columns, derived from a credential's JSON: the values a
// row stores beside vcJson so a credential can be found without reading
// every row's JSON. One function, used by every path that writes a row
// (issuance, registration, the SQLite backfill), so the columns never
// disagree with the JSON they summarise.

export interface VcLookupColumns {
  /** The credential's own type: the entry of `type` that is not VerifiableCredential. */
  vcType: string | null;
  issuerDid: string | null;
  /** The user a DelegationGrantCredential was issued on behalf of. */
  userDid: string | null;
  /** The canonical scope set, see scopeKey(). */
  scopeKey: string | null;
}

/** Sorted and de-duplicated: the order a caller lists scopes in carries no meaning. */
export function normalizeScopes(scopes: readonly string[]): string[] {
  return [...new Set(scopes)].sort();
}

/**
 * One string per scope set, independent of order and repeats, so "the same
 * scopes" is an equality test the database can index. Space-joined because
 * SCOPE_PATTERN admits no whitespace.
 */
export function scopeKey(scopes: readonly string[]): string {
  return normalizeScopes(scopes).join(' ');
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

function asStringArray(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((item) => typeof item === 'string') ? value : null;
}

export function vcLookupColumns(vc: unknown): VcLookupColumns {
  const record = asRecord(vc);
  const types = asStringArray(record['type']) ?? [];
  const subject = asRecord(record['credentialSubject']);
  // A grant names its scopes `scopes`; agent credentials use `privilegeScopes`.
  const scopes = asStringArray(subject['scopes']) ?? asStringArray(subject['privilegeScopes']);
  return {
    vcType: types.find((type) => type !== 'VerifiableCredential') ?? null,
    issuerDid: typeof record['issuer'] === 'string' ? record['issuer'] : null,
    userDid: typeof subject['userDid'] === 'string' ? subject['userDid'] : null,
    scopeKey: scopes ? scopeKey(scopes) : null,
  };
}
