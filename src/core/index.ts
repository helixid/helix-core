// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

// Barrel export — re-exports all public modules from helix-core.
// helix-api and helix-sdk-js import from '@helixid/core', not from sub-paths.
export * from './config/index.js';
export * from './crypto/index.js';
export * from './schemas/index.js';
export * from './errors/index.js';
export * from './audit/index.js';
export * from './status-list/index.js';
export * from './credentials/index.js';
export { resolveDID, clearDIDCache, evictDIDCache } from './did-resolver.js';
export * from './did/document.js';
export * from './did/resolve.js';
export * from './did/web.js';
export * from './did/rotation.js';
export * from './net/safe-fetch.js';
export * from './net/outbound.js';
export * from './card/index.js';
export * from './custody/index.js';
export * from './conformance/index.js';
// proofKeyOf / verificationMethodOfKey: consent grants signed with a KeyStore key (story F-3); the VP builder and verifier went with story F-2.
export { createEd25519Proof, verifyEd25519Proof, proofKeyOf, verificationMethodOfKey } from './proof.js';
export type { LinkedDataProof, SigningKeyMaterial } from './proof.js';
export { issueGrant, ACCEPT_TERMS_SCOPE } from './grant.js';
export { normalizeScopes, scopeKey, vcLookupColumns } from './vc-lookup.js';
export type { VcLookupColumns } from './vc-lookup.js';
export type {
  IssueGrantOptions,
  IssuerKeyMaterial,
} from './grant.js';
export type { DelegationLink } from './delegation.js';
