// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { AuditEventInput, AuditProducerEvent, Digest, EvidenceRef, PartyRef } from '../../../../src/core/audit/index.js';

export interface AuditFixture {
  trail: { sourceId: string; producer: PartyRef; tenantRef: PartyRef; binding: `urn:kya-os:audit-binding:${string}`; privacy: AuditProducerEvent['privacy'] };
  events: Array<{ name: string; input: AuditEventInput; event: AuditProducerEvent; canonical: string; digest: Digest }>;
  chain: { sourceId: string; entries: Array<{ event: AuditProducerEvent; canonical: string; digest: Digest }> };
  tool_names: { input: AuditEventInput; included: AuditProducerEvent; withheld: AuditProducerEvent };
  rejections: Array<{ name: string; event: Record<string, unknown>; path: string }>;
  references: Array<{ input: string; max_length?: number; output: string }>;
  delegation: Array<{ name: string; credential: unknown; delegation_ref: string | null; credential_digest: Digest | null }>;
  delegation_chain: { credentials: unknown[]; digests: Digest[]; chain_digest: Digest; too_long_chain_digests: null; unsigned_member_digests: null };
  evidence: {
    key_hex: string;
    key_id: string;
    tenant: PartyRef;
    purpose: string;
    aad_utf8: string;
    plaintext_utf8: string;
    media_type: string;
    ref: EvidenceRef;
    ciphertext_b64url: string;
    wrong_purpose: string;
    wrong_tenant: PartyRef;
  };
  evidence_event: { event: AuditProducerEvent; canonical: string; digest: Digest };
}

export const FIXTURES_DIR = fileURLToPath(new URL('../../../../fixtures/', import.meta.url));

/** `fixtures/kya-os-helix/audit-events.json`, the cross-language contract (stories rule 6). */
export const fixture = JSON.parse(readFileSync(`${FIXTURES_DIR}kya-os-helix/audit-events.json`, 'utf8')) as AuditFixture;
