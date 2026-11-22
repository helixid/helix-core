// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Cross-language audit fixtures (KYA-OS story A-1, stories rule 6): sample
 * producer events with their canonical form and domain-separated digest, a
 * short source chain, the rejections the strict schema must refuse, reference
 * sanitization, delegation references and digests (SPEC section 7.8,
 * appendix C.4) and one deterministic evidence object. Generated once from
 * helix-core, checked in at fixtures/kya-os-helix/audit-events.json, and
 * consumed byte for byte by helix-core, helix-sdk-js, helix-sdk-py and
 * e2e-playwright.
 *
 * Run: pnpm generate:audit-fixtures
 */

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  AUDIT_BINDING_MCP,
  AuditTrail,
  EvidenceEncryptor,
  MemoryAuditSink,
  MemoryEvidenceStore,
  credentialDigest,
  delegationChainDigest,
  delegationChainDigests,
  delegationRef,
  evidenceAad,
  sanitizeReference,
  validateAuditEvent,
  type AuditEventInput,
  type PartyRef,
} from '../src/core/audit/index.js';

const OUT_DIR = fileURLToPath(new URL('../fixtures/kya-os-helix/', import.meta.url));
mkdirSync(OUT_DIR, { recursive: true });

const TENANT: PartyRef = { kind: 'keyed_commitment', value: `sha256:${'a'.repeat(64)}`, keyId: 'tenant-key-v1' };
const PRODUCER: PartyRef = { kind: 'pairwise_did', did: 'did:key:zFixtureProducer' };
const AGENT: PartyRef = { kind: 'pairwise_did', did: 'did:key:zFixtureAgent' };
const SERVICE: PartyRef = { kind: 'public_did', did: 'did:web:orders.example' };
const SOURCE_ID = 'fixture-source-1';

/** A deterministic stream: byte n of the stream is sha256(seed || counter)[n % 32]. */
function deterministicRandom(seed: string): (length: number) => Uint8Array {
  let counter = 0;
  return (length) => {
    const out = new Uint8Array(length);
    for (let offset = 0; offset < length; offset += 32) {
      const block = createHash('sha256').update(`${seed}:${counter}`).digest();
      counter += 1;
      out.set(block.subarray(0, Math.min(32, length - offset)), offset);
    }
    return out;
  };
}

function makeTrail(sink: MemoryAuditSink, options: { includeToolNames?: boolean } = {}): AuditTrail {
  let n = 0;
  return new AuditTrail({
    sink,
    sourceId: SOURCE_ID,
    producer: PRODUCER,
    tenantRef: TENANT,
    binding: AUDIT_BINDING_MCP,
    privacy: { classification: 'internal', retentionClass: 'audit-365d' },
    clock: () => 1750000000123 + n * 1000,
    newEventId: () => `fixture-event-${(n += 1)}`,
    ...(options.includeToolNames !== undefined ? { includeToolNames: options.includeToolNames } : {}),
  });
}

const C4_ROOT = {
  id: 'urn:uuid:1111-aaaa',
  type: ['VerifiableCredential', 'DelegationCredential'],
  issuer: 'did:web:user.example.com',
  credentialSubject: { id: 'did:web:agent-a.example.com' },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2024-03-01T12:00:00Z',
    verificationMethod: 'did:web:user.example.com#key-1',
    proofPurpose: 'assertionMethod',
    proofValue: 'c2lnbmF0dXJlLW9mLXJvb3Q',
  },
};
const C4_LEAF = 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2lnbmF0dXJlLW9mLWxlYWY';
const { id: _c4RootId, ...C4_ROOT_WITHOUT_ID } = C4_ROOT;

const sampleInputs: Array<{ name: string; input: AuditEventInput }> = [
  {
    name: 'session_established',
    input: {
      eventType: 'session.established',
      actor: AGENT,
      resource: SERVICE,
      correlationId: 'call-0001',
      session: { ref: { kind: 'keyed_commitment', value: `sha256:${'b'.repeat(64)}`, keyId: 'session-key-v1' } },
      action: { category: 'session' },
      outcome: 'succeeded',
      details: { family: 'session', phase: 'established' },
    },
  },
  {
    name: 'tool_call_completed_name_withheld',
    input: {
      eventType: 'tool.call.completed',
      actor: AGENT,
      resource: SERVICE,
      correlationId: 'call-0001',
      action: { category: 'tool.call', name: 'lookup_order' },
      outcome: 'succeeded',
      details: { family: 'tool', phase: 'completed', attempt: '1' },
    },
  },
  {
    name: 'proof_verified',
    input: {
      eventType: 'proof.verified',
      actor: AGENT,
      resource: SERVICE,
      correlationId: 'call-0001',
      action: { category: 'proof' },
      outcome: 'succeeded',
      details: { family: 'proof', phase: 'verified', proofDigest: `sha256:${'c'.repeat(64)}`, verificationCode: 'PROOF_VALID' },
    },
  },
  {
    name: 'delegation_verified_with_chain',
    input: {
      eventType: 'delegation.verified',
      actor: AGENT,
      resource: SERVICE,
      correlationId: 'call-0001',
      action: { category: 'delegation' },
      outcome: 'succeeded',
      authorization: {
        source: 'delegation',
        decision: 'allowed',
        scopeId: 'orders:read',
        delegationRef: delegationRef(C4_ROOT)!,
        delegationCredentialDigest: credentialDigest(C4_ROOT)!,
        delegationChainDigests: delegationChainDigests([C4_ROOT, C4_LEAF])!,
        verificationCode: 'DELEGATION_CHAIN_VALID',
      },
      details: { family: 'delegation', phase: 'verified', delegationRef: delegationRef(C4_ROOT)!, parentRef: 'urn:uuid:0000-root' },
    },
  },
  {
    name: 'authorization_denied_with_overlong_scope',
    input: {
      eventType: 'authorization.denied',
      actor: AGENT,
      resource: SERVICE,
      correlationId: 'call-0002',
      action: { category: 'authorization' },
      outcome: 'denied',
      reason: { code: 'insufficient_scope' },
      authorization: { source: 'delegation', decision: 'denied', scopeId: 'x'.repeat(300) },
      details: { family: 'authorization', phase: 'denied' },
    },
  },
  {
    name: 'grant_used',
    input: {
      eventType: 'grant.used',
      actor: AGENT,
      resource: SERVICE,
      action: { category: 'authorization' },
      outcome: 'succeeded',
      authorization: { source: 'grant', decision: 'allowed', grantRef: 'vc:helix:grant-1' },
      details: { family: 'authorization', phase: 'grant_used', grantRef: 'vc:helix:grant-1' },
    },
  },
  {
    name: 'consent_approved',
    input: {
      eventType: 'consent.approved',
      actor: { kind: 'public_did', did: 'did:key:zFixtureUser' },
      responsibleParty: { kind: 'public_did', did: 'did:key:zFixtureUser' },
      resource: SERVICE,
      action: { category: 'consent' },
      outcome: 'succeeded',
      details: { family: 'consent', phase: 'approved', consentRef: 'vc:helix:grant-1' },
    },
  },
  {
    name: 'credential_failed',
    input: {
      eventType: 'credential.failed',
      action: { category: 'enrollment' },
      outcome: 'failed',
      reason: { code: 'enrollment_token_expired' },
      details: { family: 'consent', phase: 'credential_failed' },
    },
  },
  {
    name: 'key_rotated',
    input: {
      eventType: 'key.rotated',
      actor: SERVICE,
      action: { category: 'configuration' },
      outcome: 'succeeded',
      details: {
        family: 'key',
        phase: 'rotated',
        previousSigner: { did: 'did:web:orders.example', kid: 'did:web:orders.example#key-1', alg: 'EdDSA' },
        nextSigner: { did: 'did:web:orders.example', kid: 'did:web:orders.example#key-2', alg: 'EdDSA' },
      },
    },
  },
  {
    name: 'configuration_changed',
    input: {
      eventType: 'configuration.changed',
      action: { category: 'configuration' },
      outcome: 'succeeded',
      details: { family: 'key', phase: 'configuration_changed', configurationDigest: `sha256:${'d'.repeat(64)}` },
    },
  },
  {
    name: 'checkpoint_created',
    input: {
      eventType: 'checkpoint.created',
      action: { category: 'audit.ledger' },
      outcome: 'succeeded',
      details: { family: 'ledger', phase: 'checkpoint_created', checkpointDigest: `sha256:${'e'.repeat(64)}`, successorEpochIds: ['epoch-2'] },
    },
  },
  {
    name: 'audit_accessed',
    input: {
      eventType: 'audit.accessed',
      actor: { kind: 'public_did', did: 'did:web:operator.example' },
      action: { category: 'audit.administration' },
      outcome: 'succeeded',
      details: { family: 'administration', phase: 'accessed', purpose: 'incident-review', sourceSequence: '42' },
    },
  },
  {
    name: 'unicode_correlation',
    input: {
      eventType: 'tool.call.failed',
      actor: AGENT,
      correlationId: 'trace-\u03b1-42',
      action: { category: 'tool.call' },
      outcome: 'failed',
      reason: { code: 'handler_error' },
      details: { family: 'tool', phase: 'failed', attempt: '2' },
    },
  },
];

async function main(): Promise<void> {
  // Sample events: one trail per sample so each is sequence 1 with no predecessor.
  const samples = [];
  for (const sample of sampleInputs) {
    const sink = new MemoryAuditSink();
    const entry = await makeTrail(sink).record(sample.input);
    samples.push({ name: sample.name, input: sample.input, event: entry.event, canonical: entry.canonical, digest: entry.eventDigest });
  }

  // A short source chain: three events of one source.
  const chainSink = new MemoryAuditSink();
  const chainTrail = makeTrail(chainSink);
  for (const sample of sampleInputs.slice(0, 3)) await chainTrail.record(sample.input);
  const chain = {
    sourceId: SOURCE_ID,
    entries: chainSink.entries.map((entry) => ({ event: entry.event, canonical: entry.canonical, digest: entry.eventDigest })),
  };

  // Tool-name policy.
  const withNames = new MemoryAuditSink();
  const withoutNames = new MemoryAuditSink();
  const toolInput = sampleInputs[1]!.input;
  await makeTrail(withNames, { includeToolNames: true }).record(toolInput);
  await makeTrail(withoutNames, { includeToolNames: false }).record(toolInput);
  const toolNames = { input: toolInput, included: withNames.entries[0]!.event, withheld: withoutNames.entries[0]!.event };

  // Rejections: each is `base` with one change; `path` names where the first issue is.
  const base = samples[0]!.event;
  const rejectionCases = [
    { name: 'unknown_top_level_member', event: { ...base, extra: 'x' }, path: '' },
    { name: 'unknown_details_member', event: { ...base, details: { ...base.details, bogus: 1 } }, path: 'details' },
    { name: 'unknown_source_member', event: { ...base, source: { ...base.source, host: 'x' } }, path: 'source' },
    { name: 'unknown_action_member', event: { ...base, action: { ...base.action, arguments: { orderId: 'ORD-1' } } }, path: 'action' },
    { name: 'details_family_mismatch', event: { ...base, details: { family: 'tool', phase: 'completed', attempt: '1' } }, path: 'details.family' },
    { name: 'unknown_event_type', event: { ...base, eventType: 'session.opened' }, path: 'eventType' },
    { name: 'bad_digest_form', event: { ...base, source: { ...base.source, previousSourceEventDigest: 'sha256:xyz' } }, path: 'source.previousSourceEventDigest' },
    { name: 'bad_binding', event: { ...base, binding: 'urn:other:binding' }, path: 'binding' },
    { name: 'unknown_party_kind', event: { ...base, actor: { kind: 'email', value: 'a@b.c' } }, path: 'actor' },
    { name: 'missing_evidence_array', event: Object.fromEntries(Object.entries(base).filter(([key]) => key !== 'evidence')), path: 'evidence' },
    { name: 'occurred_at_not_integer', event: { ...base, occurredAt: 1.5 }, path: 'occurredAt' },
    { name: 'overlong_reference', event: { ...base, correlationId: 'x'.repeat(257) }, path: 'correlationId' },
  ];
  const rejections = rejectionCases.map((item) => {
    const result = validateAuditEvent(item.event);
    if (result.ok) throw new Error(`${item.name} must be refused`);
    const path = result.issues[0]!.path;
    if (!path.startsWith(item.path)) throw new Error(`${item.name}: first issue at ${path}, expected under ${item.path}`);
    return { name: item.name, event: item.event, path };
  });

  // Reference sanitization.
  const references = [
    { input: 'call-0001', output: sanitizeReference('call-0001') },
    { input: '', output: sanitizeReference('') },
    { input: 'x'.repeat(256), output: sanitizeReference('x'.repeat(256)) },
    { input: 'x'.repeat(257), output: sanitizeReference('x'.repeat(257)) },
    { input: 'line\nbreak', output: sanitizeReference('line\nbreak') },
    { input: 'zero\u200bwidth', output: sanitizeReference('zero\u200bwidth') },
    { input: 'bidi\u202eoverride', output: sanitizeReference('bidi\u202eoverride') },
    { input: 'tag\u{e0041}', output: sanitizeReference('tag\u{e0041}') },
    { input: 'lone\ud800surrogate', output: sanitizeReference('lone\ud800surrogate') },
    { input: 'trace-\u03b1-42', output: sanitizeReference('trace-\u03b1-42') },
    { input: 'emoji-\u{1f600}', output: sanitizeReference('emoji-\u{1f600}') },
    { input: 'short-bound', max_length: 5, output: sanitizeReference('short-bound', 5) },
  ];

  // Delegation references and credential digests (SPEC section 7.8, appendix C.4).
  const delegationCases: Array<{ name: string; credential: unknown }> = [
    { name: 'c4_root_object', credential: C4_ROOT },
    { name: 'c4_leaf_jwt', credential: C4_LEAF },
    { name: 'c4_root_padded_proof_value', credential: { ...C4_ROOT, proof: { ...C4_ROOT.proof, proofValue: 'c2lnbmF0dXJlLW9mLXJvb3Q=' } } },
    { name: 'c4_root_spare_bit', credential: { ...C4_ROOT, proof: { ...C4_ROOT.proof, proofValue: 'c2lnbmF0dXJlLW9mLXJvb3R' } } },
    { name: 'c4_root_space_inside', credential: { ...C4_ROOT, proof: { ...C4_ROOT.proof, proofValue: 'c2lnbmF0dXJl LW9mLXJvb3Q' } } },
    { name: 'id_is_unknown', credential: { ...C4_ROOT, id: 'unknown' } },
    { name: 'id_looks_like_digest', credential: { ...C4_ROOT, id: `sha256:${'f'.repeat(64)}` } },
    { name: 'id_overlong', credential: { ...C4_ROOT, id: 'urn:x:' + 'y'.repeat(260) } },
    { name: 'id_unprintable', credential: { ...C4_ROOT, id: 'urn:x:\u200b1' } },
    { name: 'id_from_delegation_subject', credential: { ...C4_ROOT_WITHOUT_ID, credentialSubject: { id: 'did:web:a', delegation: { id: 'urn:uuid:nested' } } } },
    { name: 'no_id', credential: C4_ROOT_WITHOUT_ID },
    { name: 'no_proof_value', credential: { ...C4_ROOT, proof: { type: 'Ed25519Signature2020' } } },
    { name: 'proof_value_not_base64', credential: { ...C4_ROOT, proof: { ...C4_ROOT.proof, proofValue: '!!!' } } },
    { name: 'proof_value_padding_before_data', credential: { ...C4_ROOT, proof: { ...C4_ROOT.proof, proofValue: 'c2ln=bmF0' } } },
    { name: 'jwt_two_segments', credential: 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319' },
    { name: 'jwt_empty_payload', credential: 'eyJhbGciOiJFZERTQSJ9..c2lnbmF0dXJlLW9mLWxlYWY' },
    { name: 'jwt_padded_signature', credential: 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2lnbmF0dXJlLW9mLWxlYWY=' },
    { name: 'jwt_wrong_padding', credential: 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2lnbmF0dXJlLW9mLWxlYWY==' },
    { name: 'jwt_signature_standard_alphabet', credential: 'eyJhbGciOiJFZERTQSJ9.eyJ2YyI6e319.c2ln+bmF0' },
    { name: 'jwt_with_vc_id', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from(JSON.stringify({ vc: { id: 'urn:uuid:jwt-vc' } })).toString('base64url')}.c2ln` },
    { name: 'jwt_with_jti', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from(JSON.stringify({ jti: 'urn:uuid:jwt-jti', vc: {} })).toString('base64url')}.c2ln` },
    { name: 'jwt_with_delegation_id', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from(JSON.stringify({ vc: { credentialSubject: { delegation: { id: 'urn:uuid:jwt-del' } } } })).toString('base64url')}.c2ln` },
    { name: 'jwt_payload_not_object', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from('[1]').toString('base64url')}.c2ln` },
    { name: 'jwt_payload_with_bom', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from('\ufeff{"vc":{"id":"x"}}').toString('base64url')}.c2ln` },
    { name: 'jwt_payload_not_json', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from('{not json').toString('base64url')}.c2ln` },
    { name: 'jwt_payload_not_utf8', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from([0xff, 0xfe, 0x7b]).toString('base64url')}.c2ln` },
    { name: 'jwt_payload_too_deep', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from('{"vc":{"id":"deep","a":' + '['.repeat(70) + ']'.repeat(70) + '}}').toString('base64url')}.c2ln` },
    { name: 'jwt_payload_depth_64_ok', credential: `eyJhbGciOiJFZERTQSJ9.${Buffer.from('{"vc":{"id":"deep64","a":' + '['.repeat(62) + ']'.repeat(62) + '}}').toString('base64url')}.c2ln` },
    { name: 'object_too_deep', credential: { ...C4_ROOT, deep: JSON.parse('['.repeat(70) + ']'.repeat(70)) } },
    { name: 'not_a_credential', credential: 42 },
    { name: 'object_unsafe_integer', credential: { ...C4_ROOT, amount: 9007199254740993 } },
  ];
  const delegation = delegationCases.map((item) => ({
    name: item.name,
    credential: item.credential,
    delegation_ref: delegationRef(item.credential) ?? null,
    credential_digest: credentialDigest(item.credential) ?? null,
  }));
  const chainDigests = delegationChainDigests([C4_ROOT, C4_LEAF])!;
  const delegationChain = {
    credentials: [C4_ROOT, C4_LEAF],
    digests: chainDigests,
    chain_digest: delegationChainDigest(chainDigests),
    too_long_chain_length: 257,
    too_long_chain_digests: delegationChainDigests(new Array<unknown>(257).fill(C4_ROOT)) ?? null,
    unsigned_member_digests: delegationChainDigests([C4_ROOT, { id: 'x' }]) ?? null,
  };

  // Evidence: a deterministic AES-256-GCM object.
  const keyHex = createHash('sha256').update('fixture-evidence-key').digest('hex');
  const encryptor = new EvidenceEncryptor({ key: keyHex, keyId: 'evidence-key-v1', randomBytes: deterministicRandom('fixture-evidence') });
  const store = new MemoryEvidenceStore();
  const purpose = 'tool.call.arguments';
  const plaintext = '{"orderId":"ORD-1001","reason":"damaged"}';
  const encrypted = encryptor.encrypt({ plaintext, mediaType: 'application/json', aad: evidenceAad(TENANT, purpose), commitPlaintext: true });
  await store.putIfAbsent(encrypted);
  const evidence = {
    key_hex: keyHex,
    key_id: 'evidence-key-v1',
    tenant: TENANT,
    purpose,
    aad_utf8: Buffer.from(evidenceAad(TENANT, purpose)).toString('utf8'),
    plaintext_utf8: plaintext,
    media_type: 'application/json',
    ref: encrypted.ref,
    ciphertext_b64url: Buffer.from(encrypted.ciphertext).toString('base64url'),
    wrong_purpose: 'tool.call.response',
    wrong_tenant: { kind: 'keyed_commitment', value: `sha256:${'9'.repeat(64)}`, keyId: 'tenant-key-v1' },
  };
  const evidenceEvent = await makeTrail(new MemoryAuditSink()).record({
    eventType: 'tool.call.started',
    actor: AGENT,
    action: { category: 'tool.call', detailRef: encrypted.ref },
    outcome: 'unknown',
    evidence: [encrypted.ref],
    details: { family: 'tool', phase: 'started', attempt: '1' },
  });

  const fixture = {
    generator: 'scripts/generate-audit-fixtures.ts',
    story: 'A-1',
    spec: { commit: 'a4d7f61', suite: '1.10.0', event_digest_domain: 'org.kya-os.audit.event.v1' },
    trail: { sourceId: SOURCE_ID, producer: PRODUCER, tenantRef: TENANT, binding: AUDIT_BINDING_MCP, privacy: { classification: 'internal', retentionClass: 'audit-365d' } },
    events: samples,
    chain,
    tool_names: toolNames,
    rejections,
    references,
    delegation,
    delegation_chain: delegationChain,
    evidence,
    evidence_event: { event: evidenceEvent.event, canonical: evidenceEvent.canonical, digest: evidenceEvent.eventDigest },
  };
  writeFileSync(`${OUT_DIR}audit-events.json`, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');
  console.log(`wrote ${OUT_DIR}audit-events.json: ${samples.length} events, ${rejections.length} rejections, ${delegation.length} delegation cases`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
