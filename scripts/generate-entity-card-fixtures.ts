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
 * Cross-language Entity Card fixtures (KYA-OS story C-A, stories rule 6):
 * generated from helix-core's own implementation, checked in at
 * fixtures/kya-os-helix/entity-card.json, and consumed by helix-core,
 * helix-sdk-js, helix-sdk-py and e2e-playwright.
 *
 * Entities under Helix hosting on `helix.test`: the bare-host org
 * (`did:web:helix.test`), an org (`did:web:helix.test:acme`), its agent
 * (`did:web:helix.test:acme:ledger-agent`, org-owned: `responsibleParty` is
 * the org, `principal` the delegating user's did:key) and its MCP service
 * (`did:web:helix.test:acme:orders-mcp`). For each: the DID document with
 * the `KyaOsEntityCard` service entry and the did:key and did:hedera forms
 * in `alsoKnownAs`, the card, both URLs, the `server.json` projection. Then
 * what a resolver must do with them: the two-step resolution over the served
 * map, the refusals (unknown field, did:key by discovery, a card for another
 * DID), `conformanceLevel` ignored on input, a proof refused, the revocation
 * cases over two test status lists, and the SafeFetch refusals.
 *
 * Run: pnpm generate:entity-card-fixtures
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  buildDidDocument,
  buildEntityCard,
  EnvSigner,
  buildStatusListCredential,
  createStatusList,
  derivePublicKey,
  didKeyFromPublicKey,
  didWebCardUrl,
  didWebDocumentUrl,
  entityCardSummary,
  publicKeyBytesToJwk,
  serverCardMeta,
  setBit,
  verificationMethodId,
  type AgentDidDocument,
  type BitstringStatusListEntry,
  type EntityCard,
  type EntityType,
  type PublicKeyJwk,
  type ServerCardMeta,
  type SignedStatusListCredential,
} from '../src/core/index.js';

export interface EntityFixture {
  kind: 'org_root' | 'org' | 'agent' | 'service';
  entity_type: EntityType;
  name: string;
  private_key_hex: string;
  public_key_jwk: PublicKeyJwk;
  did_key: string;
  did_hedera: string;
  did: string;
  kid: string;
  did_document_url: string;
  card_url: string;
  did_document: AgentDidDocument;
  card: EntityCard;
  summary: ReturnType<typeof entityCardSummary>;
  server_meta: ServerCardMeta;
}

export interface EntityCardFixtures {
  generated_from: string;
  generator: string;
  note: string;
  host: string;
  user_did_key: string;
  entities: Record<'org_root' | 'org' | 'agent' | 'service', EntityFixture>;
  /** URL → body, what the network serves for the two-step resolution. */
  served: Record<string, unknown>;
  resolution: { did: string; steps: [string, string]; card_id: string }[];
  refusals: { name: string; did?: string; card?: unknown; served?: Record<string, unknown>; reason: string }[];
  build_cases: { name: string; input: Record<string, unknown>; expected: 'card' | 'refused'; card?: EntityCard; absent?: string[] }[];
  status_lists: Record<string, unknown>;
  /** The clock the revocation cases read `status_lists` with: inside their window. */
  status_list_now: string;
  revocation_cases: { name: string; card: EntityCard; expected: { ok: boolean; conformanceLevel: string; revoked: boolean; code?: string } }[];
  safe_fetch_refusals: { url: string; reason: string }[];
  public_addresses: string[];
  non_public_addresses: string[];
}

const HOST = 'helix.test';
const ORG = 'acme';
const seed = (byte: number): string => Array.from({ length: 32 }, (_, i) => ((byte + i) & 0xff).toString(16).padStart(2, '0')).join('');
const USER_SEED = seed(0x10);

function entity(kind: EntityFixture['kind'], entityType: EntityType, name: string, privateKeyHex: string, segments: string[], extra: Partial<Parameters<typeof buildEntityCard>[0]> = {}): EntityFixture {
  const publicKey = new Uint8Array(Buffer.from(derivePublicKey(privateKeyHex), 'hex'));
  const publicKeyJwk = publicKeyBytesToJwk(publicKey);
  const did = ['did:web', HOST, ...segments].join(':');
  const didKey = didKeyFromPublicKey(publicKey);
  const didHedera = `did:hedera:testnet:z${derivePublicKey(privateKeyHex).slice(0, 44)}_0.0.${1000 + segments.length}`;
  const kid = verificationMethodId(did, 'key-1');
  const didDocument = buildDidDocument({ did, publicKeyJwk, kid: 'key-1', alsoKnownAs: [didKey, didHedera], cardServiceEndpoint: true });
  const card = buildEntityCard({ id: did, entityType, name, kid: 'key-1', publicKeyJwk, createdAt: '2026-11-21T00:00:00Z', ...extra });
  return {
    kind,
    entity_type: entityType,
    name,
    private_key_hex: privateKeyHex,
    public_key_jwk: publicKeyJwk,
    did_key: didKey,
    did_hedera: didHedera,
    did,
    kid,
    did_document_url: didWebDocumentUrl(did),
    card_url: didWebCardUrl(did),
    did_document: didDocument,
    card,
    summary: entityCardSummary(card),
    server_meta: serverCardMeta(card),
  };
}

export async function buildEntityCardFixtures(): Promise<EntityCardFixtures> {
  const userDidKey = didKeyFromPublicKey(new Uint8Array(Buffer.from(derivePublicKey(USER_SEED), 'hex')));
  const orgDid = `did:web:${HOST}:${ORG}`;
  const statusListUrl = `https://${HOST}/v1/status-list/cards`;
  const revocation: BitstringStatusListEntry = { statusListCredential: statusListUrl, statusListIndex: '7' };

  const orgRoot = entity('org_root', 'verifier', 'Helix (host)', seed(0x20), [], { capabilities: ['proof.verify', 'attestation.issue'] });
  const org = entity('org', 'verifier', 'Acme Corp', seed(0x30), [ORG], { capabilities: ['attestation.issue'] });
  const agent = entity('agent', 'agent', 'Acme Ledger Agent', seed(0x40), [ORG, 'ledger-agent'], {
    capabilities: ['handshake', 'ledger.read', 'ledger.post'],
    responsibleParty: orgDid,
    principal: userDidKey,
    delegationRef: 'vc_acme_root>del_ledger_1',
    revocation,
  });
  const service = entity('service', 'mcp', 'Acme Orders MCP', seed(0x50), [ORG, 'orders-mcp'], {
    capabilities: ['tools/list', 'tools/call'],
    responsibleParty: orgDid,
    delegationRef: 'vc_acme_root>del_orders_1',
  });
  const entities = { org_root: orgRoot, org, agent, service };

  const served: Record<string, unknown> = {};
  for (const e of Object.values(entities)) {
    served[e.did_document_url] = e.did_document;
    served[e.card_url] = e.card;
  }
  const resolution = Object.values(entities).map((e) => ({ did: e.did, steps: [e.did_document_url, e.card_url] as [string, string], card_id: e.card.id }));

  const stranger = entity('agent', 'agent', 'Stranger', seed(0x60), [ORG, 'stranger']);
  const refusals: EntityCardFixtures['refusals'] = [
    { name: 'unknown_top_level_field', card: { ...service.card, bogusField: true }, reason: 'additionalProperties' },
    { name: 'proof_on_card', card: { ...service.card, proof: { type: 'DataIntegrityProof' } }, reason: 'additionalProperties' },
    { name: 'did_key_by_discovery', did: userDidKey, reason: 'did_key_not_resolvable' },
    { name: 'malformed_did_web', did: 'did:web:helix.test:acme:ledger-agent#key-1', reason: 'malformed_did' },
    { name: 'no_card_service', did: stranger.did, served: { [stranger.did_document_url]: { ...stranger.did_document, service: [] } }, reason: 'no_card_service' },
    { name: 'card_for_another_did', did: agent.did, served: { [agent.did_document_url]: agent.did_document, [agent.card_url]: stranger.card }, reason: 'card_mismatch' },
    { name: 'did_document_for_another_did', did: agent.did, served: { [agent.did_document_url]: stranger.did_document }, reason: 'did_document_mismatch' },
    { name: 'did_document_not_served', did: agent.did, served: {}, reason: 'did_document_unavailable' },
  ];

  const buildInput = { id: service.did, entityType: 'mcp', name: service.name, kid: 'key-1', publicKeyJwk: service.public_key_jwk, capabilities: ['tools/list'] };
  const build_cases: EntityCardFixtures['build_cases'] = [
    { name: 'conformance_level_ignored', input: { ...buildInput, conformanceLevel: 'L3' }, expected: 'card', card: buildEntityCard({ ...buildInput, conformanceLevel: 'L3' } as never), absent: ['conformanceLevel'] },
    { name: 'proof_refused', input: { ...buildInput, proof: { type: 'DataIntegrityProof', proofValue: 'z' } }, expected: 'refused' },
    { name: 'unknown_member_refused', input: { ...buildInput, bogusField: true }, expected: 'refused' },
    { name: 'private_key_refused', input: { ...buildInput, publicKeyJwk: { ...service.public_key_jwk, d: 'AAAA' } }, expected: 'refused' },
  ];

  const clear = createStatusList(64);
  const revoked = setBit(clear, 7, 1);
  // The org signs its own list (story L3-C): Bitstring Status List v1.0 with its window and an eddsa-jcs-2022 proof.
  // Read with `status_list_now` (inside the window) and the org's DID document.
  const orgSigner = new EnvSigner({ did: org.did, kid: 'key-1', envVar: 'K', env: { K: org.private_key_hex } });
  const list = (encoded: string): Promise<SignedStatusListCredential> =>
    buildStatusListCredential({ id: `https://${HOST}/v1/status-list/cards`, issuer: orgDid, encodedList: encoded, validFrom: '2026-11-21T00:00:00Z', validUntil: '2026-11-22T00:00:00Z' }, orgSigner);
  const status_lists = { clear: await list(clear), revoked: await list(revoked) };
  const revocation_cases: EntityCardFixtures['revocation_cases'] = [
    { name: 'no_checker', card: agent.card, expected: { ok: false, conformanceLevel: 'L1', revoked: true, code: 'configuration_error' } },
    { name: 'clear', card: agent.card, expected: { ok: true, conformanceLevel: 'L1', revoked: false } },
    { name: 'revoked', card: agent.card, expected: { ok: false, conformanceLevel: 'L1', revoked: true, code: 'card_revoked' } },
    { name: 'no_revocation_entry', card: service.card, expected: { ok: true, conformanceLevel: 'L1', revoked: false } },
  ];

  return {
    generated_from: 'helix-core',
    generator: 'scripts/generate-entity-card-fixtures.ts',
    note: 'KYA-OS story C-A. Regenerate (pnpm generate:entity-card-fixtures) whenever src/core/card/*, src/core/did/* or src/core/net/* change; helix-core, helix-sdk-js, helix-sdk-py and e2e-playwright assert against this file. Test keys only; never real secrets.',
    host: HOST,
    user_did_key: userDidKey,
    entities,
    served,
    resolution,
    refusals,
    build_cases,
    status_lists,
    status_list_now: '2026-11-21T12:00:00Z',
    revocation_cases,
    safe_fetch_refusals: [
      { url: 'http://helix.test/acme/card.json', reason: 'scheme_refused' },
      { url: 'https://127.0.0.1/acme/card.json', reason: 'host_refused' },
      { url: 'https://169.254.169.254/latest/meta-data/', reason: 'host_refused' },
      { url: 'https://10.0.0.1/card.json', reason: 'host_refused' },
      { url: 'https://[::1]/card.json', reason: 'host_refused' },
      { url: 'https://localhost/card.json', reason: 'host_refused' },
      { url: 'https://user:secret@helix.test/card.json', reason: 'host_refused' },
      { url: 'file:///etc/passwd', reason: 'scheme_refused' },
      { url: 'not a url', reason: 'invalid_url' },
    ],
    public_addresses: ['93.184.216.34', '8.8.8.8', '2606:4700:4700::1111', '::ffff:93.184.216.34'],
    non_public_addresses: ['127.0.0.1', '127.255.255.255', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fc00::1', 'fd12::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::7f00:1', '2002:7f00:1::1'],
  };
}

export function serializeEntityCardFixtures(fixtures: EntityCardFixtures): string {
  return `${JSON.stringify(fixtures, null, 2)}\n`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const outDir = fileURLToPath(new URL('../fixtures/kya-os-helix/', import.meta.url));
  mkdirSync(outDir, { recursive: true });
  const fixtures = await buildEntityCardFixtures();
  writeFileSync(`${outDir}entity-card.json`, serializeEntityCardFixtures(fixtures));
  // eslint-disable-next-line no-console
  console.log(`wrote fixtures/kya-os-helix/entity-card.json (${Object.keys(fixtures.entities).length} entities, ${fixtures.refusals.length} refusals)`);
}
