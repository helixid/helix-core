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
 * The local verifier's fixture set (KYA-OS story F-2, stories rule 6):
 * generated once from helix-core's credential builders and the JavaScript
 * reference verifier (`@helixid/sdk-js`, `kyaos.verifier.verify`), checked
 * in at fixtures/verifier/*.json, and consumed by helix-sdk-js, helix-sdk-py
 * and e2e-playwright, which must each come to the recorded verdict and
 * reason codes for every case.
 *
 * Deterministic: fixed test keys (derived from labels, TEST-ONLY, never
 * reuse), a fixed clock and fixed ids and nonces.
 *
 * Story C-C adds `fixtures/kya-os-helix/request-proof.json`: the per-request
 * proof in the exact §11.2 order (a proof broken twice is refused for the
 * earlier step), the carrier keys (canonical and legacy `_meta` keys, read
 * from `input.meta`), and chains verified without a proof (`requireProof:
 * false`). It lives outside fixtures/verifier/ so the F-2 harnesses, which
 * read every file there, are unchanged; its expected verdicts also record
 * `agentDid`, `proofFloor`, `proofAssurance` and `warnings`.
 *
 * Run: pnpm generate:verifier-fixtures
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { kyaos } from '@helixid/sdk-js';
import {
  EnvSigner,
  buildCapabilityAttestation,
  buildDelegationHop,
  createStatusList,
  derivePublicKey,
  publicKeyToMultibase,
  rootHopInput,
  setBit,
  type BitstringStatusEntry,
  type Caveat,
  type DIDDocument,
  type SignedDelegationHop,
} from '../src/core/index.js';
import { didKeyDocument, didKeyKid } from './did-key-document.js';

const { verifier } = kyaos;

export const NOW = '2026-06-01T00:00:00Z';
const NOW_MS = Date.parse(NOW);
const VALID_FROM = '2026-01-01T00:00:00Z';
const PROOF_CREATED = '2026-01-01T00:00:01Z';
/** The resource every chain delegates: the service's DID, which is also the proof audience. */
const KEY_LABELS = ['service', 'owner', 'helix', 'parent', 'agent', 'stranger'] as const;
type KeyLabel = (typeof KEY_LABELS)[number];

export interface FixtureKey {
  private_key_hex: string;
  public_key_hex: string;
  did: string;
  kid: string;
  did_document: DIDDocument;
}

/** A status list as the `fetchStatusList` seam of the fixture harness returns it, before decoding. */
export interface FixtureStatusList {
  encoded_list: string;
  issuer?: string;
  status_purpose?: string | string[];
  id?: string;
  valid_from?: string;
  valid_until?: string;
  /** False for a cached read. */
  fresh?: boolean;
}

export type SeamSetting = {
  resolveDid: 'documents' | 'missing' | 'unknown' | 'throws';
  resolveDidKeys: 'documents' | 'missing' | 'empty' | 'throws';
  fetchStatusList: 'lists' | 'missing' | 'throws';
  nonceStore: 'fresh' | 'replayed' | 'missing' | 'throws';
  clock: 'fixed' | 'missing';
  trustedIssuers: '*' | string[];
  /** `missing` (no seam), `throws`, or the name of the environment card the seam answers with. */
  resolveCard: string;
};

export interface FixtureCase {
  name: string;
  description: string;
  /** `meta` (story C-C cases only): the request's `params._meta`, from which the proof and chain are read as a host reads them. */
  input: { proof?: unknown; chain?: unknown; request?: unknown; card?: unknown; meta?: unknown };
  seams: SeamSetting;
  options: Record<string, unknown>;
  /** Epoch ms the fixed clock answers. */
  now: number;
  expected: {
    ok: boolean;
    level: string;
    effectiveScopes: string[];
    reasons: string[];
    chainSummary: Record<string, unknown>;
    /** Story C-C cases only. */
    agentDid?: string;
    proofFloor?: boolean;
    proofAssurance?: string;
    warnings?: string[];
  };
}

export interface FixtureEnvironment {
  generated_from: string;
  generator: string;
  note: string;
  now: string;
  keys: Record<KeyLabel, FixtureKey>;
  did_documents: Record<string, DIDDocument>;
  status_lists: Record<string, FixtureStatusList>;
  cards: Record<string, unknown>;
}

function fixtureKey(label: string): FixtureKey {
  // TEST-ONLY: the private key is a hash of the label, so the fixture never changes.
  const privateKeyHex = bytesToHex(sha256(utf8ToBytes(`helix-f-2-fixture-key:${label}`)));
  const publicKeyHex = derivePublicKey(privateKeyHex);
  const did = `did:key:${publicKeyToMultibase(publicKeyHex)}`;
  return { private_key_hex: privateKeyHex, public_key_hex: publicKeyHex, did, kid: didKeyKid(did), did_document: didKeyDocument(did, publicKeyHex) };
}

/**
 * The proof with one signature byte changed. A character in the middle of the
 * signature segment: the last base64url character of a 64-byte signature
 * carries only padding bits, so changing it can leave the signature intact.
 */
function flipSignatureByte(proof: kyaos.verifier.RequestProof): kyaos.verifier.RequestProof {
  const at = proof.jws.lastIndexOf('.') + 20;
  return { ...proof, jws: `${proof.jws.slice(0, at)}${proof.jws[at] === 'A' ? 'B' : 'A'}${proof.jws.slice(at + 1)}` };
}

const DEFAULT_SEAMS: SeamSetting = { resolveDid: 'documents', resolveDidKeys: 'documents', fetchStatusList: 'lists', nonceStore: 'fresh', clock: 'fixed', trustedIssuers: '*', resolveCard: 'missing' };

/** The seams of a case, built from the environment exactly as every consumer's test harness builds them. */
export function fixtureSeams(env: FixtureEnvironment, setting: SeamSetting, usedNonces: Set<string>): Record<string, unknown> {
  const documents = env.did_documents as Record<string, unknown>;
  const resolveDid = async (did: string): Promise<unknown> => {
    if (setting.resolveDid === 'throws') throw new Error('resolver down');
    if (setting.resolveDid === 'unknown') return null;
    return documents[did] ?? null;
  };
  const resolveDidKeys = async (did: string): Promise<unknown[]> => {
    if (setting.resolveDidKeys === 'throws') throw new Error('keys down');
    if (setting.resolveDidKeys === 'empty') return [];
    const document = documents[did];
    if (document === undefined) throw new Error(`no document for ${did}`);
    return verifier.ed25519KeysOf(document as never);
  };
  const fetchStatusList = async (url: string): Promise<unknown> => {
    if (setting.fetchStatusList === 'throws') throw new Error('status service down');
    const list = env.status_lists[url];
    if (list === undefined) return undefined;
    return {
      bits: verifier.decodeStatusListBits(list.encoded_list),
      ...(list.issuer === undefined ? {} : { issuer: list.issuer }),
      ...(list.status_purpose === undefined ? {} : { statusPurpose: list.status_purpose }),
      ...(list.id === undefined ? {} : { id: list.id }),
      ...(list.valid_from === undefined ? {} : { validFrom: list.valid_from }),
      ...(list.valid_until === undefined ? {} : { validUntil: list.valid_until }),
      fresh: list.fresh ?? true,
    };
  };
  const nonceStore = {
    insert: async (nonce: string, did: string | undefined): Promise<boolean> => {
      if (setting.nonceStore === 'throws') throw new Error('nonce store down');
      const key = `${did ?? ''}|${nonce}`;
      if (setting.nonceStore === 'replayed' || usedNonces.has(key)) return false;
      usedNonces.add(key);
      return true;
    },
  };
  const resolveCard = async (): Promise<unknown> => {
    if (setting.resolveCard === 'throws') throw new Error('card host down');
    return env.cards[setting.resolveCard];
  };
  return {
    ...(setting.resolveCard === 'missing' ? {} : { resolveCard }),
    ...(setting.resolveDid === 'missing' ? {} : { resolveDid }),
    ...(setting.resolveDidKeys === 'missing' ? {} : { resolveDidKeys }),
    ...(setting.fetchStatusList === 'missing' ? {} : { fetchStatusList }),
    ...(setting.nonceStore === 'missing' ? {} : { nonceStore }),
    ...(setting.clock === 'missing' ? {} : { clock: () => NOW_MS }),
    trustedIssuers: setting.trustedIssuers,
  };
}

/** A copy of `value` without `member`. */
function withoutMember(value: object, member: string): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  delete copy[member];
  return copy;
}

export async function buildVerifierFixtures(): Promise<{ environment: FixtureEnvironment; files: Record<string, FixtureCase[]>; requestProof: FixtureCase[] }> {
  const keys = Object.fromEntries(KEY_LABELS.map((label) => [label, fixtureKey(label)])) as Record<KeyLabel, FixtureKey>;
  const signers = Object.fromEntries(
    // The documents publish each did:key's W3C method `#<multibase>`, which EnvSigner signs with by default.
    KEY_LABELS.map((label) => [label, new EnvSigner({ did: keys[label].did, envVar: 'FIXTURE_KEY', env: { FIXTURE_KEY: keys[label].private_key_hex } })]),
  ) as Record<KeyLabel, EnvSigner>;
  const didDocuments = Object.fromEntries(KEY_LABELS.map((label) => [keys[label].did, keys[label].did_document]));
  const SERVICE = keys.service.did;
  const AGENT = keys.agent.did;

  // ── status lists: one per issuer, plus the variants the status cases need ──
  const lists: Record<string, FixtureStatusList> = {};
  const listUrl = (issuer: KeyLabel, variant = '1'): string => `https://${issuer}.example/status/${variant}`;
  const window = { valid_from: VALID_FROM, valid_until: '2027-01-01T00:00:00Z' };
  for (const issuer of ['owner', 'helix', 'parent', 'agent'] as const) {
    const url = listUrl(issuer);
    lists[url] = { encoded_list: createStatusList(256), issuer: keys[issuer].did, status_purpose: 'revocation', id: url, ...window };
  }
  // Indexes 8 and 9 are set (revoked) on every issuer's main list.
  for (const issuer of ['owner', 'helix', 'parent'] as const) {
    const url = listUrl(issuer);
    lists[url]!.encoded_list = setBit(setBit(lists[url]!.encoded_list, 8, 1), 9, 1);
  }
  lists[listUrl('owner', 'stale')] = { encoded_list: createStatusList(256), issuer: keys.owner.did, status_purpose: 'revocation', id: listUrl('owner', 'stale'), valid_from: VALID_FROM, valid_until: '2026-03-01T00:00:00Z' };
  lists[listUrl('owner', 'suspension')] = { encoded_list: createStatusList(256), issuer: keys.owner.did, status_purpose: 'suspension', id: listUrl('owner', 'suspension'), ...window };
  lists[listUrl('owner', 'foreign')] = { encoded_list: createStatusList(256), issuer: keys.stranger.did, status_purpose: 'revocation', id: listUrl('owner', 'foreign'), ...window };
  lists[listUrl('owner', 'other-id')] = { encoded_list: createStatusList(256), issuer: keys.owner.did, status_purpose: 'revocation', id: listUrl('owner', '1'), ...window };
  lists[listUrl('owner', 'cached')] = { encoded_list: createStatusList(256), issuer: keys.owner.did, status_purpose: ['suspension', 'revocation'], id: listUrl('owner', 'cached'), ...window, fresh: false };
  lists[listUrl('owner', 'bare')] = { encoded_list: createStatusList(256) };

  const entryOf = (issuer: KeyLabel, index: number, variant = '1'): BitstringStatusEntry => ({
    id: `${listUrl(issuer, variant)}#${index}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: String(index),
    statusListCredential: listUrl(issuer, variant),
  });

  // ── attestations (helix-issued) and cards ──────────────────────────────
  const attestation = async (capability: string, index: number, signer: KeyLabel = 'helix'): Promise<unknown> =>
    buildCapabilityAttestation(
      {
        subjectDid: AGENT,
        capability,
        validFrom: VALID_FROM,
        validUntil: '2026-12-31T00:00:00Z',
        id: `urn:uuid:00000000-0000-4000-8000-0000000f2${String(index).padStart(3, '0')}`,
        proofCreated: PROOF_CREATED,
        statusEntry: entryOf(signer, index),
      },
      signers[signer],
    );
  const readOrders = await attestation('read:orders', 1);
  const writeOrders = await attestation('write:orders', 2);
  const readOrdersRevoked = await attestation('read:orders', 8);
  const readOrdersByStranger = await attestation('read:orders', 3, 'stranger');
  const card = (capabilities: unknown[], responsibleParty: string | undefined = keys.owner.did): Record<string, unknown> => ({
    id: AGENT,
    entityType: 'agent',
    name: 'orders-agent',
    kid: keys.agent.kid,
    capabilities,
    ...(responsibleParty === undefined ? {} : { responsibleParty }),
    proofProfile: 'org.kya-os/proof.v1',
  });
  const attested = (name: string, vc: unknown): unknown => ({ name, attestations: [{ vc }] });
  const cards: Record<string, unknown> = {
    attested: card([attested('read:orders', readOrders), attested('write:orders', writeOrders)]),
    one_bare: card([attested('read:orders', readOrders), 'write:orders']),
    revoked_attestation: card([attested('read:orders', readOrdersRevoked), attested('write:orders', writeOrders)]),
    stranger_attested: card([attested('read:orders', readOrdersByStranger), attested('write:orders', writeOrders)]),
    no_responsible_party: card([attested('read:orders', readOrders), attested('write:orders', writeOrders)], undefined),
    stranger_responsible: card([attested('read:orders', readOrders), attested('write:orders', writeOrders)], keys.stranger.did),
    malformed: { ...card([attested('read:orders', readOrders)]), unknownMember: true },
    stranger_card: { ...card([attested('read:orders', readOrders)]), id: keys.stranger.did, kid: keys.stranger.kid },
  };

  // ── the chain: owner (root) → parent → agent ───────────────────────────
  const rootCaveats: Caveat[] = [
    { type: 'MaxAmount', limit: '1000.00', currency: 'USD' },
    { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' },
  ];
  const leafCaveats: Caveat[] = [
    { type: 'MaxAmount', limit: '500.00', currency: 'USD' },
    { type: 'ValidUntil', date: '2026-12-01T00:00:00Z' },
  ];
  const rootBase = {
    invoker: keys.parent.did,
    invocationTarget: SERVICE,
    allowedAction: ['read:orders', 'write:orders', 'read:catalog'],
    caveats: rootCaveats,
    validFrom: VALID_FROM,
    validUntil: '2027-01-01T00:00:00Z',
    statusEntry: entryOf('owner', 1),
    id: 'urn:zcap:00000000-0000-4000-8000-00000000f300',
    proofCreated: PROOF_CREATED,
  };
  const root = await buildDelegationHop(rootHopInput(rootBase), signers.owner);
  const leafBase = {
    invoker: AGENT,
    parentCapability: root.credentialSubject.id,
    invocationTarget: SERVICE,
    allowedAction: ['read:orders', 'write:orders'],
    caveats: leafCaveats,
    validFrom: VALID_FROM,
    validUntil: '2026-12-01T00:00:00Z',
    statusEntry: entryOf('parent', 1),
    id: 'urn:zcap:00000000-0000-4000-8000-00000000f301',
    proofCreated: PROOF_CREATED,
  };
  const leaf = await buildDelegationHop(leafBase, signers.parent);
  /** A root re-delegated straight to the agent. */
  const directRoot = await buildDelegationHop(rootHopInput({ ...rootBase, invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f310', statusEntry: entryOf('owner', 2) }), signers.owner);
  const rootVariant = async (changes: Partial<typeof rootBase>, signer: EnvSigner = signers.owner): Promise<SignedDelegationHop> =>
    buildDelegationHop(rootHopInput({ ...rootBase, ...changes }), signer);
  const leafVariant = async (changes: Partial<typeof leafBase>, signer: EnvSigner = signers.parent): Promise<SignedDelegationHop> =>
    buildDelegationHop({ ...leafBase, ...changes }, signer);

  // ── the request and its proof ──────────────────────────────────────────
  const request = { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-1001' }, _meta: { 'org.kya-os/request-proof': 'stripped before hashing' } } };
  let nonceCounter = 0;
  const nonce = (): string => Buffer.from(`f-2-nonce-${String(++nonceCounter).padStart(4, '0')}`).toString('base64url');
  const proofBy = (signer: KeyLabel, options: Partial<Parameters<typeof verifier.signRequestProof>[2]> = {}, req: typeof request = request): Promise<kyaos.verifier.RequestProof> =>
    verifier.signRequestProof(req, signers[signer], { audience: SERVICE, now: NOW_MS, nonce: nonce(), ...options });
  const agentJkt = verifier.jwkThumbprint({ kty: 'OKP', crv: 'Ed25519', x: Buffer.from(keys.agent.public_key_hex, 'hex').toString('base64url') });

  // ── cases ──────────────────────────────────────────────────────────────
  const files: Record<string, FixtureCase[]> = { valid: [], proof: [], chain: [], status: [], seams: [], 'request-proof': [] };
  const baseOptions = { expectedAudience: SERVICE, resource: SERVICE };
  const add = async (
    file: keyof typeof files,
    name: string,
    description: string,
    input: FixtureCase['input'],
    settings: { seams?: Partial<SeamSetting>; options?: Record<string, unknown>; now?: number } = {},
  ): Promise<void> => {
    const seams: SeamSetting = { ...DEFAULT_SEAMS, ...settings.seams };
    const options = { ...baseOptions, ...settings.options };
    const now = settings.now ?? NOW_MS;
    const environment: FixtureEnvironment = { generated_from: '', generator: '', note: '', now: NOW, keys, did_documents: didDocuments, status_lists: lists, cards };
    const verifierInput =
      input.meta === undefined
        ? input
        : {
            proof: verifier.readRequestProof(input.meta),
            ...(verifier.readCarriedChain(input.meta) === undefined ? {} : { chain: verifier.readCarriedChain(input.meta) }),
            ...(input.request === undefined ? {} : { request: input.request }),
            ...(input.card === undefined ? {} : { card: input.card }),
          };
    const result = await verifier.verify(verifierInput as never, { ...fixtureSeams(environment, seams, new Set()), ...(seams.clock === 'missing' ? {} : { clock: (): number => now }) } as never, options as never);
    const cc = file === 'request-proof';
    files[file]!.push({
      name,
      description,
      input,
      seams,
      options,
      now,
      expected: {
        ok: result.ok,
        level: result.level,
        effectiveScopes: result.effectiveScopes,
        reasons: result.reasons,
        chainSummary: {
          depth: result.chainSummary.depth,
          ...(result.chainSummary.responsibleParty === undefined ? {} : { responsibleParty: result.chainSummary.responsibleParty }),
          ...(result.chainSummary.leafInvoker === undefined ? {} : { leafInvoker: result.chainSummary.leafInvoker }),
          ...(result.chainSummary.invocationTarget === undefined ? {} : { invocationTarget: result.chainSummary.invocationTarget }),
          allowedAction: result.chainSummary.allowedAction,
          fresh: result.chainSummary.fresh,
        },
        ...(cc
          ? {
              ...(result.agentDid === undefined ? {} : { agentDid: result.agentDid }),
              proofFloor: result.proofFloor,
              ...(result.proofAssurance === undefined ? {} : { proofAssurance: result.proofAssurance }),
              warnings: result.warnings,
            }
          : {}),
      },
    });
  };

  const proof = await proofBy('agent');
  const chain = [root, leaf];
  const attestedCard = cards['attested'];

  // valid
  await add('valid', 'two_hop_chain', 'owner → parent → agent, attested card, live status: L3 with both scopes', { proof, chain, request, card: attestedCard });
  await add('valid', 'single_root_hop', 'the owner delegates straight to the agent', { proof: await proofBy('agent'), chain: [directRoot], request, card: attestedCard });
  await add('valid', 'catalog_narrows', 'the service offers only read:orders', { proof: await proofBy('agent'), chain, request, card: attestedCard }, { options: { catalog: ['read:orders'] } });
  await add('valid', 'action_delegated', 'the invoked action is in the leaf allowedAction', { proof: await proofBy('agent'), chain, request, card: attestedCard }, { options: { action: 'read:orders' } });
  await add('valid', 'proof_only_no_chain', 'a proof without a chain is a valid proof that grants no scope', { proof: await proofBy('agent'), request, card: attestedCard });
  await add('valid', 'no_card', 'a chain without a card verifies at L1 with nothing attested', { proof: await proofBy('agent'), chain, request });
  await add('valid', 'card_resolved_by_seam', 'the card comes from the resolveCard seam when the input carries none', { proof: await proofBy('agent'), chain, request }, { seams: { resolveCard: 'attested' } });
  await add('valid', 'input_card_wins_over_seam', 'a card in the input is used before the seam is asked', { proof: await proofBy('agent'), chain, request, card: cards['one_bare'] }, { seams: { resolveCard: 'attested' } });
  await add('valid', 'legacy_proof_profile', 'the legacy org.kya-os/proof@1 profile id is accepted for one major version', { proof: await proofBy('agent', { profile: 'org.kya-os/proof@1' }), chain, request, card: attestedCard });
  await add('valid', 'one_bare_capability_is_l1', 'one self-declared capability floors the level at L1', { proof: await proofBy('agent'), chain, request, card: cards['one_bare'] });
  await add('valid', 'cached_status_demotes_to_l2', 'a status read from a cache keeps the call allowed at L2', { proof: await proofBy('agent'), chain: [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f311', statusEntry: entryOf('owner', 3, 'cached') })], request, card: attestedCard });
  await add('valid', 'trusted_issuer_list_with_helix', 'a trusted-issuer list naming Helix verifies the Helix attestations', { proof: await proofBy('agent'), chain, request, card: attestedCard }, { seams: { trustedIssuers: [keys.helix.did] } });
  await add('valid', 'unlisted_issuer_demotes', 'a trusted-issuer list without Helix leaves every attestation unverified: L1, no scopes', { proof: await proofBy('agent'), chain, request, card: attestedCard }, { seams: { trustedIssuers: [keys.stranger.did] } });
  await add('valid', 'stranger_attestation_under_allow_all', 'under allow-all an attestation from any issuer verifies', { proof: await proofBy('agent'), chain, request, card: cards['stranger_attested'] });
  await add('valid', 'cnf_fused_l3', 'the token cnf.jkt, the proof cnf.jkt and the key thumbprint fuse', { proof: await proofBy('agent', { cnfJkt: agentJkt }), chain, request, card: attestedCard }, { options: { tokenCnfJkt: agentJkt } });
  await add('valid', 'revoked_attestation_demotes', 'a revoked attestation collapses its capability to unverified: L1, that scope gone', { proof: await proofBy('agent'), chain, request, card: cards['revoked_attestation'] });
  await add('valid', 'no_responsible_party_on_card', 'a card without responsibleParty is not gated on the root issuer', { proof: await proofBy('agent'), chain, request, card: cards['no_responsible_party'] });
  await add('valid', 'resource_owner_pinned', 'the verifier pins the owner as the resource owner', { proof: await proofBy('agent'), chain, request, card: attestedCard }, { options: { resourceOwner: keys.owner.did } });
  await add('valid', 'trusted_root_listed', 'the root issuer is among the trusted root issuers', { proof: await proofBy('agent'), chain, request, card: attestedCard }, { options: { trustedRootIssuers: [keys.owner.did] } });

  // proof
  const tamperedSignature = flipSignatureByte(await proofBy('agent'));
  await add('proof', 'tampered_signature', 'the detached JWS no longer verifies', { proof: tamperedSignature, chain, request, card: attestedCard });
  await add('proof', 'tampered_request', 'the request body differs from the one the proof binds', { proof: await proofBy('agent'), chain, request: { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-9999' } } }, card: attestedCard });
  await add('proof', 'meta_tampering_is_free', 'a changed params._meta leaves requestHash unchanged', { proof: await proofBy('agent'), chain, request: { method: 'tools/call', params: { ...request.params, _meta: { other: 1 } } }, card: attestedCard });
  await add('proof', 'wrong_audience', 'a proof minted for another service', { proof: await proofBy('agent', { audience: keys.stranger.did }), chain, request, card: attestedCard });
  await add('proof', 'expired', 'the proof expired more than the skew ago', { proof: await proofBy('agent', { now: NOW_MS - 120_000 }), chain, request, card: attestedCard });
  await add('proof', 'created_in_future', 'the proof is created later than now plus the skew', { proof: await proofBy('agent', { now: NOW_MS + 30_000 }), chain, request, card: attestedCard });
  await add('proof', 'ttl_too_long', 'expires - created exceeds 60 seconds', { proof: await proofBy('agent', { ttlSeconds: 61 }), chain, request, card: attestedCard });
  await add('proof', 'invalid_window', 'expires is not after created', { proof: await proofBy('agent', { ttlSeconds: 0 }), chain, request, card: attestedCard });
  await add('proof', 'within_skew', 'a proof that expired within the skew is still accepted', { proof: await proofBy('agent', { now: NOW_MS - 63_000 }), chain, request, card: attestedCard });
  const strangerKid = { ...(await proofBy('agent')), kid: keys.stranger.kid };
  await add('proof', 'kid_did_mismatch', 'kid belongs to another DID than did', { proof: strangerKid, chain, request, card: attestedCard });
  const forgedPrincipal = { ...(await proofBy('stranger')), did: AGENT, kid: keys.agent.kid };
  await add('proof', 'forged_principal', 'a proof signed by a stranger claiming the agent DID fails the signature under the agent key', { proof: forgedPrincipal, chain, request, card: attestedCard });
  await add('proof', 'key_not_published', 'kid names a method the DID document does not list', { proof: { ...(await proofBy('agent')), kid: `${AGENT}#key-9` }, chain, request, card: attestedCard });
  await add('proof', 'key_not_in_did_document', 'the DID-key membership seam lists no key with the thumbprint', { proof: await proofBy('agent'), chain, request, card: attestedCard }, { seams: { resolveDidKeys: 'empty' } });
  await add('proof', 'malformed_missing_nonce', 'a proof without a nonce is not a proof', { proof: withoutMember(await proofBy('agent'), 'nonce'), chain, request, card: attestedCard });
  await add('proof', 'malformed_unknown_member', 'a proof with an unknown member is not a proof', { proof: { ...(await proofBy('agent')), extra: 1 }, chain, request, card: attestedCard });
  await add('proof', 'malformed_not_an_object', 'a string is not a proof', { proof: 'not-a-proof', chain, request, card: attestedCard });
  await add('proof', 'proof_missing', 'no proof at all', { chain, request, card: attestedCard });
  await add('proof', 'request_missing', 'no request to recompute requestHash from', { proof: await proofBy('agent'), chain, card: attestedCard });
  await add('proof', 'es256_unsupported', 'the Helix profile verifies Ed25519 only', { proof: { ...(await proofBy('agent')), alg: 'ES256' }, chain, request, card: attestedCard });
  await add('proof', 'cnf_key_mismatch', 'cnf.jkt is not the signing key thumbprint', { proof: await proofBy('agent', { cnfJkt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }), chain, request, card: attestedCard });
  await add('proof', 'cnf_required_by_token', 'the token is sender-constrained but the proof carries no cnf', { proof: await proofBy('agent'), chain, request, card: attestedCard }, { options: { tokenCnfJkt: agentJkt } });
  await add('proof', 'cnf_token_mismatch', 'the proof cnf.jkt is not the token cnf.jkt', { proof: await proofBy('agent', { cnfJkt: agentJkt }), chain, request, card: attestedCard }, { options: { tokenCnfJkt: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' } });
  await add('proof', 'cnf_present_but_token_unfused', 'a proof cnf with no token cnf is a sound L3-minus proof', { proof: await proofBy('agent', { cnfJkt: agentJkt }), chain, request, card: attestedCard });

  // chain
  const expectedChainFail = async (name: string, description: string, hops: unknown[], options: Record<string, unknown> = {}, cardName = 'attested'): Promise<void> =>
    add('chain', name, description, { proof: await proofBy('agent'), chain: hops, request, card: cards[cardName] }, { options });
  await expectedChainFail('broadened_action', 'the leaf adds read:catalog, which its parent delegated, and refund:orders, which it did not', [root, await leafVariant({ allowedAction: ['read:orders', 'refund:orders'] })]);
  await expectedChainFail('dropped_caveat', 'the leaf drops the MaxAmount caveat', [root, await leafVariant({ caveats: leafCaveats.filter((caveat) => caveat.type !== 'MaxAmount') })]);
  await expectedChainFail('widened_max_amount', 'the leaf raises MaxAmount above its parent', [root, await leafVariant({ caveats: [{ type: 'MaxAmount', limit: '1000.000001', currency: 'USD' }, leafCaveats[1]!] })]);
  await expectedChainFail('changed_currency', 'the leaf switches the MaxAmount currency', [root, await leafVariant({ caveats: [{ type: 'MaxAmount', limit: '10.00', currency: 'EUR' }, leafCaveats[1]!] })]);
  await expectedChainFail('extended_valid_until', 'the leaf expires after its parent', [root, await leafVariant({ validUntil: '2027-06-01T00:00:00Z' })]);
  await expectedChainFail('extended_valid_until_caveat', 'the leaf ValidUntil caveat is later than its parent caveat', [root, await leafVariant({ caveats: [leafCaveats[0]!, { type: 'ValidUntil', date: '2027-06-01T00:00:00Z' }] })]);
  await expectedChainFail('broken_parent_capability', 'the leaf names a parent capability that is not its parent', [root, await leafVariant({ parentCapability: 'urn:zcap:elsewhere' })]);
  await expectedChainFail('broken_continuity', 'the leaf is issued by the owner, not by the delegate the root named', [root, await leafVariant({}, signers.owner)]);
  await expectedChainFail('target_drift', 'the leaf names another resource', [root, await leafVariant({ invocationTarget: keys.stranger.did })]);
  await expectedChainFail('wrong_resource', 'the chain is evaluated at a resource other than its invocationTarget', chain, { resource: keys.stranger.did });
  await expectedChainFail('resource_owner_mismatch', 'the verifier pins another resource owner', chain, { resourceOwner: keys.stranger.did });
  await expectedChainFail('root_parent_mismatch', "the root's parentCapability is not its invocationTarget", [await buildDelegationHop({ ...rootBase, parentCapability: 'urn:zcap:not-the-resource', invoker: AGENT }, signers.owner)]);
  await expectedChainFail('expired_leaf', 'the leaf expired before now', [root, await leafVariant({ validUntil: '2026-05-01T00:00:00Z' })]);
  await expectedChainFail('not_yet_valid', 'the leaf is not valid until after now', [root, await leafVariant({ validFrom: '2026-07-01T00:00:00Z' })]);
  await expectedChainFail('malformed_hop', 'an extra credentialSubject member is refused (Core L3.5a style)', [root, { ...leaf, credentialSubject: { ...leaf.credentialSubject, role: 'admin' } }]);
  await expectedChainFail('unsigned_leaf', 'a hop without a proof fails the schema', [root, withoutMember(leaf, 'proof')]);
  const tamperedLeaf = { ...leaf, proof: { ...leaf.proof, proofValue: `${leaf.proof.proofValue.slice(0, -1)}${leaf.proof.proofValue.endsWith('1') ? '2' : '1'}` } };
  await expectedChainFail('tampered_hop_proof', 'the leaf proofValue is altered', [root, tamperedLeaf]);
  const resigned = await leafVariant({}, signers.stranger);
  await expectedChainFail('hop_signed_by_another_key', 'the leaf is signed by a key that is not its issuer\'s', [root, { ...resigned, issuer: keys.parent.did }]);
  await expectedChainFail('leaf_invoker_mismatch', 'the leaf delegates to a stranger, not the proof DID', [root, await leafVariant({ invoker: keys.stranger.did })]);
  await expectedChainFail('untrusted_root_issuer', 'the root issuer is not among the trusted root issuers', chain, { trustedRootIssuers: [keys.stranger.did] });
  await expectedChainFail('action_not_delegated', 'the invoked action is not in the leaf allowedAction', chain, { action: 'refund:orders' });
  await expectedChainFail('root_not_responsible_party', "the card's responsibleParty is not the root issuer", chain, {}, 'stranger_responsible');
  await expectedChainFail('card_malformed', 'the card carries an unknown member and the strict schema refuses it', chain, {}, 'malformed');
  await expectedChainFail('card_subject_mismatch', "the card is another DID's", chain, {}, 'stranger_card');
  await add('chain', 'card_unresolvable', 'a resolveCard seam that throws refuses the call', { proof: await proofBy('agent'), chain, request }, { seams: { resolveCard: 'throws' } });
  const stub = (index: number): unknown => ({ ...leaf, id: `urn:zcap:too-long-${index}` });
  await expectedChainFail('chain_too_long', 'eleven hops are refused for their length alone, before any entry is parsed or resolved', [root, ...Array.from({ length: 10 }, (_unused, index) => stub(index))]);
  await expectedChainFail('length_limit_lowered', 'maxChainLength 1 refuses a two-hop chain', chain, { maxChainLength: 1 });
  await expectedChainFail('empty_chain', 'an empty array carries no chain', []);
  await expectedChainFail('chain_not_an_array', 'a chain must be an array of hops', { not: 'a chain' } as never);
  await expectedChainFail('no_fallback_after_failed_chain', 'a failed carried chain is refused as is; a valid chain is never looked up in its place', [await leafVariant({ invoker: keys.stranger.did })]);

  // status
  const statusCase = async (name: string, description: string, hops: unknown[], settings: { seams?: Partial<SeamSetting>; options?: Record<string, unknown> } = {}, cardName = 'attested'): Promise<void> =>
    add('status', name, description, { proof: await proofBy('agent'), chain: hops, request, card: cards[cardName] }, settings);
  await statusCase('revoked_leaf', 'the leaf bit is set', [root, await leafVariant({ statusEntry: entryOf('parent', 9) })]);
  await statusCase('revoked_root_cascades', 'the root bit is set, so the leaf is refused with it', [await rootVariant({ statusEntry: entryOf('owner', 9) }), leaf]);
  await statusCase('stale_list', 'the list is past its validUntil', [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f320', statusEntry: entryOf('owner', 4, 'stale') })]);
  await statusCase('unavailable_list', 'the list cannot be fetched', [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f321', statusEntry: entryOf('owner', 4, 'missing') })]);
  await statusCase('list_fetch_throws', 'the status seam throws', chain, { seams: { fetchStatusList: 'throws' } });
  await statusCase('purpose_mismatch', 'a suspension list says nothing of revocation', [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f322', statusEntry: entryOf('owner', 4, 'suspension') })]);
  await statusCase('foreign_issuer_list', 'a list another DID signed cannot speak for the credential', [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f323', statusEntry: entryOf('owner', 4, 'foreign') })]);
  await statusCase('list_id_mismatch', 'a list that states another URL as its id is not the list the entry names', [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f324', statusEntry: entryOf('owner', 4, 'other-id') })]);
  await statusCase('bare_bits_list', 'a seam that reports bits alone is read on the bits alone', [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f325', statusEntry: entryOf('owner', 4, 'bare') })]);
  await statusCase('index_out_of_range', 'an index past the list names no bit', [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f326', statusEntry: entryOf('owner', 4096) })]);
  await statusCase('status_seam_missing', 'without a fetchStatusList seam a chain cannot be verified', chain, { seams: { fetchStatusList: 'missing' } });
  await statusCase('revoked_attestation_only_demotes', 'a revoked attestation demotes but does not refuse', chain, {}, 'revoked_attestation');

  // seams
  const seamCase = async (name: string, description: string, seams: Partial<SeamSetting>): Promise<void> =>
    add('seams', name, description, { proof: await proofBy('agent'), chain, request, card: attestedCard }, { seams });
  await seamCase('nonce_replayed', 'a nonce the store already holds', { nonceStore: 'replayed' });
  await seamCase('nonce_seam_missing', 'without a nonce store there is no replay defense to run', { nonceStore: 'missing' });
  await seamCase('nonce_store_throws', 'a nonce store that cannot answer', { nonceStore: 'throws' });
  await seamCase('did_membership_unverifiable', 'without resolveDidKeys the key cannot be shown to belong to the DID', { resolveDidKeys: 'missing' });
  await seamCase('did_keys_unresolvable', 'a resolveDidKeys seam that throws', { resolveDidKeys: 'throws' });
  await seamCase('did_resolver_missing', 'without resolveDid the signing key cannot be read', { resolveDid: 'missing' });
  await seamCase('did_unresolved', 'the DID does not resolve', { resolveDid: 'unknown' });
  await seamCase('did_resolver_throws', 'the DID resolver throws', { resolveDid: 'throws' });
  await seamCase('clock_seam_missing', 'without a clock nothing is dated', { clock: 'missing' });
  await seamCase('every_seam_missing', 'every missing seam is reported', { clock: 'missing', resolveDid: 'missing', resolveDidKeys: 'missing', nonceStore: 'missing' });


  // request-proof (story C-C): the §11.2 order, the carrier keys, chains without a proof.
  const cc = async (name: string, description: string, input: FixtureCase['input'], settings: { seams?: Partial<SeamSetting>; options?: Record<string, unknown> } = {}): Promise<void> =>
    add('request-proof', name, description, input, settings);
  const badSignature = flipSignatureByte;
  await cc('order_key_before_audience', 'step 4 (key membership) runs before step 5 (audience)', { proof: await proofBy('agent', { audience: keys.stranger.did }), chain, request, card: attestedCard }, { seams: { resolveDidKeys: 'empty' } });
  await cc('order_key_unresolvable_before_audience', 'step 3 (the key kid names) runs before step 5 (audience)', { proof: { ...(await proofBy('agent', { audience: keys.stranger.did })), kid: `${AGENT}#key-9` }, chain, request, card: attestedCard });
  await cc('order_audience_before_request_hash', 'step 5 (audience) runs before step 6 (requestHash)', { proof: await proofBy('agent', { audience: keys.stranger.did }), chain, request: { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-9999' } } }, card: attestedCard });
  await cc('order_request_hash_before_window', 'step 6 (requestHash) runs before step 7 (window)', { proof: await proofBy('agent', { now: NOW_MS - 120_000 }), chain, request: { method: 'tools/call', params: { name: 'lookup_order', arguments: { orderId: 'ORD-9999' } } }, card: attestedCard });
  await cc('order_window_before_nonce', 'step 7 (window) runs before step 8 (nonce)', { proof: await proofBy('agent', { now: NOW_MS - 120_000 }), chain, request, card: attestedCard }, { seams: { nonceStore: 'replayed' } });
  await cc('order_nonce_before_signature', 'step 8 (nonce) runs before step 9 (signature)', { proof: badSignature(await proofBy('agent')), chain, request, card: attestedCard }, { seams: { nonceStore: 'replayed' } });
  await cc('order_signature_before_cnf', 'step 9 (signature) runs before step 10 (cnf fusion)', { proof: badSignature(await proofBy('agent')), chain, request, card: attestedCard }, { options: { tokenCnfJkt: agentJkt } });
  await cc('order_nonce_seam_at_step_8', 'without a nonce store the proof is refused at step 8, after its earlier bindings held', { proof: await proofBy('agent', { audience: keys.stranger.did }), chain, request, card: attestedCard }, { seams: { nonceStore: 'missing' } });
  await cc('canonical_key', 'the proof and chain read from _meta under the canonical keys', { meta: { 'org.kya-os/request-proof': await proofBy('agent'), 'org.kya-os/delegation-chain': chain }, request, card: attestedCard });
  await cc('legacy_key', 'a proof under the legacy carrier key org.kya-os/proof@1 verifies for one major version', { meta: { 'org.kya-os/proof@1': await proofBy('agent'), 'org.kya-os/delegation-chain': chain }, request, card: attestedCard });
  await cc('legacy_key_and_profile', 'the legacy carrier key with the legacy prf', { meta: { 'org.kya-os/proof@1': await proofBy('agent', { profile: 'org.kya-os/proof@1' }), 'org.kya-os/delegation-chain': chain }, request, card: attestedCard });
  await cc('canonical_key_wins', 'with both keys present the canonical one is read, whatever the legacy one holds', { meta: { 'org.kya-os/request-proof': await proofBy('agent'), 'org.kya-os/proof@1': 'ignored', 'org.kya-os/delegation-chain': chain }, request, card: attestedCard });
  await cc('canonical_key_wins_when_broken', 'with both keys present a broken canonical proof is not replaced by the legacy one', { meta: { 'org.kya-os/request-proof': { prf: 'org.kya-os/proof.v1' }, 'org.kya-os/proof@1': await proofBy('agent'), 'org.kya-os/delegation-chain': chain }, request, card: attestedCard });
  await cc('meta_members_not_covered', 'host members added to params._meta leave requestHash unchanged', { proof: await proofBy('agent'), chain, request: { method: 'tools/call', params: { ...request.params, _meta: { progressToken: 7, 'vendor/x': { a: 1 } } } }, card: attestedCard });
  await cc('cnf_fused_l3_assurance', 'the three thumbprints fuse: L3 assurance, no diagnostic', { proof: await proofBy('agent', { cnfJkt: agentJkt }), chain, request, card: attestedCard }, { options: { tokenCnfJkt: agentJkt } });
  await cc('cnf_unfused_l3_minus', 'a proof cnf with no token cnf: L3-minus, with the cnf diagnostic', { proof: await proofBy('agent', { cnfJkt: agentJkt }), chain, request, card: attestedCard });
  await cc('chain_without_proof_required', 'by default a chain without a proof is refused proof_missing', { chain, request, card: attestedCard });
  await cc('chain_without_proof_l2', 'a chain without a proof, allowed to go without one: verified, L2, the leaf delegate as the agent', { chain, request, card: attestedCard }, { options: { requireProof: false } });
  await cc('chain_without_proof_cached_l2', 'a chain without a proof on a cached status read stays L2, fresh false', { chain: [await rootVariant({ invoker: AGENT, id: 'urn:zcap:00000000-0000-4000-8000-00000000f311', statusEntry: entryOf('owner', 3, 'cached') })], request, card: attestedCard }, { options: { requireProof: false } });
  await cc('chain_without_proof_unattested_l1', 'a chain without a proof and a card with a bare capability: L1', { chain, request, card: cards['one_bare'] }, { options: { requireProof: false } });
  await cc('chain_without_proof_card_by_seam', 'a chain without a proof reads the leaf delegate\'s card from the seam', { chain, request }, { seams: { resolveCard: 'attested' }, options: { requireProof: false } });
  await cc('chain_without_proof_broken', 'a chain without a proof is verified in full: a broadened leaf is refused', { chain: [root, await leafVariant({ allowedAction: ['read:orders', 'refund:orders'] })], request, card: attestedCard }, { options: { requireProof: false } });
  await cc('chain_without_proof_revoked', 'a chain without a proof is checked for revocation: a revoked leaf is refused', { chain: [root, await leafVariant({ statusEntry: entryOf('parent', 9) })], request, card: attestedCard }, { options: { requireProof: false } });
  await cc('chain_without_proof_card_mismatch', 'a chain without a proof and a card of another DID than the leaf delegate', { chain, request, card: cards['stranger_card'] }, { options: { requireProof: false } });
  await cc('chain_without_proof_wrong_party', "a chain without a proof whose root issuer is not the card's responsibleParty", { chain, request, card: cards['stranger_responsible'] }, { options: { requireProof: false } });
  await cc('nothing_presented', 'no proof and no chain is proof_missing even when a proof is optional', { request, card: attestedCard }, { options: { requireProof: false } });
  await cc('proof_with_chain_optional', 'a proof present is verified in full when a proof is optional: a bad signature is refused', { proof: badSignature(await proofBy('agent')), chain, request, card: attestedCard }, { options: { requireProof: false } });

  const environment: FixtureEnvironment = {
    generated_from: 'helix-core scripts/gen-fixtures.ts with @helixid/sdk-js kyaos.verifier (the JavaScript reference)',
    generator: 'pnpm generate:verifier-fixtures',
    note: 'TEST-ONLY keys derived from labels; never reuse. Regenerate whenever the verifier or a builder changes and commit the diff. Do not hand-edit.',
    now: NOW,
    keys,
    did_documents: didDocuments,
    status_lists: lists,
    cards,
  };
  const { 'request-proof': requestProof, ...verifierFiles } = files;
  return { environment, files: verifierFiles, requestProof: requestProof! };
}

/** The text of fixtures/kya-os-helix/request-proof.json (story C-C): its cases, on the F-2 environment. */
export function requestProofFile(environment: FixtureEnvironment, cases: FixtureCase[]): string {
  return `${JSON.stringify({ generated_from: environment.generated_from, environment: 'fixtures/verifier/environment.json', cases }, null, 2)}\n`;
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const { environment, files, requestProof } = await buildVerifierFixtures();
  const dir = fileURLToPath(new URL('../fixtures/verifier/', import.meta.url));
  mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}environment.json`, `${JSON.stringify(environment, null, 2)}\n`);
  let total = 0;
  for (const [name, cases] of Object.entries(files)) {
    writeFileSync(`${dir}${name}.json`, `${JSON.stringify({ generated_from: environment.generated_from, cases }, null, 2)}\n`);
    total += cases.length;
  }
  console.log(`fixtures/verifier: environment.json and ${Object.keys(files).length} case files, ${total} cases`);
  // Story C-C: beside the F-2 set, on the same environment (fixtures/verifier/environment.json).
  const helixDir = fileURLToPath(new URL('../fixtures/kya-os-helix/', import.meta.url));
  writeFileSync(`${helixDir}request-proof.json`, requestProofFile(environment, requestProof));
  console.log(`fixtures/kya-os-helix/request-proof.json: ${requestProof.length} cases`);
}
