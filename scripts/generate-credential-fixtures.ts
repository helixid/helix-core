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
 * Cross-language credential fixtures (KYA-OS story F-1, stories rule 6):
 * generated once from helix-core's builders and checked in at
 * fixtures/kya-os-helix/credentials.json, then consumed by helix-core,
 * helix-sdk-py and e2e-playwright. Deterministic: fixed test keys (derived
 * from labels, TEST-ONLY, never reuse), a fixed clock and fixed ids.
 *
 * Run: pnpm generate:credential-fixtures
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import {
  EnvSigner,
  attestedCapabilityEntry,
  buildCapabilityAttestation,
  buildDIDDocument,
  buildDelegationHop,
  buildIdentityCredential,
  buildIdentityVerificationCredential,
  createStatusList,
  derivePublicKey,
  deriveConformanceLevel,
  checkCapabilities,
  evaluateDelegationChain,
  deriveEffectiveScopes,
  publicKeyToMultibase,
  rootHopInput,
  setBit,
  signDataIntegrity,
  type BitstringStatusEntry,
  type CardCapability,
  type Caveat,
  type DIDDocument,
  type DelegationChainEvaluation,
  type JwsDidDocument,
  type SignedDelegationHop,
  type TrustedIssuers,
} from '../src/core/index.js';

export interface FixtureKey {
  private_key_hex: string;
  public_key_hex: string;
  did: string;
  kid: string;
  did_document: DIDDocument;
}

export interface ChainCase {
  name: string;
  description: string;
  hops: unknown[];
  options: { resource?: string; resourceOwner?: string; now: string; maxChainLength?: number };
  expected: Pick<DelegationChainEvaluation, 'ok' | 'allowedAction' | 'depth'> & {
    code?: string;
    responsibleParty?: string;
    leafInvoker?: string;
  };
  /** Whether every hop's proof verifies against the fixture DID documents. */
  proofs_ok: boolean;
}

export interface EffectiveScopesCase {
  name: string;
  attestations: string[];
  leaf_allowed_action: string[];
  catalog: string[];
  expected: string[];
  /** The retired verifier's formula this case equals, for the parity test. */
  legacy?: { privilege_scopes: string[]; grant_scopes: string[] | null; expected: string[] };
}

export interface CardLevelCase {
  name: string;
  capabilities: CardCapability[];
  subject_did: string;
  trusted_issuers: TrustedIssuers;
  proof_floor_ok: boolean;
  revocation_fresh: boolean;
  expected_check: { verified: string[]; unverified: string[] };
  expected_level: 'L1' | 'L2' | 'L3';
}

export interface SchemaRejection {
  name: string;
  kind: 'identity' | 'attestation' | 'hop';
  document: unknown;
  violation_path: string;
}

export interface CredentialFixtures {
  generated_from: string;
  generator: string;
  note: string;
  now: string;
  status_list_url: string;
  /** The status list every entry points at, with the revoked attestation's bit set. */
  status_list_encoded: string;
  keys: Record<string, FixtureKey>;
  did_documents: Record<string, DIDDocument>;
  identity: { input: Record<string, unknown>; credential: unknown };
  identity_verification: { input: Record<string, unknown>; credential: unknown };
  attestations: { name: string; signer: string; input: Record<string, unknown>; credential: unknown; revoked: boolean }[];
  chains: ChainCase[];
  effective_scopes: EffectiveScopesCase[];
  card_levels: CardLevelCase[];
  schema_rejections: SchemaRejection[];
}

export const NOW = '2026-06-01T00:00:00Z';
export const STATUS_LIST_URL = 'https://helix.example/v1/status-list/helix-status-list-1';
const VALID_FROM = '2026-01-01T00:00:00Z';
const PROOF_CREATED = '2026-01-01T00:00:01Z';
const RESOURCE = 'did:web:service.example:orders';

const KEY_LABELS = ['helix', 'owner', 'user', 'parent', 'child', 'grandchild', 'stranger'] as const;
type KeyLabel = (typeof KEY_LABELS)[number];

function fixtureKey(label: string): FixtureKey {
  // TEST-ONLY: the private key is a hash of the label, so the fixture never changes.
  const privateKeyHex = bytesToHex(sha256(utf8ToBytes(`helix-f-1-fixture-key:${label}`)));
  const publicKeyHex = derivePublicKey(privateKeyHex);
  const did = `did:key:${publicKeyToMultibase(publicKeyHex)}`;
  return { private_key_hex: privateKeyHex, public_key_hex: publicKeyHex, did, kid: `${did}#key-1`, did_document: buildDIDDocument(did, publicKeyHex) };
}

/** A copy of `value` without `member`. */
function withoutMember(value: object, member: string): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  delete copy[member];
  return copy;
}

let statusIndex = 0;
function nextStatusEntry(): BitstringStatusEntry & { index: number } {
  statusIndex += 1;
  return {
    id: `${STATUS_LIST_URL}#${statusIndex}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: String(statusIndex),
    statusListCredential: STATUS_LIST_URL,
    index: statusIndex,
  };
}

function entry(): BitstringStatusEntry {
  return withoutMember(nextStatusEntry(), 'index') as unknown as BitstringStatusEntry;
}

export async function buildCredentialFixtures(): Promise<CredentialFixtures> {
  statusIndex = 0;
  const keys = Object.fromEntries(KEY_LABELS.map((label) => [label, fixtureKey(label)])) as Record<KeyLabel, FixtureKey>;
  const signers = Object.fromEntries(
    KEY_LABELS.map((label) => [label, new EnvSigner({ did: keys[label].did, envVar: 'FIXTURE_KEY', env: { FIXTURE_KEY: keys[label].private_key_hex } })]),
  ) as Record<KeyLabel, EnvSigner>;
  const didDocuments = Object.fromEntries(KEY_LABELS.map((label) => [keys[label].did, keys[label].did_document]));
  const resolve = async (did: string): Promise<JwsDidDocument | undefined> => didDocuments[did] as unknown as JwsDidDocument | undefined;

  // ── identity ────────────────────────────────────────────────────────────
  const identityInput = {
    agentDid: keys.child.did,
    name: 'orders-agent',
    ownerDid: keys.owner.did,
    id: 'urn:uuid:00000000-0000-4000-8000-00000000f101',
    validFrom: VALID_FROM,
    validUntil: '2027-01-01T00:00:00Z',
    proofCreated: PROOF_CREATED,
  };
  const identity = await buildIdentityCredential({ ...identityInput, statusEntry: entry() }, signers.helix);

  const verificationInput = {
    subjectDid: keys.owner.did,
    subjectType: 'organization' as const,
    verificationLevel: 'enhanced' as const,
    provider: 'kyb.example',
    id: 'urn:uuid:00000000-0000-4000-8000-00000000f102',
    validFrom: VALID_FROM,
    validUntil: '2027-01-01T00:00:00Z',
    proofCreated: PROOF_CREATED,
  };
  const identityVerification = await buildIdentityVerificationCredential({ ...verificationInput, statusEntry: entry() }, signers.helix);

  // ── attestations ────────────────────────────────────────────────────────
  const attestationSpecs: { name: string; signer: KeyLabel; capability: string; revoked: boolean }[] = [
    { name: 'read_orders_helix', signer: 'helix', capability: 'read:orders', revoked: false },
    { name: 'read_catalog_owner', signer: 'owner', capability: 'read:catalog', revoked: false },
    { name: 'write_orders_helix_revoked', signer: 'helix', capability: 'write:orders', revoked: true },
  ];
  let encodedList = createStatusList(256);
  const attestations: CredentialFixtures['attestations'] = [];
  for (const [position, spec] of attestationSpecs.entries()) {
    const status = nextStatusEntry();
    const index = status.index;
    const statusEntry = withoutMember(status, 'index') as unknown as BitstringStatusEntry;
    const input = {
      subjectDid: keys.child.did,
      capability: spec.capability,
      validUntil: '2026-12-31T00:00:00Z',
      id: `urn:uuid:00000000-0000-4000-8000-00000000f2${String(position).padStart(2, '0')}`,
      validFrom: VALID_FROM,
      proofCreated: PROOF_CREATED,
    };
    const credential = await buildCapabilityAttestation({ ...input, statusEntry }, signers[spec.signer]);
    if (spec.revoked) encodedList = setBit(encodedList, index, 1);
    attestations.push({ name: spec.name, signer: spec.signer, input, credential, revoked: spec.revoked });
  }

  // ── a three-hop chain: user (root) → parent → child → grandchild ───────
  const rootCaveats: Caveat[] = [
    { type: 'MaxAmount', limit: '1000.00', currency: 'USD' },
    { type: 'ValidUntil', date: '2027-01-01T00:00:00Z' },
    { type: 'Region', regions: ['EU'] },
  ];
  const hop1Caveats: Caveat[] = [
    { type: 'MaxAmount', limit: '500.00', currency: 'USD' },
    { type: 'ValidUntil', date: '2026-12-01T00:00:00Z' },
    { type: 'Region', regions: ['EU'] },
  ];
  const hop2Caveats: Caveat[] = [
    { type: 'MaxAmount', limit: '100.5', currency: 'USD' },
    { type: 'ValidUntil', date: '2026-09-01T00:00:00Z' },
    { type: 'Region', regions: ['EU'] },
  ];
  const root = await buildDelegationHop(
    rootHopInput({
      invoker: keys.parent.did,
      invocationTarget: RESOURCE,
      allowedAction: ['read:orders', 'write:orders', 'read:catalog'],
      caveats: rootCaveats,
      validFrom: VALID_FROM,
      validUntil: '2027-01-01T00:00:00Z',
      statusEntry: entry(),
      id: 'urn:zcap:00000000-0000-4000-8000-00000000f300',
      proofCreated: PROOF_CREATED,
    }),
    signers.user,
  );
  const hop1Base = {
    invoker: keys.child.did,
    parentCapability: root.credentialSubject.id,
    invocationTarget: RESOURCE,
    allowedAction: ['read:orders', 'read:catalog'],
    caveats: hop1Caveats,
    validFrom: VALID_FROM,
    validUntil: '2026-12-01T00:00:00Z',
    statusEntry: entry(),
    id: 'urn:zcap:00000000-0000-4000-8000-00000000f301',
    proofCreated: PROOF_CREATED,
  };
  const hop1 = await buildDelegationHop(hop1Base, signers.parent);
  const hop2Base = {
    invoker: keys.grandchild.did,
    parentCapability: hop1.credentialSubject.id,
    invocationTarget: RESOURCE,
    allowedAction: ['read:orders'],
    caveats: hop2Caveats,
    validFrom: VALID_FROM,
    validUntil: '2026-09-01T00:00:00Z',
    statusEntry: entry(),
    id: 'urn:zcap:00000000-0000-4000-8000-00000000f302',
    proofCreated: PROOF_CREATED,
  };
  const hop2 = await buildDelegationHop(hop2Base, signers.child);
  const leafStatus = hop2.credentialStatus;

  /** A variant of the leaf, re-signed by `signer` (default the child) so proofs hold and only the local rule under test breaks. */
  const leafVariant = async (changes: Partial<typeof hop2Base>, signer: EnvSigner = signers.child): Promise<SignedDelegationHop> =>
    buildDelegationHop({ ...hop2Base, statusEntry: leafStatus, ...changes }, signer);

  const chainOptions = { resource: RESOURCE, now: NOW };
  const valid = evaluateDelegationChain([root, hop1, hop2], { ...chainOptions, now: Date.parse(NOW) });
  const chains: ChainCase[] = [];
  const addChain = (name: string, description: string, hops: unknown[], options: ChainCase['options'], proofsOk = true): void => {
    const evaluation = evaluateDelegationChain(hops, {
      ...(options.resource === undefined ? {} : { resource: options.resource }),
      ...(options.resourceOwner === undefined ? {} : { resourceOwner: options.resourceOwner }),
      ...(options.maxChainLength === undefined ? {} : { maxChainLength: options.maxChainLength }),
      now: Date.parse(options.now),
    });
    chains.push({
      name,
      description,
      hops,
      options,
      expected: {
        ok: evaluation.ok,
        ...(evaluation.code === undefined ? {} : { code: evaluation.code }),
        ...(evaluation.responsibleParty === undefined ? {} : { responsibleParty: evaluation.responsibleParty }),
        ...(evaluation.leafInvoker === undefined ? {} : { leafInvoker: evaluation.leafInvoker }),
        allowedAction: evaluation.allowedAction,
        depth: evaluation.depth,
      },
      proofs_ok: proofsOk,
    });
  };
  if (!valid.ok) throw new Error(`fixture chain does not evaluate: ${valid.reasons.join('; ')}`);
  addChain('three_hop_valid', 'user → parent → child → grandchild, every hop narrows its parent', [root, hop1, hop2], chainOptions);
  addChain('single_root', 'the root alone grants the parent its full authority', [root], chainOptions);
  addChain('resource_owner_asserted', 'the verifier pins the user as the resource owner and the chain roots there', [root, hop1, hop2], { ...chainOptions, resourceOwner: keys.user.did });
  addChain('resource_owner_mismatch', 'the verifier pins another resource owner', [root, hop1, hop2], { ...chainOptions, resourceOwner: keys.stranger.did });
  addChain('broadened_action', 'the leaf adds write:orders, which its parent never delegated', [root, hop1, await leafVariant({ allowedAction: ['read:orders', 'write:orders'] })], chainOptions);
  addChain('dropped_caveat', 'the leaf drops the MaxAmount caveat', [root, hop1, await leafVariant({ caveats: hop2Caveats.filter((caveat) => caveat.type !== 'MaxAmount') })], chainOptions);
  addChain('widened_max_amount', 'the leaf raises MaxAmount above its parent', [root, hop1, await leafVariant({ caveats: [{ type: 'MaxAmount', limit: '500.000001', currency: 'USD' }, hop2Caveats[1]!, hop2Caveats[2]!] })], chainOptions);
  addChain('changed_currency', 'the leaf switches the MaxAmount currency', [root, hop1, await leafVariant({ caveats: [{ type: 'MaxAmount', limit: '10.00', currency: 'EUR' }, hop2Caveats[1]!, hop2Caveats[2]!] })], chainOptions);
  addChain('changed_unknown_caveat', 'the leaf alters a caveat type it does not understand instead of replicating it', [root, hop1, await leafVariant({ caveats: [hop2Caveats[0]!, hop2Caveats[1]!, { type: 'Region', regions: ['EU', 'US'] }] })], chainOptions);
  addChain('extended_valid_until', 'the leaf expires after its parent', [root, hop1, await leafVariant({ validUntil: '2026-12-15T00:00:00Z' })], chainOptions);
  addChain('extended_valid_until_caveat', 'the leaf ValidUntil caveat is later than its parent caveat', [root, hop1, await leafVariant({ caveats: [hop2Caveats[0]!, { type: 'ValidUntil', date: '2026-12-15T00:00:00Z' }, hop2Caveats[2]!] })], chainOptions);
  addChain('broken_parent_capability', 'the leaf names a parent capability that is not its parent', [root, hop1, await leafVariant({ parentCapability: 'urn:zcap:elsewhere' })], chainOptions);
  addChain('broken_continuity', 'the leaf is issued by the parent agent, not by the delegate the previous hop named', [root, hop1, await leafVariant({}, signers.parent)], chainOptions);
  addChain('target_drift', 'the leaf names another resource', [root, hop1, await leafVariant({ invocationTarget: 'did:web:service.example:payments' })], chainOptions);
  addChain('wrong_resource', 'the chain is evaluated at a resource other than its invocationTarget', [root, hop1, hop2], { ...chainOptions, resource: 'did:web:other.example' });
  addChain(
    'root_parent_mismatch',
    "the root's parentCapability is not its invocationTarget",
    [
      await buildDelegationHop(
        {
          invoker: keys.parent.did,
          parentCapability: 'urn:zcap:not-the-resource',
          invocationTarget: RESOURCE,
          allowedAction: ['read:orders'],
          validFrom: VALID_FROM,
          validUntil: '2027-01-01T00:00:00Z',
          statusEntry: root.credentialStatus,
          id: 'urn:zcap:00000000-0000-4000-8000-00000000f310',
          proofCreated: PROOF_CREATED,
        },
        signers.user,
      ),
    ],
    chainOptions,
  );
  addChain('expired_leaf', 'evaluated after the leaf validUntil', [root, hop1, hop2], { ...chainOptions, now: '2026-10-01T00:00:00Z' });
  addChain('not_yet_valid', 'evaluated before validFrom', [root, hop1, hop2], { ...chainOptions, now: '2025-12-01T00:00:00Z' });
  addChain('within_clock_skew', 'evaluated 60 seconds after the leaf validUntil, inside the 120 second tolerance', [root, hop1, hop2], { ...chainOptions, now: '2026-09-01T00:01:00Z' });
  addChain('too_long', 'eleven hops are refused for their length before any is read', Array.from({ length: 11 }, () => root), chainOptions);
  addChain('length_limit_lowered', 'a verifier may cap the chain lower than 10', [root, hop1, hop2], { ...chainOptions, maxChainLength: 2 });
  addChain('empty', 'no hops at all', [], chainOptions);
  const contaminatedSigned = await signDataIntegrity(
    { ...withoutMember(hop2 as unknown as Record<string, unknown>, 'proof'), credentialSubject: { ...hop2.credentialSubject, scopes: ['admin:all'] } },
    signers.child,
    { created: PROOF_CREATED },
  );
  addChain('extra_subject_member', 'the leaf credentialSubject carries a member the profile does not name (Core L3.5a)', [root, hop1, contaminatedSigned], chainOptions);
  addChain('unsigned_leaf', 'the leaf has no proof', [root, hop1, withoutMember(hop2, 'proof')], chainOptions);
  const tampered = { ...hop2, credentialSubject: { ...hop2.credentialSubject, allowedAction: ['read:orders'] }, proof: { ...hop2.proof, proofValue: `${hop2.proof.proofValue.slice(0, -1)}${hop2.proof.proofValue.endsWith('1') ? '2' : '1'}` } };
  addChain('tampered_proof', 'the leaf proofValue is altered: local rules hold, the proof does not', [root, hop1, tampered], chainOptions, false);

  // ── effective scopes ────────────────────────────────────────────────────
  const attested = attestations.map((a) => (a.credential as { credentialSubject: { capability: string } }).credentialSubject.capability);
  const effectiveScopes: EffectiveScopesCase[] = [];
  const addScopes = (name: string, attestationNames: string[], leaf: string[], catalog: string[], legacy?: EffectiveScopesCase['legacy']): void => {
    effectiveScopes.push({
      name,
      attestations: attestationNames,
      leaf_allowed_action: leaf,
      catalog,
      expected: deriveEffectiveScopes(attestationNames, leaf, catalog),
      ...(legacy === undefined ? {} : { legacy }),
    });
  };
  addScopes('three_hop_leaf', attested, valid.allowedAction, ['read:orders', 'write:orders', 'read:catalog']);
  addScopes('catalog_narrows', attested, ['read:orders', 'read:catalog'], ['read:catalog']);
  addScopes('attestations_narrow', ['read:orders'], ['read:orders', 'read:catalog'], ['read:orders', 'read:catalog']);
  addScopes('nothing_delegated', attested, [], ['read:orders']);
  addScopes('duplicates_collapse', ['read:orders', 'read:orders'], ['read:orders'], ['read:orders']);
  // The retired VP verifier's formula: privilegeScopes ∩ grant scopes (or privilegeScopes alone without a grant),
  // over the credentials of fixtures/golden-vectors/vp-builder.json.
  addScopes('golden_agent_only', ['read:calendar', 'read:email'], ['read:calendar', 'read:email'], ['read:calendar', 'read:email'], {
    privilege_scopes: ['read:calendar', 'read:email'],
    grant_scopes: null,
    expected: ['read:calendar', 'read:email'],
  });
  addScopes('golden_agent_with_grant', ['read:calendar', 'read:email'], ['read:calendar'], ['read:calendar', 'read:email'], {
    privilege_scopes: ['read:calendar', 'read:email'],
    grant_scopes: ['read:calendar'],
    expected: ['read:calendar'],
  });

  // ── card levels ─────────────────────────────────────────────────────────
  const byName = (name: string): unknown => attestations.find((a) => a.name === name)!.credential;
  const statusLists = { [STATUS_LIST_URL]: { credentialSubject: { encodedList } } };
  const cardLevels: CardLevelCase[] = [];
  const addCard = async (
    name: string,
    capabilities: CardCapability[],
    trustedIssuers: TrustedIssuers,
    proofFloorOk: boolean,
    revocationFresh: boolean,
  ): Promise<void> => {
    const check = await checkCapabilities(capabilities, resolve, {
      subjectDid: keys.child.did,
      trustedIssuers,
      now: Date.parse(NOW),
      statusLists,
    });
    cardLevels.push({
      name,
      capabilities,
      subject_did: keys.child.did,
      trusted_issuers: trustedIssuers,
      proof_floor_ok: proofFloorOk,
      revocation_fresh: revocationFresh,
      expected_check: check,
      expected_level: deriveConformanceLevel(check, proofFloorOk, revocationFresh),
    });
  };
  const fullyAttested: CardCapability[] = [
    attestedCapabilityEntry('read:orders', [byName('read_orders_helix')]),
    attestedCapabilityEntry('read:catalog', [byName('read_catalog_owner')]),
  ];
  await addCard('fully_attested_allow_all', fullyAttested, '*', false, true);
  await addCard('one_bare_capability', [...fullyAttested, 'handshake'], '*', false, true);
  await addCard('owner_unlisted', fullyAttested, [keys.helix.did], false, true);
  await addCard('owner_listed', fullyAttested, [keys.helix.did, keys.owner.did], false, true);
  await addCard('revoked_attestation', [...fullyAttested, attestedCapabilityEntry('write:orders', [byName('write_orders_helix_revoked')])], '*', false, true);
  await addCard('proof_floor_lifts_to_l3', fullyAttested, '*', true, true);
  await addCard('stale_revocation_demotes_to_l2', fullyAttested, '*', true, false);
  await addCard('wrong_subject', [attestedCapabilityEntry('read:orders', [byName('read_orders_helix')])], '*', false, true);
  cardLevels[cardLevels.length - 1]!.subject_did = keys.grandchild.did;
  {
    const last = cardLevels[cardLevels.length - 1]!;
    const check = await checkCapabilities(last.capabilities, resolve, { subjectDid: last.subject_did, trustedIssuers: '*', now: Date.parse(NOW), statusLists });
    last.expected_check = check;
    last.expected_level = deriveConformanceLevel(check, false, true);
  }

  // ── schema rejections ───────────────────────────────────────────────────
  const schemaRejections: SchemaRejection[] = [
    {
      name: 'identity_with_scopes',
      kind: 'identity',
      document: { ...identity, credentialSubject: { ...identity.credentialSubject, privilegeScopes: ['read:orders'] } },
      violation_path: '$.credentialSubject.privilegeScopes',
    },
    {
      name: 'attestation_without_valid_until',
      kind: 'attestation',
      document: withoutMember(attestations[0]!.credential as Record<string, unknown>, 'validUntil'),
      violation_path: '$',
    },
    { name: 'hop_extra_subject_member', kind: 'hop', document: contaminatedSigned, violation_path: '$.credentialSubject.scopes' },
    { name: 'hop_valid_until_without_offset', kind: 'hop', document: { ...hop2, validUntil: '2026-09-01T00:00:00' }, violation_path: '$.validUntil' },
    { name: 'hop_without_delegate', kind: 'hop', document: { ...hop2, credentialSubject: withoutMember(hop2.credentialSubject as unknown as Record<string, unknown>, 'invoker') }, violation_path: '$.credentialSubject' },
  ];

  return {
    generated_from: 'helix-core',
    generator: 'scripts/generate-credential-fixtures.ts',
    note: 'KYA-OS story F-1 credential split. Regenerate with pnpm generate:credential-fixtures whenever src/core/credentials/ changes. Keys are TEST-ONLY. Do not hand-edit.',
    now: NOW,
    status_list_url: STATUS_LIST_URL,
    status_list_encoded: encodedList,
    keys,
    did_documents: didDocuments,
    identity: { input: identityInput, credential: identity },
    identity_verification: { input: verificationInput, credential: identityVerification },
    attestations,
    chains,
    effective_scopes: effectiveScopes,
    card_levels: cardLevels,
    schema_rejections: schemaRejections,
  };
}

export function serializeCredentialFixtures(fixtures: CredentialFixtures): string {
  return `${JSON.stringify(fixtures, null, 2)}\n`;
}

const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const outDir = fileURLToPath(new URL('../fixtures/kya-os-helix/', import.meta.url));
  mkdirSync(outDir, { recursive: true });
  writeFileSync(`${outDir}credentials.json`, serializeCredentialFixtures(await buildCredentialFixtures()));
  // eslint-disable-next-line no-console
  console.log(`wrote ${outDir}credentials.json`);
}
