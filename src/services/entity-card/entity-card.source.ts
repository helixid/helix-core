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
 * What a Helix-hosted Entity Card says, from Helix's records (KYA-OS story
 * C-A): the DID record gives the document, its first assertion key (`kid`,
 * `publicKeyJwk`) and the subject type; the agent and service records give
 * the name. The `revocation` entry is the agent identity VC's status entry
 * (story F-1 builds that credential) and `responsibleParty` / `principal`
 * come from the caller's records (L3-H's root hop): both arrive through the
 * optional `details` hook, so this source stays usable before those stories
 * land.
 *
 * Serving is the route's job (`routes/entity-card`); this is the lookup
 * behind it, and the one place that reads a Helix database for a card. The
 * verify path never does (stories, rule 4).
 */

import { CAPABILITY_ATTESTATION_TYPE, IDENTITY_CREDENTIAL_TYPE, type BuildEntityCardInput, type EntityType, type Level2Capability } from '../../core/index.js';
import type { EntityCardRecord, EntityCardSource } from '../../routes/entity-card/index.js';

export interface EntityCardDetails {
  name?: string | undefined;
  entityType?: EntityType | undefined;
  capabilities?: BuildEntityCardInput['capabilities'];
  responsibleParty?: string | undefined;
  principal?: string | undefined;
  delegationRef?: string | undefined;
  revocation?: BuildEntityCardInput['revocation'];
}

export interface EntityCardSourceOptions {
  /** The did:web host (`DID_DOMAIN`), with its port when it has one. */
  host: string;
  didRepository: {
    findDidById(did: string): Promise<{ subjectType: string; didDocument: unknown; deactivatedAt?: Date | null } | null>;
  };
  agentRecords?: { findByDid(did: string): Promise<{ name: string | null } | null> } | undefined;
  services?: { findByDid(did: string): Promise<{ name: string } | null> } | undefined;
  /** The entity type of a DID that is neither an agent nor a service (an org, the host itself). Default `verifier`. */
  orgEntityType?: EntityType | undefined;
  /** Name, accountability and revocation details Helix's other records know for `did`. */
  details?: ((did: string, subjectType: string) => Promise<EntityCardDetails | undefined>) | undefined;
  /**
   * What the agent's credentials say on its card, for members `details` does
   * not name: usually `credentialCardDetails`, so every agent Helix hosts,
   * whoever holds its key, publishes its attestations, its responsible party
   * and its revocation entry (F-3 parity).
   */
  credentials?: ((did: string, subjectType: string) => Promise<EntityCardDetails | undefined>) | undefined;
}

/** What `credentialCardDetails` reads: the active credentials of a subject, of one type. */
export interface ActiveCredentialStore {
  listActiveBySubjectDid(subjectDid: string, vcType?: string): Promise<Array<Record<string, unknown>>>;
}

/**
 * An agent's card capabilities from the capability attestations Helix holds
 * for it (story F-1: one `CapabilityAttestationCredential` per scope; C-B
 * point 2: `{ name, attestations: [{ vc }] }`): every active attestation whose
 * subject is the agent, grouped by capability in the order they were issued.
 * Undefined when it has none. A verifier checks each attestation itself
 * (issuer allowlist, proof, `validUntil`, status); this only publishes them.
 */
export async function attestedCardCapabilities(store: ActiveCredentialStore, did: string): Promise<Level2Capability[] | undefined> {
  const capabilities: Level2Capability[] = [];
  for (const vc of await store.listActiveBySubjectDid(did, CAPABILITY_ATTESTATION_TYPE)) {
    const subject = vc['credentialSubject'] as { id?: unknown; capability?: unknown } | undefined;
    if (subject?.id !== did || typeof subject.capability !== 'string' || subject.capability === '') continue;
    const named = capabilities.find((entry) => entry.name === subject.capability);
    if (named) named.attestations.push({ vc });
    else capabilities.push({ name: subject.capability, attestations: [{ vc }] });
  }
  return capabilities.length === 0 ? undefined : capabilities;
}

/**
 * An agent's card members from the credentials Helix holds for it (F-3
 * parity, Harish 2026-11-23): its active capability attestations
 * (`capabilities`), and from its newest active identity credential (F-1) the
 * `responsibleParty` it names and its status entry as the card's `revocation`
 * (C-A point 3). Nothing for any other subject, or a member it has no
 * credential for.
 */
export function credentialCardDetails(store: ActiveCredentialStore): (did: string, subjectType: string) => Promise<EntityCardDetails | undefined> {
  return async (did, subjectType) => {
    if (subjectType !== 'agent') return undefined;
    const details: EntityCardDetails = {};
    const capabilities = await attestedCardCapabilities(store, did);
    if (capabilities) details.capabilities = capabilities;
    const identity = (await store.listActiveBySubjectDid(did, IDENTITY_CREDENTIAL_TYPE))
      .filter((vc) => (vc['credentialSubject'] as { id?: unknown } | undefined)?.id === did)
      .at(-1);
    const party = (identity?.['credentialSubject'] as { responsibleParty?: unknown } | undefined)?.responsibleParty;
    if (typeof party === 'string' && party !== '') details.responsibleParty = party;
    const status = identity?.['credentialStatus'] as { statusListCredential?: unknown; statusListIndex?: unknown } | undefined;
    if (typeof status?.statusListCredential === 'string' && (typeof status.statusListIndex === 'string' || typeof status.statusListIndex === 'number')) {
      details.revocation = { statusListCredential: status.statusListCredential, statusListIndex: String(status.statusListIndex) };
    }
    return Object.keys(details).length === 0 ? undefined : details;
  };
}

interface AssertionKey {
  kid: string;
  publicKeyJwk: unknown;
}

/** The first assertion method of a DID document that carries a public JWK, as the card's `kid` and key. */
export function assertionKeyOf(document: unknown): AssertionKey | undefined {
  const doc = document as { id?: unknown; assertionMethod?: unknown; verificationMethod?: unknown } | null;
  if (!doc || !Array.isArray(doc.verificationMethod)) return undefined;
  const wanted = Array.isArray(doc.assertionMethod) ? doc.assertionMethod[0] : undefined;
  const wantedId = typeof wanted === 'string' ? wanted : typeof wanted === 'object' && wanted !== null ? (wanted as { id?: unknown }).id : undefined;
  const methods = doc.verificationMethod as { id?: unknown; publicKeyJwk?: unknown }[];
  const method = methods.find((candidate) => {
    const id = typeof candidate?.id === 'string' ? candidate.id : undefined;
    if (id === undefined) return false;
    if (wantedId === undefined) return true;
    const absolute = typeof wantedId === 'string' && wantedId.startsWith('#') ? `${String(doc.id)}${wantedId}` : wantedId;
    return id === absolute;
  });
  if (!method || typeof method.id !== 'string' || typeof method.publicKeyJwk !== 'object' || method.publicKeyJwk === null) return undefined;
  const jwk = method.publicKeyJwk as { kty?: unknown; crv?: unknown; x?: unknown };
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return undefined;
  return { kid: method.id, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x } };
}

function defaultEntityType(subjectType: string, orgEntityType: EntityType): EntityType {
  if (subjectType === 'agent') return 'agent';
  if (subjectType === 'service') return 'mcp';
  return orgEntityType;
}

/** The members of `value` that are set: `details` wins only where it says something. */
function definedMembers(value: EntityCardDetails): EntityCardDetails {
  return Object.fromEntries(Object.entries(value).filter(([, member]) => member !== undefined)) as EntityCardDetails;
}

export function createEntityCardSource(options: EntityCardSourceOptions): EntityCardSource {
  const orgEntityType = options.orgEntityType ?? 'verifier';
  return {
    host: options.host,
    async find(did: string): Promise<EntityCardRecord | null> {
      const record = await options.didRepository.findDidById(did);
      if (!record) return null;
      const details: EntityCardDetails = {
        ...((await options.credentials?.(did, record.subjectType)) ?? {}),
        ...definedMembers((await options.details?.(did, record.subjectType)) ?? {}),
      };
      const named =
        details.name ??
        (record.subjectType === 'agent' ? (await options.agentRecords?.findByDid(did))?.name : undefined) ??
        (record.subjectType === 'service' ? (await options.services?.findByDid(did))?.name : undefined) ??
        did;
      const key = assertionKeyOf(record.didDocument);
      return {
        didDocument: record.didDocument,
        deactivatedAt: record.deactivatedAt,
        card: {
          entityType: details.entityType ?? defaultEntityType(record.subjectType, orgEntityType),
          name: named,
          ...(key === undefined ? {} : { kid: key.kid, publicKeyJwk: key.publicKeyJwk }),
          ...(details.capabilities === undefined ? {} : { capabilities: details.capabilities }),
          ...(details.responsibleParty === undefined ? {} : { responsibleParty: details.responsibleParty }),
          ...(details.principal === undefined ? {} : { principal: details.principal }),
          ...(details.delegationRef === undefined ? {} : { delegationRef: details.delegationRef }),
          ...(details.revocation === undefined ? {} : { revocation: details.revocation }),
        },
      };
    },
  };
}
