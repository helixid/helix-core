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
 * `buildEntityCard` (KYA-OS story C-A): the `card.json` of a Helix agent,
 * service or org. It writes `id`, `entityType`, `name`, `kid`,
 * `publicKeyJwk`, `capabilities`, `responsibleParty`, an optional
 * `principal`, `delegationRef`, `revocation` as a Bitstring Status List entry
 * and `proofProfile: "org.kya-os/proof.v1"`, and nothing else: never a
 * `conformanceLevel` (a verifier recomputes it; one given on input is
 * ignored), never a proof (it rides per request), never an unknown field (a
 * `proof` or any other member on input is refused). The result is checked
 * against the strict card schema before it is returned.
 */

import { ValidationError } from '../errors/HelixError.js';
import { publicKeyJwkBytes, verificationMethodId, type PublicKeyJwk } from '../did/document.js';
import { didWebDocumentUrl, parseDidWeb } from '../did/web.js';
import {
  ENTITY_TYPES,
  PROOF_PROFILE_V1,
  parseEntityCard,
  type BitstringStatusListEntry,
  type Capability,
  type CardAttestation,
  type CimdBinding,
  type EntityCard,
  type EntityType,
} from './schema.js';

export interface BuildEntityCardInput {
  /** The entity's DID: did:web for anything accountable, did:key for a dev or human card. */
  id: string;
  entityType: EntityType;
  name: string;
  /** Verification-method fragment (`key-1`) or full id (`<did>#key-1`); omitted with no key. */
  kid?: string | undefined;
  /** The public half only: `{kty: "OKP", crv: "Ed25519", x}`. Private material is refused. */
  publicKeyJwk?: unknown;
  capabilities?: readonly Capability[] | undefined;
  /** The ultimately accountable DID: the org for an org-owned agent (from L3-H's root hop). */
  responsibleParty?: string | undefined;
  /** The user who delegated, when `responsibleParty` is an org. */
  principal?: string | undefined;
  delegationRef?: string | undefined;
  /** The status entry of the credential backing the card: the agent identity VC (F-1). */
  revocation?: BitstringStatusListEntry | undefined;
  /** The DID document URL; derived from a did:web when omitted. */
  didDocument?: string | undefined;
  createdAt?: string | undefined;
  attestations?: readonly CardAttestation[] | undefined;
  cimd?: CimdBinding | undefined;
  /** The per-request proof profile to advertise; default `org.kya-os/proof.v1`. */
  proofProfile?: EntityCard['proofProfile'] | undefined;
  /** Ignored: the level is derived by a verifier, never claimed by the card. */
  conformanceLevel?: unknown;
}

const INPUT_MEMBERS = new Set([
  'id', 'entityType', 'name', 'kid', 'publicKeyJwk', 'capabilities', 'responsibleParty', 'principal',
  'delegationRef', 'revocation', 'didDocument', 'createdAt', 'attestations', 'cimd', 'proofProfile', 'conformanceLevel',
]);

function isDid(value: unknown): value is string {
  return typeof value === 'string' && /^did:(?:key|web):[^\s#?/]+$/.test(value);
}

export function buildEntityCard(input: BuildEntityCardInput): EntityCard {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new ValidationError('buildEntityCard needs an input object');
  }
  const foreign = Object.keys(input).filter((member) => !INPUT_MEMBERS.has(member));
  if (foreign.length > 0) {
    throw new ValidationError(`Entity Card input carries unknown members (${foreign.join(', ')}); a card never carries a proof or an unknown field`);
  }
  if (!isDid(input.id)) {
    throw new ValidationError('Entity Card id must be a did:web or did:key DID without path, query or fragment');
  }
  if (!ENTITY_TYPES.includes(input.entityType)) {
    throw new ValidationError(`Entity Card entityType must be one of ${ENTITY_TYPES.join(', ')}`);
  }
  if (typeof input.name !== 'string' || input.name.length === 0) {
    throw new ValidationError('Entity Card name must be a non-empty string');
  }
  for (const [member, value] of [['responsibleParty', input.responsibleParty], ['principal', input.principal]] as const) {
    if (value !== undefined && !isDid(value)) {
      throw new ValidationError(`Entity Card ${member} must be a did:web or did:key DID`);
    }
  }

  let publicKeyJwk: PublicKeyJwk | undefined;
  if (input.publicKeyJwk !== undefined) {
    const bytes = publicKeyJwkBytes(input.publicKeyJwk);
    publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(bytes).toString('base64url') };
  }
  const kid = input.kid === undefined ? undefined : verificationMethodId(input.id, input.kid);
  if (publicKeyJwk !== undefined && kid !== undefined) publicKeyJwk = { ...publicKeyJwk, kid };

  const didDocument = input.didDocument ?? (parseDidWeb(input.id) === undefined ? undefined : didWebDocumentUrl(input.id));

  const card: EntityCard = {
    id: input.id,
    entityType: input.entityType,
    name: input.name,
    ...(kid === undefined ? {} : { kid }),
    ...(publicKeyJwk === undefined ? {} : { publicKeyJwk }),
    ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
    ...(input.capabilities === undefined ? {} : { capabilities: [...input.capabilities] }),
    ...(input.responsibleParty === undefined ? {} : { responsibleParty: input.responsibleParty }),
    ...(input.principal === undefined ? {} : { principal: input.principal }),
    ...(input.delegationRef === undefined ? {} : { delegationRef: input.delegationRef }),
    ...(input.attestations === undefined ? {} : { attestations: [...input.attestations] }),
    ...(didDocument === undefined ? {} : { didDocument }),
    proofProfile: input.proofProfile ?? PROOF_PROFILE_V1,
    ...(input.cimd === undefined ? {} : { cimd: input.cimd }),
    ...(input.revocation === undefined ? {} : { revocation: input.revocation }),
  };
  return parseEntityCard(card);
}
