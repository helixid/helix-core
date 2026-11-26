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
 * One delegation hop in the SPEC.md §6.10 shape (story F-1 point 3): a VC
 * 2.0 whose `credentialSubject` IS an attenuated ZCAP-LD capability, with
 * `issuer` (the delegator), `invoker` (the delegate), `parentCapability`,
 * `invocationTarget`, `allowedAction`, caveats, `validUntil`, a Bitstring
 * status entry and an `eddsa-jcs-2022` proof for `assertionMethod` by the
 * hop's issuer. Any issuer can sign the root: a user's did:key at consent
 * (story L3-H), a resource owner, or Helix.
 */

import { randomUUID } from 'node:crypto';
import type { Signer } from '../crypto/signer.js';
import { signDataIntegrity, verifyDataIntegrity, type DidResolver } from './data-integrity.js';
import { requireDid, type CredentialRefusal } from './identity.js';
import { credentialSchemaViolations, describeViolations } from './validation.js';
import {
  DELEGATION_CREDENTIAL_TYPE,
  DELEGATION_HOP_CONTEXT,
  type BitstringStatusEntry,
  type Caveat,
  type DelegationCredential,
  type SignedDelegationHop,
} from './types.js';

export interface BuildDelegationHopInput {
  /** The delegate DID. */
  invoker: string;
  /** The parent capability id; for the root hop, the `invocationTarget` itself. */
  parentCapability: string;
  /** The resource DID or URI, constant along the chain. */
  invocationTarget: string;
  allowedAction: readonly string[];
  caveats?: readonly Caveat[];
  validUntil: string;
  statusEntry: BitstringStatusEntry;
  /** The capability id, `credentialSubject.id`; default `urn:zcap:<uuid>`. The VC `id` is the same value. */
  id?: string;
  validFrom?: string;
  proofCreated?: string;
}

/** The root hop names the resource as its own parent (SPEC.md §6.10, "root"). */
export function rootHopInput(
  input: Omit<BuildDelegationHopInput, 'parentCapability'>,
): BuildDelegationHopInput {
  return { ...input, parentCapability: input.invocationTarget };
}

export async function buildDelegationHop(
  input: BuildDelegationHopInput,
  signer: Signer,
): Promise<SignedDelegationHop> {
  requireDid(input.invoker, 'invoker');
  if (typeof input.parentCapability !== 'string' || input.parentCapability === '') {
    throw new Error('parentCapability is required');
  }
  if (typeof input.invocationTarget !== 'string' || input.invocationTarget === '') {
    throw new Error('invocationTarget is required');
  }
  if (!Array.isArray(input.allowedAction) || input.allowedAction.some((action) => typeof action !== 'string' || action === '')) {
    throw new Error('allowedAction must be an array of non-empty strings');
  }
  if (typeof input.validUntil !== 'string') throw new Error('validUntil is required');
  const id = input.id ?? `urn:zcap:${randomUUID()}`;
  const credential: DelegationCredential = {
    '@context': [...DELEGATION_HOP_CONTEXT],
    id,
    type: ['VerifiableCredential', DELEGATION_CREDENTIAL_TYPE],
    issuer: signer.did,
    ...(input.validFrom === undefined ? {} : { validFrom: input.validFrom }),
    validUntil: input.validUntil,
    credentialSubject: {
      id,
      invoker: input.invoker,
      parentCapability: input.parentCapability,
      invocationTarget: input.invocationTarget,
      allowedAction: [...input.allowedAction],
      ...(input.caveats === undefined ? {} : { caveats: input.caveats.map((caveat) => ({ ...caveat })) }),
    },
    credentialStatus: input.statusEntry,
  };
  const signed = await signDataIntegrity(
    credential as unknown as Record<string, unknown>,
    signer,
    input.proofCreated === undefined ? {} : { created: input.proofCreated },
  );
  return signed as unknown as SignedDelegationHop;
}

export type HopVerification =
  | { ok: true; hop: SignedDelegationHop; issuer: string; invoker: string }
  | CredentialRefusal;

/** The delegate a hop names: `invoker`, falling back to `controller`. */
export function invokerOf(hop: Pick<DelegationCredential, 'credentialSubject'>): string | undefined {
  return hop.credentialSubject.invoker ?? hop.credentialSubject.controller;
}

/**
 * Shape (the Helix hop schema, which refuses an unknown `credentialSubject`
 * member, Core L3.5a style) and proof of one hop. Attenuation, windows and
 * continuity are the chain's business (./chain.ts).
 */
export async function verifyDelegationHop(value: unknown, resolveDid: DidResolver): Promise<HopVerification> {
  const violations = credentialSchemaViolations('hop', value);
  if (violations.length > 0) {
    return { ok: false, reason: 'schema_invalid', message: describeViolations(violations) };
  }
  const hop = value as SignedDelegationHop;
  const proof = await verifyDataIntegrity(hop as unknown as Record<string, unknown>, resolveDid);
  if (!proof.ok) return proof;
  return { ok: true, hop, issuer: hop.issuer, invoker: invokerOf(hop)! };
}
