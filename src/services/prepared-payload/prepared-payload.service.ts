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
//
// Implements the "prepare"/"finalize" split from docs/proposal-sdk-api-only.md:
// the API constructs the unsigned VC payload (the highest-drift-risk logic if
// every SDK reimplemented it), the client signs the returned hash with its
// own private key — which never leaves the client — and finalize() attaches
// that signature to produce the final SignedVC.
//
// prepareDelegation()/finalizeDelegation() port helix-core's
// buildDelegationVC() payload construction (delegation.ts) minus the signing
// step. Not exposed over HTTP any more (the old `/v1/vcs/delegation/*` route
// existed only for the SDK's wallet-based delegate(), removed with agent
// self-custody) — called internally by AgentService.delegateAuthority(),
// which signs with the custody-held key in between prepare and finalize.
//
// prepareGrant()/finalizeGrant() do the same for issueGrant() (grant.ts),
// and remain a public HTTP route: the SP holds its own key and signs
// locally, so prepare/finalize really does cross the wire to it.
//
// This used to also serve agent-renewal (wallet-based, agent-self-custody);
// removed when agent self-custody was retired — see prepareAgentRenewal()
// in git history if resurrecting it.

import { randomUUID } from 'node:crypto';
import {
  ErrorCode,
  HelixError,
  MaxDelegationDepthExceededError,
  PreparedPayloadAlreadyConsumedError,
  PreparedPayloadExpiredError,
  PreparedPayloadNotFoundError,
  PreparedPayloadPurposeMismatchError,
  PreparedPayloadSignatureInvalidError,
  SelfDelegationNotAllowedError,
  VC_CONTEXTS,
  base58btcEncode,
  getStatusListLength,
  hashCanonicalPayload,
  resolveDID as resolveDIDCore,
  validateScopeSubset,
  verifySignature,
  type SignedVC,
} from '../../core/index.js';
import type {
  FinalizeInput,
  IPreparedPayloadService,
  PrepareDelegationInput,
  PrepareGrantInput,
  PrepareResult,
} from './IPreparedPayloadService.js';
import type {
  PreparedPayloadRecord,
  PreparedPayloadRepository,
} from '../../repositories/prepared-payload.repository.js';
import type { IDIDService } from '../did/did.service.js';
import { extractEd25519PublicKeyHexFromDIDDocument } from '../did/publicKey.js';

const PREPARE_TTL_SECONDS = 5 * 60;

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export class PreparedPayloadService implements IPreparedPayloadService {
  constructor(
    private readonly repository: PreparedPayloadRepository,
    private readonly didService: IDIDService,
  ) {}

  // -- delegation ------------------------------------------------------

  async prepareDelegation(input: PrepareDelegationInput): Promise<PrepareResult> {
    if (input.to === input.delegatorDid) {
      throw new SelfDelegationNotAllowedError(input.delegatorDid);
    }

    const parentSubject = input.fromVC.credentialSubject as {
      privilegeScopes?: unknown;
      delegationDepth?: number;
      maxDelegationDepth?: number;
    };
    if (!Array.isArray(parentSubject.privilegeScopes)) {
      throw new HelixError(
        ErrorCode.VALIDATION_ERROR,
        'fromVC has no privilege scopes to delegate from',
        400,
      );
    }
    const parentDepth = parentSubject.delegationDepth ?? 0;
    const maxDepth = parentSubject.maxDelegationDepth ?? 0;

    validateScopeSubset(parentSubject.privilegeScopes as string[], input.scopes);
    if (parentDepth + 1 > maxDepth) {
      throw new MaxDelegationDepthExceededError();
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + input.expiresIn * 1000);
    const parentChain =
      (input.fromVC as unknown as { delegationChain?: SignedVC[] }).delegationChain ?? [];

    // Mirrors helix-core/src/delegation.ts buildDelegationVC() payload
    // construction exactly, minus the `proof` field.
    const payload = {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://helixid.io/contexts/v1'],
      id: `vc:helix:delegation:${randomUUID()}`,
      type: ['VerifiableCredential', 'HelixAgentCredential'],
      issuer: input.delegatorDid,
      validFrom: now.toISOString(),
      validUntil: expiresAt.toISOString(),
      credentialSubject: {
        id: input.to,
        type: 'HelixAgent' as const,
        privilegeScopes: input.scopes,
        agentName: input.to,
        delegatedFrom: input.delegatorDid,
        delegationDepth: parentDepth + 1,
        maxDelegationDepth: maxDepth,
        parentVcId: input.fromVC.id,
      },
      delegationChain: [...parentChain, input.fromVC],
    };

    return this.store('delegation', payload, input.delegatorDid);
  }

  async finalizeDelegation(input: FinalizeInput): Promise<SignedVC> {
    return this.finalize('delegation', input);
  }

  // -- grant -------------------------------------------------------------

  async prepareGrant(input: PrepareGrantInput): Promise<PrepareResult> {
    const listLength = getStatusListLength(input.statusList.credentialSubject.encodedList);
    // Random assignment, same accepted-collision-risk approach as
    // helix-core/src/grant.ts issueGrant() (see epic Part E / register D9).
    const index = Math.floor(Math.random() * listLength);

    const now = new Date();
    const STANDING_GRANT_VALID_MS = 10 * 365 * 24 * 60 * 60 * 1000;
    const SESSION_GRANT_VALID_MS = 24 * 60 * 60 * 1000;
    const validMs = input.durability === 'standing' ? STANDING_GRANT_VALID_MS : SESSION_GRANT_VALID_MS;

    const payload = {
      '@context': [...VC_CONTEXTS],
      id: `vc:helix:grant:${randomUUID()}`,
      type: ['VerifiableCredential', 'DelegationGrantCredential'],
      issuer: input.issuerDid,
      validFrom: now.toISOString(),
      validUntil: new Date(now.getTime() + validMs).toISOString(),
      credentialStatus: {
        id: `${input.statusListCredentialUrl}#${index}`,
        type: 'BitstringStatusListEntry' as const,
        statusPurpose: 'revocation' as const,
        statusListIndex: index.toString(),
        statusListCredential: input.statusListCredentialUrl,
      },
      credentialSubject: {
        id: input.agentDid,
        type: 'DelegationGrant' as const,
        userDid: input.userDid,
        scopes: input.scopes,
        durability: input.durability,
        ...(input.serviceDid !== undefined ? { serviceDid: input.serviceDid } : {}),
      },
    };

    return this.store('grant', payload, input.issuerDid);
  }

  async finalizeGrant(input: FinalizeInput): Promise<SignedVC> {
    return this.finalize('grant', input);
  }

  // -- shared prepare/finalize plumbing -----------------------------------

  private async store(
    purpose: 'delegation' | 'grant',
    payload: Record<string, unknown>,
    expectedSignerDid: string,
  ): Promise<PrepareResult> {
    const canonicalHash = toHex(hashCanonicalPayload(payload));
    const expiresAt = new Date(Date.now() + PREPARE_TTL_SECONDS * 1000);

    const record = await this.repository.create({
      purpose,
      unsignedPayload: JSON.stringify(payload),
      canonicalHash,
      expectedSignerDid,
      expiresAt,
    });

    return {
      token: record.token,
      unsignedPayload: payload,
      canonicalHash,
      expiresAt: expiresAt.toISOString(),
    };
  }

  private async finalize(purpose: 'delegation' | 'grant', input: FinalizeInput): Promise<SignedVC> {
    const record = await this.repository.findByToken(input.token);
    this.assertUsable(record, purpose);

    // verificationMethod is expected to be `${did}#fragment`; the DID must
    // match whoever this payload was prepared for.
    const signerDid = input.verificationMethod.split('#')[0] ?? '';
    if (signerDid !== record!.expectedSignerDid) {
      throw new PreparedPayloadSignatureInvalidError(
        'verificationMethod does not match the DID this payload was prepared for',
      );
    }

    const publicKeyHex = await this.resolveEd25519PublicKeyHex(signerDid);
    const hashBytes = Buffer.from(record!.canonicalHash, 'hex');
    const isValid = await verifySignature(hashBytes, input.signatureHex, publicKeyHex);
    if (!isValid) {
      throw new PreparedPayloadSignatureInvalidError();
    }

    const consumed = await this.repository.markConsumedAtomically(input.token);
    if (!consumed) {
      // Lost a race with a concurrent finalize call against the same token.
      throw new PreparedPayloadAlreadyConsumedError();
    }

    const payload = JSON.parse(record!.unsignedPayload) as Record<string, unknown>;
    return {
      ...payload,
      proof: {
        type: 'Ed25519Signature2020',
        created: input.proofCreatedAt ?? new Date().toISOString(),
        verificationMethod: input.verificationMethod,
        proofPurpose: 'assertionMethod',
        proofValue: base58btcEncode(Buffer.from(input.signatureHex, 'hex')),
      },
    } as unknown as SignedVC;
  }

  private assertUsable(
    record: PreparedPayloadRecord | null,
    purpose: 'delegation' | 'grant',
  ): asserts record is PreparedPayloadRecord {
    if (!record) {
      throw new PreparedPayloadNotFoundError();
    }
    if (record.purpose !== purpose) {
      throw new PreparedPayloadPurposeMismatchError();
    }
    if (record.consumedAt) {
      throw new PreparedPayloadAlreadyConsumedError();
    }
    if (record.expiresAt.getTime() < Date.now()) {
      throw new PreparedPayloadExpiredError();
    }
  }

  private async resolveEd25519PublicKeyHex(did: string): Promise<string> {
    try {
      const document = await this.didService.resolveDID(did, 'req_prepare_finalize');
      return extractEd25519PublicKeyHexFromDIDDocument(document);
    } catch (err: unknown) {
      if (err instanceof HelixError && err.code === ErrorCode.DID_NOT_FOUND) {
        const document = await resolveDIDCore(did);
        return extractEd25519PublicKeyHexFromDIDDocument(document);
      }
      throw err;
    }
  }
}
