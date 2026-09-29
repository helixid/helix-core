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

import type { SignedVC } from '../../core/index.js';

export interface PrepareResult {
  token: string;
  unsignedPayload: Record<string, unknown>;
  canonicalHash: string;
  expiresAt: string;
}

export interface PrepareDelegationInput {
  /** DID of the delegator — becomes `issuer` and `credentialSubject.delegatedFrom`. */
  delegatorDid: string;
  /** The delegator's own currently-held agent-authority VC. */
  fromVC: SignedVC;
  to: string;
  scopes: string[];
  expiresIn: number;
}

export interface PrepareGrantInput {
  /** SP's own issuer DID — becomes `issuer` of the grant VC. */
  issuerDid: string;
  agentDid: string;
  userDid: string;
  scopes: string[];
  durability: 'standing' | 'session';
  serviceDid?: string;
  /** Current status list credential, unmodified — caller (SP) owns storage. */
  statusList: { credentialSubject: { encodedList: string } };
  statusListCredentialUrl: string;
}

export interface FinalizeInput {
  token: string;
  verificationMethod: string;
  /** Hex-encoded raw Ed25519 signature over the hash returned by prepare(). */
  signatureHex: string;
  /** Optional; defaults to now if omitted. */
  proofCreatedAt?: string;
}

export interface IPreparedPayloadService {
  /**
   * Called internally by the server-custody AgentService.delegateAuthority()
   * (prepare, sign with the custody-held key, finalize) — not exposed over
   * HTTP; the old external `/v1/vcs/delegation/*` route was removed with
   * agent self-custody, since it existed only for the SDK's wallet-based
   * delegate(), which needed the delegator's own key.
   */
  prepareDelegation(input: PrepareDelegationInput): Promise<PrepareResult>;
  finalizeDelegation(input: FinalizeInput): Promise<SignedVC>;
  prepareGrant(input: PrepareGrantInput): Promise<PrepareResult>;
  finalizeGrant(input: FinalizeInput): Promise<SignedVC>;
}
