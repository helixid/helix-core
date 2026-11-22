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
 * What consent-grant issuance needs from KYA-OS story F-3 for services and
 * agents created through the custody routes: a service's key is in the
 * KeyStore, never in did_keys, so grants are signed through a KeyStoreSigner
 * (stories rule 8: KeyStore only, no second key location), and such an agent
 * counts as onboarded. CustodyService implements it.
 */

import type { Signer } from '../../core/index.js';

/**
 * Which server-side path asks for the signature, and its request: each
 * signature is audited as CUSTODIAL_SIGNATURE. Consent grants are the only one:
 * there is no VP signing any more (story F-2 removed it), and the old
 * delegation path is gone with story F-1; KYA-OS delegation hops and request
 * proofs are signed client side through the generic /sign route.
 */
export interface CustodialSigningUse {
  requestId: string;
  purpose: 'grant';
}

export interface CustodialKeys {
  /**
   * The Signer over the KeyStore key of an active `keyCustody: helix` agent or service, or undefined.
   * Every signature it makes is audited like one through the custody sign route (F-3 point 8).
   */
  signerFor(did: string, subjectType: 'agent' | 'service', use: CustodialSigningUse): Promise<Signer | undefined>;
  /** Whether `did` is an active agent created through the custody routes, whoever holds its key. */
  isActiveAgent(did: string): Promise<boolean>;
}
