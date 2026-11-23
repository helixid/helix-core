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
 * What consent-grant and delegation-hop issuance need from KYA-OS story F-3 for
 * services and agents created through the custody routes: a service's key is in the
 * KeyStore, never in did_keys, so grants are signed through a KeyStoreSigner
 * (stories rule 8: KeyStore only, no second key location), and such an agent
 * counts as onboarded. CustodyService implements it.
 */

import type { Signer } from '../../core/index.js';

/**
 * Which server-side path asks for the signature, and its request: each
 * signature is audited as a custodial signature (F-3 point 8). Consent grants
 * signed by a custodial service; delegation hops Helix issues on behalf of a
 * custodial agent or service (`POST /v1/grants`, `/v1/grants/:id/hops`); and
 * (story L3-C) the issuer's own status list, which the StatusListPublisher
 * signs. There is no VP signing (story F-2 removed it). A custodial agent can
 * still sign its own hops and request proofs client side through the /sign
 * route.
 */
export interface CustodialSigningUse {
  requestId: string;
  purpose: 'grant' | 'hop' | 'status_list';
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
