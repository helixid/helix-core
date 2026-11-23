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

import { z } from 'zod';

/**
 * Runtime schema for a status-list credential Helix serves or accepts: W3C
 * Bitstring Status List v1.0 with its window and its issuer's
 * `DataIntegrityProof` (KYA-OS story L3-C). One format for every issuer's
 * list; the proof itself is checked by `verifyDataIntegrity`.
 */
export const StatusListCredentialSchema = z.object({
  '@context': z.array(z.string()).min(1),
  id: z.string(),
  type: z.array(z.string()),
  issuer: z.string(),
  validFrom: z.string(),
  validUntil: z.string(),
  credentialSubject: z.object({
    id: z.string(),
    type: z.literal('BitstringStatusList'),
    statusPurpose: z.literal('revocation'),
    encodedList: z.string(),
  }),
  proof: z.object({
    type: z.literal('DataIntegrityProof'),
    cryptosuite: z.literal('eddsa-jcs-2022'),
    created: z.string().optional(),
    verificationMethod: z.string(),
    proofPurpose: z.literal('assertionMethod'),
    proofValue: z.string(),
  }),
});
