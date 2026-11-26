// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * One verified link of the retired VP path's agent-credential chain. The
 * verifier that reported it is gone with KYA-OS story F-2; the type stays for
 * consumers that still name it (helix-server-enterprise). The
 * chain builder that used to live here (`buildDelegationVC`, `delegationDepth`
 * / `maxDelegationDepth`) is gone with KYA-OS story F-1: delegation is a
 * chain of `DelegationCredential` hops (src/core/credentials/hop.ts).
 */
export interface DelegationLink {
  issuer: string;
  subject: string;
  vcId: string;
  scopes: string[];
  delegationDepth: number;
}
