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
 * The audit events of KYA-OS story F-3 point 8: every custody choice,
 * change and custodial signature, with the actor and the agent, service or
 * owner. One place emits them, through the audit trail interface the API
 * already has (`IAuditLogger`); when the typed audit trail of story A-1
 * replaces it, only this adapter changes (choice, activation, change and key
 * events map to `configuration.changed`, a custodial signature to
 * `proof.generated`, a refusal to `proof.rejected`).
 *
 * A custodial signature is recorded by the digest and length of what was
 * signed, never the bytes themselves.
 */

import { createHash } from 'node:crypto';
import { AuditEvents, type CustodyChoiceSource, type CustodySubjectType, type DidHostingMode, type KeyCustodyMode } from '../../core/index.js';
import type { IAuditLogger } from '../../core/audit/index.js';
import type { HopReissueResult } from './hop-reissue.js';

/** Who did it: `admin` for the admin key, `account:<id>` in the hosted build, `enrollment-token` for `helix init`. */
export type CustodyActor = string;

interface Base {
  requestId: string;
  actor: CustodyActor;
  subjectType: CustodySubjectType;
  did: string;
}

export function payloadDigest(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export class CustodyAudit {
  constructor(private readonly logger: IAuditLogger) {}

  chosen(event: Base & { keyCustody: KeyCustodyMode; didHosting: DidHostingMode; source: { keyCustody: CustodyChoiceSource; didHosting: CustodyChoiceSource } }): void {
    void this.logger.log(AuditEvents.CUSTODY_CHOSEN, { ...event });
  }

  activated(event: Base & { keyCustody: KeyCustodyMode; didHosting: DidHostingMode; kid: string; resolution: 'helix-hosted' | 'verified' }): void {
    void this.logger.log(AuditEvents.CUSTODY_ACTIVATED, { ...event });
  }

  /** AGENT_ONBOARDED, the enrollment event the agent service logs for an onboarded agent, with the same fields. */
  agentOnboarded(event: { requestId: string; agentDid: string; agentName: string; keyCustody: KeyCustodyMode; didHosting: DidHostingMode }): void {
    void this.logger.log(AuditEvents.AGENT_ONBOARDED, { ...event });
  }

  changed(event: Base & {
    from: KeyCustodyMode;
    to: KeyCustodyMode;
    oldKid: string;
    newKid: string;
    retiresAt: string;
    hopReissue: HopReissueResult;
  }): void {
    void this.logger.log(AuditEvents.CUSTODY_CHANGED, { ...event });
  }

  keyRevoked(event: Base & { kid: string; location: 'self' | 'helix' }): void {
    void this.logger.log(AuditEvents.CUSTODY_KEY_REVOKED, { ...event });
  }

  keyShredded(event: Base & { kid: string }): void {
    void this.logger.log(AuditEvents.CUSTODY_KEY_SHREDDED, { ...event });
  }

  signature(event: Base & { kid: string; payload: Uint8Array }): void {
    const { payload, ...rest } = event;
    void this.logger.log(AuditEvents.CUSTODIAL_SIGNATURE, {
      ...rest,
      payloadDigest: payloadDigest(payload),
      payloadBytes: payload.length,
    });
  }

  signingRefused(event: Base & { reason: string }): void {
    void this.logger.log(AuditEvents.CUSTODIAL_SIGNING_REFUSED, { ...event });
  }
}
