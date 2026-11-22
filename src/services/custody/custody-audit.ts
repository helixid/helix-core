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
 * owner. One place emits them, as typed events on story A-1's audit trail:
 *
 *   choice, activation, key revocation and shredding
 *       `configuration.changed`, action category `custody`
 *   custody change (a key rotation)  `key.rotated`, previous and next signer
 *   custodial signature              `proof.generated`, the payload digest
 *   refused custodial signing        `proof.rejected`, a reason code
 *   agent activated                  `credential.verified`, action
 *       `onboarding/agent_onboarded`, the event the agent service records
 *
 * Events carry no free text: the subject DID is the `resource` (the `actor`
 * of a signature, since the subject is the one signing), the request id is
 * the `correlationId`, and the facts of a change (modes, source, kid, who
 * asked) are committed through `configurationDigest`. A custodial signature
 * is recorded by the digest of what was signed, never the bytes themselves.
 * A failure to record never breaks the request.
 */

import { createHash } from 'node:crypto';
import {
  jsonDigest,
  publicDid,
  type AuditEventInput,
  type AuditTrail,
  type CustodyChoiceSource,
  type CustodySubjectType,
  type Digest,
  type DidHostingMode,
  type KeyCustodyMode,
} from '../../core/index.js';
import type { HopReissueResult } from './hop-reissue.js';

/** Who did it: `admin` for the admin key, `account:<id>` in the hosted build, `enrollment-token` for `helix init`, `system` for the re-check. */
export type CustodyActor = string;

/** Why custodial signing was refused: the subject is self-custody, or the kid is not an active Helix-held key. */
export type CustodialSigningRefusal = 'custody_self' | 'key_not_active';

/** The action category every custody event carries. */
export const CUSTODY_AUDIT_CATEGORY = 'custody';

interface Base {
  requestId: string;
  actor: CustodyActor;
  subjectType: CustodySubjectType;
  did: string;
}

export function payloadDigest(bytes: Uint8Array): Digest {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}

export class CustodyAudit {
  constructor(private readonly trail: AuditTrail) {}

  private record(input: AuditEventInput): void {
    try {
      this.trail.record(input).catch(reportAuditFailure);
    } catch (error) {
      reportAuditFailure(error);
    }
  }

  private configurationChanged(name: string, base: Base, facts: Record<string, unknown>): void {
    const { requestId, did, ...rest } = base;
    this.record({
      eventType: 'configuration.changed',
      action: { category: CUSTODY_AUDIT_CATEGORY, name },
      outcome: 'succeeded',
      correlationId: requestId,
      resource: publicDid(did),
      details: { family: 'key', phase: 'configuration_changed', configurationDigest: jsonDigest({ did, ...rest, ...facts }) },
    });
  }

  chosen(event: Base & { keyCustody: KeyCustodyMode; didHosting: DidHostingMode; source: { keyCustody: CustodyChoiceSource; didHosting: CustodyChoiceSource } }): void {
    const { requestId, actor, subjectType, did, ...facts } = event;
    this.configurationChanged('chosen', { requestId, actor, subjectType, did }, facts);
  }

  activated(event: Base & { keyCustody: KeyCustodyMode; didHosting: DidHostingMode; kid: string; resolution: 'helix-hosted' | 'verified' }): void {
    const { requestId, actor, subjectType, did, ...facts } = event;
    this.configurationChanged('activated', { requestId, actor, subjectType, did }, facts);
  }

  /** The onboarding event the agent service records for an onboarded agent, naming its identity credential. */
  agentOnboarded(event: { requestId: string; agentDid: string; credentialId?: string | undefined }): void {
    this.record({
      eventType: 'credential.verified',
      action: { category: 'onboarding', name: 'agent_onboarded' },
      outcome: 'succeeded',
      correlationId: event.requestId,
      actor: publicDid(event.agentDid),
      details: {
        family: 'consent',
        phase: 'credential_verified',
        ...(event.credentialId !== undefined ? { consentRef: event.credentialId } : {}),
      },
    });
  }

  changed(event: Base & {
    from: KeyCustodyMode;
    to: KeyCustodyMode;
    oldKid: string;
    newKid: string;
    retiresAt: string;
    hopReissue: HopReissueResult;
  }): void {
    const { requestId, did, oldKid, newKid, ...facts } = event;
    this.record({
      eventType: 'key.rotated',
      action: { category: CUSTODY_AUDIT_CATEGORY, name: 'changed' },
      outcome: 'succeeded',
      correlationId: requestId,
      resource: publicDid(did),
      details: {
        family: 'key',
        phase: 'rotated',
        previousSigner: { did, kid: oldKid, alg: 'EdDSA' },
        nextSigner: { did, kid: newKid, alg: 'EdDSA' },
        configurationDigest: jsonDigest({ did, oldKid, newKid, ...facts }),
      },
    });
  }

  keyRevoked(event: Base & { kid: string; location: 'self' | 'helix' }): void {
    const { requestId, actor, subjectType, did, ...facts } = event;
    this.configurationChanged('key_revoked', { requestId, actor, subjectType, did }, facts);
  }

  keyShredded(event: Base & { kid: string }): void {
    const { requestId, actor, subjectType, did, ...facts } = event;
    this.configurationChanged('key_shredded', { requestId, actor, subjectType, did }, facts);
  }

  /** The subject is the signer, so it is the actor; the request's caller is attributed by the request id. */
  signature(event: Base & { kid: string; payload: Uint8Array }): void {
    this.record({
      eventType: 'proof.generated',
      action: { category: CUSTODY_AUDIT_CATEGORY, name: 'custodial_signature' },
      outcome: 'succeeded',
      correlationId: event.requestId,
      actor: publicDid(event.did),
      details: { family: 'proof', phase: 'generated', proofDigest: payloadDigest(event.payload) },
    });
  }

  signingRefused(event: Base & { code: CustodialSigningRefusal }): void {
    this.record({
      eventType: 'proof.rejected',
      action: { category: CUSTODY_AUDIT_CATEGORY, name: 'custodial_signature' },
      outcome: 'denied',
      correlationId: event.requestId,
      actor: publicDid(event.did),
      reason: { code: event.code },
      details: { family: 'proof', phase: 'rejected', verificationCode: event.code },
    });
  }
}
