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

import {
  HelixError,
  ErrorCode,
  createStatusList,
  setBit,
  base58btcEncode,
  derivePublicKey,
  hashCanonicalPayload,
  resolveDID as resolveDIDCore,
  signBytes,
  verifyEd25519Proof,
  type HelixVC,
  type SignedVC,
  VPMultipleActiveVCError,
  vcLookupColumns,
  delegationRef,
  delegationReference,
  publicDid,
  type AuditEventInput,
  type AuditTrail,
  type PartyRef,
} from '../../core/index.js';
import * as crypto from 'node:crypto';
import { VcRepository, type VCRecord } from '../../repositories/vc.repository.js';
import type { IDIDService } from '../did/did.service.js';
import type { ICache } from '../../cache/ICache.js';
import { NoopCache } from '../../cache/NoopCache.js';
import { extractEd25519PublicKeyHexFromDIDDocument } from '../did/publicKey.js';

type CredentialSubject = {
  agentName?: string;
  userId?: string;
  parentVcId?: string;
};

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

function asSignedVC(value: unknown): SignedVC {
  return value as SignedVC;
}

function getCredentialSubject(value: unknown): CredentialSubject {
  const record = asRecord(value);
  return asRecord(record.credentialSubject) as CredentialSubject;
}

/**
 * A user credential (HelixUserCredential). Agents are not issued credentials
 * here: onboarding gives them an AgentIdentityCredential and one
 * CapabilityAttestationCredential per scope (story F-1, CredentialService).
 */
export interface IssueVCParams extends ReconcileOptions {
  subjectDid: string;
  subjectType: 'user';
  userId: string;
  expiresInSeconds?: number | undefined;
  /** Explicit expiry. `null` issues a VC with no validUntil. Takes precedence over expiresInSeconds. */
  expiresAt?: Date | null | undefined;
}

export interface IssueVCResult extends Partial<ReconcileResult> {
  vcId: string;
  vc: SignedVC;
  statusListIndex: number;
  expiresAt: string | null;
}

export interface ReconcileOptions {
  /**
   * Also revoke every other active credential with the same identity but
   * a different scope set, so the one just stored is the only one standing.
   */
  revokeExisting?: boolean | undefined;
}

/** What reconcileActive() did to the credentials that were active before this one. */
export interface ReconcileResult {
  /** Same identity and scope set: revoked in favour of the new one, and chained to it. */
  replacedVcIds: string[];
  /** Same identity, other scopes: revoked because `revokeExisting` asked for it. */
  revokedVcIds: string[];
  /** Would have been revoked, but active delegations still hang off them, so they stay. */
  retainedVcIds: string[];
}

export interface VCDetails {
  vcId: string;
  vc: SignedVC;
  status: 'active' | 'revoked' | 'expired';
  expiresAt: string | null;
  revokedAt: string | null;
  renewedByVcId: string | null;
}

export interface ListVCFilters {
  subjectDid?: string | undefined;
  /** Credentials this DID signed: an agent's delegations, a service's grants. */
  issuerDid?: string | undefined;
  status?: string | undefined;
  limit?: number | undefined;
}

export interface VCSummary {
  vcId: string;
  subjectDid: string;
  /** The credential's own type, e.g. AgentIdentityCredential, CapabilityAttestationCredential or DelegationGrantCredential. */
  vcType?: string | undefined;
  agentName?: string | undefined;
  scopes: string[];
  status: 'active' | 'revoked' | 'expired';
  issuedAt: string;
  expiresAt: string | null;
  parentVcId?: string | undefined;
}

/** Renewal of a user credential: a fresh validity. Identity credentials renew through CredentialService.renewIdentity. */
export interface RenewVCOptions {
  expiresInSeconds?: number | undefined;
}

/**
 * Interface for Verifiable Credential lifecycle operations.
 */
export interface IVCService {
  findActiveBySubjectDid(
    subjectDid: string,
    vcType?: string,
  ): Promise<Record<string, unknown> | null>;
  listActiveBySubjectDid(
    subjectDid: string,
    vcType?: string,
  ): Promise<Array<Record<string, unknown>>>;
  issueVC(params: IssueVCParams, requestId: string): Promise<IssueVCResult>;
  listVCs(filters?: ListVCFilters): Promise<VCSummary[]>;
  getVC(vcId: string, requestId: string): Promise<VCDetails>;
  revokeVC(
    vcId: string,
    requestId: string,
  ): Promise<{ vcId: string; revoked: true; revokedAt: string }>;
  renewVC(
    vcId: string,
    overrides: RenewVCOptions,
    requestId: string,
  ): Promise<IssueVCResult & { previousVcId: string }>;
  getVCStatus(vcId: string): Promise<'active' | 'revoked' | 'expired'>;
  findRecordByVcId(vcId: string): Promise<{
    vcId: string;
    vc: Record<string, unknown>;
    status: 'active' | 'revoked' | 'expired';
  } | null>;
  createStatusList(input?: { listId?: string; length?: number }): Promise<{ listId: string; encodedList: string }>;
  registerSignedVC(vc: SignedVC, options?: ReconcileOptions): Promise<ReconcileResult>;

  /** See IVCService.registerExternalVC() in ./IVCService.ts. */
  registerExternalVC(
    vc: SignedVC,
    requestId: string,
    options?: ReconcileOptions,
  ): Promise<{ vcId: string; alreadyRegistered: boolean } & Partial<ReconcileResult>>;

  /** See IVCService.claimStatusListEntry() in ./IVCService.ts. */
  claimStatusListEntry(): Promise<{
    statusList: { credentialSubject: { encodedList: string } };
    statusListCredentialUrl: string;
    statusListIndex: number;
  }>;

  /** See IVCService.registerIssuedGrant() in ./IVCService.ts. */
  registerIssuedGrant(vc: SignedVC, requestId: string, options?: ReconcileOptions): Promise<ReconcileResult>;

  /** See IVCService.listActiveGrants() in ./IVCService.ts. */
  listActiveGrants(lookup: { agentDid: string; serviceDid: string; userDid: string }): Promise<SignedVC[]>;
}

/**
 * Implementation of Verifiable Credential lifecycle management.
 */

const DID_PATTERN = /^did:[^\r\n]+$/;

/** A `public_did` reference, or nothing when the value is not a DID: the event then names no party rather than failing validation. */
function didRef(value: string | undefined): PartyRef | undefined {
  return value !== undefined && DID_PATTERN.test(value) ? publicDid(value) : undefined;
}

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}

export class VCService implements IVCService {
  private readonly DEFAULT_STATUS_LIST_ID = 'helix-status-list-1';

  constructor(
    private readonly vcRepo: VcRepository,
    private readonly didService: IDIDService,
    private readonly auditTrail: AuditTrail,
    private readonly signingKeyHex: string,
    private readonly issuerDid: string,
    private readonly apiBaseUrl: string,
    private readonly statusListCache: ICache<string> = new NoopCache<string>(),
    private readonly statusListCacheTtlSeconds = 60,
  ) {}

  /** Records one typed audit event; a failure to record never breaks the request. */
  private audit(input: AuditEventInput): void {
    try {
      this.auditTrail.record(input).catch(reportAuditFailure);
    } catch (error) {
      reportAuditFailure(error);
    }
  }

  /** `delegation.issued` for a credential this platform now holds; `parentRef` names what it renews or derives from. */
  private auditCredentialIssued(requestId: string, name: string, subjectDid: string, ref: string, parentRef?: string): void {
    const resource = didRef(subjectDid);
    this.audit({
      eventType: 'delegation.issued',
      action: { category: 'credential', name },
      outcome: 'succeeded',
      correlationId: requestId,
      ...(resource !== undefined ? { resource } : {}),
      details: {
        family: 'delegation',
        phase: 'issued',
        delegationRef: ref,
        ...(parentRef !== undefined ? { parentRef } : {}),
      },
    });
  }

  private auditCredentialRevoked(requestId: string, subjectDid: string, vcId: string, code?: string): void {
    const resource = didRef(subjectDid);
    this.audit({
      eventType: 'delegation.revoked',
      action: { category: 'credential', name: 'revoked' },
      outcome: 'succeeded',
      correlationId: requestId,
      ...(resource !== undefined ? { resource } : {}),
      ...(code !== undefined ? { reason: { code } } : {}),
      details: { family: 'delegation', phase: 'revoked', delegationRef: delegationReference(vcId) },
    });
  }

  /** `consent.approved`: the service (issuer) recorded the user's consent to the agent. */
  private auditConsentRegistered(requestId: string, vc: SignedVC, agentDid: string, userDid: string | undefined): void {
    const actor = didRef(agentDid);
    const resource = didRef(vc.issuer);
    const responsibleParty = didRef(userDid);
    this.audit({
      eventType: 'consent.approved',
      action: { category: 'consent', name: 'grant_registered' },
      outcome: 'succeeded',
      correlationId: requestId,
      ...(actor !== undefined ? { actor } : {}),
      ...(resource !== undefined ? { resource } : {}),
      ...(responsibleParty !== undefined ? { responsibleParty } : {}),
      details: { family: 'consent', phase: 'approved', consentRef: vc.id },
    });
  }

  async findActiveBySubjectDid(
    subjectDid: string,
    vcType?: string,
  ): Promise<Record<string, unknown> | null> {
    const records = await this.vcRepo.findActiveBySubjectDid(subjectDid, vcType);
    if (records.length > 1) {
      throw new VPMultipleActiveVCError();
    }
    const record = records.at(-1);
    if (!record) return null;
    return (
      typeof record.vcJson === 'string' ? JSON.parse(record.vcJson) : record.vcJson
    ) as Record<string, unknown>;
  }

  async listActiveBySubjectDid(
    subjectDid: string,
    vcType?: string,
  ): Promise<Array<Record<string, unknown>>> {
    const records = await this.vcRepo.findActiveBySubjectDid(subjectDid, vcType);
    return records.map(
      (record) =>
        (typeof record.vcJson === 'string' ? JSON.parse(record.vcJson) : record.vcJson) as Record<
          string,
          unknown
        >,
    );
  }

  async findActiveByVcIdForSubject(
    vcId: string,
    subjectDid: string,
    vcType?: string,
  ): Promise<Record<string, unknown> | null> {
    const record = await this.vcRepo.findByVcId(vcId);
    if (
      !record ||
      record.subjectDid !== subjectDid ||
      record.revokedAt ||
      (record.expiresAt !== null && record.expiresAt.getTime() <= Date.now())
    ) {
      return null;
    }
    const vc = (
      typeof record.vcJson === 'string' ? JSON.parse(record.vcJson) : record.vcJson
    ) as Record<string, unknown>;
    if (vcType) {
      const types = Array.isArray(vc['type']) ? vc['type'] : [];
      if (!types.includes(vcType)) return null;
    }
    return vc;
  }

  async listActiveGrants(lookup: {
    agentDid: string;
    serviceDid: string;
    userDid: string;
  }): Promise<SignedVC[]> {
    const records = await this.vcRepo.findActiveByIdentity({
      vcType: 'DelegationGrantCredential',
      subjectDid: lookup.agentDid,
      issuerDid: lookup.serviceDid,
      userDid: lookup.userDid,
    });
    return records.map(
      (record) =>
        (typeof record.vcJson === 'string' ? JSON.parse(record.vcJson) : record.vcJson) as SignedVC,
    );
  }

  /**
   * The one rule every kind of credential follows once it is stored: a
   * credential is identified by (type, issuer, subject, user) plus its scope
   * set. Storing one whose identity and scopes an active credential already
   * carries *refreshes* that credential -- the old one is revoked and
   * chained to the new through renewedByVcId, the new one having been stored
   * first so there is never a moment without one. A different scope set
   * stands beside the existing ones (a VP presents them all and the
   * verifier takes the union), unless `revokeExisting` asks for the others
   * to go.
   *
   * One exception, for delegation: a credential that active delegated
   * credentials still point at (their parentVcId) is never revoked here,
   * since the sub-agents' chains would break -- it is reported as retained
   * and stays active until those delegations lapse.
   */
  async reconcileActive(
    vc: SignedVC,
    options: ReconcileOptions,
    requestId: string,
  ): Promise<ReconcileResult> {
    const result: ReconcileResult = { replacedVcIds: [], revokedVcIds: [], retainedVcIds: [] };
    const columns = vcLookupColumns(vc);
    const subjectDid = (vc.credentialSubject as { id?: unknown }).id;
    if (!columns.vcType || !columns.issuerDid || typeof subjectDid !== 'string') return result;

    const siblings = (
      await this.vcRepo.findActiveByIdentity({
        vcType: columns.vcType,
        issuerDid: columns.issuerDid,
        subjectDid,
        userDid: columns.userDid,
      })
    ).filter((record) => record.vcId !== vc.id);
    const sameScopes = siblings.filter((record) => (record.scopeKey ?? null) === columns.scopeKey);
    const otherScopes = options.revokeExisting ? siblings.filter((record) => !sameScopes.includes(record)) : [];

    for (const old of sameScopes) {
      await this.vcRepo.markAsRenewed(old.vcId, vc.id);
      (await this.retire(old, requestId) ? result.replacedVcIds : result.retainedVcIds).push(old.vcId);
    }
    for (const old of otherScopes) {
      (await this.retire(old, requestId) ? result.revokedVcIds : result.retainedVcIds).push(old.vcId);
    }
    return result;
  }

  /** Revokes `record` unless active delegations hang off it. True when revoked. */
  private async retire(record: VCRecord, requestId: string): Promise<boolean> {
    if ((await this.vcRepo.findActiveChildren(record.vcId)).length > 0) return false;

    const list = await this.vcRepo.findStatusListById(this.DEFAULT_STATUS_LIST_ID);
    if (!list) throw new Error('Status list missing during revocation');
    // Only a credential whose status entry is on this platform's own list
    // has a bit to flip; a delegation VC (no status entry, placeholder index
    // 0) or an externally-signed one (the SP's list) is revoked by its row
    // alone, and must not flip someone else's bit 0.
    const ownsBit = this.pointsAtDefaultList(record.vcJson);
    const encoded = ownsBit ? setBit(list.encodedList, record.statusListIndex, 1) : list.encodedList;
    await this.vcRepo.revokeVc(record.vcId, this.DEFAULT_STATUS_LIST_ID, encoded);
    if (ownsBit) await this.statusListCache.delete(this.DEFAULT_STATUS_LIST_ID);

    this.auditCredentialRevoked(requestId, record.subjectDid, record.vcId, 'superseded');
    return true;
  }

  private pointsAtDefaultList(vcJson: unknown): boolean {
    // Stored JSON may come back as a string (the sqlite driver) or an object.
    let vc: unknown = vcJson;
    if (typeof vc === 'string') {
      try {
        vc = JSON.parse(vc);
      } catch {
        return false;
      }
    }
    const status = asRecord(asRecord(vc).credentialStatus);
    return status.statusListCredential === `${this.apiBaseUrl}/v1/status-list/${this.DEFAULT_STATUS_LIST_ID}`;
  }

  /**
   * Persists an already-signed VC without issuing or re-signing it — see
   * IVCService.registerSignedVC()'s doc comment. A delegation carrying its
   * own entry on this platform's status list (delegateAuthority claims one)
   * is stored with that index, so revoking it flips its bit. One without
   * (delegations made before that) keeps the placeholder 0, which nothing
   * reads as a bit of its own: such a record is revoked by its row's
   * revokedAt alone (see revokeVC / retire).
   */
  async registerSignedVC(vc: SignedVC, options: ReconcileOptions = {}): Promise<ReconcileResult> {
    const subject = (vc as unknown as { credentialSubject: CredentialSubject & { id: string; scopes?: string[] } })
      .credentialSubject;
    const validUntil = (vc as unknown as { validUntil?: string }).validUntil;
    const ownIndex = this.pointsAtDefaultList(vc) ? Number(vc.credentialStatus?.statusListIndex) : NaN;
    await this.vcRepo.createVc({
      vcId: vc.id,
      subjectDid: subject.id,
      subjectType: 'agent',
      vcJson: vc,
      privilegeScopes: subject.scopes,
      statusListIndex: Number.isInteger(ownIndex) ? ownIndex : 0,
      expiresAt: validUntil ? new Date(validUntil) : null,
      parentVcId: subject.parentVcId,
      ...vcLookupColumns(vc),
    });
    return this.reconcileActive(vc, options, 'register-signed-vc');
  }

  /**
   * Registers a VC signed outside this platform — see
   * IVCService.registerExternalVC(). Nothing here trusts the submitted
   * credential: the proof is checked against the issuer's own DID document,
   * so a forged or tampered grant is rejected before it reaches storage.
   */
  async registerExternalVC(
    vc: SignedVC,
    requestId: string,
    options: ReconcileOptions = {},
  ): Promise<{ vcId: string; alreadyRegistered: boolean } & Partial<ReconcileResult>> {
    // Idempotent by vcId: a retried consent callback or a re-run seed must
    // not duplicate the row, and must not look like a failure to the caller.
    const existing = await this.vcRepo.findByVcId(vc.id);
    if (existing) {
      return { vcId: vc.id, alreadyRegistered: true };
    }

    const { proof, ...unsigned } = vc as SignedVC & { proof?: { proofValue: string } };
    if (!proof?.proofValue) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'VC carries no proof to verify', 400);
    }

    let issuerDoc;
    try {
      issuerDoc = await resolveDIDCore(vc.issuer);
    } catch {
      throw new HelixError(
        ErrorCode.VC_ISSUER_NOT_FOUND,
        `Issuer DID ${vc.issuer} could not be resolved`,
        400,
      );
    }

    const signatureValid = await verifyEd25519Proof(
      unsigned as Record<string, unknown>,
      proof,
      issuerDoc,
    );
    if (!signatureValid) {
      throw new HelixError(
        ErrorCode.VC_SIGNATURE_INVALID,
        'VC proof does not verify against its issuer DID',
        400,
      );
    }

    const validUntil = (vc as unknown as { validUntil?: string }).validUntil;
    const expiresAt = validUntil ? new Date(validUntil) : null;
    if (expiresAt && Number.isNaN(expiresAt.getTime())) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'VC has no usable validUntil', 400);
    }
    if (expiresAt && expiresAt.getTime() <= Date.now()) {
      throw new HelixError(ErrorCode.VC_EXPIRED, 'Cannot register an already-expired VC', 400);
    }

    const subject = vc.credentialSubject as unknown as {
      id: string;
      scopes?: string[];
    };

    // vcs.subjectDid is a FK onto dids. An onboarded agent is already
    // registered; this covers a grant naming a DID this server has not
    // stored, and mirrors issueVC()'s own fallback.
    try {
      await this.didService.resolveDID(subject.id, requestId);
    } catch (err: unknown) {
      if (err instanceof HelixError && err.code === ErrorCode.DID_NOT_FOUND) {
        let resolved: Awaited<ReturnType<typeof resolveDIDCore>>;
        try {
          resolved = await resolveDIDCore(subject.id);
        } catch {
          throw new HelixError(ErrorCode.VC_SUBJECT_DID_NOT_FOUND, 'Subject DID not found', 404);
        }
        await this.didService.registerResolvedDID(subject.id, resolved, 'agent', requestId);
      } else {
        throw err;
      }
    }

    // A DelegationGrant names its scopes `scopes`; the row's scope column
    // stores them so the grant stays queryable by scope.
    const privilegeScopes = subject.scopes;

    await this.vcRepo.createVc({
      vcId: vc.id,
      subjectDid: subject.id,
      subjectType: 'agent',
      vcJson: vc,
      privilegeScopes,
      // Placeholder index, as in registerSignedVC(): an SP-issued grant
      // carries its own credentialStatus pointing at the SP's status list,
      // so revocation is checked there rather than against an index this
      // platform claimed.
      statusListIndex: 0,
      expiresAt,
      ...vcLookupColumns(vc),
    });

    this.auditCredentialIssued(requestId, 'registered', subject.id, delegationRef(vc) ?? delegationReference(vc.id));

    const reconciled = await this.reconcileActive(vc, options, requestId);
    return { vcId: vc.id, alreadyRegistered: false, ...reconciled };
  }

  async issueVC(params: IssueVCParams, requestId: string): Promise<IssueVCResult> {
    // 1. Only user credentials are issued here. The body of POST /v1/vcs is
    // not typed at runtime, so an agent request is refused explicitly: agents
    // get an AgentIdentityCredential and capability attestations (story F-1).
    const body = params as unknown as Record<string, unknown>;
    if (body['subjectType'] !== 'user') {
      throw new HelixError(
        ErrorCode.VALIDATION_ERROR,
        "Only user credentials are issued here (subjectType 'user'); agents receive an AgentIdentityCredential and capability attestations from POST /v1/agents",
        400,
      );
    }
    if (typeof body['userId'] !== 'string' || body['userId'] === '' || body['privilegeScopes'] !== undefined || body['agentName'] !== undefined) {
      throw new HelixError(
        ErrorCode.VALIDATION_ERROR,
        'User VCs require userId and must not include privilegeScopes or agentName',
        400,
      );
    }

    // 2. Validate subject exists
    try {
      await this.didService.resolveDID(params.subjectDid, requestId);
    } catch (err: unknown) {
      if (err instanceof HelixError && err.code === ErrorCode.DID_NOT_FOUND) {
        let resolved: Awaited<ReturnType<typeof resolveDIDCore>>;
        try {
          resolved = await resolveDIDCore(params.subjectDid);
        } catch {
          throw new HelixError(ErrorCode.VC_SUBJECT_DID_NOT_FOUND, 'Subject DID not found', 404);
        }
        // resolveDIDCore validates the DID is *resolvable* (locally for
        // did:key, or over HTTP for did:web) but never persists it. Without
        // this, the subjectDid FK below fails under FK-enforcing storage
        // (Postgres) for any DID that reached us this way -- e.g. a
        // client-supplied agentDid on the single-roundtrip /v1/enroll path.
        // SQLite's lax FK enforcement was masking this gap.
        await this.didService.registerResolvedDID(params.subjectDid, resolved, params.subjectType, requestId);
      } else {
        throw err;
      }
    }

    // 3. Claim status list index
    let list = await this.vcRepo.findStatusListById(this.DEFAULT_STATUS_LIST_ID);
    if (!list) {
      const statusList = await this.createStatusList({ listId: this.DEFAULT_STATUS_LIST_ID });
      list = {
        listId: this.DEFAULT_STATUS_LIST_ID,
        encodedList: statusList.encodedList,
        nextIndex: 0,
      };
    }

    if (list.nextIndex >= 131072) {
      throw new HelixError(
        ErrorCode.STATUS_LIST_INDEX_EXHAUSTED,
        'Default status list is full',
        503,
      );
    }

    await this.assertIssuerSigningKeyMatches(requestId);

    const { claimedIndex } = await this.vcRepo.claimNextIndex(this.DEFAULT_STATUS_LIST_ID);

    // 4. Build VC
    const cuid = crypto.randomUUID().replace(/-/g, '').slice(0, 24);
    const vcId = `vc:helix:${cuid}`;
    const now = new Date();
    const expiresAt =
      params.expiresAt !== undefined
        ? params.expiresAt
        : new Date(now.getTime() + (params.expiresInSeconds || 7776000) * 1000);
    const validUntilField = expiresAt ? { validUntil: expiresAt.toISOString() } : {};

    const credentialStatus = {
      id: `${this.apiBaseUrl}/v1/status-list/${this.DEFAULT_STATUS_LIST_ID}#${claimedIndex}`,
      type: 'BitstringStatusListEntry' as const,
      statusPurpose: 'revocation' as const,
      statusListIndex: claimedIndex.toString(),
      statusListCredential: `${this.apiBaseUrl}/v1/status-list/${this.DEFAULT_STATUS_LIST_ID}`,
    };
    const credential: HelixVC = {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://helixid.io/contexts/v1'],
      id: vcId,
      type: ['VerifiableCredential', 'HelixUserCredential'],
      issuer: this.issuerDid,
      validFrom: now.toISOString(),
      ...validUntilField,
      credentialStatus,
      credentialSubject: {
        id: params.subjectDid,
        type: 'HelixUser',
        userId: params.userId,
      },
    };

    // 5. Sign VC (SHA-256 + Ed25519)
    const signedVc = await this.signCredential(credential);

    // 6. Persist
    await this.vcRepo.createVc({
      vcId,
      subjectDid: params.subjectDid,
      subjectType: params.subjectType,
      vcJson: signedVc,
      statusListIndex: claimedIndex,
      expiresAt,
      ...vcLookupColumns(signedVc),
    });

    // 7. Audit
    this.auditCredentialIssued(
      requestId,
      'issued',
      params.subjectDid,
      delegationRef(signedVc) ?? delegationReference(vcId),
    );

    const reconciled = await this.reconcileActive(
      signedVc,
      { revokeExisting: params.revokeExisting },
      requestId,
    );

    return {
      vcId,
      vc: signedVc,
      statusListIndex: claimedIndex,
      expiresAt: expiresAt?.toISOString() ?? null,
      ...reconciled,
    };
  }

  async listVCs(filters: ListVCFilters = {}): Promise<VCSummary[]> {
    const records = await this.vcRepo.findMany({
      subjectDid: filters.subjectDid,
      issuerDid: filters.issuerDid,
    });
    const limit = filters.limit ?? 50;
    const now = Date.now();

    const summaries = records.map((record): VCSummary => {
      let status: 'active' | 'revoked' | 'expired' = 'active';
      if (record.revokedAt) status = 'revoked';
      else if (record.expiresAt && record.expiresAt.getTime() <= now) status = 'expired';

      const vcJson =
        typeof record.vcJson === 'string' ? JSON.parse(record.vcJson) : record.vcJson;
      const subject = getCredentialSubject(vcJson);
      const scopes = Array.isArray(record.privilegeScopes)
        ? (record.privilegeScopes as string[])
        : typeof record.privilegeScopes === 'string'
          ? (JSON.parse(record.privilegeScopes) as string[])
          : [];
      const validFrom = (asRecord(vcJson).validFrom as string | undefined) ?? '';
      const parentVcId = record.parentVcId ?? subject.parentVcId;

      const vcType = record.vcType ?? vcLookupColumns(vcJson).vcType;

      return {
        vcId: record.vcId,
        subjectDid: record.subjectDid,
        ...(vcType ? { vcType } : {}),
        ...(subject.agentName ? { agentName: subject.agentName } : {}),
        scopes,
        status,
        issuedAt: record.createdAt?.toISOString() ?? validFrom,
        expiresAt: record.expiresAt?.toISOString() ?? null,
        ...(parentVcId ? { parentVcId } : {}),
      };
    });

    const filtered = filters.status
      ? summaries.filter((summary) => summary.status === filters.status)
      : summaries;
    return filtered.slice(0, limit);
  }

  async getVC(vcId: string, requestId: string): Promise<VCDetails> {
    void requestId;
    const record = await this.vcRepo.findByVcId(vcId);
    if (!record) {
      throw new HelixError(ErrorCode.VC_NOT_FOUND, 'Credential not found', 404);
    }

    const now = new Date();
    let status: 'active' | 'revoked' | 'expired' = 'active';
    if (record.revokedAt) status = 'revoked';
    else if (record.expiresAt && record.expiresAt < now) status = 'expired';

    return {
      vcId: record.vcId,
      vc: asSignedVC(record.vcJson),
      status,
      expiresAt: record.expiresAt?.toISOString() ?? null,
      revokedAt: record.revokedAt?.toISOString() || null,
      renewedByVcId: record.renewedByVcId,
    };
  }

  async getVCStatus(vcId: string): Promise<'active' | 'revoked' | 'expired'> {
    const record = await this.vcRepo.findByVcId(vcId);
    if (!record) throw new HelixError(ErrorCode.VC_NOT_FOUND, 'Credential not found', 404);
    if (record.revokedAt) return 'revoked';
    if (record.expiresAt && record.expiresAt < new Date()) return 'expired';
    return 'active';
  }

  async findRecordByVcId(vcId: string): Promise<{
    vcId: string;
    vc: Record<string, unknown>;
    status: 'active' | 'revoked' | 'expired';
  } | null> {
    const record = await this.vcRepo.findByVcId(vcId);
    if (!record) return null;
    let status: 'active' | 'revoked' | 'expired' = 'active';
    if (record.revokedAt) status = 'revoked';
    else if (record.expiresAt && record.expiresAt.getTime() <= Date.now()) status = 'expired';
    return {
      vcId: record.vcId,
      vc: asRecord(record.vcJson),
      status,
    };
  }

  async revokeVC(
    vcId: string,
    requestId: string,
  ): Promise<{ vcId: string; revoked: true; revokedAt: string }> {
    const record = await this.vcRepo.findByVcId(vcId);
    if (!record) {
      throw new HelixError(ErrorCode.VC_NOT_FOUND, 'Credential not found', 404);
    }

    if (record.revokedAt) {
      throw new HelixError(ErrorCode.VC_ALREADY_REVOKED, 'Credential already revoked', 409);
    }

    const list = await this.vcRepo.findStatusListById(this.DEFAULT_STATUS_LIST_ID);
    if (!list) throw new Error('Status list missing during revocation');

    // Same rule as retire(): only a credential whose status entry is on this
    // platform's own list has a bit to flip. A delegation without its own
    // entry (placeholder index 0) or an externally-signed credential (another
    // issuer's list) is revoked by its row alone -- flipping
    // record.statusListIndex for those would revoke whichever credential
    // really owns that bit.
    const ownsBit = this.pointsAtDefaultList(record.vcJson);
    const newEncoded = ownsBit ? setBit(list.encodedList, record.statusListIndex, 1) : list.encodedList;

    const updatedRecord = await this.vcRepo.revokeVc(vcId, this.DEFAULT_STATUS_LIST_ID, newEncoded);
    if (ownsBit) await this.statusListCache.delete(this.DEFAULT_STATUS_LIST_ID);

    this.auditCredentialRevoked(requestId, record.subjectDid, vcId);

    return {
      vcId,
      revoked: true,
      revokedAt: updatedRecord.revokedAt!.toISOString(),
    };
  }

  async renewVC(
    vcId: string,
    overrides: RenewVCOptions,
    requestId: string,
  ): Promise<IssueVCResult & { previousVcId: string }> {
    const record = await this.vcRepo.findByVcId(vcId);
    if (!record) {
      throw new HelixError(ErrorCode.VC_NOT_FOUND, 'Credential not found', 404);
    }
    if (record.revokedAt) {
      throw new HelixError(ErrorCode.VC_ALREADY_REVOKED, 'Cannot renew a revoked credential', 409);
    }

    const vcJson = asRecord(record.vcJson);
    const types = Array.isArray(vcJson['type']) ? (vcJson['type'] as unknown[]) : [];
    const subject = getCredentialSubject(vcJson);
    // Only a user credential renews here. An agent's identity credential
    // renews through CredentialService.renewIdentity (the route tries that
    // first); attestations, delegation hops and grants are re-issued by
    // whoever signs them, never re-signed as another credential type.
    if (!types.includes('HelixUserCredential') || typeof subject.userId !== 'string') {
      throw new HelixError(
        ErrorCode.VALIDATION_ERROR,
        'Only user credentials renew here; identity credentials renew through the credential service, and attestations, delegation hops and grants are re-issued by their issuer',
        400,
      );
    }
    const newVcResult = await this.issueVC(
      {
        subjectDid: record.subjectDid,
        subjectType: 'user',
        userId: subject.userId,
        expiresInSeconds: overrides.expiresInSeconds,
      },
      requestId,
    );

    await this.vcRepo.markAsRenewed(vcId, newVcResult.vcId);

    this.auditCredentialIssued(requestId, 'renewed', record.subjectDid, delegationReference(newVcResult.vcId), vcId);

    return {
      ...newVcResult,
      previousVcId: vcId,
    };
  }

  async claimStatusListEntry(): Promise<{
    statusList: { credentialSubject: { encodedList: string } };
    statusListCredentialUrl: string;
    statusListIndex: number;
  }> {
    let list = await this.vcRepo.findStatusListById(this.DEFAULT_STATUS_LIST_ID);
    if (!list) {
      const created = await this.createStatusList({ listId: this.DEFAULT_STATUS_LIST_ID });
      list = {
        listId: this.DEFAULT_STATUS_LIST_ID,
        encodedList: created.encodedList,
        nextIndex: 0,
      };
    }
    if (list.nextIndex >= 131072) {
      throw new HelixError(ErrorCode.STATUS_LIST_INDEX_EXHAUSTED, 'Default status list is full', 503);
    }
    const { claimedIndex } = await this.vcRepo.claimNextIndex(this.DEFAULT_STATUS_LIST_ID);
    return {
      statusList: { credentialSubject: { encodedList: list.encodedList } },
      statusListCredentialUrl: `${this.apiBaseUrl}/v1/status-list/${this.DEFAULT_STATUS_LIST_ID}`,
      statusListIndex: claimedIndex,
    };
  }

  async registerIssuedGrant(
    vc: SignedVC,
    requestId: string,
    options: ReconcileOptions = {},
  ): Promise<ReconcileResult> {
    const subject = vc.credentialSubject as unknown as {
      id: string;
      userDid?: string;
      scopes?: string[];
      durability?: string;
    };
    const validUntil = (vc as unknown as { validUntil?: string }).validUntil;
    const index = Number(vc.credentialStatus?.statusListIndex ?? 0);

    // vcs.subjectDid is a FK onto dids; an agent that was onboarded here is
    // already registered, this covers one this server has only seen in a VP.
    await this.ensureSubjectDidRegistered(subject.id, requestId);

    await this.vcRepo.createVc({
      vcId: vc.id,
      subjectDid: subject.id,
      subjectType: 'agent',
      vcJson: vc,
      privilegeScopes: subject.scopes,
      statusListIndex: Number.isInteger(index) ? index : 0,
      expiresAt: validUntil ? new Date(validUntil) : null,
      ...vcLookupColumns(vc),
    });

    this.auditConsentRegistered(requestId, vc, subject.id, subject.userDid);

    return this.reconcileActive(vc, options, requestId);
  }

  private async ensureSubjectDidRegistered(did: string, requestId: string): Promise<void> {
    try {
      await this.didService.resolveDID(did, requestId);
    } catch (err: unknown) {
      if (err instanceof HelixError && err.code === ErrorCode.DID_NOT_FOUND) {
        let resolved: Awaited<ReturnType<typeof resolveDIDCore>>;
        try {
          resolved = await resolveDIDCore(did);
        } catch {
          throw new HelixError(ErrorCode.VC_SUBJECT_DID_NOT_FOUND, 'Subject DID not found', 404);
        }
        await this.didService.registerResolvedDID(did, resolved, 'agent', requestId);
      } else {
        throw err;
      }
    }
  }

  /**
   * Creates (or resets) a status list row. Serving and signing lists is the
   * StatusListService's (story L3-C): one signed list per issuer DID.
   */
  async createStatusList(input: { listId?: string; length?: number } = {}): Promise<{ listId: string; encodedList: string }> {
    const listId = input.listId ?? this.DEFAULT_STATUS_LIST_ID;
    const encodedList = createStatusList(input.length);
    await this.vcRepo.createStatusList(listId, encodedList);
    await this.statusListCache.delete(listId);
    return { listId, encodedList };
  }

  private async signCredential(credential: HelixVC): Promise<SignedVC> {
    const signatureHex = await signBytes(hashCanonicalPayload(credential), this.signingKeyHex);
    const proofValue = base58btcEncode(Buffer.from(signatureHex, 'hex'));

    return {
      ...credential,
      proof: {
        type: 'Ed25519Signature2020',
        created: new Date().toISOString(),
        verificationMethod: `${this.issuerDid}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue,
      },
    };
  }

  private async assertIssuerSigningKeyMatches(requestId: string): Promise<void> {
    let issuerDocument: Awaited<ReturnType<IDIDService['resolveDID']>>;
    try {
      issuerDocument = await this.didService.resolveDID(this.issuerDid, requestId);
    } catch {
      throw new HelixError(
        ErrorCode.VC_ISSUER_NOT_FOUND,
        'Configured issuer DID could not be resolved',
        500,
      );
    }

    const expectedPublicKey = derivePublicKey(this.signingKeyHex).toLowerCase();
    const issuerPublicKey = extractEd25519PublicKeyHexFromDIDDocument(issuerDocument);
    if (issuerPublicKey !== expectedPublicKey) {
      throw new HelixError(
        ErrorCode.ISSUER_SIGNING_KEY_MISMATCH,
        'Configured issuer DID public key does not match HELIX_SIGNING_KEY',
        500,
        { issuerDid: this.issuerDid },
      );
    }
  }
}
