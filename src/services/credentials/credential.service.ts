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
 * Issuance side of KYA-OS story F-1: identity credentials, capability
 * attestations and delegation hops, each signed by the right Signer (the
 * Helix issuer, a key Helix holds in custody, or an owner's SDK through a
 * signed credential the request carries), each with its own entry on the
 * platform status list, and a copy of each kept in the `vcs` table for the
 * console. No private key is read here: signing goes through a Signer.
 */

import {
  CAPABILITY_ATTESTATION_TYPE,
  DELEGATION_CREDENTIAL_TYPE,
  ErrorCode,
  HelixError,
  IDENTITY_CREDENTIAL_TYPE,
  buildCapabilityAttestation,
  buildDelegationHop,
  buildIdentityCredential,
  credentialDigest,
  delegationRef,
  UNKNOWN_DELEGATION_REF,
  evaluateDelegationChain,
  invokerOf,
  publicDid,
  resolveDID as resolveDIDCore,
  rootHopInput,
  verifyCapabilityAttestation,
  type BitstringStatusEntry,
  type AuditEventInput,
  type AuditTrail,
  type Caveat,
  type JwsDidDocument,
  type PartyRef,
  type Signer,
  type SignedCapabilityAttestation,
  type SignedDelegationHop,
  type SignedIdentityCredential,
} from '../../core/index.js';

const DID_PATTERN = /^did:[^\r\n]+$/;

/** A `public_did` reference, or nothing when the value is not a DID: the event then names no party rather than failing validation. */
function didRef(value: unknown): PartyRef | undefined {
  return typeof value === 'string' && DID_PATTERN.test(value) ? publicDid(value) : undefined;
}

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}
import type { VcRepository, VCRecord } from '../../repositories/vc.repository.js';
import type { DidKeyRepository } from '../../repositories/did-key.repository.js';
import type { IKeyCustody } from '../key-custody/key-custody.js';
import type { IDIDService } from '../did/IDIDService.js';
import { CustodySigner } from './custody-signer.js';
import { CUSTODIAL_SIGNING_SUBJECTS, type CustodialKeys } from '../custody/custodial-keys.js';
import type { BoundWindow, HopReissueInput, HopReissueResult, HopReissuer, KidHopsInput, PendingIssuerHop } from '../custody/hop-reissue.js';

/** The two years a credential lives by default; attestations and hops may be shorter. */
const DEFAULT_VALID_MS = 2 * 365 * 24 * 60 * 60 * 1000;

export type CredentialStatus = 'active' | 'revoked' | 'expired';

export interface StoredCredential<T = Record<string, unknown>> {
  vcId: string;
  status: CredentialStatus;
  credential: T;
  revokedAt: string | null;
}

/** The Helix copy of everything issued to one agent (story F-1 point 7). */
export interface AgentCredentials {
  agentDid: string;
  identity: StoredCredential<SignedIdentityCredential> | null;
  attestations: StoredCredential<SignedCapabilityAttestation>[];
  hops: StoredCredential<SignedDelegationHop>[];
}

export interface IssueIdentityInput {
  agentDid: string;
  name: string;
  ownerDid: string;
  validUntil?: Date | null;
}

export interface IssueAttestationsInput {
  agentDid: string;
  capabilities: readonly string[];
  validUntil?: Date | null;
  /** Default: the Helix issuer. An owner signs through the SDK instead (see `registerAttestation`). */
  signer?: Signer;
}

export interface IssueRootHopInput {
  /** The signing party: the Helix issuer, or a DID whose key Helix holds in custody. */
  issuer: string;
  invoker: string;
  invocationTarget: string;
  allowedAction: readonly string[];
  caveats?: readonly Caveat[];
  validUntil?: string;
}

export interface IssueHopInput {
  invoker: string;
  allowedAction: readonly string[];
  caveats?: readonly Caveat[];
  validUntil?: string;
}

/**
 * What this service needs for status: an entry on the issuing DID's own list
 * (story L3-C: one signed list per issuer), and revocation; `revokeMany`
 * revokes a cascade in one transaction when the store offers it.
 */
export interface CredentialStatusStore {
  claimStatusListEntry(issuerDid?: string): Promise<{ statusListCredentialUrl: string; statusListIndex: number }>;
  revokeVC(vcId: string, requestId: string): Promise<{ vcId: string; revoked: true; revokedAt: string }>;
  revokeMany?(vcIds: readonly string[], context: { requestId: string }): Promise<unknown>;
}

export type CredentialVcRepository = Pick<
  VcRepository,
  'createVc' | 'findByVcId' | 'findMany' | 'findActiveBySubjectDid' | 'findActiveChildren' | 'markAsRenewed'
>;

export interface RenewIdentityInput {
  expiresInSeconds?: number | undefined;
}

export interface RenewedIdentity {
  vcId: string;
  vc: SignedIdentityCredential;
  previousVcId: string;
  expiresAt: string | null;
  statusListIndex: number;
}

function statusOf(record: VCRecord): CredentialStatus {
  if (record.revokedAt) return 'revoked';
  if (record.expiresAt && record.expiresAt.getTime() <= Date.now()) return 'expired';
  return 'active';
}

function stored<T>(record: VCRecord): StoredCredential<T> {
  const json = typeof record.vcJson === 'string' ? JSON.parse(record.vcJson) : record.vcJson;
  return {
    vcId: record.vcId,
    status: statusOf(record),
    credential: json as T,
    revokedAt: record.revokedAt?.toISOString() ?? null,
  };
}

/** Whether a hop record was issued while the key of `bound` was current (story C-E point 4). */
function issuedIn(record: VCRecord, bound: BoundWindow | undefined): boolean {
  if (!bound) return true;
  const at = record.createdAt?.getTime();
  if (at === undefined) return false;
  return at >= bound.from.getTime() && (bound.until === null || at < bound.until.getTime());
}

/** The grant a hop carries, apart from its id, status entry and proof: what a reissue keeps. */
function grantOf(hop: SignedDelegationHop): string {
  const subject = hop.credentialSubject;
  return JSON.stringify([
    hop.issuer,
    subject.invoker ?? subject.controller,
    subject.parentCapability,
    subject.invocationTarget,
    [...subject.allowedAction].sort(),
    subject.caveats ?? [],
    hop.validFrom ?? null,
    hop.validUntil,
  ]);
}

export class CredentialService implements HopReissuer {
  private custodialKeys: CustodialKeys | undefined;

  constructor(
    private readonly vcRepo: CredentialVcRepository,
    private readonly statusStore: CredentialStatusStore,
    private readonly didService: Pick<IDIDService, 'resolveDID' | 'registerResolvedDID'>,
    private readonly helixSigner: Signer,
    private readonly keyRepository: Pick<DidKeyRepository, 'findByDid'>,
    private readonly keyCustody: IKeyCustody,
    private readonly auditTrail: AuditTrail,
  ) {}

  /** Records one typed audit event (KYA-OS A-1); a failure to record never breaks the request. */
  private audit(input: AuditEventInput): void {
    try {
      this.auditTrail.record(input).catch(reportAuditFailure);
    } catch (error) {
      reportAuditFailure(error);
    }
  }

  /**
   * `delegation.issued` for a credential this platform now holds (identity,
   * capability attestation or delegation hop): named by its SPEC 7.8
   * reference with its digest; `parentRef` names the hop it derives from or
   * the credential it renews.
   */
  private auditIssued(credential: unknown, subjectDid: string, name: 'issued' | 'registered' | 'renewed' | 'reissued', requestId: string, parentRef?: string): void {
    const record = credential as Record<string, unknown>;
    const ref = delegationRef(credential) ?? UNKNOWN_DELEGATION_REF;
    const digest = credentialDigest(credential);
    const actor = didRef(record['issuer']);
    const resource = didRef(subjectDid);
    this.audit({
      eventType: 'delegation.issued',
      action: { category: 'credential', name },
      outcome: 'succeeded',
      correlationId: requestId,
      ...(actor !== undefined ? { actor } : {}),
      ...(resource !== undefined ? { resource } : {}),
      authorization: { source: 'delegation', decision: 'allowed', delegationRef: ref, ...(digest !== undefined ? { delegationCredentialDigest: digest } : {}) },
      details: { family: 'delegation', phase: 'issued', delegationRef: ref, ...(parentRef !== undefined ? { parentRef } : {}) },
    });
  }

  /** The Helix issuer DID, the responsible party of record when an agent has no owner DID. */
  get issuerDid(): string {
    return this.helixSigner.did;
  }

  /** A fresh entry on the issuing DID's own status list, as the credential carries it. */
  private async statusEntry(issuerDid: string): Promise<BitstringStatusEntry> {
    const entry = await this.statusStore.claimStatusListEntry(issuerDid);
    return {
      id: `${entry.statusListCredentialUrl}#${entry.statusListIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: entry.statusListIndex.toString(),
      statusListCredential: entry.statusListCredentialUrl,
    };
  }

  private static validUntil(value: Date | null | undefined): string {
    if (value === null) return new Date(Date.now() + DEFAULT_VALID_MS).toISOString();
    return (value ?? new Date(Date.now() + DEFAULT_VALID_MS)).toISOString();
  }

  /**
   * KYA-OS story F-3: agents and services created through the custody routes
   * keep their key in the KeyStore, not in did_keys. With this attached, Helix
   * signs a delegation hop for such a subject when its key custody is
   * `helix`, through a KeyStoreSigner (stories rule 8), audited as a
   * custodial signature; a custodial agent delegates exactly as an agent
   * whose key is in did_keys does.
   */
  attachCustodialKeys(keys: CustodialKeys): void {
    this.custodialKeys = keys;
  }

  /**
   * The Signer for `did`: the Helix issuer, the KeyStore key of an active
   * custodial agent, service or owner (F-3; stories rule 8), else a key a
   * pre-F-3 deployment still holds in did_keys. A self-custody subject's key
   * never reaches Helix: it signs its own hops.
   */
  async signerFor(did: string, requestId = 'unspecified'): Promise<Signer> {
    if (did === this.helixSigner.did) return this.helixSigner;
    for (const subjectType of CUSTODIAL_SIGNING_SUBJECTS) {
      const signer = await this.custodialKeys?.signerFor(did, subjectType, { requestId, purpose: 'hop' });
      if (signer) return signer;
    }
    const record = await this.keyRepository.findByDid(did);
    if (record) return new CustodySigner(did, record, this.keyCustody);
    throw new HelixError(ErrorCode.AGENT_KEY_NOT_FOUND, `No key held for ${did}`, 404);
  }

  /** `vcs.subjectDid` is a foreign key onto `dids`: a DID this server has only seen in a credential is registered first. */
  private async ensureSubjectRegistered(did: string, requestId: string): Promise<void> {
    try {
      await this.didService.resolveDID(did, requestId);
    } catch (error: unknown) {
      if (!(error instanceof HelixError) || error.code !== ErrorCode.DID_NOT_FOUND) throw error;
      let resolved: Awaited<ReturnType<typeof resolveDIDCore>>;
      try {
        resolved = await resolveDIDCore(did);
      } catch {
        throw new HelixError(ErrorCode.VC_SUBJECT_DID_NOT_FOUND, 'Subject DID not found', 404);
      }
      await this.didService.registerResolvedDID(did, resolved, 'agent', requestId);
    }
  }

  private async store(
    credential: { id: string; credentialSubject: { id?: string }; validUntil?: string; credentialStatus: BitstringStatusEntry },
    subjectDid: string,
    scopes: string[] | undefined,
    parentVcId: string | undefined,
    requestId: string,
    name: 'issued' | 'registered' | 'reissued' = 'issued',
  ): Promise<void> {
    await this.ensureSubjectRegistered(subjectDid, requestId);
    const index = Number(credential.credentialStatus.statusListIndex);
    const record = credential as unknown as Record<string, unknown>;
    const types = record['type'] as string[];
    await this.vcRepo.createVc({
      vcId: credential.id,
      subjectDid,
      subjectType: 'agent',
      vcJson: credential,
      privilegeScopes: scopes,
      statusListIndex: Number.isInteger(index) ? index : 0,
      expiresAt: credential.validUntil ? new Date(credential.validUntil) : null,
      parentVcId,
      vcType: types.find((type) => type !== 'VerifiableCredential') ?? null,
      issuerDid: record['issuer'] as string,
      userDid: null,
      scopeKey: scopes ? [...new Set(scopes)].sort().join(' ') : null,
    });
    this.auditIssued(credential, subjectDid, name, requestId, parentVcId);
  }

  async issueIdentity(input: IssueIdentityInput, requestId: string): Promise<SignedIdentityCredential> {
    const statusEntry = await this.statusEntry(this.helixSigner.did);
    const identity = await buildIdentityCredential(
      {
        agentDid: input.agentDid,
        name: input.name,
        ownerDid: input.ownerDid,
        statusEntry,
        ...(input.validUntil ? { validUntil: input.validUntil.toISOString() } : {}),
      },
      this.helixSigner,
    );
    await this.store(identity, input.agentDid, undefined, undefined, requestId);
    return identity;
  }

  /**
   * Re-issue an identity credential: same agent, name and responsible party,
   * a fresh id and validity. The old record stays active and points at the
   * new one through `renewedByVcId`. Returns null when `vcId` is not an
   * identity credential, so the caller can fall back to the legacy VC path.
   */
  async renewIdentity(vcId: string, input: RenewIdentityInput, requestId: string): Promise<RenewedIdentity | null> {
    const record = await this.vcRepo.findByVcId(vcId);
    if (!record || record.vcType !== IDENTITY_CREDENTIAL_TYPE) return null;
    if (record.revokedAt) {
      throw new HelixError(ErrorCode.VC_ALREADY_REVOKED, 'Cannot renew a revoked credential', 409);
    }
    const previous = stored<SignedIdentityCredential>(record).credential;
    const validUntil = input.expiresInSeconds
      ? new Date(Date.now() + input.expiresInSeconds * 1000)
      : (record.expiresAt ?? null);
    const identity = await this.issueIdentity(
      {
        agentDid: previous.credentialSubject.id,
        name: previous.credentialSubject.name,
        ownerDid: previous.credentialSubject.responsibleParty,
        validUntil,
      },
      requestId,
    );
    await this.vcRepo.markAsRenewed(vcId, identity.id);
    this.auditIssued(identity, previous.credentialSubject.id, 'renewed', requestId, vcId);
    return {
      vcId: identity.id,
      vc: identity,
      previousVcId: vcId,
      expiresAt: identity.validUntil ?? null,
      statusListIndex: Number(identity.credentialStatus.statusListIndex),
    };
  }

  /** One attestation per capability, signed by `signer` (default the Helix issuer). */
  async issueAttestations(input: IssueAttestationsInput, requestId: string): Promise<SignedCapabilityAttestation[]> {
    const signer = input.signer ?? this.helixSigner;
    const issued: SignedCapabilityAttestation[] = [];
    for (const capability of input.capabilities) {
      const statusEntry = await this.statusEntry(signer.did);
      const attestation = await buildCapabilityAttestation(
        {
          subjectDid: input.agentDid,
          capability,
          validUntil: CredentialService.validUntil(input.validUntil),
          statusEntry,
        },
        signer,
      );
      await this.store(attestation, input.agentDid, [capability], undefined, requestId);
      issued.push(attestation);
    }
    return issued;
  }

  /**
   * An attestation the owner signed through the SDK (self-custody: the key
   * stayed with the owner). Verified against the issuer's DID document
   * before Helix keeps a copy; the subject must be `agentDid`.
   */
  async registerAttestation(agentDid: string, value: unknown, requestId: string): Promise<SignedCapabilityAttestation> {
    const verdict = await verifyCapabilityAttestation(
      value,
      async (did) => (await resolveDIDCore(did)) as unknown as JwsDidDocument,
      { subjectDid: agentDid },
    );
    if (!verdict.ok) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, `attestation refused: ${verdict.reason}: ${verdict.message}`, 400);
    }
    if (await this.vcRepo.findByVcId(verdict.credential.id)) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'attestation already registered', 409);
    }
    await this.store(verdict.credential, agentDid, [verdict.capability], undefined, requestId, 'registered');
    return verdict.credential;
  }

  /**
   * Revokes one credential through the status store (story L3-C: its bit on
   * the issuer's list, and the revocation signal). Revoking an agent's
   * identity credential revokes the agent (Cleanup, Harish's pick A): every
   * active capability attestation of that agent is revoked with it, so no
   * verifier keeps granting its scopes. The agent's card keeps the revoked
   * identity's status entry as its `revocation`. Hops are separate grants and
   * are revoked on their own (`revokeHop`).
   */
  async revokeVC(vcId: string, requestId: string): Promise<{ vcId: string; revoked: true; revokedAt: string }> {
    const record = await this.vcRepo.findByVcId(vcId);
    const result = await this.statusStore.revokeVC(vcId, requestId);
    if (record?.vcType === IDENTITY_CREDENTIAL_TYPE) {
      const attestations = await this.vcRepo.findActiveBySubjectDid(record.subjectDid, CAPABILITY_ATTESTATION_TYPE);
      for (const attestation of attestations) await this.statusStore.revokeVC(attestation.vcId, requestId);
    }
    return result;
  }

  /** Revokes every active attestation of `capability` for the agent through the status list; identity is untouched. */
  async revokeAttestation(agentDid: string, capability: string, requestId: string): Promise<string[]> {
    const active = await this.vcRepo.findActiveBySubjectDid(agentDid, CAPABILITY_ATTESTATION_TYPE);
    const matching = active.filter((record) => stored<SignedCapabilityAttestation>(record).credential.credentialSubject.capability === capability);
    if (matching.length === 0) {
      throw new HelixError(ErrorCode.VC_NOT_FOUND, `No active attestation of ${capability} for ${agentDid}`, 404);
    }
    const revoked: string[] = [];
    for (const record of matching) {
      await this.statusStore.revokeVC(record.vcId, requestId);
      revoked.push(record.vcId);
    }
    return revoked;
  }

  /** The root of a chain: `parentCapability` is the resource itself. Any issuer Helix can sign for may issue it. */
  async issueRootHop(input: IssueRootHopInput, requestId: string): Promise<SignedDelegationHop> {
    const signer = await this.signerFor(input.issuer, requestId);
    const statusEntry = await this.statusEntry(signer.did);
    const hop = await buildDelegationHop(
      rootHopInput({
        invoker: input.invoker,
        invocationTarget: input.invocationTarget,
        allowedAction: input.allowedAction,
        ...(input.caveats === undefined ? {} : { caveats: input.caveats }),
        validUntil: input.validUntil ?? CredentialService.validUntil(undefined),
        statusEntry,
      }),
      signer,
    );
    const evaluation = evaluateDelegationChain([hop]);
    if (!evaluation.ok) {
      throw new HelixError(ErrorCode.DELEGATION_CHAIN_INVALID, evaluation.reasons.join('; '), 400);
    }
    await this.store(hop, input.invoker, [...input.allowedAction], undefined, requestId);
    return hop;
  }

  /** The chain a stored hop sits on, root to leaf, by following `parentVcId`. */
  async chainOf(hopId: string): Promise<SignedDelegationHop[]> {
    const chain: SignedDelegationHop[] = [];
    let current = await this.vcRepo.findByVcId(hopId);
    while (current) {
      if (chain.length >= 10) {
        throw new HelixError(ErrorCode.DELEGATION_CHAIN_INVALID, 'stored chain exceeds the maximum depth', 400);
      }
      chain.unshift(stored<SignedDelegationHop>(current).credential);
      current = current.parentVcId ? await this.vcRepo.findByVcId(current.parentVcId) : null;
    }
    return chain;
  }

  /**
   * A child hop under the stored hop `parentId`, signed by the parent's
   * invoker (continuity: you may only re-delegate what was delegated to your
   * key), refused before signing when it would not attenuate the chain.
   */
  async issueHop(parentId: string, input: IssueHopInput, requestId: string): Promise<{ hop: SignedDelegationHop; chain: SignedDelegationHop[] }> {
    const parentRecord = await this.vcRepo.findByVcId(parentId);
    if (!parentRecord || parentRecord.vcType !== DELEGATION_CREDENTIAL_TYPE) {
      throw new HelixError(ErrorCode.DELEGATION_PARENT_VC_NOT_FOUND, `No delegation hop ${parentId}`, 404);
    }
    if (statusOf(parentRecord) !== 'active') {
      throw new HelixError(ErrorCode.DELEGATION_CHAIN_INVALID, `Delegation hop ${parentId} is ${statusOf(parentRecord)}`, 400);
    }
    const parentChain = await this.chainOf(parentId);
    const parent = parentChain[parentChain.length - 1]!;
    const delegate = parent.credentialSubject.invoker ?? parent.credentialSubject.controller!;
    const signer = await this.signerFor(delegate, requestId);
    const statusEntry = await this.statusEntry(signer.did);
    const hop = await buildDelegationHop(
      {
        invoker: input.invoker,
        parentCapability: parent.credentialSubject.id,
        invocationTarget: parent.credentialSubject.invocationTarget,
        allowedAction: input.allowedAction,
        ...(input.caveats === undefined ? {} : { caveats: input.caveats }),
        validUntil: input.validUntil ?? parent.validUntil,
        statusEntry,
      },
      signer,
    );
    const chain = [...parentChain, hop];
    const evaluation = evaluateDelegationChain(chain);
    if (!evaluation.ok) {
      throw new HelixError(ErrorCode.DELEGATION_CHAIN_INVALID, evaluation.reasons.join('; '), 400);
    }
    await this.store(hop, input.invoker, [...input.allowedAction], parentId, requestId);
    return { hop, chain };
  }

  /** Revokes a hop and, cascading (SPEC.md §6.5), every active hop below it. */
  async revokeHop(hopId: string, requestId: string): Promise<string[]> {
    const record = await this.vcRepo.findByVcId(hopId);
    if (!record || record.vcType !== DELEGATION_CREDENTIAL_TYPE) {
      throw new HelixError(ErrorCode.VC_NOT_FOUND, `No delegation hop ${hopId}`, 404);
    }
    // The hop first, then every active descendant, parents before children.
    const order: string[] = [];
    const walk = async (id: string): Promise<void> => {
      const current = await this.vcRepo.findByVcId(id);
      if (current && !current.revokedAt) order.push(id);
      for (const child of await this.vcRepo.findActiveChildren(id)) await walk(child.vcId);
    };
    await walk(hopId);
    if (order.length === 0) return [];
    if (this.statusStore.revokeMany !== undefined) {
      // One transaction for the whole cascade (story L3-C point 5).
      await this.statusStore.revokeMany(order, { requestId });
      return order;
    }
    for (const id of order) await this.statusStore.revokeVC(id, requestId);
    return order;
  }

  /** Story C-E point 5: a fresh identity credential for the same agent after a key compromise; its id, or null for a non-identity. */
  async reissueIdentity(input: { vcId: string }, requestId: string): Promise<string | null> {
    return (await this.renewIdentity(input.vcId, {}, requestId))?.vcId ?? null;
  }

  /** The active hops delegated to `did` while the key of `bound` was current, oldest first. */
  private async hopsBoundTo(did: string, bound: BoundWindow | undefined): Promise<VCRecord[]> {
    const hops = await this.vcRepo.findActiveBySubjectDid(did, DELEGATION_CREDENTIAL_TYPE);
    return hops
      .filter((record) => issuedIn(record, bound) && invokerOf(stored<SignedDelegationHop>(record).credential) === did)
      .sort((a, b) => (a.createdAt?.getTime() ?? 0) - (b.createdAt?.getTime() ?? 0));
  }

  /**
   * Story C-E point 4: the agent's leaf hops bound to its old key, reissued
   * by their issuers bound to the new one: same parent, target, actions,
   * caveats and window, a new id and status entry. Hops with hops below them
   * stay as they are (the agent signed those children with a key that stays
   * valid for what it signed). A hop whose issuer holds its own key is
   * reported for that issuer's SDK to reissue.
   */
  async reissueHopsForKid(input: HopReissueInput): Promise<HopReissueResult> {
    const reissuedHops: Record<string, string> = {};
    const pendingIssuers: PendingIssuerHop[] = [];
    for (const record of await this.hopsBoundTo(input.did, input.bound)) {
      if ((await this.vcRepo.findActiveChildren(record.vcId)).length > 0) continue;
      const hop = stored<SignedDelegationHop>(record).credential;
      let signer: Signer;
      try {
        signer = await this.signerFor(hop.issuer, input.requestId);
      } catch {
        pendingIssuers.push({ hopId: hop.id, issuer: hop.issuer });
        continue;
      }
      const subject = hop.credentialSubject;
      const fresh = await buildDelegationHop(
        {
          invoker: input.did,
          parentCapability: subject.parentCapability,
          invocationTarget: subject.invocationTarget,
          allowedAction: subject.allowedAction,
          ...(subject.caveats === undefined ? {} : { caveats: subject.caveats }),
          ...(hop.validFrom === undefined ? {} : { validFrom: hop.validFrom }),
          validUntil: hop.validUntil,
          statusEntry: await this.statusEntry(signer.did),
        },
        signer,
      );
      await this.store(fresh, input.did, [...subject.allowedAction], record.parentVcId ?? undefined, input.requestId, 'reissued');
      reissuedHops[hop.id] = fresh.id;
    }
    return { reissued: Object.keys(reissuedHops).length, pending: false, reissuedHops, pendingIssuers };
  }

  /**
   * Story C-E point 4: the overlap of `kid` ended, so the hops bound to it
   * that were reissued for the new key expire (revoked through the status
   * lists). A hop with no reissued twin (one that has hops below it, or
   * whose issuer has not reissued it yet) runs to its own `validUntil`.
   */
  async expireHopsForKid(input: KidHopsInput): Promise<string[]> {
    const ended = input.bound?.until;
    if (!ended) return [];
    const bound = await this.hopsBoundTo(input.did, input.bound);
    if (bound.length === 0) return [];
    const later = await this.hopsBoundTo(input.did, { from: ended, until: null });
    const successors = new Set(later.map((record) => grantOf(stored<SignedDelegationHop>(record).credential)));
    const expired: string[] = [];
    for (const record of bound) {
      if (!successors.has(grantOf(stored<SignedDelegationHop>(record).credential))) continue;
      if ((await this.vcRepo.findActiveChildren(record.vcId)).length > 0) continue;
      expired.push(...(await this.revokeHop(record.vcId, input.requestId)));
    }
    return expired;
  }

  /** Story C-E point 5: `kid` is compromised, so every hop bound to it is revoked with every hop below it (L3-C cascade). */
  async revokeHopsForKid(input: KidHopsInput): Promise<string[]> {
    const revoked: string[] = [];
    for (const record of await this.hopsBoundTo(input.did, input.bound)) {
      if (revoked.includes(record.vcId)) continue;
      revoked.push(...(await this.revokeHop(record.vcId, input.requestId)));
    }
    return revoked;
  }

  /** Everything Helix keeps for one agent, in issuance order; the active identity not yet renewed, else the latest. */
  async listAgentCredentials(agentDid: string): Promise<AgentCredentials> {
    const records = [...(await this.vcRepo.findMany({ subjectDid: agentDid }))].sort(
      (a, b) => (a.createdAt?.getTime() ?? 0) - (b.createdAt?.getTime() ?? 0) || a.vcId.localeCompare(b.vcId),
    );
    const identityRecords = records.filter((record) => record.vcType === IDENTITY_CREDENTIAL_TYPE);
    const identities = identityRecords.map((record) => stored<SignedIdentityCredential>(record));
    // A renewed identity points at its successor, so the head of the lineage is the active one nobody renewed.
    const current = identities.find((identity, index) => identity.status === 'active' && !identityRecords[index]!.renewedByVcId);
    const activeIdentities = identities.filter((identity) => identity.status === 'active');
    return {
      agentDid,
      identity: current ?? activeIdentities[activeIdentities.length - 1] ?? identities[identities.length - 1] ?? null,
      attestations: records
        .filter((record) => record.vcType === CAPABILITY_ATTESTATION_TYPE)
        .map((record) => stored<SignedCapabilityAttestation>(record)),
      hops: records
        .filter((record) => record.vcType === DELEGATION_CREDENTIAL_TYPE)
        .map((record) => stored<SignedDelegationHop>(record)),
    };
  }
}
