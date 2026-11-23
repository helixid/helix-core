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
 * Custody preference at onboarding (KYA-OS story F-3).
 *
 * Every agent, service and owner gets two independent choices, resolved from
 * a per-subject override, the account preference, or the built-in default
 * (self-custody, Helix hosting):
 *
 *   keyCustody  self   the key is generated and held client side; Helix only
 *                      ever sees the public JWK (self-custody invariant);
 *               helix  Helix generates the key in its KeyStore and signs on
 *                      the account's behalf through `sign()`, audited;
 *   didHosting  own    a did:web on the owner's domain; the subject activates
 *                      only once the documents resolve from there (SafeFetch);
 *               helix  a did:web under the Helix domain, served by Helix
 *                      (story C-A's routes).
 *
 * Self-custody onboarding is two calls with an enrollment token
 * (`enrollmentChallenge`, `enroll`), driven by `helix init` in the SDK, with
 * a proof of possession of the new key. Full custodial onboarding is one
 * call. Changing custody is a rotation (point 6): a new key in the new
 * place, both keys in the DID document during the overlap, the hop-reissue
 * seam called, the old key revoked at the end of the overlap and, when it
 * was Helix-held, shredded through the KeyStore at once, so Helix never
 * holds a key for a self-custody subject.
 *
 * Helix's database holds no private key for a self-custody subject: none is
 * ever sent, and the KeyStore is only asked to generate for `helix` custody.
 */

import { randomBytes } from 'node:crypto';
import {
  CustodialSigningRefusedError,
  CustodyStateInvalidError,
  CustodySubjectNotFoundError,
  DidDocumentUnresolvedError,
  EnrollmentProofInvalidError,
  ErrorCode,
  HelixError,
  ValidationError,
  base64UrlDecodeStrict,
  base64UrlEncode,
  buildDidDocument,
  buildEntityCard,
  cardEndpointOf,
  custodyLabel,
  didKeyFromPublicKey,
  didWebCardUrl,
  didWebDocumentUrl,
  issueDidWeb,
  ownDidWebProblem,
  type HelixDidKind,
  enrollmentProofMessage,
  evictDIDCache,
  findScopeProblem,
  getOutboundFetch,
  isConformantCustody,
  KeyStoreSigner,
  isCustodySubjectType,
  isKeyCustodyMode,
  parseDidWeb,
  parseEntityCard,
  parseScopes,
  publicKeyJwkBytes,
  publicKeyToMultibaseOf,
  resolveCustodyChoice,
  rotationProofFresh,
  rotationProofMessage,
  sameDid,
  verificationMethodId,
  verifyProofOfPossession,
  versionDidDocument,
  type AgentDidDocument,
  type DocumentKey,
  type CustodyDefaults,
  type CustodyLabel,
  type CustodySubjectType,
  type DidHostingMode,
  type EntityCard,
  type EntityType,
  type KeyCustodyMode,
  type KeyStore,
  type OutboundFetch,
  type PublicKeyJwk,
  type ConformanceSubject,
  type Signer,
} from '../../core/index.js';
import type { AuditTrail } from '../../core/index.js';
import type {
  CustodyKeyRow,
  CustodyRecordFilter,
  CustodyRecordPatch,
  CustodyRecordRow,
  CustodyStatus,
  NewCustodyKey,
  NewCustodyRecord,
} from '../../repositories/custody.repository.js';
import type { ServiceCreateData, ServiceRecord } from '../../repositories/service.repository.js';
import { hashToken, normalizeDomain } from '../agent/agent.service.js';
import { generateServiceId } from '../service-provider/service-provider.service.js';
import { hostedUrls } from '../../routes/entity-card/index.js';
import { CustodyAudit, type CustodyActor, type CustodyFactsSink } from './custody-audit.js';
import { pendingHopReissuer, type BoundWindow, type HopReissueResult, type HopReissuer } from './hop-reissue.js';
import type { CustodialKeys, CustodialSigningSubject, CustodialSigningUse } from './custodial-keys.js';
import type { EntityCardDetails } from '../entity-card/entity-card.source.js';

export const DEFAULT_ENROLLMENT_TTL_SECONDS = 24 * 60 * 60;
export const DEFAULT_ROTATION_OVERLAP_SECONDS = 24 * 60 * 60;
export const MAX_SIGN_PAYLOAD_BYTES = 64 * 1024;
export const CUSTODY_DID_UPDATE_TYPE = 'custody_rotation';
/** The bound the agent-create route's enrollment token documented for `maxDelegationDepth`. */
export const MAX_DELEGATION_DEPTH_LIMIT = 5;

/** What the service needs from the custody tables; `CustodyRepository` is the production one. */
export interface CustodyRecords {
  createRecord(row: NewCustodyRecord): Promise<CustodyRecordRow>;
  findRecord(did: string): Promise<CustodyRecordRow | null>;
  findRecordByEnrollmentToken(tokenHash: string): Promise<CustodyRecordRow | null>;
  updateRecord(did: string, patch: CustodyRecordPatch): Promise<CustodyRecordRow>;
  claimEnrollment(did: string, at: Date): Promise<boolean>;
  transitionStatus(did: string, from: CustodyStatus, patch: CustodyRecordPatch): Promise<CustodyRecordRow | null>;
  listDueRechecks(now: Date, limit: number): Promise<CustodyRecordRow[]>;
  claimRecheck(did: string, expected: Date, next: { nextRecheckAt: Date | null; recheckAttempts: number }): Promise<boolean>;
  listRecords(filter?: CustodyRecordFilter): Promise<CustodyRecordRow[]>;
  addKey(row: NewCustodyKey): Promise<CustodyKeyRow>;
  listKeys(did: string): Promise<CustodyKeyRow[]>;
  /** Story C-E: subjects with a retiring key whose overlap ended by `now`. */
  listRetiringDue?(now: Date, limit: number): Promise<string[]>;
  updateKey(did: string, kid: string, patch: Partial<Pick<CustodyKeyRow, 'status' | 'retiresAt' | 'revokedAt'>>): Promise<CustodyKeyRow>;
}

export interface CustodyDidRecords {
  createDid(data: {
    id: string;
    subjectType: string;
    controller: string;
    publicKey: string;
    publicKeyMultibase?: string | undefined;
    hederaTransactionId: string;
    didDocument: unknown;
  }): Promise<unknown>;
  findDidById(did: string): Promise<{ didDocument: unknown; deactivatedAt?: Date | null } | null>;
  updateDidDocument(did: string, didDocument: unknown, update: { updateType: string; hederaTransactionId: string; payload: unknown }): Promise<unknown>;
}

/**
 * Credential issuance for custody agents: story F-1's identity credential and
 * one capability attestation per scope, as every agent gets them
 * (CredentialService implements this). Key custody and DID hosting are not
 * in the credential: they stay in the custody record, where the conformance
 * report and the `custody: helix` label read them.
 */
export interface CustodyCredentials {
  /** The responsible party of record when an agent names no owner (the Helix issuer). */
  readonly issuerDid: string;
  issueIdentity(input: { agentDid: string; name: string; ownerDid: string }, requestId: string): Promise<{ id: string }>;
  issueAttestations(input: { agentDid: string; capabilities: readonly string[] }, requestId: string): Promise<readonly { id: string }[]>;
  /**
   * Story C-E point 5: a fresh identity credential for the same agent after a
   * key compromise, so the card's backing credential and revocation entry are
   * new; resolves to its id, or null when `vcId` is not an identity.
   */
  reissueIdentity?(vcId: string, requestId: string): Promise<string | null>;
}

export interface CustodyServices {
  create(data: ServiceCreateData): Promise<ServiceRecord>;
  findByName(name: string): Promise<ServiceRecord | null>;
  findByDid(did: string): Promise<ServiceRecord | null>;
}

export interface CustodyServiceOptions {
  records: CustodyRecords;
  keyStore: KeyStore;
  didRepository: CustodyDidRecords;
  credentials: CustodyCredentials;
  services?: CustodyServices | undefined;
  /** Story A-1's typed audit trail; custody events are recorded through `CustodyAudit`. */
  auditTrail: AuditTrail;
  /** Keeps each custody event's committed facts beside it (story F-4 point 6); see `CustodyFactsSink`. */
  auditFacts?: CustodyFactsSink | undefined;
  hopReissuer?: HopReissuer | undefined;
  /** `DID_DOMAIN`: the raw Helix did:web host (`host[:port]`, not percent-encoded). Needed for `helix` hosting. */
  host: string;
  /**
   * What an agent's credentials put on its card (F-3 parity): its
   * attestations, responsible party and revocation entry, as the hosted card
   * route publishes them (`credentialCardDetails`). With it, an active
   * agent's documents carry them too, so an owner hosting its own did:web
   * republishes a card that says the same.
   */
  credentialDetails?: ((did: string, subjectType: string) => Promise<EntityCardDetails | undefined>) | undefined;
  /** The origin Helix-hosted documents are reachable at, when it is not `https://<host>`. */
  publicOrigin?: string | undefined;
  /** The DID service's document cache, dropped when a document changes. */
  didCache?: { delete(did: string): Promise<unknown> | unknown } | undefined;
  /** Where own-hosted documents are read from; default the SafeFetch seam of story C-A. */
  outboundFetch?: (() => OutboundFetch) | undefined;
  enrollmentTtlSeconds?: number | undefined;
  rotationOverlapSeconds?: number | undefined;
  /** The background re-check of own-hosted subjects waiting for their documents; see `recheckPending`. */
  recheck?: { [K in keyof CustodyRecheckSettings]?: number | undefined } | undefined;
  clock?: (() => Date) | undefined;
}

/**
 * The background re-check's schedule (config `CUSTODY_RECHECK_*`): the first
 * check `initialIntervalSeconds` after the subject starts waiting, each next
 * one twice as long after the last, at most `maxIntervalSeconds`; none once
 * the subject waited `giveUpAfterSeconds` (manual activation still works).
 * At most `batchSize` subjects per run, and one per owner host.
 */
export interface CustodyRecheckSettings {
  initialIntervalSeconds: number;
  maxIntervalSeconds: number;
  giveUpAfterSeconds: number;
  batchSize: number;
}

export const DEFAULT_RECHECK_SETTINGS: CustodyRecheckSettings = {
  initialIntervalSeconds: 120,
  maxIntervalSeconds: 3600,
  giveUpAfterSeconds: 3 * 24 * 3600,
  batchSize: 20,
};

/** What one background re-check run did. */
export interface CustodyRecheckRun {
  /** Subjects whose documents were read this run. */
  checked: string[];
  activated: OnboardingResult[];
  /** Subjects whose re-checks stopped this run: they waited `giveUpAfterSeconds`. */
  stopped: string[];
  /** Due subjects left for the next run: another instance claimed them, or their host was already checked this run. */
  deferred: string[];
}

/** The actor of activations the background re-check makes. */
export const RECHECK_ACTOR = 'system';

/** Per-call context the route supplies. */
export interface CustodyContext {
  requestId: string;
  actor: CustodyActor;
  /** The account preference, when the caller belongs to an account that has one. */
  defaults?: CustodyDefaults | undefined;
  /**
   * The caller's own DID when it acts for an account (F-3 follow-up, Harish
   * 2026-11-23): an agent it creates names it as owner, so the identity
   * credential's and the card's `responsibleParty` is the account, and the
   * account roots the agent's delegation chains (`responsibleParty ===
   * issuer(root)`). An `ownerDid` in the request must be this DID.
   */
  owner?: string | undefined;
}

interface ChoiceInput {
  keyCustody?: unknown;
  didHosting?: unknown;
  /** The owner's did:web, for `own` hosting. */
  did?: unknown;
}

export interface CreateAgentInput extends ChoiceInput {
  name: string;
  scopes?: string[] | undefined;
  /**
   * Domains the agent will call: bare hosts or http(s) URLs, normalized to
   * `https://<host>` for a bare host and published in the agent's DID document
   * as `#domain-N` LinkedDomains service entries, as the agent-create route did.
   */
  requestedDomains?: string[] | undefined;
  /** How deep the agent may delegate: a whole number from 0 (the default) to 5, written on its identity credential. */
  maxDelegationDepth?: number | undefined;
  ownerDid?: string | undefined;
  /** Enrollment token lifetime in whole days (self-custody). Default one day. */
  expiry?: number | undefined;
}

export interface CreateServiceInput extends ChoiceInput {
  name: string;
  domain: string;
  requiredScopes: string[];
  description?: string | undefined;
  framework?: string | undefined;
  /** Self-custody: the public half of the service's key (its middleware holds the private half). */
  publicKeyJwk?: unknown;
  kid?: string | undefined;
}

export interface CreateOwnerInput extends ChoiceInput {
  name: string;
  entityType?: EntityType | undefined;
  publicKeyJwk?: unknown;
  kid?: string | undefined;
}

export interface CustodyKeyView {
  kid: string;
  location: 'self' | 'helix';
  status: 'active' | 'retiring' | 'retired' | 'revoked';
  createdAt: string;
  retiresAt: string | null;
  revokedAt: string | null;
}

export interface CustodyView {
  did: string;
  subjectType: CustodySubjectType;
  name: string | null;
  keyCustody: KeyCustodyMode;
  didHosting: DidHostingMode;
  label: CustodyLabel;
  /** False for `custody: helix`: excluded from every conformance claim (SPEC §4.5). */
  conformant: boolean;
  status: CustodyRecordRow['status'];
  kid: string | null;
  credentialVcId: string | null;
  keys: CustodyKeyView[];
}

export interface PublishedDocuments {
  didDocument: AgentDidDocument;
  card: EntityCard;
  didDocumentUrl: string;
  cardUrl: string;
}

export interface OnboardingResult extends CustodyView {
  /** Self-custody only, returned once: what `helix init` takes. */
  enrollmentToken?: string;
  enrollmentExpiresAt?: string;
  /** Once a key exists: the documents, served by Helix (`helix` hosting) or to publish on the owner's domain (`own`). */
  documents?: PublishedDocuments;
  /** `own` hosting: the documents must be published at the owner's domain, then `activate`. */
  publishRequired?: boolean;
  vcId?: string;
  service?: ServiceRecord;
}

export interface EnrollmentChallenge {
  did: string;
  kid: string;
  nonce: string;
  keyCustody: 'self';
  didHosting: DidHostingMode;
  name: string | null;
  didDocumentUrl: string;
  cardUrl: string;
}

export interface SignResult {
  did: string;
  kid: string;
  alg: 'EdDSA';
  signature: string;
}

export interface ChangeCustodyInput {
  keyCustody: unknown;
  /** Target `self`: the new public key, never the private one. */
  publicKeyJwk?: unknown;
  /** Target `self`: the fragment for the new key; default the next `key-<n>`. */
  kid?: string | undefined;
  /** Target `self`: proof of possession, the new key's signature over `rotationProofMessage`. */
  proof?: { issuedAt?: unknown; signature?: unknown } | undefined;
  /** How long both keys stay in the DID document. 0 ends the overlap at once. */
  overlapSeconds?: number | undefined;
}

/** Story C-E: a rotation, in place (no `keyCustody`, or the current one) or into the other custody. */
export interface RotateKeyInput extends Omit<ChangeCustodyInput, 'keyCustody'> {
  keyCustody?: unknown;
  /** SDK `rotateKey()`: the current key's signature over the same rotation message (base64url). */
  currentKeyProof?: { signature?: unknown } | undefined;
}

export interface RevokeKeyResult extends CustodyView {
  revokedKid: string;
  /** Delegation hops bound to the revoked kid, revoked with their descendants. */
  revokedHops: string[];
  rotationSequence: number;
  documents: PublishedDocuments;
}

export interface ChangeCustodyResult extends CustodyView {
  previousKid: string;
  /** The DID document's version after the rotation (story C-E point 2). */
  rotationSequence: number;
  previousKeyShredded: boolean;
  retiresAt: string;
  hopReissue: HopReissueResult;
  documents: PublishedDocuments;
  publishRequired: boolean;
}

/**
 * `requestedDomains` as the agent-create route took it: an array of bare
 * hosts or http(s) URLs, each normalized the same way; anything else is
 * INVALID_SERVICE_ENDPOINT_URL. Null when none were given.
 */
function readRequestedDomains(value: unknown): string[] | null {
  if (value === undefined) return null;
  if (!Array.isArray(value)) throw new ValidationError('requestedDomains must be an array of domains');
  const domains: string[] = [];
  for (const domain of value) {
    const normalized = typeof domain === 'string' ? normalizeDomain(domain) : null;
    if (!normalized) throw new HelixError(ErrorCode.INVALID_SERVICE_ENDPOINT_URL, 'Invalid domain URL', 400);
    domains.push(normalized);
  }
  return domains.length > 0 ? domains : null;
}

function readMaxDelegationDepth(value: unknown): number {
  if (value === undefined) return 0;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > MAX_DELEGATION_DEPTH_LIMIT) {
    throw new ValidationError(`maxDelegationDepth must be a whole number from 0 to ${MAX_DELEGATION_DEPTH_LIMIT}`);
  }
  return value;
}

/** The DID document's `#domain-N` LinkedDomains entries, as DIDService.createDID writes them. */
function domainServices(domains: readonly string[] | null): { id: string; type: 'LinkedDomains'; serviceEndpoint: string }[] {
  return (domains ?? []).map((serviceEndpoint, index) => ({ id: `#domain-${index + 1}`, type: 'LinkedDomains', serviceEndpoint }));
}

function entityTypeOf(subjectType: CustodySubjectType, owner?: EntityType): EntityType {
  if (subjectType === 'agent') return 'agent';
  if (subjectType === 'service') return 'mcp';
  return owner ?? 'verifier';
}

function iso(value: Date | null): string | null {
  return value ? value.toISOString() : null;
}

function nextFragment(keys: CustodyKeyRow[]): { fragment: string; sequence: number } {
  const sequence = keys.reduce((max, key) => Math.max(max, key.sequence), 0) + 1;
  return { fragment: `key-${sequence}`, sequence };
}

/**
 * Story C-E point 2: the version of a subject's DID document, derived from
 * its keys so it can only grow: one step per key added and one per key
 * revoked (the two changes that alter the document's key set); `updated`
 * is the latest of those instants.
 */
export function documentVersion(keys: readonly CustodyKeyRow[]): { rotationSequence: number; updated: string } {
  let latest = 0;
  for (const key of keys) {
    latest = Math.max(latest, key.createdAt.getTime(), key.status === 'revoked' && key.revokedAt ? key.revokedAt.getTime() : 0);
  }
  const revoked = keys.filter((key) => key.status === 'revoked').length;
  return { rotationSequence: Math.max(1, keys.length + revoked), updated: new Date(latest || Date.now()).toISOString() };
}

/** When `kid` was current: from its creation until the next key's (story C-E: the hops issued then are bound to it). */
export function boundWindow(keys: readonly CustodyKeyRow[], kid: string): BoundWindow | undefined {
  const key = keys.find((candidate) => candidate.kid === kid);
  if (!key) return undefined;
  const next = keys.filter((candidate) => candidate.sequence > key.sequence).sort((a, b) => a.sequence - b.sequence)[0];
  return { from: key.createdAt, until: next ? next.createdAt : null };
}

/**
 * The keys of the document, current first: a superseded key with
 * `validUntil` (the end of its overlap), a compromised one also with
 * `revoked`.
 */
function documentKeys(keys: readonly CustodyKeyRow[], currentKid: string | null): DocumentKey[] {
  const ordered = [...keys.filter((key) => key.kid === currentKid), ...keys.filter((key) => key.kid !== currentKid)];
  return ordered.map((key) => ({
    kid: key.kid,
    publicKeyJwk: key.publicKeyJwk,
    ...(key.kid !== currentKid && key.retiresAt ? { validUntil: key.retiresAt.toISOString() } : {}),
    ...(key.status === 'revoked' && key.revokedAt ? { revoked: key.revokedAt.toISOString() } : {}),
  }));
}

function definedOnly<T extends object>(value: T): { [K in keyof T]?: Exclude<T[K], undefined> } {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined)) as { [K in keyof T]?: Exclude<T[K], undefined> };
}

/** The host a did:web's documents are read from: re-checks read one subject per host per run. */
function hostOf(did: string): string {
  try {
    return new URL(didWebDocumentUrl(did)).host;
  } catch {
    return did;
  }
}

export class CustodyService implements CustodialKeys {
  private readonly audit: CustodyAudit;
  private readonly hopReissuer: HopReissuer;
  private readonly clock: () => Date;
  private readonly outboundFetch: () => OutboundFetch;
  private readonly recheckSettings: CustodyRecheckSettings;

  constructor(private readonly options: CustodyServiceOptions) {
    this.recheckSettings = { ...DEFAULT_RECHECK_SETTINGS, ...definedOnly(options.recheck ?? {}) };
    this.audit = new CustodyAudit(options.auditTrail, options.auditFacts);
    this.hopReissuer = options.hopReissuer ?? pendingHopReissuer;
    this.clock = options.clock ?? ((): Date => new Date());
    this.outboundFetch = options.outboundFetch ?? getOutboundFetch;
  }

  // ------------------------------------------------------------------ agents

  /**
   * Point 3 (custodial, one call) and the first half of point 2
   * (self-custody: a pending agent and its enrollment token).
   */
  async createAgent(input: CreateAgentInput, context: CustodyContext): Promise<OnboardingResult> {
    const name = typeof input?.name === 'string' ? input.name.trim() : '';
    if (!name) throw new ValidationError('name is required');
    const scopes = Array.isArray(input.scopes) ? parseScopes(input.scopes) : [];
    const scopeProblem = input.scopes === undefined || Array.isArray(input.scopes) ? findScopeProblem(scopes) : 'scopes must be an array';
    if (scopeProblem) throw new HelixError(ErrorCode.VC_INVALID_PRIVILEGE_SCOPE, `Invalid scopes: ${scopeProblem}`, 400);
    if (input.ownerDid !== undefined && (typeof input.ownerDid !== 'string' || !input.ownerDid.startsWith('did:'))) {
      throw new ValidationError('ownerDid must be a DID');
    }
    if (context.owner !== undefined && input.ownerDid !== undefined && input.ownerDid !== context.owner) {
      throw new ValidationError("ownerDid must be your account's DID: an agent answers to the account that creates it");
    }
    const ownerDid = context.owner ?? (input.ownerDid as string | undefined);
    if (input.expiry !== undefined && !(Number.isInteger(input.expiry) && input.expiry > 0)) {
      throw new ValidationError('expiry must be a positive whole number of days');
    }
    const requestedDomains = readRequestedDomains(input.requestedDomains);
    const maxDelegationDepth = readMaxDelegationDepth(input.maxDelegationDepth);
    const choice = resolveCustodyChoice({ keyCustody: input.keyCustody, didHosting: input.didHosting }, context.defaults);
    const did = await this.subjectDid(choice.didHosting, input.did, 'agents');
    const base: NewCustodyRecord = {
      did,
      subjectType: 'agent',
      keyCustody: choice.keyCustody,
      didHosting: choice.didHosting,
      status: 'pending_key',
      kid: null,
      name,
      ownerDid: ownerDid ?? null,
      scopes,
      requestedDomains,
      maxDelegationDepth,
      enrollmentTokenHash: null,
      enrollmentExpiresAt: null,
      enrollmentNonce: null,
      enrollmentUsedAt: null,
      credentialVcId: null,
      activatedAt: null,
    };

    if (choice.keyCustody === 'self') {
      const token = `enroll:${randomBytes(24).toString('hex')}`;
      const ttlSeconds = input.expiry !== undefined ? input.expiry * 86_400 : this.options.enrollmentTtlSeconds ?? DEFAULT_ENROLLMENT_TTL_SECONDS;
      const expiresAt = new Date(this.clock().getTime() + ttlSeconds * 1000);
      const record = await this.options.records.createRecord({ ...base, enrollmentTokenHash: hashToken(token), enrollmentExpiresAt: expiresAt });
      this.audit.chosen({ requestId: context.requestId, actor: context.actor, subjectType: 'agent', did, keyCustody: choice.keyCustody, didHosting: choice.didHosting, source: choice.source });
      return { ...(await this.view(record)), enrollmentToken: token, enrollmentExpiresAt: expiresAt.toISOString() };
    }

    const kid = verificationMethodId(did, 'key-1');
    const publicKeyJwk = await this.options.keyStore.generate({ did, kid, subjectType: 'agent' });
    await this.options.records.createRecord({ ...base, kid });
    this.audit.chosen({ requestId: context.requestId, actor: context.actor, subjectType: 'agent', did, keyCustody: choice.keyCustody, didHosting: choice.didHosting, source: choice.source });
    return this.registerKey(did, kid, publicKeyJwk, 'helix', context);
  }

  /** Point 2, `helix init` step 1: the DID and kid to generate for, and the nonce to sign. */
  async enrollmentChallenge(enrollmentToken: unknown): Promise<EnrollmentChallenge> {
    const record = await this.pendingEnrollment(enrollmentToken);
    const nonce = randomBytes(32).toString('hex');
    await this.options.records.updateRecord(record.did, { enrollmentNonce: nonce });
    const urls = this.urlsFor(record.did, record.didHosting);
    return {
      did: record.did,
      kid: verificationMethodId(record.did, 'key-1'),
      nonce,
      keyCustody: 'self',
      didHosting: record.didHosting,
      name: record.name,
      didDocumentUrl: urls.didDocument,
      cardUrl: urls.card,
    };
  }

  /**
   * Point 2, `helix init` step 2: the public JWK and a proof of possession.
   * The request carries no private material (the route refuses any), and
   * nothing is generated here: Helix holds no private key for this agent.
   */
  async enroll(
    input: { enrollmentToken: unknown; publicKeyJwk: unknown; kid?: unknown; signature: unknown },
    context: CustodyContext,
  ): Promise<OnboardingResult> {
    const record = await this.pendingEnrollment(input.enrollmentToken);
    if (!record.enrollmentNonce) {
      throw new CustodyStateInvalidError('Ask for the enrollment challenge first (POST /v1/agents/enroll/challenge)');
    }
    if (input.kid !== undefined && typeof input.kid !== 'string') throw new ValidationError('kid must be a string');
    const kid = verificationMethodId(record.did, (input.kid as string | undefined) ?? 'key-1');
    const publicKey = publicKeyJwkBytes(input.publicKeyJwk);
    if (!verifyProofOfPossession(enrollmentProofMessage({ did: record.did, kid, nonce: record.enrollmentNonce }), input.signature, publicKey)) {
      throw new EnrollmentProofInvalidError('The enrollment proof is not the new key\'s signature over the challenge');
    }
    if (!(await this.options.records.claimEnrollment(record.did, this.clock()))) {
      throw new CustodyStateInvalidError('The enrollment token was already used');
    }
    await this.options.records.updateRecord(record.did, { kid, enrollmentNonce: null });
    const publicKeyJwk: PublicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: base64UrlEncode(publicKey) };
    return this.registerKey(record.did, kid, publicKeyJwk, 'self', context);
  }

  // ---------------------------------------------------------------- services

  /** `POST /v1/services` with a custody choice: the per-service override of point 1. */
  async createService(input: CreateServiceInput, context: CustodyContext): Promise<OnboardingResult> {
    if (!this.options.services) throw new HelixError(ErrorCode.INTERNAL_ERROR, 'Service records are not configured', 503);
    const name = typeof input?.name === 'string' ? input.name.trim() : '';
    const domain = typeof input?.domain === 'string' ? input.domain.trim() : '';
    const requiredScopes = Array.isArray(input?.requiredScopes) ? parseScopes(input.requiredScopes) : [];
    if (!name || !domain || requiredScopes.length === 0) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'name, domain and requiredScopes are required', 400);
    }
    const scopeProblem = findScopeProblem(requiredScopes);
    if (scopeProblem) throw new HelixError(ErrorCode.VALIDATION_ERROR, `requiredScopes: ${scopeProblem}`, 400);
    if (await this.options.services.findByName(name)) {
      throw new HelixError(ErrorCode.SERVICE_ALREADY_EXISTS, `Service already enrolled: ${name}`, 409);
    }
    const choice = resolveCustodyChoice({ keyCustody: input.keyCustody, didHosting: input.didHosting }, context.defaults);
    const clientKey = this.clientKey(choice.keyCustody, input.publicKeyJwk);
    const did = await this.subjectDid(choice.didHosting, input.did, 'services');
    const kid = verificationMethodId(did, input.kid ?? 'key-1');
    const publicKeyJwk = clientKey ?? (await this.options.keyStore.generate({ did, kid, subjectType: 'service' }));
    await this.options.records.createRecord(this.newRecord(did, 'service', choice.keyCustody, choice.didHosting, name, kid));
    this.audit.chosen({ requestId: context.requestId, actor: context.actor, subjectType: 'service', did, keyCustody: choice.keyCustody, didHosting: choice.didHosting, source: choice.source });
    const result = await this.registerKey(did, kid, publicKeyJwk, choice.keyCustody, context);
    const service = await this.options.services.create({
      id: generateServiceId(),
      did,
      name,
      domain,
      requiredScopes,
      description: input.description?.trim() || null,
      framework: input.framework?.trim() || null,
    });
    return { ...result, service };
  }

  // ------------------------------------------------------------------ owners

  /** Point 7: the owner's key for attestations follows the same two modes. */
  async createOwner(input: CreateOwnerInput, context: CustodyContext): Promise<OnboardingResult> {
    const name = typeof input?.name === 'string' ? input.name.trim() : '';
    if (!name) throw new ValidationError('name is required');
    const choice = resolveCustodyChoice({ keyCustody: input.keyCustody, didHosting: input.didHosting }, context.defaults);
    const clientKey = this.clientKey(choice.keyCustody, input.publicKeyJwk);
    const did = await this.subjectDid(choice.didHosting, input.did, 'accounts');
    const kid = verificationMethodId(did, input.kid ?? 'key-1');
    const publicKeyJwk = clientKey ?? (await this.options.keyStore.generate({ did, kid, subjectType: 'owner' }));
    await this.options.records.createRecord(this.newRecord(did, 'owner', choice.keyCustody, choice.didHosting, name, kid));
    this.audit.chosen({ requestId: context.requestId, actor: context.actor, subjectType: 'owner', did, keyCustody: choice.keyCustody, didHosting: choice.didHosting, source: choice.source });
    return this.registerKey(did, kid, publicKeyJwk, choice.keyCustody, context, input.entityType);
  }

  // -------------------------------------------------------------- activation

  /**
   * Own hosting: reads the DID document (and the card it anchors) from the
   * owner's domain through SafeFetch and activates the subject only when the
   * document is the DID's and lists the registered key, and the card is a
   * valid Entity Card of the DID carrying the same key.
   */
  async activate(did: string, context: CustodyContext, expectedSubjectType?: CustodySubjectType): Promise<OnboardingResult> {
    const record = await this.requireRecord(did, expectedSubjectType);
    if (record.status !== 'pending_resolution') {
      throw new CustodyStateInvalidError(`${did} is ${record.status}; only an own-hosted subject waiting for its documents is activated`, { status: record.status });
    }
    const keys = await this.options.records.listKeys(did);
    const current = keys.find((key) => key.kid === record.kid);
    if (!current) throw new CustodyStateInvalidError(`${did} has no registered key`);
    await this.checkResolution(did, current);
    return this.markActive(record, context, 'verified');
  }

  /**
   * One run of the background re-check: own-hosted subjects waiting for their
   * documents whose check is due are checked as `activate` checks them
   * (SafeFetch; the document lists the registered key; the card is valid)
   * and activated when they pass, audited with the actor `system`.
   *
   * Safe with several API instances: each due subject is claimed with a
   * compare-and-set on its next check time before its documents are read,
   * and activation itself is a compare-and-set on its status. Gentle on
   * owners' domains: each subject backs off (see CustodyRecheckSettings), a
   * run checks at most `batchSize` subjects and one per host, and checks stop
   * a bounded time after the subject started waiting.
   */
  async recheckPending(onActivated?: (result: OnboardingResult, requestId: string) => Promise<void> | void): Promise<CustodyRecheckRun> {
    const now = this.clock();
    const settings = this.recheckSettings;
    const run: CustodyRecheckRun = { checked: [], activated: [], stopped: [], deferred: [] };
    const hosts = new Set<string>();
    for (const record of await this.options.records.listDueRechecks(now, settings.batchSize)) {
      const since = record.pendingResolutionSince ?? record.updatedAt;
      if (now.getTime() - since.getTime() >= settings.giveUpAfterSeconds * 1000) {
        if (await this.options.records.claimRecheck(record.did, record.nextRecheckAt!, { nextRecheckAt: null, recheckAttempts: record.recheckAttempts })) run.stopped.push(record.did);
        continue;
      }
      const host = hostOf(record.did);
      if (hosts.has(host)) {
        run.deferred.push(record.did);
        continue;
      }
      const attempts = record.recheckAttempts + 1;
      const waitSeconds = Math.min(settings.initialIntervalSeconds * 2 ** attempts, settings.maxIntervalSeconds);
      const claimed = await this.options.records.claimRecheck(record.did, record.nextRecheckAt!, {
        nextRecheckAt: new Date(now.getTime() + waitSeconds * 1000),
        recheckAttempts: attempts,
      });
      if (!claimed) {
        run.deferred.push(record.did);
        continue;
      }
      hosts.add(host);
      run.checked.push(record.did);
      const result = await this.recheckOne(record);
      if (result) {
        run.activated.push(result);
        await onActivated?.(result, result.requestId);
      }
    }
    return run;
  }

  private async recheckOne(record: CustodyRecordRow): Promise<(OnboardingResult & { requestId: string }) | undefined> {
    const current = (await this.options.records.listKeys(record.did)).find((key) => key.kid === record.kid);
    if (!current) return undefined;
    try {
      await this.checkResolution(record.did, current);
    } catch {
      // Not live yet, or not readable: the next check is already scheduled. One subject never stops the run.
      return undefined;
    }
    const requestId = `custody-recheck:${randomBytes(8).toString('hex')}`;
    try {
      return { ...(await this.markActive(record, { requestId, actor: RECHECK_ACTOR }, 'verified')), requestId };
    } catch (error) {
      // Activated meanwhile by "Check and activate", helix init or another instance.
      if (error instanceof CustodyStateInvalidError) return undefined;
      throw error;
    }
  }

  /** Whether `token` is the enrollment token this subject was created with (the CLI activates with it). */
  async enrollmentTokenMatches(did: string, token: unknown): Promise<boolean> {
    if (typeof token !== 'string' || token.length === 0) return false;
    const record = await this.options.records.findRecord(did);
    return Boolean(record?.enrollmentTokenHash && record.enrollmentTokenHash === hashToken(token));
  }

  // ----------------------------------------------------------------- signing

  /**
   * Custodial signing (point 3): a raw Ed25519 signature with the subject's
   * KeyStore key, audited. Refused, and the refusal audited, for a
   * self-custody subject: Helix holds no key for it.
   */
  async sign(
    did: string,
    input: { payload: unknown; kid?: unknown },
    context: CustodyContext,
    expectedSubjectType: CustodySubjectType,
  ): Promise<SignResult> {
    const record = await this.requireRecord(did, expectedSubjectType);
    if (record.keyCustody !== 'helix') {
      const reason = 'its key custody is self: the private key is held by the owner and never reaches Helix';
      this.audit.signingRefused({ requestId: context.requestId, actor: context.actor, subjectType: record.subjectType, did, code: 'custody_self' });
      throw new CustodialSigningRefusedError(did, reason);
    }
    if (record.status !== 'active') {
      throw new CustodyStateInvalidError(`${did} is ${record.status}; Helix signs for active subjects only`, { status: record.status });
    }
    await this.finalizeDue(record, context);
    const payload = typeof input?.payload === 'string' ? base64UrlDecodeStrict(input.payload) : undefined;
    if (payload === undefined) throw new ValidationError('payload must be base64url bytes');
    if (payload.length === 0 || payload.length > MAX_SIGN_PAYLOAD_BYTES) {
      throw new ValidationError(`payload must be 1 to ${MAX_SIGN_PAYLOAD_BYTES} bytes`);
    }
    const kid = input.kid === undefined ? record.kid! : verificationMethodId(did, String(input.kid));
    const key = (await this.options.records.listKeys(did)).find((candidate) => candidate.kid === kid);
    if (!key || key.status !== 'active' || key.location !== 'helix') {
      const reason = `${kid} is not an active Helix-held key of this subject`;
      this.audit.signingRefused({ requestId: context.requestId, actor: context.actor, subjectType: record.subjectType, did, code: 'key_not_active' });
      throw new CustodialSigningRefusedError(did, reason);
    }
    const signature = await this.options.keyStore.sign({ did, kid }, payload);
    this.audit.signature({ requestId: context.requestId, actor: context.actor, subjectType: record.subjectType, did, kid, payload });
    return { did, kid, alg: 'EdDSA', signature: base64UrlEncode(signature) };
  }

  // ---------------------------------------------------- rotation (story C-E)

  /** F-3 point 6: changing custody is a key rotation into the other place. */
  async changeCustody(did: string, input: ChangeCustodyInput, context: CustodyContext, expectedSubjectType?: CustodySubjectType): Promise<ChangeCustodyResult> {
    if (!isKeyCustodyMode(input?.keyCustody)) throw new ValidationError('keyCustody must be self or helix');
    return this.rotate(did, input, context, { expectedSubjectType, custodyChange: true });
  }

  /**
   * Story C-E points 1 and 7: a new key in the same place (or, with
   * `keyCustody`, the other place), both keys in the DID document for the
   * overlap, the old one then kept with `validUntil`. A self-custody key is
   * generated client side and only its public half arrives, with a proof of
   * possession; a Helix-held key is generated in the KeyStore.
   *
   * `authorizedBy: 'current-key'` is the SDK's `rotateKey()` without an
   * account: `currentKeyProof` must be the current (self-held) key's
   * signature over the same rotation message, so only the holder of the
   * current key may replace it. Otherwise the route authorised the caller.
   */
  async rotateKey(
    did: string,
    input: RotateKeyInput,
    context: CustodyContext,
    options: { expectedSubjectType?: CustodySubjectType | undefined; authorizedBy?: 'route' | 'current-key' } = {},
  ): Promise<ChangeCustodyResult> {
    if (input?.keyCustody !== undefined && !isKeyCustodyMode(input.keyCustody)) throw new ValidationError('keyCustody must be self or helix');
    return this.rotate(did, input, context, { expectedSubjectType: options.expectedSubjectType, custodyChange: false, authorizedBy: options.authorizedBy ?? 'route' });
  }

  private async rotate(
    did: string,
    input: RotateKeyInput,
    context: CustodyContext,
    mode: { expectedSubjectType?: CustodySubjectType | undefined; custodyChange: boolean; authorizedBy?: 'route' | 'current-key' },
  ): Promise<ChangeCustodyResult> {
    let record = await this.requireRecord(did, mode.expectedSubjectType);
    const target: KeyCustodyMode = isKeyCustodyMode(input.keyCustody) ? input.keyCustody : record.keyCustody;
    if (record.status !== 'active') {
      throw new CustodyStateInvalidError(`${did} is ${record.status}; keys rotate on an active subject`, { status: record.status });
    }
    if (mode.custodyChange && record.keyCustody === target) throw new CustodyStateInvalidError(`${did} already has key custody ${target}`);
    const overlapSeconds = input.overlapSeconds ?? this.options.rotationOverlapSeconds ?? DEFAULT_ROTATION_OVERLAP_SECONDS;
    if (!Number.isInteger(overlapSeconds) || overlapSeconds < 0) throw new ValidationError('overlapSeconds must be a whole number of seconds, 0 or more');

    record = await this.finalizeDue(record, context);
    const keys = await this.options.records.listKeys(did);
    const previous = keys.find((key) => key.kid === record.kid);
    if (!previous) throw new CustodyStateInvalidError(`${did} has no current key`);
    const next = nextFragment(keys);
    const newKid = verificationMethodId(did, target === 'self' && input.kid ? input.kid : next.fragment);
    if (keys.some((key) => key.kid === newKid)) throw new ValidationError(`${newKid} was already used by this subject`);

    if (mode.authorizedBy === 'current-key') {
      // Only the holder of the current self-held key may replace it without an account.
      if (previous.location !== 'self' || target !== 'self') {
        throw new CustodialSigningRefusedError(did, 'a rotation authorised by the current key is for a self-custody key replaced by another self-custody key');
      }
      if (!input.kid) throw new ValidationError('kid is required when the current key authorises the rotation');
      const issuedAt = input.proof?.issuedAt;
      const message = typeof issuedAt === 'string' ? rotationProofMessage({ did, kid: newKid, issuedAt }) : undefined;
      if (!message || !verifyProofOfPossession(message, input.currentKeyProof?.signature, publicKeyJwkBytes(previous.publicKeyJwk))) {
        throw new EnrollmentProofInvalidError('currentKeyProof is not the current key\'s signature over the rotation message');
      }
    }

    let publicKeyJwk: PublicKeyJwk;
    if (target === 'self') {
      const publicKey = publicKeyJwkBytes(input.publicKeyJwk);
      const issuedAt = input.proof?.issuedAt;
      if (!rotationProofFresh(issuedAt, this.clock().getTime())) {
        throw new EnrollmentProofInvalidError('proof.issuedAt must be an ISO-8601 instant within five minutes of now');
      }
      if (!verifyProofOfPossession(rotationProofMessage({ did, kid: newKid, issuedAt: issuedAt as string }), input.proof?.signature, publicKey)) {
        throw new EnrollmentProofInvalidError('The rotation proof is not the new key\'s signature');
      }
      publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: base64UrlEncode(publicKey) };
    } else {
      if (input.publicKeyJwk !== undefined) throw new ValidationError('A Helix-held key is generated in Helix; send no publicKeyJwk');
      publicKeyJwk = await this.options.keyStore.generate({ did, kid: newKid, subjectType: record.subjectType });
    }

    const now = this.clock();
    const retiresAt = new Date(now.getTime() + overlapSeconds * 1000);
    await this.options.records.addKey({ did, kid: newKid, location: target, publicKeyJwk, status: 'active', sequence: next.sequence, retiresAt: null, revokedAt: null });
    await this.options.records.updateKey(did, previous.kid, { status: 'retiring', retiresAt });
    // Helix must hold no key for a self-custody subject: an old Helix-held
    // key leaving Helix is shredded now (F-3 point 6). Its public half stays
    // in the document, so proofs it made before still verify. A rotation
    // inside the KeyStore keeps the old key until its overlap ends.
    let previousKeyShredded = false;
    if (previous.location === 'helix' && target === 'self') {
      previousKeyShredded = await this.options.keyStore.shred({ did, kid: previous.kid });
      if (previousKeyShredded) this.audit.keyShredded({ requestId: context.requestId, actor: context.actor, subjectType: record.subjectType, did, kid: previous.kid });
    }

    // The identity credential carries no custody facts (story F-1), so a
    // rotation keeps it; the custody record says which key is current.
    record = await this.options.records.updateRecord(did, { keyCustody: target, kid: newKid });
    const keysNow = await this.options.records.listKeys(did);
    const hopReissue = await this.hopReissuer.reissueHopsForKid({ did, oldKid: previous.kid, newKid, requestId: context.requestId, bound: boundWindow(keysNow, previous.kid) });
    const version = documentVersion(keysNow);
    this.audit.rotated({
      requestId: context.requestId,
      actor: context.actor,
      subjectType: record.subjectType,
      did,
      name: mode.custodyChange ? 'changed' : 'rotated',
      from: previous.location,
      to: target,
      oldKid: previous.kid,
      newKid,
      rotationSequence: version.rotationSequence,
      retiresAt: retiresAt.toISOString(),
      hopReissue,
    });
    if (overlapSeconds === 0) {
      record = await this.finalizeDue(record, context, true);
    }
    const documents = await this.republish(record);
    return {
      ...(await this.view(record)),
      previousKid: previous.kid,
      previousKeyShredded,
      retiresAt: retiresAt.toISOString(),
      rotationSequence: documentVersion(await this.options.records.listKeys(did)).rotationSequence,
      hopReissue,
      documents,
      publishRequired: record.didHosting === 'own',
    };
  }

  /**
   * Story C-E point 5, the compromise path: `kid` (a superseded key; the
   * current key is replaced by a rotation first) is revoked at once. It stays
   * in the DID document marked `revoked`, so nothing it signed is accepted
   * any more; its overlap ends; every delegation hop bound to it is revoked
   * through the status lists, cascading (L3-C); a Helix-held copy is
   * shredded; and the card's backing credential is reissued, so the card
   * names the current key and a fresh revocation entry.
   */
  async revokeKey(did: string, kid: unknown, context: CustodyContext, expectedSubjectType?: CustodySubjectType): Promise<RevokeKeyResult> {
    let record = await this.requireRecord(did, expectedSubjectType);
    if (typeof kid !== 'string' || kid.length === 0) throw new ValidationError('kid is required');
    const fullKid = verificationMethodId(did, kid);
    const key = (await this.options.records.listKeys(did)).find((candidate) => candidate.kid === fullKid);
    if (!key) throw new ValidationError(`${fullKid} is not a key of ${did}`);
    if (key.kid === record.kid) {
      throw new CustodyStateInvalidError(`${fullKid} is the current key; rotate to a new key first, then revoke this one (lost-key recovery waits for the responsible party, story L3-H)`);
    }
    if (key.status === 'revoked') throw new CustodyStateInvalidError(`${fullKid} is already revoked`, { status: 'revoked' });
    const now = this.clock();
    await this.options.records.updateKey(did, fullKid, { status: 'revoked', revokedAt: now, retiresAt: key.retiresAt && key.retiresAt.getTime() < now.getTime() ? key.retiresAt : now });
    if (key.location === 'helix' && (await this.options.keyStore.shred({ did, kid: fullKid }))) {
      this.audit.keyShredded({ requestId: context.requestId, actor: context.actor, subjectType: record.subjectType, did, kid: fullKid });
    }
    const revokedHops = (await this.hopReissuer.revokeHopsForKid?.({ did, kid: fullKid, requestId: context.requestId, bound: boundWindow(await this.options.records.listKeys(did), fullKid) })) ?? [];
    let credentialVcId = record.credentialVcId;
    if (record.subjectType === 'agent' && record.credentialVcId && this.options.credentials.reissueIdentity) {
      credentialVcId = (await this.options.credentials.reissueIdentity(record.credentialVcId, context.requestId)) ?? record.credentialVcId;
      if (credentialVcId !== record.credentialVcId) record = await this.options.records.updateRecord(did, { credentialVcId });
    }
    const rotationSequence = documentVersion(await this.options.records.listKeys(did)).rotationSequence;
    this.audit.keyCompromised({
      requestId: context.requestId,
      actor: context.actor,
      subjectType: record.subjectType,
      did,
      oldKid: fullKid,
      newKid: record.kid!,
      rotationSequence,
      location: key.location,
      revokedHops: revokedHops.length,
      credentialVcId,
    });
    const documents = await this.republish(record);
    return { ...(await this.view(record)), revokedKid: fullKid, revokedHops, rotationSequence, documents };
  }

  /**
   * Story C-E point 6, not built: lost-key recovery is authorised by the
   * responsible party as root issuer (story L3-H decides who that is per
   * journey). Until then it is refused, and never possible from the agent
   * side alone.
   */
  async recoverAgentKey(did: string): Promise<never> {
    throw new HelixError(
      ErrorCode.KEY_RECOVERY_UNAVAILABLE,
      `Lost-key recovery for ${String(did)} needs the responsible party's authorisation (story L3-H); rotate with the current key or the account instead`,
      501,
    );
  }

  /**
   * Ends the overlap of every retiring key whose time is up (or all of them
   * with `force`): the key is retired (it stays in the document with
   * `validUntil`), a Helix-held copy is shredded, and the hops bound to it
   * expire.
   */
  async finalizeRotation(did: string, context: CustodyContext, options: { force?: boolean } = {}, expectedSubjectType?: CustodySubjectType): Promise<CustodyView & { retired: string[]; documents: PublishedDocuments }> {
    const record = await this.requireRecord(did, expectedSubjectType);
    const before = (await this.options.records.listKeys(did)).filter((key) => key.status === 'retired').map((key) => key.kid);
    const updated = await this.finalizeDue(record, context, options.force === true);
    const after = (await this.options.records.listKeys(did)).filter((key) => key.status === 'retired').map((key) => key.kid);
    const documents = await this.republish(updated);
    return { ...(await this.view(updated)), retired: after.filter((kid) => !before.includes(kid)), documents };
  }

  /** The background half of `finalizeRotation`: every subject whose overlap ended, at most `limit` per run. */
  async finalizeDueRotations(limit = this.recheckSettings.batchSize): Promise<string[]> {
    const dids = (await this.options.records.listRetiringDue?.(this.clock(), limit)) ?? [];
    const finalized: string[] = [];
    for (const did of dids) {
      const record = await this.options.records.findRecord(did);
      if (!record) continue;
      await this.finalizeDue(record, { requestId: `rotation-finalize-${randomBytes(6).toString('hex')}`, actor: RECHECK_ACTOR });
      finalized.push(did);
    }
    return finalized;
  }

  // ----------------------------------------------------------------- reading

  /** The subject's custody, with its current documents for an agent (an own-hosted owner publishes these). */
  async getCustody(did: string, expectedSubjectType?: CustodySubjectType): Promise<CustodyView & { documents?: PublishedDocuments }> {
    const record = await this.requireRecord(did, expectedSubjectType);
    const documents = record.subjectType === 'agent' ? await this.currentDocuments(record) : undefined;
    return { ...(await this.view(record)), ...(documents ? { documents } : {}) };
  }

  /** The custody view of each DID that has a record; the console labels its lists with these. */
  async custodyOf(dids: readonly string[]): Promise<CustodyView[]> {
    const records = await this.options.records.listRecords({ dids });
    return Promise.all(records.map((record) => this.view(record)));
  }

  /** Every custody subject, as the conformance report takes them. */
  async conformanceSubjects(): Promise<ConformanceSubject[]> {
    const records = await this.options.records.listRecords();
    return records.map((record) => ({
      did: record.did,
      subjectType: record.subjectType,
      keyCustody: record.keyCustody,
      didHosting: record.didHosting,
      name: record.name,
      status: record.status,
    }));
  }

  /**
   * The KeyStore signer of an active custodial agent, service or owner, for
   * server-side signing (grants, hops, status lists): only a `keyCustody:
   * helix` subject has one; a self-custody key never reaches Helix.
   */
  async signerFor(did: string, subjectType: CustodialSigningSubject, use: CustodialSigningUse): Promise<Signer | undefined> {
    const record = await this.options.records.findRecord(did);
    if (!record || record.subjectType !== subjectType || record.keyCustody !== 'helix' || record.status !== 'active' || !record.kid) return undefined;
    const signer = new KeyStoreSigner(this.options.keyStore, did, record.kid);
    const kid = signer.verificationMethodId;
    return {
      did,
      kid: signer.kid,
      sign: async (payload: Uint8Array): Promise<Uint8Array> => {
        const signature = await signer.sign(payload);
        this.audit.signature({ requestId: use.requestId, actor: `custodial-${use.purpose}`, subjectType, did, kid, payload });
        return signature;
      },
    };
  }

  /** Whether `did` is an active agent created through the custody routes, whoever holds its key. */
  async isActiveAgent(did: string): Promise<boolean> {
    const record = await this.options.records.findRecord(did);
    return record?.subjectType === 'agent' && record.status === 'active';
  }

  /** Card details for story C-A's entity-card source: the name Helix recorded for the subject. */
  async cardDetails(did: string): Promise<{ name: string } | undefined> {
    const record = await this.options.records.findRecord(did);
    return record?.name ? { name: record.name } : undefined;
  }

  // ---------------------------------------------------------------- internal

  private newRecord(
    did: string,
    subjectType: CustodySubjectType,
    keyCustody: KeyCustodyMode,
    didHosting: DidHostingMode,
    name: string,
    kid: string,
  ): NewCustodyRecord {
    return {
      did,
      subjectType,
      keyCustody,
      didHosting,
      status: 'pending_key',
      kid,
      name,
      ownerDid: null,
      scopes: null,
      requestedDomains: null,
      maxDelegationDepth: 0,
      enrollmentTokenHash: null,
      enrollmentExpiresAt: null,
      enrollmentNonce: null,
      enrollmentUsedAt: null,
      credentialVcId: null,
      activatedAt: null,
    };
  }

  /** Self custody needs the client's public key; helix custody must not carry one. */
  private clientKey(keyCustody: KeyCustodyMode, publicKeyJwk: unknown): PublicKeyJwk | undefined {
    if (keyCustody === 'helix') {
      if (publicKeyJwk !== undefined) throw new ValidationError('keyCustody helix: Helix generates the key; send no publicKeyJwk');
      return undefined;
    }
    if (publicKeyJwk === undefined) throw new ValidationError('keyCustody self: publicKeyJwk (the public half of the client-held key) is required');
    return { kty: 'OKP', crv: 'Ed25519', x: base64UrlEncode(publicKeyJwkBytes(publicKeyJwk)) };
  }

  private requireHost(): string {
    if (!this.options.host) {
      throw new HelixError(ErrorCode.INTERNAL_ERROR, 'Helix DID hosting needs DID_DOMAIN to be configured', 503);
    }
    return this.options.host;
  }

  /**
   * `helix` hosting: a fresh `did:web:<DID_DOMAIN>:<kind>:<hex>` (agents,
   * services, and owners as `accounts`); `own`: the owner's did:web, any
   * path, checked (`ownDidWebProblem`: no unencoded port) and unused.
   */
  private async subjectDid(didHosting: DidHostingMode, ownDid: unknown, kind: HelixDidKind): Promise<string> {
    if (didHosting === 'own') {
      const problem = ownDid === undefined ? 'didHosting own needs did: the did:web on your own domain' : ownDidWebProblem(ownDid);
      if (problem !== undefined) throw new ValidationError(problem);
      const own = ownDid as string;
      if (this.options.host && parseDidWeb(own)!.host.toLowerCase() === this.options.host.toLowerCase()) {
        throw new ValidationError('That did:web is under the Helix domain; choose didHosting helix instead');
      }
      await this.assertUnused(own);
      return own;
    }
    if (ownDid !== undefined) throw new ValidationError('didHosting helix: Helix issues the did:web; send no did');
    const host = this.requireHost();
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const did = issueDidWeb({ host, kind });
      if (!(await this.options.records.findRecord(did)) && !(await this.options.didRepository.findDidById(did))) return did;
    }
    /* v8 ignore next */
    throw new HelixError(ErrorCode.INTERNAL_ERROR, 'Could not mint an unused did:web', 500);
  }

  private async assertUnused(did: string): Promise<void> {
    if ((await this.options.records.findRecord(did)) || (await this.options.didRepository.findDidById(did))) {
      throw new HelixError(ErrorCode.DID_ALREADY_EXISTS, `${did} is already registered`, 409);
    }
  }

  private async pendingEnrollment(enrollmentToken: unknown): Promise<CustodyRecordRow> {
    if (typeof enrollmentToken !== 'string' || enrollmentToken.length === 0) throw new ValidationError('enrollmentToken is required');
    const record = await this.options.records.findRecordByEnrollmentToken(hashToken(enrollmentToken));
    if (!record) throw new HelixError(ErrorCode.ENROLLMENT_TOKEN_NOT_FOUND, 'Enrollment token not found', 404);
    if (record.enrollmentUsedAt || record.status !== 'pending_key') {
      throw new HelixError(ErrorCode.ENROLLMENT_TOKEN_ALREADY_USED, 'Enrollment token already used', 409);
    }
    if (record.enrollmentExpiresAt && record.enrollmentExpiresAt.getTime() <= this.clock().getTime()) {
      throw new HelixError(ErrorCode.ENROLLMENT_TOKEN_EXPIRED, 'Enrollment token expired', 410);
    }
    return record;
  }

  private async requireRecord(did: string, expectedSubjectType?: CustodySubjectType): Promise<CustodyRecordRow> {
    const record = typeof did === 'string' ? await this.options.records.findRecord(did) : null;
    if (!record || (expectedSubjectType !== undefined && record.subjectType !== expectedSubjectType)) {
      throw new CustodySubjectNotFoundError(String(did));
    }
    return record;
  }

  private urlsFor(did: string, didHosting: DidHostingMode): { didDocument: string; card: string } {
    if (didHosting === 'helix') return hostedUrls(did, this.options.publicOrigin);
    return { didDocument: didWebDocumentUrl(did), card: didWebCardUrl(did) };
  }

  /** Stores the first key, publishes the DID document, and activates a Helix-hosted subject. */
  private async registerKey(
    did: string,
    kid: string,
    publicKeyJwk: PublicKeyJwk,
    location: KeyCustodyMode,
    context: CustodyContext,
    ownerEntityType?: EntityType,
  ): Promise<OnboardingResult> {
    await this.options.records.addKey({ did, kid, location, publicKeyJwk, status: 'active', sequence: 1, retiresAt: null, revokedAt: null });
    const record = (await this.options.records.findRecord(did))!;
    const publicKey = publicKeyJwkBytes(publicKeyJwk);
    const documents = await this.documentsFor(record, [{ kid, publicKeyJwk }], documentVersion(await this.options.records.listKeys(did)), ownerEntityType);
    await this.options.didRepository.createDid({
      id: did,
      subjectType: record.subjectType,
      controller: did,
      publicKey: Buffer.from(publicKey).toString('hex'),
      publicKeyMultibase: publicKeyToMultibaseOf(publicKey),
      hederaTransactionId: `custody:${record.keyCustody}:${record.didHosting}`,
      didDocument: documents.didDocument,
    });
    if (record.didHosting === 'helix') {
      const active = await this.markActive(record, context, 'helix-hosted');
      return { ...active, documents: active.documents ?? documents };
    }
    const now = this.clock();
    const pending = await this.options.records.updateRecord(did, {
      status: 'pending_resolution',
      pendingResolutionSince: now,
      recheckAttempts: 0,
      nextRecheckAt: new Date(now.getTime() + this.recheckSettings.initialIntervalSeconds * 1000),
    });
    return { ...(await this.view(pending)), documents, publishRequired: true };
  }

  private async markActive(record: CustodyRecordRow, context: CustodyContext, resolution: 'helix-hosted' | 'verified'): Promise<OnboardingResult> {
    // Compare-and-set first, so two requests or API instances (a manual
    // activation and the background re-check) never both activate, nor both
    // issue an identity credential.
    let active = await this.options.records.transitionStatus(record.did, record.status, { status: 'active', activatedAt: this.clock(), nextRecheckAt: null });
    if (!active) {
      throw new CustodyStateInvalidError(`${record.did} was activated by another request`, { status: 'active' });
    }
    let vcId: string | undefined;
    if (record.subjectType === 'agent') {
      try {
        vcId = await this.issueCredential(record, context);
      } catch (error) {
        await this.options.records.updateRecord(record.did, { status: record.status, activatedAt: null, nextRecheckAt: record.nextRecheckAt });
        throw error;
      }
      active = await this.options.records.updateRecord(record.did, { credentialVcId: vcId });
    }
    this.audit.activated({
      requestId: context.requestId,
      actor: context.actor,
      subjectType: record.subjectType,
      did: record.did,
      keyCustody: record.keyCustody,
      didHosting: record.didHosting,
      kid: record.kid!,
      resolution,
    });
    if (record.subjectType === 'agent') {
      // The same enrollment event the agent service logs when an agent is onboarded.
      this.audit.agentOnboarded({ requestId: context.requestId, agentDid: record.did, credentialId: vcId });
    }
    // An agent's documents now carry what its credentials say on the card; an
    // own-hosted agent's owner republishes that card (helix activate does).
    const documents = record.subjectType === 'agent' ? await this.currentDocuments(active) : undefined;
    return { ...(await this.view(active)), ...(vcId ? { vcId } : {}), ...(documents ? { documents } : {}) };
  }

  /** The subject's documents from all its keys, current key first (what `republish` stores). */
  private async currentDocuments(record: CustodyRecordRow): Promise<PublishedDocuments | undefined> {
    const keys = await this.options.records.listKeys(record.did);
    if (!keys.some((key) => key.kid === record.kid)) return undefined;
    return this.documentsFor(record, documentKeys(keys, record.kid), documentVersion(keys));
  }

  /**
   * Story F-1's credentials for the agent: the identity credential (its id is
   * the record's `credentialVcId`) and one capability attestation per scope.
   * `maxDelegationDepth` and `requestedDomains` stay on the custody record.
   */
  private async issueCredential(record: CustodyRecordRow, context: CustodyContext): Promise<string> {
    const credentials = this.options.credentials;
    const identity = await credentials.issueIdentity(
      { agentDid: record.did, name: record.name ?? record.did, ownerDid: record.ownerDid ?? credentials.issuerDid },
      context.requestId,
    );
    if (record.scopes && record.scopes.length > 0) {
      await credentials.issueAttestations({ agentDid: record.did, capabilities: record.scopes }, context.requestId);
    }
    return identity.id;
  }

  /** The DID document listing `keys` (current first) and the card anchored to it. */
  private async documentsFor(
    record: CustodyRecordRow,
    keys: DocumentKey[],
    version: { rotationSequence: number; updated: string },
    ownerEntityType?: EntityType,
  ): Promise<PublishedDocuments> {
    const urls = this.urlsFor(record.did, record.didHosting);
    const [current, ...others] = keys;
    const currentBytes = publicKeyJwkBytes(current!.publicKeyJwk);
    // Story C-E: every key the subject had, current first, each superseded
    // one with its validity, under the document's version.
    const document = versionDidDocument(
      buildDidDocument({
        did: record.did,
        publicKeyJwk: current!.publicKeyJwk,
        kid: current!.kid,
        alsoKnownAs: [didKeyFromPublicKey(currentBytes)],
        service: domainServices(record.requestedDomains),
        cardServiceEndpoint: urls.card,
      }),
      others,
      version,
    );
    const fromCredentials = record.status === 'active' ? await this.options.credentialDetails?.(record.did, record.subjectType) : undefined;
    const card = buildEntityCard({
      id: record.did,
      entityType: entityTypeOf(record.subjectType, ownerEntityType),
      name: record.name ?? record.did,
      kid: current!.kid,
      publicKeyJwk: current!.publicKeyJwk,
      didDocument: urls.didDocument,
      ...(fromCredentials?.capabilities === undefined ? {} : { capabilities: fromCredentials.capabilities }),
      ...(fromCredentials?.responsibleParty === undefined ? {} : { responsibleParty: fromCredentials.responsibleParty }),
      ...(fromCredentials?.revocation === undefined ? {} : { revocation: fromCredentials.revocation }),
    });
    return { didDocument: document, card, didDocumentUrl: urls.didDocument, cardUrl: urls.card };
  }

  /**
   * Rewrites the stored DID document from all the subject's keys (story
   * C-E: superseded keys stay with `validUntil`, compromised ones with
   * `revoked`) under its current `rotationSequence`.
   */
  private async republish(record: CustodyRecordRow): Promise<PublishedDocuments> {
    const keys = await this.options.records.listKeys(record.did);
    const ordered = documentKeys(keys, record.kid);
    const version = documentVersion(keys);
    const documents = await this.documentsFor(record, ordered, version);
    await this.options.didRepository.updateDidDocument(record.did, documents.didDocument, {
      updateType: CUSTODY_DID_UPDATE_TYPE,
      hederaTransactionId: '',
      payload: { keyCustody: record.keyCustody, kids: ordered.map((key) => key.kid), rotationSequence: version.rotationSequence },
    });
    evictDIDCache(record.did);
    await this.options.didCache?.delete(record.did);
    return documents;
  }

  /** Retires the retiring keys whose overlap ended (all of them with `force`). */
  private async finalizeDue(record: CustodyRecordRow, context: CustodyContext, force = false): Promise<CustodyRecordRow> {
    const now = this.clock();
    const due = (await this.options.records.listKeys(record.did)).filter(
      (key) => key.status === 'retiring' && (force || (key.retiresAt !== null && key.retiresAt.getTime() <= now.getTime())),
    );
    if (due.length === 0) return record;
    for (const key of due) {
      // A forced end moves validUntil to now: the key signs nothing later.
      const retiresAt = key.retiresAt && key.retiresAt.getTime() <= now.getTime() ? key.retiresAt : now;
      await this.options.records.updateKey(record.did, key.kid, { status: 'retired', retiresAt });
      if (key.location === 'helix' && (await this.options.keyStore.shred({ did: record.did, kid: key.kid }))) {
        this.audit.keyShredded({ requestId: context.requestId, actor: context.actor, subjectType: record.subjectType, did: record.did, kid: key.kid });
      }
      const bound = boundWindow(await this.options.records.listKeys(record.did), key.kid);
      const expired = (await this.hopReissuer.expireHopsForKid?.({ did: record.did, kid: key.kid, requestId: context.requestId, bound })) ?? [];
      this.audit.keyRetired({ requestId: context.requestId, actor: context.actor, subjectType: record.subjectType, did: record.did, kid: key.kid, location: key.location, expiredHops: expired.length });
    }
    await this.republish(record);
    return record;
  }

  private async checkResolution(did: string, key: CustodyKeyRow): Promise<void> {
    const fetchLike = this.outboundFetch();
    const read = async (url: string, what: string): Promise<unknown> => {
      let response;
      try {
        response = await fetchLike(url, { headers: { accept: 'application/json' } });
      } catch (error) {
        throw new DidDocumentUnresolvedError(did, `${what} could not be read from ${url}: ${error instanceof Error ? error.message : String(error)}`);
      }
      if (!response.ok) throw new DidDocumentUnresolvedError(did, `${what} at ${url} answered HTTP ${response.status}`);
      try {
        return await response.json();
      } catch {
        throw new DidDocumentUnresolvedError(did, `${what} at ${url} is not JSON`);
      }
    };

    const documentUrl = didWebDocumentUrl(did);
    const document = (await read(documentUrl, 'The DID document')) as { id?: unknown; verificationMethod?: unknown } | null;
    if (!document || typeof document.id !== 'string' || !sameDid(document.id, did)) {
      throw new DidDocumentUnresolvedError(did, `the document at ${documentUrl} is not the document of ${did}`);
    }
    const methods = Array.isArray(document.verificationMethod) ? (document.verificationMethod as { id?: unknown; publicKeyJwk?: { x?: unknown } }[]) : [];
    const fragment = key.kid.slice(key.kid.indexOf('#'));
    const listed = methods.find((method) => (method.id === key.kid || method.id === fragment) && method.publicKeyJwk?.x === key.publicKeyJwk.x);
    if (!listed) throw new DidDocumentUnresolvedError(did, `the document at ${documentUrl} does not list the registered key ${key.kid}`);

    const cardUrl = cardEndpointOf(document) ?? didWebCardUrl(did);
    let card: EntityCard;
    try {
      card = parseEntityCard(await read(cardUrl, 'The Entity Card'));
    } catch (error) {
      if (error instanceof DidDocumentUnresolvedError) throw error;
      throw new DidDocumentUnresolvedError(did, `the card at ${cardUrl} is not a valid Entity Card: ${(error as Error).message}`);
    }
    if (!sameDid(card.id, did)) throw new DidDocumentUnresolvedError(did, `the card at ${cardUrl} is not the card of ${did}`);
    if (card.publicKeyJwk !== undefined && card.publicKeyJwk.x !== key.publicKeyJwk.x) {
      throw new DidDocumentUnresolvedError(did, `the card at ${cardUrl} carries another key than ${key.kid}`);
    }
  }

  private async view(record: CustodyRecordRow): Promise<CustodyView> {
    const keys = await this.options.records.listKeys(record.did);
    return {
      did: record.did,
      subjectType: isCustodySubjectType(record.subjectType) ? record.subjectType : 'agent',
      name: record.name,
      keyCustody: record.keyCustody,
      didHosting: record.didHosting,
      label: custodyLabel(record.keyCustody),
      conformant: isConformantCustody(record.keyCustody),
      status: record.status,
      kid: record.kid,
      credentialVcId: record.credentialVcId,
      keys: keys.map((key) => ({
        kid: key.kid,
        location: key.location,
        status: key.status,
        createdAt: key.createdAt.toISOString(),
        retiresAt: iso(key.retiresAt),
        revokedAt: iso(key.revokedAt),
      })),
    };
  }
}
