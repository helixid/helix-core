// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Service Providers as custodial identities. A service is enrolled here the
// way an agent is onboarded: the platform generates the key pair, creates
// the DID, records the service in `services` and holds the private key in
// did_keys. Nobody outside the platform ever holds a service key, so
// issuing a consent grant on the service's behalf is a single API call
// (POST /v1/service-delegation-grants) that builds, signs and stores the
// credential in one go — the old prepare/finalize round trip existed only
// so an SP could sign with a key it kept itself, which is no longer a thing.

import { randomBytes } from 'node:crypto';
import {
  ErrorCode,
  HelixError,
  AgentActiveCredentialNotFoundError,
  ConsentGrantScopeNotAllowedError,
  ConsentNoGrantableScopesError,
  DelegateeNotAnAgentError,
  ServiceKeyNotFoundError,
  ServiceRevokedError,
  issueGrant,
  ACCEPT_TERMS_SCOPE,
  findScopeProblem,
  normalizeScopes,
  parseScopes,
  CAPABILITY_ATTESTATION_TYPE,
  IDENTITY_CREDENTIAL_TYPE,
  attestedCapabilities,
  jsonDigest,
  publicDid,
  type AuditEventInput,
  type AuditTrail,
  type Digest,
  type SignedVC,
  type SigningKeyMaterial,
} from '../../core/index.js';
import type { CustodialKeys } from '../custody/custodial-keys.js';
import type { DidKeyRepository } from '../../repositories/did-key.repository.js';
import type { ServiceRecord, ServiceRepository } from '../../repositories/service.repository.js';
import type { IDIDService } from '../did/IDIDService.js';
import type { IVCService, ReconcileResult } from '../vc/IVCService.js';
import type { IKeyCustody } from '../key-custody/key-custody.js';

export interface EnrollServiceInput {
  /** Also the `targetService` a VP names. Unique on a self-hosted server. */
  name: string;
  /** Host the service is reachable at, e.g. api.sp.example. */
  domain: string;
  /**
   * Scopes an agent may present to this service; holding any one of them is
   * enough. Each entry is split by the scope rule, so ['a,b', 'c'] is a, b, c.
   */
  requiredScopes: string[];
  description?: string;
  /** Informational label ('express', 'flask', ...). */
  framework?: string;
}

export interface IssueDelegationGrantInput {
  /** The service granting on the user's behalf — the grant's `issuer`. */
  serviceDid: string;
  /** The agent the user is delegating to — the grant's subject. */
  agentDid: string;
  /** The consenting user. Recorded as given, never resolved. */
  userDid: string;
  scopes: string[];
  durability?: 'standing' | 'session';
  /**
   * Also revoke every other grant this service holds for the same user and
   * agent, so the new one is the only consent that stands. Off by default:
   * a consent with a different scope set is added beside the existing ones.
   */
  revokeExisting?: boolean;
  /**
   * Whether the consent also covers agents this agent delegates to. Omitted,
   * the grant carries no flag and verifiers treat it as allowed.
   */
  allowDelegation?: boolean;
}

/** The grant, plus what storing it did to the grants active before it (see IVCService.ReconcileResult). */
export interface IssueDelegationGrantResult extends ReconcileResult {
  grantVC: SignedVC;
}

export interface IServiceProviderService {
  enroll(input: EnrollServiceInput, requestId: string): Promise<ServiceRecord>;
  issueDelegationGrant(
    input: IssueDelegationGrantInput,
    requestId: string,
  ): Promise<IssueDelegationGrantResult>;
  getAgentScopes(agentDid: string): Promise<AgentScopesResult>;
}

/** The scopes an agent is attested for (story F-1), which bound what any consent to it may grant. */
export interface AgentScopesResult {
  agentDid: string;
  scopes: string[];
}

/** What this needs from the VC service; a Pick so either IVCService shape fits. */
export type GrantVCStore = Pick<IVCService, 'claimStatusListEntry' | 'registerIssuedGrant' | 'listActiveBySubjectDid'>;

/** Same shape as the other ids (`enroll:`, `vc:helix:`) so rows are recognisable on sight. */
export function generateServiceId(): string {
  return `svc:${randomBytes(6).toString('hex')}`;
}

function reportAuditFailure(error: unknown): void {
  console.error('AUDIT_RECORD_FAILED', error instanceof Error ? error.message : String(error));
}

export class ServiceProviderService implements IServiceProviderService {
  private custodialKeys: CustodialKeys | undefined;

  constructor(
    private readonly didService: Pick<IDIDService, 'createDID'>,
    private readonly vcService: GrantVCStore,
    private readonly serviceRepository: ServiceRepository,
    private readonly didKeyRepository: DidKeyRepository,
    private readonly keyCustody: IKeyCustody,
    private readonly auditTrail: AuditTrail,
  ) {}

  /**
   * KYA-OS story F-3: services and agents created through the custody routes
   * keep their key in the KeyStore, not in did_keys. With this attached, a
   * custodial service signs consent grants through a KeyStoreSigner (stories
   * rule 8), and such agents can receive grants.
   */
  attachCustodialKeys(keys: CustodialKeys): void {
    this.custodialKeys = keys;
  }

  /** The service's signing key: its did_keys key, else its KeyStore key, else SERVICE_KEY_NOT_FOUND. */
  private async serviceKey(serviceDid: string, requestId: string): Promise<<T>(use: (key: SigningKeyMaterial) => T | Promise<T>) => Promise<T>> {
    const record = await this.didKeyRepository.findByDid(serviceDid);
    if (record) {
      if (record.subjectType !== 'service') throw new ServiceKeyNotFoundError(serviceDid);
      return (use) => this.keyCustody.signWith(record, (privateKeyHex) => use({ did: serviceDid, privateKeyHex }));
    }
    const signer = await this.custodialKeys?.signerFor(serviceDid, 'service', { requestId, purpose: 'grant' });
    if (signer) return async (use) => use({ did: serviceDid, signer });
    throw new ServiceKeyNotFoundError(serviceDid);
  }

  /** Records one typed audit event; a failure to record never breaks the request. */
  private audit(input: AuditEventInput): void {
    try {
      this.auditTrail.record(input).catch(reportAuditFailure);
    } catch (error) {
      reportAuditFailure(error);
    }
  }

  async enroll(input: EnrollServiceInput, requestId: string): Promise<ServiceRecord> {
    const name = input.name?.trim();
    const domain = input.domain?.trim();
    const requiredScopes = Array.isArray(input.requiredScopes) ? parseScopes(input.requiredScopes) : [];
    if (!name || !domain || requiredScopes.length === 0) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'name, domain and requiredScopes are required', 400);
    }
    const scopeProblem = findScopeProblem(requiredScopes);
    if (scopeProblem) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, `requiredScopes: ${scopeProblem}`, 400);
    }
    if (await this.serviceRepository.findByName(name)) {
      throw new HelixError(ErrorCode.SERVICE_ALREADY_EXISTS, `Service already enrolled: ${name}`, 409);
    }

    const { publicKey, encrypted } = this.keyCustody.generateAndEncrypt();
    const created = await this.didService.createDID(publicKey, 'service', [], requestId);
    await this.didKeyRepository.create({ did: created.did, subjectType: 'service', ...encrypted });

    const record = await this.serviceRepository.create({
      id: generateServiceId(),
      did: created.did,
      name,
      domain,
      requiredScopes,
      description: input.description?.trim() || null,
      framework: input.framework?.trim() || null,
    });

    this.audit({
      eventType: 'configuration.changed',
      action: { category: 'service', name: 'enrolled' },
      outcome: 'succeeded',
      correlationId: requestId,
      resource: publicDid(created.did),
      details: {
        family: 'key',
        phase: 'configuration_changed',
        configurationDigest: jsonDigest({ serviceId: record.id, serviceDid: created.did }) as Digest,
      },
    });

    return record;
  }

  /**
   * One consent grant per (user, agent, service, scope set): consenting
   * again to the same scopes refreshes the grant, a different scope set
   * stands beside the existing ones, `revokeExisting` clears those. That
   * is the rule every stored credential follows, applied by
   * registerIssuedGrant() -- see VCService.reconcileActive().
   */
  async issueDelegationGrant(
    input: IssueDelegationGrantInput,
    requestId: string,
  ): Promise<IssueDelegationGrantResult> {
    const durability = input.durability ?? 'standing';
    if (!Array.isArray(input.scopes) || input.scopes.length === 0) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'scopes must be a non-empty array', 400);
    }
    const scopeProblem = findScopeProblem(input.scopes);
    if (scopeProblem) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, `scopes: ${scopeProblem}`, 400);
    }
    if (durability !== 'standing' && durability !== 'session') {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, "durability must be 'standing' or 'session'", 400);
    }
    if (typeof input.userDid !== 'string' || !input.userDid.startsWith('did:')) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'userDid must be a DID', 400);
    }
    if (typeof input.agentDid !== 'string' || !input.agentDid.startsWith('did:')) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'agentDid must be a DID', 400);
    }
    if (input.allowDelegation !== undefined && typeof input.allowDelegation !== 'boolean') {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'allowDelegation must be a boolean', 400);
    }
    if (input.agentDid === input.serviceDid) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'A service cannot grant to itself', 400);
    }

    // The signer: an enrolled, unrevoked service whose key this server holds.
    const service = typeof input.serviceDid === 'string'
      ? await this.serviceRepository.findByDid(input.serviceDid)
      : null;
    if (!service) {
      throw new HelixError(ErrorCode.SERVICE_NOT_FOUND, `Service not found: ${input.serviceDid}`, 404);
    }
    if (service.revokedAt) {
      throw new ServiceRevokedError(input.serviceDid);
    }
    const withKey = await this.serviceKey(input.serviceDid, requestId);

    // The delegatee must be an onboarded agent with an active identity
    // credential, and the grant may only carry scopes it holds an active
    // capability attestation for: consent cannot hand an agent authority it
    // is not attested for.
    const { scopes: agentScopes } = await this.getAgentScopes(input.agentDid);
    const scopes = normalizeScopes(input.scopes);
    const held = new Set(agentScopes);
    const notHeld = scopes.filter((scope) => scope !== ACCEPT_TERMS_SCOPE && !held.has(scope));
    if (notHeld.length > 0) {
      throw new ConsentGrantScopeNotAllowedError(notHeld);
    }
    if (scopes.every((scope) => scope === ACCEPT_TERMS_SCOPE)) {
      throw new ConsentNoGrantableScopesError();
    }

    const entry = await this.vcService.claimStatusListEntry();
    const { grantVC } = await withKey((key) =>
      issueGrant(
        {
          agentDid: input.agentDid,
          userDid: input.userDid,
          scopes,
          durability,
          serviceDid: input.serviceDid,
          ...(input.allowDelegation !== undefined ? { allowDelegation: input.allowDelegation } : {}),
          statusList: entry.statusList as Parameters<typeof issueGrant>[0]['statusList'],
          statusListCredentialUrl: entry.statusListCredentialUrl,
          statusListIndex: entry.statusListIndex,
        },
        key,
      ),
    );

    const reconciled = await this.vcService.registerIssuedGrant(grantVC, requestId, {
      revokeExisting: input.revokeExisting,
    });

    return { grantVC, ...reconciled };
  }

  /**
   * The agent's scopes (story F-1): the capabilities named by its active
   * CapabilityAttestationCredentials, Helix-issued at onboarding or
   * owner-signed and registered since, each once in issuance order. The agent
   * must also hold an active AgentIdentityCredential: a grant to an agent
   * whose identity is revoked or expired could never be honoured. "Active"
   * is per the database (not revoked, not expired).
   */
  async getAgentScopes(agentDid: string): Promise<AgentScopesResult> {
    if (typeof agentDid !== 'string' || !agentDid.startsWith('did:')) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'agentDid must be a DID', 400);
    }
    // An agent this server onboarded: one whose key it holds in did_keys
    // (onboarded before F-3), or an active agent created through the custody
    // routes (KYA-OS story F-3), whose key is in the KeyStore or with its owner.
    const agentKey = await this.didKeyRepository.findByDid(agentDid);
    const onboarded = agentKey ? agentKey.subjectType === 'agent' : ((await this.custodialKeys?.isActiveAgent(agentDid)) ?? false);
    if (!onboarded) {
      throw new DelegateeNotAnAgentError(agentDid);
    }
    const identities = await this.vcService.listActiveBySubjectDid(agentDid, IDENTITY_CREDENTIAL_TYPE);
    if (identities.length === 0) {
      throw new AgentActiveCredentialNotFoundError(agentDid);
    }
    const attestations = await this.vcService.listActiveBySubjectDid(agentDid, CAPABILITY_ATTESTATION_TYPE);
    const named = attestations.filter(
      (vc): vc is { credentialSubject: { capability: string } } & Record<string, unknown> =>
        typeof (vc['credentialSubject'] as { capability?: unknown } | undefined)?.capability === 'string',
    );
    return { agentDid, scopes: attestedCapabilities(named) };
  }
}
