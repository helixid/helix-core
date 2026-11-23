// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Service Providers as custodial identities. A service is enrolled here the
// way an agent is onboarded: the platform generates the key pair, creates
// the DID, records the service in `services` and holds the private key in
// did_keys. Consent is no longer a grant the service signs for its user:
// since KYA-OS story L3-H the user's own did:key signs the root hop at
// consent (services/consent/), so a service holds no key able to sign as a
// user. What stays here is enrollment and the agent's attested scopes, which
// bound what any consent to it may grant.

import { randomBytes } from 'node:crypto';
import {
  ErrorCode,
  HelixError,
  AgentActiveCredentialNotFoundError,
  DelegateeNotAnAgentError,
  findScopeProblem,
  parseScopes,
  CAPABILITY_ATTESTATION_TYPE,
  IDENTITY_CREDENTIAL_TYPE,
  attestedCapabilities,
  jsonDigest,
  publicDid,
  type AuditEventInput,
  type AuditTrail,
  type Digest,
} from '../../core/index.js';
import type { CustodialKeys } from '../custody/custodial-keys.js';
import type { DidKeyRepository } from '../../repositories/did-key.repository.js';
import type { ServiceRecord, ServiceRepository } from '../../repositories/service.repository.js';
import type { IDIDService } from '../did/IDIDService.js';
import type { IVCService } from '../vc/IVCService.js';
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

export interface IServiceProviderService {
  enroll(input: EnrollServiceInput, requestId: string): Promise<ServiceRecord>;
  getAgentScopes(agentDid: string): Promise<AgentScopesResult>;
}

/** The scopes an agent is attested for (story F-1), which bound what any consent to it may grant. */
export interface AgentScopesResult {
  agentDid: string;
  scopes: string[];
}

/** What this needs from the VC service; a Pick so either IVCService shape fits. */
export type GrantVCStore = Pick<IVCService, 'listActiveBySubjectDid'>;

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
