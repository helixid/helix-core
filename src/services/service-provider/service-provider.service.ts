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
  DelegateeNotAnAgentError,
  ServiceKeyNotFoundError,
  ServiceRevokedError,
  issueGrant,
  normalizeScopes,
  AuditEvents,
  type SignedVC,
} from '../../core/index.js';
import type { IAuditLogger } from '../../core/audit/index.js';
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
  requiredScope: string;
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
}

/** What this needs from the VC service; a Pick so either IVCService shape fits. */
export type GrantVCStore = Pick<IVCService, 'claimStatusListEntry' | 'registerIssuedGrant' | 'listActiveBySubjectDid'>;

/** Same shape as the other ids (`enroll:`, `vc:helix:`) so rows are recognisable on sight. */
export function generateServiceId(): string {
  return `svc:${randomBytes(6).toString('hex')}`;
}

export class ServiceProviderService implements IServiceProviderService {
  constructor(
    private readonly didService: Pick<IDIDService, 'createDID'>,
    private readonly vcService: GrantVCStore,
    private readonly serviceRepository: ServiceRepository,
    private readonly didKeyRepository: DidKeyRepository,
    private readonly keyCustody: IKeyCustody,
    private readonly auditLogger: IAuditLogger,
  ) {}

  async enroll(input: EnrollServiceInput, requestId: string): Promise<ServiceRecord> {
    const name = input.name?.trim();
    const domain = input.domain?.trim();
    const requiredScope = input.requiredScope?.trim();
    if (!name || !domain || !requiredScope) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'name, domain and requiredScope are required', 400);
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
      requiredScope,
      description: input.description?.trim() || null,
      framework: input.framework?.trim() || null,
    });

    this.auditLogger.log(AuditEvents.SERVICE_ENROLLED, {
      requestId,
      serviceId: record.id,
      serviceDid: created.did,
      serviceName: name,
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
    if (durability !== 'standing' && durability !== 'session') {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, "durability must be 'standing' or 'session'", 400);
    }
    if (typeof input.userDid !== 'string' || !input.userDid.startsWith('did:')) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'userDid must be a DID', 400);
    }
    if (typeof input.agentDid !== 'string' || !input.agentDid.startsWith('did:')) {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, 'agentDid must be a DID', 400);
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
    const keyRecord = await this.didKeyRepository.findByDid(input.serviceDid);
    if (!keyRecord || keyRecord.subjectType !== 'service') {
      throw new ServiceKeyNotFoundError(input.serviceDid);
    }

    // The delegatee: an agent this server onboarded (so holds a key for).
    // Only such an agent can ever present the grant, since presenting means
    // the server signing a VP with that key.
    const agentKey = await this.didKeyRepository.findByDid(input.agentDid);
    if (!agentKey || agentKey.subjectType !== 'agent') {
      throw new DelegateeNotAnAgentError(input.agentDid);
    }
    // ...and that still holds an active HelixAgentCredential per the DB: a
    // grant to a revoked or expired agent could never be presented anyway.
    const agentVCs = await this.vcService.listActiveBySubjectDid(input.agentDid, 'HelixAgentCredential');
    if (agentVCs.length === 0) {
      throw new AgentActiveCredentialNotFoundError(input.agentDid);
    }

    const scopes = normalizeScopes(input.scopes);
    const entry = await this.vcService.claimStatusListEntry();
    const { grantVC } = await this.keyCustody.signWith(keyRecord, (privateKeyHex) =>
      issueGrant(
        {
          agentDid: input.agentDid,
          userDid: input.userDid,
          scopes,
          durability,
          serviceDid: input.serviceDid,
          statusList: entry.statusList as Parameters<typeof issueGrant>[0]['statusList'],
          statusListCredentialUrl: entry.statusListCredentialUrl,
          statusListIndex: entry.statusListIndex,
        },
        { did: input.serviceDid, privateKeyHex },
      ),
    );

    const reconciled = await this.vcService.registerIssuedGrant(grantVC, requestId, {
      revokeExisting: input.revokeExisting,
    });

    return { grantVC, ...reconciled };
  }
}
