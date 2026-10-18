import { buildStatusListCredential, createStatusList, setBit } from '../../src/core/index.js';
import type { SignedVC } from '../../src/core/index.js';
import type {
  IVCService,
  IssueVCInput,
  IssueVCResult,
  ReconcileOptions,
  ReconcileResult,
  VCStatus,
} from '../../src/services/vc/IVCService.js';
import { scopeKey } from '../../src/core/vc-lookup.js';

export class MockVCService implements IVCService {
  private status: VCStatus = 'active';
  private activeVC: Record<string, unknown> | null = {
    id: 'vc:test:1',
    type: ['VerifiableCredential', 'HelixAgentCredential'],
    validUntil: new Date(Date.now() + 60_000).toISOString(),
    credentialStatus: {
      statusListCredential: 'http://localhost:3000/v1/status-list/helix-status-list-1',
      statusListIndex: '0',
    },
    credentialSubject: { privilegeScopes: ['read'] },
  };

  setStatus(status: VCStatus): void {
    this.status = status;
  }

  setActiveVC(vc: Record<string, unknown> | null): void {
    this.activeVC = vc;
  }

  async findActiveBySubjectDid(
    _subjectDid: string,
    vcType?: string,
  ): Promise<Record<string, unknown> | null> {
    if (!this.activeVC) return null;
    if (vcType) {
      const types = (this.activeVC['type'] as string[]) || [];
      if (!types.includes(vcType)) return null;
    }
    return this.activeVC;
  }

  async findActiveByVcIdForSubject(
    vcId: string,
    _subjectDid: string,
    vcType?: string,
  ): Promise<Record<string, unknown> | null> {
    if (!this.activeVC || this.activeVC['id'] !== vcId) return null;
    if (vcType) {
      const types = (this.activeVC['type'] as string[]) || [];
      if (!types.includes(vcType)) return null;
    }
    return this.activeVC;
  }

  async registerSignedVC(vc: SignedVC, _options?: ReconcileOptions): Promise<ReconcileResult> {
    this.activeVC = vc as unknown as Record<string, unknown>;
    return { replacedVcIds: [], revokedVcIds: [], retainedVcIds: [] };
  }

  async listActiveBySubjectDid(
    _subjectDid: string,
    vcType?: string,
  ): Promise<Array<Record<string, unknown>>> {
    if (!this.activeVC) return [];
    if (vcType) {
      const types = (this.activeVC['type'] as string[]) || [];
      if (!types.includes(vcType)) return [];
    }
    return [this.activeVC];
  }

  async getVCStatus(): Promise<VCStatus> {
    return this.status;
  }

  async listVCs(): Promise<Array<{
    vcId: string;
    subjectDid: string;
    agentName?: string;
    scopes: string[];
    status: VCStatus;
    issuedAt: string;
    expiresAt: string;
    parentVcId?: string;
  }>> {
    return [{
      vcId: 'vc:test:1',
      subjectDid: 'did:web:agent.example.com',
      agentName: 'Test Agent',
      scopes: ['read'],
      status: this.status,
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    }];
  }

  async getStatusList(): Promise<{ credentialSubject: { encodedList: string } }> {
    const list = this.status === 'revoked' ? setBit(createStatusList(), 0, 1) : createStatusList();
    return { credentialSubject: { encodedList: list } };
  }

  async createStatusList(input?: { listId?: string; length?: number }): Promise<{
    '@context': string[];
    id: string;
    type: string[];
    issuer: string;
    validFrom: string;
    credentialSubject: {
      id: string;
      type: 'BitstringStatusList';
      statusPurpose: 'revocation';
      encodedList: string;
    };
  }> {
    const listId = input?.listId ?? 'helix-status-list-1';
    const encodedList = createStatusList(input?.length);
    return buildStatusListCredential(listId, encodedList, 'did:web:localhost:3000', 'http://localhost:3000');
  }

  async findRecordByVcId(
    vcId: string,
  ): Promise<{ vcId: string; vc: Record<string, unknown>; status: VCStatus } | null> {
    if (!this.activeVC || this.activeVC['id'] !== vcId) return null;
    return { vcId, vc: this.activeVC, status: this.status };
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async issueVC(input: IssueVCInput, _requestId: string): Promise<IssueVCResult> {
    const vc = {
      id: 'vc:mock:issued',
      type: [
        'VerifiableCredential',
        input.subjectType === 'agent' ? 'HelixAgentCredential' : 'HelixUserCredential',
      ],
      credentialSubject: { id: input.subjectDid },
      validUntil: new Date(Date.now() + (input.expiresInSeconds ?? 7776000) * 1000).toISOString(),
    };
    return {
      vcId: 'vc:mock:issued',
      vc,
      statusListIndex: 0,
      expiresAt: vc.validUntil,
    };
  }

  registeredExternalVCs: SignedVC[] = [];

  async registerExternalVC(
    vc: SignedVC,
    _requestId: string,
  ): Promise<{ vcId: string; alreadyRegistered: boolean }> {
    const alreadyRegistered = this.registeredExternalVCs.some((seen) => seen.id === vc.id);
    if (!alreadyRegistered) this.registeredExternalVCs.push(vc);
    return { vcId: vc.id, alreadyRegistered };
  }

  claimedStatusListIndex = 0;
  registeredGrants: SignedVC[] = [];

  async claimStatusListEntry(): Promise<{
    statusList: { credentialSubject: { encodedList: string } };
    statusListCredentialUrl: string;
    statusListIndex: number;
  }> {
    const { createStatusList } = await import('../../src/core/index.js');
    return {
      statusList: { credentialSubject: { encodedList: createStatusList(256) } },
      statusListCredentialUrl: 'https://api.example/v1/status-list/helix-status-list-1',
      statusListIndex: this.claimedStatusListIndex++,
    };
  }

  revokedVcIds: string[] = [];
  renewals: Array<{ oldVcId: string; newVcId: string }> = [];

  /** Stores the grant and applies the same one-per-scope-set rule VCService.reconcileActive() does. */
  async registerIssuedGrant(
    vc: SignedVC,
    _requestId: string,
    options: ReconcileOptions = {},
  ): Promise<ReconcileResult> {
    const subject = vc.credentialSubject as { id?: string; userDid?: string; scopes?: string[] };
    const siblings = await this.listActiveGrants({
      agentDid: subject.id ?? '',
      serviceDid: vc.issuer,
      userDid: subject.userDid ?? '',
    });
    this.registeredGrants.push(vc);

    const key = scopeKey(subject.scopes ?? []);
    const result: ReconcileResult = { replacedVcIds: [], revokedVcIds: [], retainedVcIds: [] };
    for (const old of siblings) {
      const oldScopes = (old.credentialSubject as { scopes?: string[] }).scopes ?? [];
      if (scopeKey(oldScopes) === key) {
        this.renewals.push({ oldVcId: old.id, newVcId: vc.id });
        this.revokedVcIds.push(old.id);
        result.replacedVcIds.push(old.id);
      } else if (options.revokeExisting) {
        this.revokedVcIds.push(old.id);
        result.revokedVcIds.push(old.id);
      }
    }
    return result;
  }

  /** The registered grants that match and have not been revoked here, in registration order. */
  async listActiveGrants(lookup: { agentDid: string; serviceDid: string; userDid: string }): Promise<SignedVC[]> {
    return this.registeredGrants.filter((vc) => {
      const subject = vc.credentialSubject as { id?: string; userDid?: string };
      return (
        !this.revokedVcIds.includes(vc.id) &&
        vc.issuer === lookup.serviceDid &&
        subject.id === lookup.agentDid &&
        subject.userDid === lookup.userDid
      );
    });
  }

  async revokeVC(vcId: string, _requestId: string): Promise<{ vcId: string; revoked: true; revokedAt: string }> {
    this.revokedVcIds.push(vcId);
    return { vcId, revoked: true, revokedAt: new Date().toISOString() };
  }
}
