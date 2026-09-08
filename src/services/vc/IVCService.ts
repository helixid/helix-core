import type { SignedVC } from '../../core/index.js';

export type VCStatus = 'active' | 'revoked' | 'expired';

export interface IssueVCInput {
  subjectDid: string;
  subjectType: 'agent' | 'user';
  privilegeScopes?: string[];
  agentName?: string;
  userId?: string;
  expiresInSeconds: number;
  delegatedFrom?: string;
  delegationDepth?: number;
  maxDelegationDepth?: number;
  parentVcId?: string;
}

export interface IssueVCResult {
  vcId: string;
  vc: Record<string, unknown>;
  statusListIndex: number;
  expiresAt: string;
}

export interface IVCService {
  findActiveBySubjectDid(
    subjectDid: string,
    vcType?: string,
  ): Promise<Record<string, unknown> | null>;
  /**
   * Like findActiveBySubjectDid(), but returns every active credential
   * instead of throwing when there's more than one -- for callers (see
   * AgentService.delegateAuthority()) that can disambiguate themselves
   * rather than needing "there's exactly one" as a precondition.
   */
  listActiveBySubjectDid(
    subjectDid: string,
    vcType?: string,
  ): Promise<Array<Record<string, unknown>>>;
  findActiveByVcIdForSubject(
    vcId: string,
    subjectDid: string,
    vcType?: string,
  ): Promise<Record<string, unknown> | null>;
  findRecordByVcId(vcId: string): Promise<{
    vcId: string;
    vc: Record<string, unknown>;
    status: VCStatus;
  } | null>;
  getVCStatus(vcId: string): Promise<VCStatus>;
  getStatusList(listId: string): Promise<{ credentialSubject: { encodedList: string } }>;
  createStatusList(input?: {
    listId?: string;
    length?: number;
  }): Promise<{
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
  }>;
  issueVC(input: IssueVCInput, requestId: string): Promise<IssueVCResult>;
  /**
   * Persists an already-signed VC produced outside issueVC()'s own
   * issuer-signed path — specifically, a delegation VC signed by the
   * delegator agent's own custodial key (see AgentService.delegateAuthority()
   * and PreparedPayloadService.finalizeDelegation()), not this service's
   * platform issuer key. Skips issueVC()'s signing and status-list-index
   * claiming entirely; this only makes the VC findable again via
   * findActiveBySubjectDid()/findActiveByVcIdForSubject() for a later hop of
   * delegation. No audit event here — the caller (delegateAuthority) already
   * logs VC_DELEGATED for this VC.
   */
  registerSignedVC(vc: SignedVC): Promise<void>;
}
