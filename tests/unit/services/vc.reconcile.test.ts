// Copyright 2026 DgVerse LLP
//
// The one rule every stored credential follows (VCService.reconcileActive):
// same identity + same scope set refreshes, a different scope set stands
// beside, revokeExisting clears the others, and nothing active delegations
// still hang off is ever revoked. Run against the in-memory repository so
// the rule is exercised end to end: issue, store, look up, revoke, chain.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { VCService } from '../../../src/services/vc/vc.service.js';
import { VcRepository } from '../../../src/repositories/vc.repository.js';
import { buildDIDDocument, derivePublicKey, getBit, type SignedVC } from '../../../src/core/index.js';

const signingKey = 'a'.repeat(64);
const issuerDid = 'did:hedera:testnet:testissuer';
const agentDid = 'did:key:z6MkAgent';

describe('VCService.reconcileActive', () => {
  let repository: VcRepository;
  let audit: { log: ReturnType<typeof vi.fn> };
  let service: VCService;

  beforeEach(() => {
    repository = new VcRepository();
    audit = { log: vi.fn() };
    const didService = {
      resolveDID: vi.fn(async (did: string) =>
        did === issuerDid ? { didDocument: buildDIDDocument(issuerDid, derivePublicKey(signingKey)) } : {},
      ),
      registerResolvedDID: vi.fn(),
    };
    service = new VCService(repository, didService as never, audit as never, signingKey, issuerDid, 'http://localhost');
  });

  const issue = (scopes: string[], revokeExisting = false) =>
    service.issueVC({ subjectDid: agentDid, subjectType: 'agent', agentName: 'A', privilegeScopes: scopes, revokeExisting }, 'r');

  async function activeIds(): Promise<string[]> {
    return (await service.listActiveBySubjectDid(agentDid, 'HelixAgentCredential')).map((vc) => vc['id'] as string);
  }

  it('re-issuing the same scopes refreshes: old revoked on the status list and chained to the new', async () => {
    const first = await issue(['read:b', 'read:a']);
    const second = await issue(['read:a', 'read:b']);

    expect(second.replacedVcIds).toEqual([first.vcId]);
    expect(second.revokedVcIds).toEqual([]);
    expect(await activeIds()).toEqual([second.vcId]);
    expect((await service.getVC(first.vcId, 'r')).renewedByVcId).toBe(second.vcId);
    const list = await service.getStatusList('helix-status-list-1');
    expect(getBit(list.credentialSubject.encodedList, first.statusListIndex)).toBe(1);
    expect(getBit(list.credentialSubject.encodedList, second.statusListIndex)).toBe(0);
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({ event: 'VC_REVOKED', vcId: first.vcId, reason: 'superseded' }));
  });

  it('a different scope set stands beside the existing one; revokeExisting clears the others', async () => {
    const first = await issue(['read:a']);
    const second = await issue(['read:a', 'read:b']);
    expect(second.replacedVcIds).toEqual([]);
    expect(await activeIds()).toEqual([first.vcId, second.vcId]);

    const third = await issue(['read:c'], true);
    expect(third.revokedVcIds).toEqual([first.vcId, second.vcId]);
    expect(await activeIds()).toEqual([third.vcId]);
  });

  it('credentials for another subject or from another issuer are a different identity', async () => {
    const mine = await issue(['read:a']);
    await service.issueVC(
      { subjectDid: 'did:key:z6MkOther', subjectType: 'agent', agentName: 'B', privilegeScopes: ['read:a'], revokeExisting: true },
      'r',
    );
    expect(await activeIds()).toEqual([mine.vcId]);
  });

  it('never revokes a credential that active delegations still point at', async () => {
    const parent = await issue(['read:a']);
    const child = {
      id: 'vc:helix:child',
      type: ['VerifiableCredential', 'HelixAgentCredential'],
      issuer: agentDid,
      validFrom: new Date().toISOString(),
      credentialSubject: {
        id: 'did:key:z6MkSub',
        type: 'HelixAgent',
        privilegeScopes: ['read:a'],
        delegatedFrom: agentDid,
        parentVcId: parent.vcId,
      },
      proof: { type: 'Ed25519Signature2020', created: '', verificationMethod: '', proofPurpose: 'assertionMethod', proofValue: 'x' },
    } as unknown as SignedVC;
    await service.registerSignedVC(child);

    const refreshed = await issue(['read:a']);
    expect(refreshed.replacedVcIds).toEqual([]);
    expect(refreshed.retainedVcIds).toEqual([parent.vcId]);
    // Chained anyway, and both still active: the sub-agent's chain holds.
    expect((await service.getVC(parent.vcId, 'r')).renewedByVcId).toBe(refreshed.vcId);
    expect(await activeIds()).toEqual([parent.vcId, refreshed.vcId]);
  });

  it('a delegation VC with no status entry of its own is revoked by its row alone', async () => {
    const delegation = (id: string, scopes: string[]) =>
      ({
        id,
        type: ['VerifiableCredential', 'HelixAgentCredential'],
        issuer: agentDid,
        validFrom: new Date().toISOString(),
        credentialSubject: { id: 'did:key:z6MkSub', type: 'HelixAgent', privilegeScopes: scopes, delegatedFrom: agentDid },
        proof: { type: 'Ed25519Signature2020', created: '', verificationMethod: '', proofPurpose: 'assertionMethod', proofValue: 'x' },
      }) as unknown as SignedVC;
    // Something else owns bit 0 of the platform list; a placeholder-index
    // delegation VC must not flip it when superseded.
    const owner = await issue(['read:z']);
    expect(owner.statusListIndex).toBe(0);

    await service.registerSignedVC(delegation('vc:d1', ['read:a']));
    const result = await service.registerSignedVC(delegation('vc:d2', ['read:a']));

    expect(result.replacedVcIds).toEqual(['vc:d1']);
    expect((await service.getVC('vc:d1', 'r')).status).toBe('revoked');
    const list = await service.getStatusList('helix-status-list-1');
    expect(getBit(list.credentialSubject.encodedList, 0)).toBe(0);
  });
});
