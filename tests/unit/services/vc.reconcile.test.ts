// Copyright 2026 DgVerse LLP
//
// The one rule every stored credential follows (VCService.reconcileActive):
// same identity + same scope set refreshes, a different scope set stands
// beside, revokeExisting clears the others, and nothing active delegations
// still hang off is ever revoked. Run against the in-memory repository so
// the rule is exercised end to end: store, look up, revoke, chain. The
// credentials are DelegationGrantCredentials (what reaches this rule today:
// a service's grant to an agent for a user), stored through registerSignedVC.

import { randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { VCService } from '../../../src/services/vc/vc.service.js';
import { VcRepository } from '../../../src/repositories/vc.repository.js';
import { buildDIDDocument, derivePublicKey, getBit, type SignedVC } from '../../../src/core/index.js';

const signingKey = 'a'.repeat(64);
const issuerDid = 'did:hedera:testnet:testissuer';
const agentDid = 'did:key:z6MkAgent';
const serviceDid = 'did:web:orders.example';
const userDid = 'did:web:mock.local:users:alice';
const GRANT = 'DelegationGrantCredential';

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

  /** A service's grant on the platform list, stored the way grants are, with what reconcile did. */
  async function issue(
    scopes: string[],
    revokeExisting = false,
    who: { subject?: string; issuer?: string } = {},
  ): Promise<{ vcId: string; statusListIndex: number; replacedVcIds: string[]; revokedVcIds: string[]; retainedVcIds: string[] }> {
    const entry = await service.claimStatusListEntry();
    const vc = {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://helixid.io/contexts/v1'],
      id: `urn:uuid:${randomUUID()}`,
      type: ['VerifiableCredential', GRANT],
      issuer: who.issuer ?? serviceDid,
      validFrom: new Date().toISOString(),
      credentialStatus: {
        id: `${entry.statusListCredentialUrl}#${entry.statusListIndex}`,
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: String(entry.statusListIndex),
        statusListCredential: entry.statusListCredentialUrl,
      },
      credentialSubject: { id: who.subject ?? agentDid, type: 'DelegationGrant', userDid, scopes, durability: 'standing' },
      proof: { type: 'Ed25519Signature2020', created: '', verificationMethod: '', proofPurpose: 'assertionMethod', proofValue: 'x' },
    } as unknown as SignedVC;
    const result = await service.registerSignedVC(vc, { revokeExisting });
    return { vcId: vc.id, statusListIndex: entry.statusListIndex, ...result };
  }

  async function activeIds(): Promise<string[]> {
    return (await service.listActiveBySubjectDid(agentDid, GRANT)).map((vc) => vc['id'] as string);
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
    const otherSubject = await issue(['read:a'], true, { subject: 'did:key:z6MkOther' });
    const otherIssuer = await issue(['read:a'], true, { issuer: 'did:web:other-service.example' });
    // Neither revokeExisting touched this agent's grant from this service.
    expect(otherSubject.revokedVcIds).toEqual([]);
    expect(otherIssuer.revokedVcIds).toEqual([]);
    expect(otherIssuer.replacedVcIds).toEqual([]);
    expect(await activeIds()).toEqual([mine.vcId, otherIssuer.vcId]);
  });

  it('never revokes a credential that active delegations still point at', async () => {
    const parent = await issue(['read:a']);
    const child = {
      id: 'urn:zcap:child',
      type: ['VerifiableCredential', 'DelegationCredential'],
      issuer: agentDid,
      validFrom: new Date().toISOString(),
      credentialSubject: { id: 'did:key:z6MkSub', parentVcId: parent.vcId },
      proof: { type: 'DataIntegrityProof', created: '', verificationMethod: '', proofPurpose: 'assertionMethod', proofValue: 'x' },
    } as unknown as SignedVC;
    await service.registerSignedVC(child);

    const refreshed = await issue(['read:a']);
    expect(refreshed.replacedVcIds).toEqual([]);
    expect(refreshed.retainedVcIds).toEqual([parent.vcId]);
    // Chained anyway, and both still active: the sub-agent's chain holds.
    expect((await service.getVC(parent.vcId, 'r')).renewedByVcId).toBe(refreshed.vcId);
    expect(await activeIds()).toEqual([parent.vcId, refreshed.vcId]);
  });

  it('a credential with no status entry of its own is revoked by its row alone', async () => {
    const delegation = (id: string, scopes: string[]) =>
      ({
        id,
        type: ['VerifiableCredential', GRANT],
        issuer: serviceDid,
        validFrom: new Date().toISOString(),
        credentialSubject: { id: 'did:key:z6MkSub', type: 'DelegationGrant', userDid, scopes, durability: 'standing' },
        proof: { type: 'Ed25519Signature2020', created: '', verificationMethod: '', proofPurpose: 'assertionMethod', proofValue: 'x' },
      }) as unknown as SignedVC;
    // Something else owns bit 0 of the platform list; a placeholder-index
    // credential with no status entry must not flip it when superseded.
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
