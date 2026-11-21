// Copyright 2026 DgVerse LLP
// KYA-OS story F-3 point 1: the agent's identity credential records keyCustody and didHosting.
import { describe, expect, it, vi } from 'vitest';
import { AgentVCSchema, buildDIDDocument, createStatusList, derivePublicKey } from '../../../src/core/index.js';
import { VCService } from '../../../src/services/vc/vc.service.js';

function service() {
  const signingKey = 'a'.repeat(64);
  const issuerDid = 'did:hedera:testnet:testissuer';
  const repository = {
    findStatusListById: vi.fn().mockResolvedValue({ id: 'l1', nextIndex: 0, encodedList: createStatusList() }),
    claimNextIndex: vi.fn().mockResolvedValue({ list: { id: 'l1' }, claimedIndex: 0 }),
    createVc: vi.fn().mockResolvedValue({ vcId: 'v1', vcJson: {} }),
    findActiveByIdentity: vi.fn().mockResolvedValue([]),
    findActiveChildren: vi.fn().mockResolvedValue([]),
  };
  const didService = {
    resolveDID: vi.fn().mockResolvedValue({ didDocument: buildDIDDocument(issuerDid, derivePublicKey(signingKey)) }),
  };
  return new VCService(repository as never, didService as never, { log: vi.fn() } as never, signingKey, issuerDid, 'http://localhost');
}

describe('identity credential custody claims', () => {
  it('writes keyCustody and didHosting onto the credential subject when given', async () => {
    const issued = await service().issueVC(
      { subjectDid: 'did:web:h:o:a', subjectType: 'agent', agentName: 'A', privilegeScopes: [], keyCustody: 'helix', didHosting: 'own' },
      'req',
    );
    expect(issued.vc.credentialSubject).toMatchObject({ id: 'did:web:h:o:a', keyCustody: 'helix', didHosting: 'own' });
    expect(AgentVCSchema.parse(issued.vc).credentialSubject).toMatchObject({ keyCustody: 'helix', didHosting: 'own' });
  });

  it('leaves them out when not given, and the schema refuses other values', async () => {
    const issued = await service().issueVC({ subjectDid: 'did:web:h:o:b', subjectType: 'agent', agentName: 'B', privilegeScopes: [] }, 'req');
    expect(issued.vc.credentialSubject).not.toHaveProperty('keyCustody');
    expect(issued.vc.credentialSubject).not.toHaveProperty('didHosting');
    const tampered = { ...issued.vc, credentialSubject: { ...issued.vc.credentialSubject, keyCustody: 'custodial' } };
    expect(AgentVCSchema.safeParse(tampered).success).toBe(false);
  });
});
