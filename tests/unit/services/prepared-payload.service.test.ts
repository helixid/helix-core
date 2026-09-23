// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// End-to-end unit test of the prepare/finalize split from
// docs/proposal-sdk-api-only.md: the service builds the unsigned payload,
// the test plays the role of the SDK by signing the returned hash locally
// with a real Ed25519 key (never touching the service), then finalize()
// must accept that signature and return a fully signed VC.

import { describe, it, expect } from 'vitest';
import {
  DIDNotFoundError,
  generateKeyPair,
  hashCanonicalPayload,
  publicKeyToMultibase,
  signData,
  createStatusList,
  buildStatusListCredential,
  MaxDelegationDepthExceededError,
  ScopeEscalationDeniedError,
  PreparedPayloadNotFoundError,
  PreparedPayloadExpiredError,
  PreparedPayloadAlreadyConsumedError,
  PreparedPayloadPurposeMismatchError,
  PreparedPayloadSignatureInvalidError,
  SelfDelegationNotAllowedError,
  type SignedVC,
} from '../../../src/core/index.js';
import { PreparedPayloadService } from '../../../src/services/prepared-payload/prepared-payload.service.js';
import { PreparedPayloadRepository } from '../../../src/repositories/prepared-payload.repository.js';
import type { IDIDService } from '../../../src/services/did/did.service.js';

function didKey(publicKeyHex: string): string {
  return `did:key:${publicKeyToMultibase(publicKeyHex)}`;
}

/** A "did:key" always looks unresolvable to the persisted-DID service, so
 * finalize() falls back to core (self-certifying) resolution — exactly the
 * path a real delegator/SP key takes. */
class AlwaysMissingDIDService implements Partial<IDIDService> {
  async resolveDID(did: string): Promise<never> {
    throw new DIDNotFoundError(did);
  }
}

function makeActor() {
  const keys = generateKeyPair();
  return { did: didKey(keys.publicKey), privateKeyHex: keys.privateKey, publicKeyHex: keys.publicKey };
}

async function signPrepareResult(privateKeyHex: string, canonicalHash: string): Promise<string> {
  return signData(Buffer.from(canonicalHash, 'hex'), privateKeyHex);
}

function makeService(): PreparedPayloadService {
  const repo = new PreparedPayloadRepository();
  const didService = new AlwaysMissingDIDService() as unknown as IDIDService;
  return new PreparedPayloadService(repo, didService);
}

function makeAgentVC(subjectDid: string, delegatedFrom?: string): SignedVC {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://helixid.io/contexts/v1'],
    id: 'vc:helix:agent:test-root',
    type: ['VerifiableCredential', 'HelixAgentCredential'],
    issuer: 'did:key:z6MkIssuerExample',
    validFrom: '2026-01-01T00:00:00.000Z',
    validUntil: '2026-12-31T23:59:59.000Z',
    credentialSubject: {
      id: subjectDid,
      type: 'HelixAgent',
      privilegeScopes: ['read:calendar', 'read:email'],
      agentName: 'root-agent',
      delegationDepth: 0,
      maxDelegationDepth: 2,
      ...(delegatedFrom ? { delegatedFrom } : {}),
    },
    proof: {
      type: 'Ed25519Signature2020',
      created: '2026-01-01T00:00:00.000Z',
      verificationMethod: 'did:key:z6MkIssuerExample#key-1',
      proofPurpose: 'assertionMethod',
      proofValue: 'zPlaceholder',
    },
  } as unknown as SignedVC;
}

describe('PreparedPayloadService — delegation', () => {
  it('prepares a delegation payload whose hash matches hashCanonicalPayload of the returned payload', async () => {
    const service = makeService();
    const delegator = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    const result = await service.prepareDelegation({
      delegatorDid: delegator.did,
      fromVC,
      to: 'did:key:z6MkChildAgentExample',
      scopes: ['read:calendar'],
      expiresIn: 3600,
    });

    expect(result.token).toBeTruthy();
    const rehashed = Buffer.from(hashCanonicalPayload(result.unsignedPayload)).toString('hex');
    expect(rehashed).toBe(result.canonicalHash);
    expect(result.unsignedPayload.issuer).toBe(delegator.did);
    expect((result.unsignedPayload.credentialSubject as { delegationDepth: number }).delegationDepth).toBe(1);
  });

  it('rejects scope escalation beyond the parent VC scopes', async () => {
    const service = makeService();
    const delegator = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    await expect(
      service.prepareDelegation({
        delegatorDid: delegator.did,
        fromVC,
        to: 'did:key:z6MkChildAgentExample',
        scopes: ['admin:everything'],
        expiresIn: 3600,
      }),
    ).rejects.toBeInstanceOf(ScopeEscalationDeniedError);
  });

  it('rejects delegating to the delegator\'s own DID', async () => {
    const service = makeService();
    const delegator = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    await expect(
      service.prepareDelegation({
        delegatorDid: delegator.did,
        fromVC,
        to: delegator.did,
        scopes: ['read:calendar'],
        expiresIn: 3600,
      }),
    ).rejects.toBeInstanceOf(SelfDelegationNotAllowedError);
  });

  it('rejects delegation beyond maxDelegationDepth', async () => {
    const service = makeService();
    const delegator = makeActor();
    const fromVC = makeAgentVC(delegator.did);
    (fromVC.credentialSubject as unknown as { delegationDepth: number }).delegationDepth = 2;
    (fromVC.credentialSubject as unknown as { maxDelegationDepth: number }).maxDelegationDepth = 2;

    await expect(
      service.prepareDelegation({
        delegatorDid: delegator.did,
        fromVC,
        to: 'did:key:z6MkChildAgentExample',
        scopes: ['read:calendar'],
        expiresIn: 3600,
      }),
    ).rejects.toBeInstanceOf(MaxDelegationDepthExceededError);
  });

  it('completes the full prepare -> sign -> finalize round trip', async () => {
    const service = makeService();
    const delegator = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    const prepared = await service.prepareDelegation({
      delegatorDid: delegator.did,
      fromVC,
      to: 'did:key:z6MkChildAgentExample',
      scopes: ['read:calendar'],
      expiresIn: 3600,
    });

    const signatureHex = await signPrepareResult(delegator.privateKeyHex, prepared.canonicalHash);
    const signedVP = await service.finalizeDelegation({
      token: prepared.token,
      verificationMethod: `${delegator.did}#key-1`,
      signatureHex,
    });

    expect(signedVP.issuer).toBe(delegator.did);
    expect(signedVP.proof.proofPurpose).toBe('assertionMethod');
    expect(signedVP.proof.verificationMethod).toBe(`${delegator.did}#key-1`);
  });

  it('rejects finalize with a signature from the wrong key', async () => {
    const service = makeService();
    const delegator = makeActor();
    const impostor = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    const prepared = await service.prepareDelegation({
      delegatorDid: delegator.did,
      fromVC,
      to: 'did:key:z6MkChildAgentExample',
      scopes: ['read:calendar'],
      expiresIn: 3600,
    });

    const badSignature = await signPrepareResult(impostor.privateKeyHex, prepared.canonicalHash);
    await expect(
      service.finalizeDelegation({
        token: prepared.token,
        // verificationMethod claims to be the delegator, but the signature
        // was produced by a different key.
        verificationMethod: `${delegator.did}#key-1`,
        signatureHex: badSignature,
      }),
    ).rejects.toBeInstanceOf(PreparedPayloadSignatureInvalidError);
  });

  it('rejects finalize when verificationMethod DID does not match the expected signer', async () => {
    const service = makeService();
    const delegator = makeActor();
    const impostor = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    const prepared = await service.prepareDelegation({
      delegatorDid: delegator.did,
      fromVC,
      to: 'did:key:z6MkChildAgentExample',
      scopes: ['read:calendar'],
      expiresIn: 3600,
    });

    const signatureHex = await signPrepareResult(impostor.privateKeyHex, prepared.canonicalHash);
    await expect(
      service.finalizeDelegation({
        token: prepared.token,
        verificationMethod: `${impostor.did}#key-1`,
        signatureHex,
      }),
    ).rejects.toBeInstanceOf(PreparedPayloadSignatureInvalidError);
  });

  it('rejects finalize on an unknown token', async () => {
    const service = makeService();
    await expect(
      service.finalizeDelegation({
        token: 'nope',
        verificationMethod: 'did:key:z6MkSomeone#key-1',
        signatureHex: 'ab',
      }),
    ).rejects.toBeInstanceOf(PreparedPayloadNotFoundError);
  });

  it('rejects a second finalize against an already-consumed token', async () => {
    const service = makeService();
    const delegator = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    const prepared = await service.prepareDelegation({
      delegatorDid: delegator.did,
      fromVC,
      to: 'did:key:z6MkChildAgentExample',
      scopes: ['read:calendar'],
      expiresIn: 3600,
    });
    const signatureHex = await signPrepareResult(delegator.privateKeyHex, prepared.canonicalHash);

    await service.finalizeDelegation({
      token: prepared.token,
      verificationMethod: `${delegator.did}#key-1`,
      signatureHex,
    });

    await expect(
      service.finalizeDelegation({
        token: prepared.token,
        verificationMethod: `${delegator.did}#key-1`,
        signatureHex,
      }),
    ).rejects.toBeInstanceOf(PreparedPayloadAlreadyConsumedError);
  });

  it('rejects finalizing a delegation token against the grant endpoint', async () => {
    const service = makeService();
    const delegator = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    const prepared = await service.prepareDelegation({
      delegatorDid: delegator.did,
      fromVC,
      to: 'did:key:z6MkChildAgentExample',
      scopes: ['read:calendar'],
      expiresIn: 3600,
    });
    const signatureHex = await signPrepareResult(delegator.privateKeyHex, prepared.canonicalHash);

    await expect(
      service.finalizeGrant({
        token: prepared.token,
        verificationMethod: `${delegator.did}#key-1`,
        signatureHex,
      }),
    ).rejects.toBeInstanceOf(PreparedPayloadPurposeMismatchError);
  });

  it('rejects finalize after the prepare token has expired', async () => {
    const service = makeService();
    const delegator = makeActor();
    const fromVC = makeAgentVC(delegator.did);

    // expiresIn only controls the *delegation VC's* validity window, not the
    // prepare token's 5-minute TTL — so to exercise expiry we reach into the
    // repository directly rather than waiting 5 real minutes.
    const prepared = await service.prepareDelegation({
      delegatorDid: delegator.did,
      fromVC,
      to: 'did:key:z6MkChildAgentExample',
      scopes: ['read:calendar'],
      expiresIn: 3600,
    });

    const repo = (service as unknown as { repository: PreparedPayloadRepository }).repository;
    const record = await repo.findByToken(prepared.token);
    expect(record).not.toBeNull();
    // Simulate expiry by creating a fresh repository row with the same
    // shape but an already-past expiresAt, and pointing a fresh service at it.
    const expiredRepo = new PreparedPayloadRepository();
    const expiredResult = await expiredRepo.create({
      purpose: 'delegation',
      unsignedPayload: JSON.stringify(prepared.unsignedPayload),
      canonicalHash: prepared.canonicalHash,
      expectedSignerDid: delegator.did,
      expiresAt: new Date(Date.now() - 1000),
    });
    const expiredService = new PreparedPayloadService(
      expiredRepo,
      new AlwaysMissingDIDService() as unknown as IDIDService,
    );
    const signatureHex = await signPrepareResult(delegator.privateKeyHex, prepared.canonicalHash);
    await expect(
      expiredService.finalizeDelegation({
        token: expiredResult.token,
        verificationMethod: `${delegator.did}#key-1`,
        signatureHex,
      }),
    ).rejects.toBeInstanceOf(PreparedPayloadExpiredError);
  });
});

describe('PreparedPayloadService — grant', () => {
  it('completes the full prepare -> sign -> finalize round trip', async () => {
    const service = makeService();
    const issuer = makeActor();
    const statusList = buildStatusListCredential(
      'sp-status-list-1',
      createStatusList(),
      issuer.did,
      'https://sp.example',
    );

    const prepared = await service.prepareGrant({
      issuerDid: issuer.did,
      agentDid: 'did:key:z6MkAgentExample',
      userDid: 'did:key:z6MkUserExample',
      scopes: ['read:calendar'],
      durability: 'standing',
      statusList,
      statusListCredentialUrl: 'https://sp.example/status/1',
    });

    const signatureHex = await signPrepareResult(issuer.privateKeyHex, prepared.canonicalHash);
    const grantVC = await service.finalizeGrant({
      token: prepared.token,
      verificationMethod: `${issuer.did}#key-1`,
      signatureHex,
    });

    expect(grantVC.issuer).toBe(issuer.did);
    expect((grantVC as unknown as { type: string[] }).type).toContain('DelegationGrantCredential');
    expect(grantVC.proof.verificationMethod).toBe(`${issuer.did}#key-1`);
  });
});
