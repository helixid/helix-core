// Copyright 2026 DgVerse LLP
// KYA-OS story C-E: key rotation in place, the current key authorising it, KeyStore rotation, compromise and the recovery seam.
import { describe, expect, it } from 'vitest';
import {
  CustodialSigningRefusedError,
  CustodyStateInvalidError,
  EnrollmentProofInvalidError,
  HelixError,
  KeyStoreKeyShreddedError,
  ValidationError,
  base64UrlEncode,
  signDataIntegrity,
  verifyDataIntegrity,
  type AgentDidDocument,
  type JwsDidDocument,
} from '../../../../src/core/index.js';
import { boundWindow, documentVersion } from '../../../../src/services/custody/custody.service.js';
import type { HopReissuer, KidHopsInput } from '../../../../src/services/custody/hop-reissue.js';
import type { CustodyKeyRow } from '../../../../src/repositories/custody.repository.js';
import { clientKey, enrollmentSignature, CustodyEvents, events, harness, rotationProof, type ClientKey, type Harness } from './harness.js';

async function documentOf(h: Harness, did: string): Promise<AgentDidDocument> {
  return (await h.dids.findDidById(did))!.didDocument as AgentDidDocument;
}

async function onboardSelf(h: Harness, key: ClientKey = clientKey()) {
  const created = await h.service.createAgent({ name: 'Self bot', scopes: ['read:orders'], keyCustody: 'self' }, h.context());
  const challenge = await h.service.enrollmentChallenge(created.enrollmentToken);
  const enrolled = await h.service.enroll(
    { enrollmentToken: created.enrollmentToken, publicKeyJwk: key.publicKeyJwk, signature: enrollmentSignature(key, challenge.did, challenge.kid, challenge.nonce) },
    h.context({ actor: 'enrollment-token' }),
  );
  return { enrolled, key };
}

/** A reissuer that records what it was asked. */
function recordingReissuer(): HopReissuer & { calls: Record<string, unknown[]> } {
  const calls: Record<string, unknown[]> = { reissue: [], expire: [], revoke: [] };
  return {
    calls,
    reissueHopsForKid: async (input) => {
      calls['reissue']!.push(input);
      return { reissued: 1, pending: false, reissuedHops: { 'urn:zcap:old': 'urn:zcap:new' }, pendingIssuers: [] };
    },
    expireHopsForKid: async (input: KidHopsInput) => {
      calls['expire']!.push(input);
      return ['urn:zcap:old'];
    },
    revokeHopsForKid: async (input: KidHopsInput) => {
      calls['revoke']!.push(input);
      return ['urn:zcap:a', 'urn:zcap:b'];
    },
  };
}

describe('rotating a self-custody key in place (C-E point 1)', () => {
  it('registers only the new public half; both keys are listed for the overlap; the version moves on; hops are reissued', async () => {
    const reissuer = recordingReissuer();
    const h = harness({ hopReissuer: reissuer });
    const { enrolled, key } = await onboardSelf(h);
    const oldKid = enrolled.kid!;
    const signedBefore = await signDataIntegrity({ issuer: enrolled.did, n: 1 }, { did: enrolled.did, kid: 'key-1', sign: async (bytes) => Buffer.from(key.sign(bytes), 'base64url') }, { created: h.now.value.toISOString() });

    const next = clientKey();
    const newKid = `${enrolled.did}#key-2`;
    const rotated = await h.service.rotateKey(
      enrolled.did,
      { publicKeyJwk: next.publicKeyJwk, kid: 'key-2', proof: rotationProof(next, enrolled.did, newKid, h.now.value.toISOString()), overlapSeconds: 3600 },
      h.context({ actor: 'did:web:helix.example:accounts:00ff' }),
      { expectedSubjectType: 'agent' },
    );
    expect(rotated).toMatchObject({ keyCustody: 'self', kid: newKid, previousKid: oldKid, previousKeyShredded: false, rotationSequence: 2, hopReissue: { reissued: 1 } });
    expect(rotated.retiresAt).toBe(new Date(h.now.value.getTime() + 3_600_000).toISOString());
    expect(reissuer.calls['reissue']).toEqual([expect.objectContaining({ did: enrolled.did, oldKid, newKid, bound: { from: expect.any(Date), until: expect.any(Date) } })]);

    const document = await documentOf(h, enrolled.did);
    expect(document).toMatchObject({ rotationSequence: 2, updated: expect.any(String) });
    expect(document.verificationMethod.map((method) => [method.id, method.validUntil ?? null])).toEqual([[newKid, null], [oldKid, rotated.retiresAt]]);
    // A proof made before the rotation verifies after it, against the superseded key.
    expect(await verifyDataIntegrity(signedBefore, async () => document as unknown as JwsDidDocument)).toMatchObject({ ok: true, verificationMethod: oldKid });
    // Helix never held either key.
    expect(await h.keyStore.list(enrolled.did)).toEqual([]);
    expect(events(h, CustodyEvents.CUSTODY_CHANGED)).toEqual([
      expect.objectContaining({ name: 'rotated', from: 'self', to: 'self', oldKid, newKid, rotationSequence: 2, actor: 'did:web:helix.example:accounts:00ff' }),
    ]);
  });

  it('the current key may authorise its own replacement (the SDK rotateKey without an account)', async () => {
    const h = harness();
    const { enrolled, key } = await onboardSelf(h);
    const next = clientKey();
    const newKid = `${enrolled.did}#key-2`;
    const proof = rotationProof(next, enrolled.did, newKid, h.now.value.toISOString());
    const currentKeyProof = { signature: rotationProof(key, enrolled.did, newKid, proof.issuedAt).signature };
    const rotated = await h.service.rotateKey(enrolled.did, { publicKeyJwk: next.publicKeyJwk, kid: 'key-2', proof, currentKeyProof }, h.context({ actor: enrolled.did }), { authorizedBy: 'current-key' });
    expect(rotated.kid).toBe(newKid);

    // Another key's signature, a missing kid, or a signature over another message is refused.
    const third = clientKey();
    const kid3 = `${enrolled.did}#key-3`;
    const proof3 = rotationProof(third, enrolled.did, kid3, h.now.value.toISOString());
    await expect(
      h.service.rotateKey(enrolled.did, { publicKeyJwk: third.publicKeyJwk, kid: 'key-3', proof: proof3, currentKeyProof: { signature: rotationProof(key, enrolled.did, kid3, proof3.issuedAt).signature } }, h.context(), { authorizedBy: 'current-key' }),
    ).rejects.toThrow(EnrollmentProofInvalidError);
    await expect(h.service.rotateKey(enrolled.did, { publicKeyJwk: third.publicKeyJwk, proof: proof3, currentKeyProof: {} }, h.context(), { authorizedBy: 'current-key' })).rejects.toThrow(/kid is required/);
    await expect(
      h.service.rotateKey(enrolled.did, { publicKeyJwk: third.publicKeyJwk, kid: 'key-3', proof: { signature: proof3.signature }, currentKeyProof: { signature: 'AA' } }, h.context(), { authorizedBy: 'current-key' }),
    ).rejects.toThrow(EnrollmentProofInvalidError);
  });

  it('a custodial key cannot be replaced by a current-key proof, nor moved to the other custody that way', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    await expect(h.service.rotateKey(agent.did, { keyCustody: 'helix' }, h.context(), { authorizedBy: 'current-key' })).rejects.toThrow(CustodialSigningRefusedError);
    await expect(h.service.rotateKey(agent.did, { keyCustody: 'custodial' }, h.context())).rejects.toThrow(/self or helix/);
  });
});

describe('Helix-held keys rotate inside the KeyStore (C-E point 7)', () => {
  it('the new key is generated in the KeyStore, the old one still signs nothing new, and is shredded when the overlap ends', async () => {
    const reissuer = recordingReissuer();
    const h = harness({ hopReissuer: reissuer });
    const agent = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    const oldKid = agent.kid!;
    const rotated = await h.service.rotateKey(agent.did, {}, h.context());
    const newKid = `${agent.did}#key-2`;
    expect(rotated).toMatchObject({ keyCustody: 'helix', kid: newKid, previousKeyShredded: false, rotationSequence: 2 });
    expect((await h.keyStore.list(agent.did)).map((key) => [key.kid, key.shreddedAt === null])).toEqual([[oldKid, true], [newKid, true]]);
    // Helix signs with the new key only.
    expect((await h.service.sign(agent.did, { payload: 'AQ' }, h.context(), 'agent')).kid).toBe(newKid);
    await expect(h.service.sign(agent.did, { payload: 'AQ', kid: 'key-1' }, h.context(), 'agent')).rejects.toThrow(CustodialSigningRefusedError);
    await expect(h.service.rotateKey(agent.did, { publicKeyJwk: clientKey().publicKeyJwk }, h.context())).rejects.toThrow(/send no publicKeyJwk/);

    // The overlap ends on the background tick: the old key retires, is shredded, its reissued hops expire.
    h.now.value = new Date(h.now.value.getTime() + 86_400_001);
    expect(await h.service.finalizeDueRotations()).toEqual([agent.did]);
    expect(await h.service.finalizeDueRotations()).toEqual([]);
    await expect(h.keyStore.sign({ did: agent.did, kid: oldKid }, new Uint8Array([1]))).rejects.toThrow(KeyStoreKeyShreddedError);
    expect(reissuer.calls['expire']).toEqual([expect.objectContaining({ did: agent.did, kid: oldKid })]);
    expect(events(h, CustodyEvents.CUSTODY_KEY_RETIRED)).toEqual([expect.objectContaining({ kid: oldKid, location: 'helix', expiredHops: 1, actor: 'system' })]);
    expect(events(h, CustodyEvents.CUSTODY_KEY_SHREDDED)).toEqual([expect.objectContaining({ kid: oldKid })]);
    const document = await documentOf(h, agent.did);
    expect(document.verificationMethod.find((method) => method.id === oldKid)).toMatchObject({ validUntil: rotated.retiresAt });
  });

  it('a store without the due-overlap query finalizes nothing in the background', async () => {
    const h = harness();
    (h.service as unknown as { options: { records: { listRetiringDue?: unknown } } }).options.records.listRetiringDue = undefined;
    expect(await h.service.finalizeDueRotations()).toEqual([]);
  });
});

describe('the compromise path (C-E point 5)', () => {
  it('revoking a superseded key marks it revoked in the document, ends its overlap, revokes its hops and reissues the card credential', async () => {
    const reissuer = recordingReissuer();
    const reissued: string[] = [];
    const h = harness({ hopReissuer: reissuer });
    // The harness's credentials gain the identity reissue C-E uses.
    (h.service as unknown as { options: { credentials: { reissueIdentity?: unknown } } }).options.credentials.reissueIdentity = async (input: { vcId: string; agentDid: string }) => {
      reissued.push(`${input.vcId}@${input.agentDid}`);
      return 'vc:test:renewed';
    };
    const { enrolled, key } = await onboardSelf(h);
    const oldKid = enrolled.kid!;
    const signedBefore = await signDataIntegrity({ issuer: enrolled.did, n: 1 }, { did: enrolled.did, kid: 'key-1', sign: async (bytes) => Buffer.from(key.sign(bytes), 'base64url') }, { created: h.now.value.toISOString() });
    const next = clientKey();
    await h.service.rotateKey(enrolled.did, { publicKeyJwk: next.publicKeyJwk, proof: rotationProof(next, enrolled.did, `${enrolled.did}#key-2`, h.now.value.toISOString()) }, h.context());
    h.now.value = new Date(h.now.value.getTime() + 60_000);

    const revoked = await h.service.revokeKey(enrolled.did, 'key-1', h.context({ actor: 'did:web:helix.example:accounts:00ff' }), 'agent');
    expect(revoked).toMatchObject({ revokedKid: oldKid, revokedHops: ['urn:zcap:a', 'urn:zcap:b'], rotationSequence: 3, credentialVcId: 'vc:test:renewed' });
    expect(reissued).toEqual([`vc:test:1@${enrolled.did}`]);
    expect(reissuer.calls['revoke']).toEqual([expect.objectContaining({ did: enrolled.did, kid: oldKid, bound: expect.objectContaining({ until: expect.any(Date) }) })]);
    expect(revoked.keys.find((entry) => entry.kid === oldKid)).toMatchObject({ status: 'revoked', revokedAt: h.now.value.toISOString(), retiresAt: h.now.value.toISOString() });

    const document = await documentOf(h, enrolled.did);
    expect(document).toMatchObject({ rotationSequence: 3 });
    expect(document.verificationMethod.find((method) => method.id === oldKid)).toMatchObject({ validUntil: h.now.value.toISOString(), revoked: h.now.value.toISOString() });
    // Even a proof made before the compromise is refused now.
    expect(await verifyDataIntegrity(signedBefore, async () => document as unknown as JwsDidDocument)).toMatchObject({ ok: false, reason: 'key_revoked' });
    expect(events(h, CustodyEvents.CUSTODY_KEY_COMPROMISED)).toEqual([
      expect.objectContaining({ oldKid, newKid: `${enrolled.did}#key-2`, rotationSequence: 3, revokedHops: 2, credentialVcId: 'vc:test:renewed', actor: 'did:web:helix.example:accounts:00ff' }),
    ]);
    // A retiring key that is revoked never retires later.
    h.now.value = new Date(h.now.value.getTime() + 2 * 86_400_000);
    expect(await h.service.finalizeDueRotations()).toEqual([]);
    expect((await h.service.getCustody(enrolled.did)).keys[0]).toMatchObject({ status: 'revoked' });
  });

  it('a Helix-held key revoked is shredded; the identity is kept when nothing reissues it', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    await h.service.rotateKey(agent.did, {}, h.context());
    h.now.value = new Date(h.now.value.getTime() + 2 * 86_400_000);
    await h.service.finalizeRotation(agent.did, h.context());
    const revoked = await h.service.revokeKey(agent.did, `${agent.did}#key-1`, h.context());
    // Already shredded when its overlap ended; a retired key's validUntil stays where it was.
    expect(revoked).toMatchObject({ revokedHops: [], credentialVcId: 'vc:test:1' });
    expect(revoked.keys[0]).toMatchObject({ status: 'revoked', retiresAt: new Date(new Date('2026-11-21T10:00:00Z').getTime() + 86_400_000).toISOString() });
  });

  it('refuses to revoke the current key, a key twice, or a kid that is not the subject’s', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    await expect(h.service.revokeKey(agent.did, agent.kid, h.context())).rejects.toThrow(/current key; rotate to a new key first/);
    await expect(h.service.revokeKey(agent.did, 'key-9', h.context())).rejects.toThrow(ValidationError);
    await expect(h.service.revokeKey(agent.did, undefined, h.context())).rejects.toThrow(/kid is required/);
    await h.service.rotateKey(agent.did, {}, h.context());
    await h.service.revokeKey(agent.did, 'key-1', h.context());
    await expect(h.service.revokeKey(agent.did, 'key-1', h.context())).rejects.toThrow(CustodyStateInvalidError);
    // Revoking the custodial key shreds it at once.
    await expect(h.keyStore.sign({ did: agent.did, kid: `${agent.did}#key-1` }, new Uint8Array([1]))).rejects.toThrow(KeyStoreKeyShreddedError);
  });
});

describe('rotation edges', () => {
  it('a reissue that returns nothing keeps the credential; a background run skips a subject gone since it was listed', async () => {
    const h = harness();
    (h.service as unknown as { options: { credentials: { reissueIdentity?: unknown } } }).options.credentials.reissueIdentity = async () => null;
    const agent = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    await h.service.rotateKey(agent.did, {}, h.context());
    expect((await h.service.revokeKey(agent.did, 'key-1', h.context())).credentialVcId).toBe('vc:test:1');
    const records = (h.service as unknown as { options: { records: { listRetiringDue: unknown } } }).options.records;
    records.listRetiringDue = async () => ['did:web:helix.example:agents:gone'];
    expect(await h.service.finalizeDueRotations()).toEqual([]);
  });

  it('a Helix-held key already gone from the store is not reported shredded; a record without its key row cannot rotate', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    await h.keyStore.shred({ did: agent.did, kid: agent.kid! });
    const next = clientKey();
    const changed = await h.service.changeCustody(agent.did, { keyCustody: 'self', publicKeyJwk: next.publicKeyJwk, proof: rotationProof(next, agent.did, `${agent.did}#key-2`, h.now.value.toISOString()) }, h.context());
    expect(changed.previousKeyShredded).toBe(false);
    await h.records.updateRecord(agent.did, { kid: `${agent.did}#key-9` });
    await expect(h.service.rotateKey(agent.did, {}, h.context())).rejects.toThrow(/has no current key/);
  });

  it('three keys: each was current until the next one', async () => {
    const h = harness();
    const agent = await h.service.createAgent({ name: 'Custodial', keyCustody: 'helix' }, h.context());
    await h.service.rotateKey(agent.did, { overlapSeconds: 0 }, h.context());
    h.now.value = new Date(h.now.value.getTime() + 1000);
    await h.service.rotateKey(agent.did, { overlapSeconds: 0 }, h.context());
    const keys = await h.records.listKeys(agent.did);
    expect(boundWindow(keys, `${agent.did}#key-1`)).toEqual({ from: keys[0]!.createdAt, until: keys[1]!.createdAt });
    expect((await h.dids.findDidById(agent.did))!.didDocument).toMatchObject({ rotationSequence: 3 });
  });
});

describe('lost-key recovery waits for story L3-H (C-E point 6)', () => {
  it('is refused with a 501 that names the responsible party', async () => {
    const h = harness();
    const error = await h.service.recoverAgentKey('did:web:helix.example:agents:00').catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(HelixError);
    expect(error).toMatchObject({ code: 'KEY_RECOVERY_UNAVAILABLE', httpStatus: 501, message: expect.stringMatching(/responsible party/) });
  });
});

describe('document version and key windows', () => {
  const key = (sequence: number, status: CustodyKeyRow['status'], createdAt: string, revokedAt: string | null = null): CustodyKeyRow => ({
    did: 'd',
    kid: `d#key-${sequence}`,
    location: 'self',
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: base64UrlEncode(new Uint8Array(32)) },
    status,
    sequence,
    createdAt: new Date(createdAt),
    retiresAt: null,
    revokedAt: revokedAt ? new Date(revokedAt) : null,
  });

  it('counts one step per key and one per revocation; updated is the latest of those', () => {
    expect(documentVersion([key(1, 'active', '2026-11-20T00:00:00Z')])).toEqual({ rotationSequence: 1, updated: '2026-11-20T00:00:00.000Z' });
    expect(
      documentVersion([key(1, 'revoked', '2026-11-20T00:00:00Z', '2026-11-22T00:00:00Z'), key(2, 'active', '2026-11-21T00:00:00Z')]),
    ).toEqual({ rotationSequence: 3, updated: '2026-11-22T00:00:00.000Z' });
    expect(documentVersion([]).rotationSequence).toBe(1);
  });

  it('a key was current from its creation until the next one', () => {
    const keys = [key(2, 'active', '2026-11-21T00:00:00Z'), key(1, 'retired', '2026-11-20T00:00:00Z')];
    expect(boundWindow(keys, 'd#key-1')).toEqual({ from: new Date('2026-11-20T00:00:00Z'), until: new Date('2026-11-21T00:00:00Z') });
    expect(boundWindow(keys, 'd#key-2')).toEqual({ from: new Date('2026-11-21T00:00:00Z'), until: null });
    expect(boundWindow(keys, 'd#key-3')).toBeUndefined();
  });
});
