// Copyright 2026 DgVerse LLP
// KYA-OS story L3-H: an in-memory consent world with real keys: the KeyStore holds the user keys, the
// credential service issues the hops onto per-issuer status lists, the revocation service revokes them.
import { vi } from 'vitest';
import { kyaos } from '@helixid/sdk-js';
import {
  EnvSigner,
  derivePublicKey,
  didKeyDocument,
  publicKeyToMultibase,
  type DIDDocument,
  type Signer,
} from '../../../../src/core/index.js';
import type { DidResolver } from '../../../../src/core/credentials/index.js';
import { VcRepository } from '../../../../src/repositories/vc.repository.js';
import { DidKeyRepository } from '../../../../src/repositories/did-key.repository.js';
import { WrappedKeyRepository } from '../../../../src/repositories/custody.repository.js';
import { ConsentRepository } from '../../../../src/repositories/consent.repository.js';
import { AesGcmKeyCustody } from '../../../../src/services/key-custody/key-custody.js';
import { CredentialService } from '../../../../src/services/credentials/credential.service.js';
import { StatusListPublisher, StatusListService } from '../../../../src/services/status-lists/status-list.service.js';
import { RevocationService } from '../../../../src/services/revocation/revocation.service.js';
import { DbKeyStore } from '../../../../src/services/custody/db-key-store.js';
import { UserKeyService } from '../../../../src/services/consent/user-key.service.js';
import { ConsentService, type ConsentServiceOptions } from '../../../../src/services/consent/consent.service.js';
import {
  CONSENT_RENEWAL_TYP,
  CONSENT_REQUEST_TYP,
  CONSENT_WITHDRAWAL_TYP,
  signRequest,
} from '../../../../src/services/consent/signed-request.js';
import { InProcessCache } from '../../../../src/cache/InProcessCache.js';
import { TestAuditTrail } from '../../../utils/TestAuditTrail.js';
import { testDidDocument } from '../../../utils/didDocuments.js';

export const API = 'https://api.helix.test';

function keyed(hex: string, did?: string): { did: string; signer: Signer; publicKey: string } {
  const publicKey = derivePublicKey(hex);
  const id = did ?? `did:key:${publicKeyToMultibase(publicKey)}`;
  return { did: id, publicKey, signer: new EnvSigner({ did: id, envVar: 'K', env: { K: hex }, ...(id.startsWith('did:web:') ? { kid: 'key-1' } : {}) }) };
}

export const HELIX = keyed('1'.repeat(64));
export const SERVICE = keyed('3'.repeat(64), 'did:web:shop.example:services:aa11');
export const OTHER_SERVICE = keyed('4'.repeat(64), 'did:web:air.example:services:bb22');
export const STRANGER_SERVICE = keyed('6'.repeat(64), 'did:web:nobody.example:services:cc33');
export const AGENT = keyed('5'.repeat(64), 'did:web:helix.example:agents:dd44');
export const OTHER_AGENT = keyed('7'.repeat(64), 'did:web:helix.example:agents:ee55');

export interface WorldOptions {
  agentScopes?: Record<string, string[] | undefined>;
  consent?: Partial<ConsentServiceOptions>;
}

export function consentWorld(options: WorldOptions = {}) {
  const documents: Record<string, DIDDocument> = {};
  for (const party of [HELIX, SERVICE, OTHER_SERVICE, STRANGER_SERVICE, AGENT, OTHER_AGENT]) documents[party.did] = testDidDocument(party.did, party.publicKey);
  const resolve = (async (did: string) => (did.startsWith('did:key:') ? didKeyDocument(did) : (documents[did] ?? null))) as unknown as DidResolver;
  let now = Date.now();
  const clock = (): number => now;
  const vcRepo = new VcRepository();
  const audit = new TestAuditTrail();
  const repo = new ConsentRepository();
  const keyTable = new WrappedKeyRepository();
  const keyStore = new DbKeyStore({ table: keyTable, keyEncryptionKey: 'ab'.repeat(32), clock: () => new Date(now) });
  const userKeys = new UserKeyService({ repo, keyStore, audit, clock });
  const publisher = new StatusListPublisher({
    repo: vcRepo,
    helixIssuerDid: HELIX.did,
    apiBaseUrl: API,
    signerFor: async (did) => (await userKeys.statusListSignerFor(did)) ?? (did === HELIX.did ? HELIX.signer : undefined),
    resolveDid: resolve,
    listTtlSeconds: 600,
    refreshBeforeSeconds: 60,
    signedCache: new InProcessCache<string>(),
    audit,
    clock,
  });
  const statusLists = new StatusListService({ publisher, repo: vcRepo, audit });
  const credentials = new CredentialService(
    vcRepo,
    statusLists,
    { resolveDID: vi.fn(async () => ({})), registerResolvedDID: vi.fn(async () => undefined) } as never,
    HELIX.signer,
    new DidKeyRepository(),
    new AesGcmKeyCustody('22'.repeat(32)),
    audit,
  );
  const revocations = new RevocationService({ repo: vcRepo, statusLists, resolveDid: resolve, audience: `${API}/v1/revocations`, clock });
  const known: Record<string, { name?: string }> = { [SERVICE.did]: { name: 'Shop' }, [OTHER_SERVICE.did]: {} };
  const consent = new ConsentService({
    repo,
    userKeys,
    credentials,
    revocations,
    resolveDid: resolve,
    apiBaseUrl: API,
    serviceOf: async (did) => known[did],
    agentScopesOf: async (did) => options.agentScopes?.[did],
    audit,
    clock,
    ...options.consent,
  });

  /** The unsigned root grant a service fills from its catalog. */
  const grant = (overrides: { agent?: string; service?: string; scopes?: string[]; windowSeconds?: number } = {}): Record<string, unknown> => {
    const service = overrides.service ?? SERVICE.did;
    return {
      validUntil: new Date(now + (overrides.windowSeconds ?? 86400) * 1000).toISOString(),
      credentialSubject: {
        invoker: overrides.agent ?? AGENT.did,
        invocationTarget: service,
        parentCapability: service,
        allowedAction: overrides.scopes ?? ['orders:read'],
      },
    };
  };
  const signed = (body: Record<string, unknown>, signer: Signer, typ: string, path: string): Promise<string> =>
    signRequest(body, signer, typ, `${API}/v1/consent/${path}`, now);
  const requestJws = (body: Record<string, unknown>, signer: Signer = SERVICE.signer): Promise<string> =>
    signed({ serviceUserId: 'user-1', grant: grant(), ...body }, signer, CONSENT_REQUEST_TYP, 'requests');
  const renewalJws = (body: Record<string, unknown>, signer: Signer = AGENT.signer): Promise<string> => signed(body, signer, CONSENT_RENEWAL_TYP, 'renewals');
  const withdrawalJws = (body: Record<string, unknown>, signer: Signer = SERVICE.signer): Promise<string> =>
    signed(body, signer, CONSENT_WITHDRAWAL_TYP, 'withdrawals');

  /** Request, page, click: the approved consent. */
  const consentTo = async (body: Record<string, unknown> = {}, signer: Signer = SERVICE.signer) => {
    const created = await consent.createRequest(await requestJws(body, signer), 'req-create');
    const page = await consent.openPage(created.id);
    const approved = await consent.approve(created.id, { cookieToken: page.pageToken, formToken: page.pageToken, grantDigest: page.request.grantDigest }, 'req-approve');
    return { created, page, approved };
  };

  /** Reads a hop's bit the way a verifier does: the list's proof first (by its own issuer), then the bit. */
  const bitOf = async (credential: { credentialStatus: { statusListCredential: string; statusListIndex: string } }) => {
    const listId = publisher.listIdOfUrl(credential.credentialStatus.statusListCredential)!;
    const list = await statusLists.getSigned(listId);
    const read = await kyaos.verifier.readBitstringStatusList(list, { resolveDid: resolve as never });
    return { issuer: list.issuer, bit: Boolean(kyaos.verifier.readStatusBit(read.bits, Number(credential.credentialStatus.statusListIndex))) };
  };

  return {
    documents,
    resolve,
    vcRepo,
    audit,
    repo,
    keyTable,
    keyStore,
    userKeys,
    publisher,
    statusLists,
    credentials,
    revocations,
    consent,
    known,
    grant,
    requestJws,
    renewalJws,
    withdrawalJws,
    consentTo,
    bitOf,
    advance: (seconds: number) => {
      now += seconds * 1000;
    },
    now: () => now,
  };
}

export type ConsentWorld = ReturnType<typeof consentWorld>;
