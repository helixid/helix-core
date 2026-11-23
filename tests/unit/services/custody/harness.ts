// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: a CustodyService over in-memory tables, a real DbKeyStore, and a fake owner's domain.
import * as ed25519 from '@noble/ed25519';
import {
  base64UrlEncode,
  enrollmentProofMessage,
  publicKeyBytesToJwk,
  rotationProofMessage,
  type OutboundFetch,
  type PublicKeyJwk,
} from '../../../../src/core/index.js';
import { DidRepository } from '../../../../src/repositories/did.repository.js';
import { ServiceRepository } from '../../../../src/repositories/service.repository.js';
import { CustodyRepository } from '../../../../src/repositories/custody.repository.js';
import { InMemoryWrappedKeyStorageDriver } from '../../../../src/repositories/drivers/custody.drivers.js';
import { DbKeyStore } from '../../../../src/services/custody/db-key-store.js';
import { CustodyService, type CustodyContext, type CustodyServiceOptions } from '../../../../src/services/custody/custody.service.js';
import { CustodyAudit, payloadDigest } from '../../../../src/services/custody/custody-audit.js';
import { TestAuditTrail } from '../../../utils/TestAuditTrail.js';

/**
 * The custody facts each CustodyAudit call carried, by the event names F-3
 * used before story A-1. The typed events those calls record are tested in
 * custody-audit.test.ts; the service tests assert the facts.
 */
export const CustodyEvents = {
  CUSTODY_CHOSEN: 'CUSTODY_CHOSEN',
  CUSTODY_ACTIVATED: 'CUSTODY_ACTIVATED',
  AGENT_ONBOARDED: 'AGENT_ONBOARDED',
  CUSTODY_CHANGED: 'CUSTODY_CHANGED',
  CUSTODY_KEY_REVOKED: 'CUSTODY_KEY_REVOKED',
  CUSTODY_KEY_SHREDDED: 'CUSTODY_KEY_SHREDDED',
  CUSTODIAL_SIGNATURE: 'CUSTODIAL_SIGNATURE',
  CUSTODIAL_SIGNING_REFUSED: 'CUSTODIAL_SIGNING_REFUSED',
} as const;

const METHOD_EVENTS: Record<string, string> = {
  chosen: CustodyEvents.CUSTODY_CHOSEN,
  activated: CustodyEvents.CUSTODY_ACTIVATED,
  agentOnboarded: CustodyEvents.AGENT_ONBOARDED,
  changed: CustodyEvents.CUSTODY_CHANGED,
  keyRevoked: CustodyEvents.CUSTODY_KEY_REVOKED,
  keyShredded: CustodyEvents.CUSTODY_KEY_SHREDDED,
  signature: CustodyEvents.CUSTODIAL_SIGNATURE,
  signingRefused: CustodyEvents.CUSTODIAL_SIGNING_REFUSED,
};

/** The custody facts recorded, oldest first, plus the typed trail they went to. */
export interface CustodyAuditCapture {
  events: { event: { event: string }; payload: Record<string, unknown> }[];
  trail: TestAuditTrail;
}

/** Wraps the service's CustodyAudit so each call's facts are kept; a signature's payload is kept by digest and length. */
function captureCustodyAudit(service: CustodyService, trail: TestAuditTrail): CustodyAuditCapture {
  const capture: CustodyAuditCapture = { events: [], trail };
  const audit = (service as unknown as { audit: CustodyAudit }).audit;
  for (const [method, event] of Object.entries(METHOD_EVENTS)) {
    const original = (audit as unknown as Record<string, (input: Record<string, unknown>) => void>)[method]!.bind(audit);
    (audit as unknown as Record<string, (input: Record<string, unknown>) => void>)[method] = (input) => {
      const { payload, ...rest } = input;
      const facts = payload instanceof Uint8Array ? { ...rest, payloadDigest: payloadDigest(payload), payloadBytes: payload.length } : input;
      capture.events.push({ event: { event }, payload: facts });
      original(input);
    };
  }
  return capture;
}

export const HOST = 'helix.example';
export const KEK = '5a'.repeat(32);

export interface ClientKey {
  seed: Uint8Array;
  publicKeyJwk: PublicKeyJwk;
  sign(message: Uint8Array): string;
  forms: string[];
}

let counter = 1;
/** A key the "client" generates and holds; Helix must never see `seed` in any form. */
export function clientKey(): ClientKey {
  const seed = new Uint8Array(32).map((_, index) => (counter * 13 + index * 5 + 1) % 256);
  counter += 1;
  const publicKeyJwk = publicKeyBytesToJwk(ed25519.getPublicKey(seed));
  return {
    seed,
    publicKeyJwk,
    sign: (message) => base64UrlEncode(ed25519.sign(message, seed)),
    forms: [Buffer.from(seed).toString('hex'), Buffer.from(seed).toString('base64url'), Buffer.from(seed).toString('base64')],
  };
}

export function enrollmentSignature(key: ClientKey, did: string, kid: string, nonce: string): string {
  return key.sign(enrollmentProofMessage({ did, kid, nonce }));
}

export function rotationProof(key: ClientKey, did: string, kid: string, issuedAt = new Date().toISOString()) {
  return { issuedAt, signature: key.sign(rotationProofMessage({ did, kid, issuedAt })) };
}

export interface Harness {
  service: CustodyService;
  records: CustodyRepository;
  wrapped: InMemoryWrappedKeyStorageDriver;
  keyStore: DbKeyStore;
  dids: DidRepository;
  services: ServiceRepository;
  audit: CustodyAuditCapture;
  /** Identity credentials issued (story F-1), in order; `vcId` is `vc:test:<n>`. */
  issued: { input: Record<string, unknown>; vcId: string }[];
  /** Capability attestations issued, one per scope. */
  attested: { agentDid: string; capability: string; vcId: string }[];
  /** The owner's domain: URL → JSON body (or a status code). */
  web: Map<string, unknown>;
  fetched: string[];
  now: { value: Date };
  didCacheDeleted: string[];
  context(overrides?: Partial<CustodyContext>): CustodyContext;
}

export function harness(overrides: Partial<CustodyServiceOptions> = {}): Harness {
  const records = new CustodyRepository();
  const wrapped = new InMemoryWrappedKeyStorageDriver();
  const keyStore = new DbKeyStore({ table: wrapped, keyEncryptionKey: KEK });
  const dids = new DidRepository();
  const services = new ServiceRepository();
  const trail = new TestAuditTrail();
  const issued: Harness['issued'] = [];
  const attested: Harness['attested'] = [];
  const web = new Map<string, unknown>();
  const fetched: string[] = [];
  const now = { value: new Date('2026-11-21T10:00:00Z') };
  const didCacheDeleted: string[] = [];
  const outbound: OutboundFetch = async (url) => {
    fetched.push(url);
    const body = web.get(url);
    if (body === undefined) return { ok: false, status: 404, json: async () => ({}) };
    if (typeof body === 'number') return { ok: false, status: body, json: async () => ({}) };
    if (body instanceof Error) throw body;
    if (body === 'not-json') return { ok: true, status: 200, json: async () => { throw new SyntaxError('bad'); } };
    return { ok: true, status: 200, json: async () => JSON.parse(JSON.stringify(body)) };
  };
  const service = new CustodyService({
    records,
    keyStore,
    didRepository: dids,
    credentials: {
      issuerDid: 'did:web:helix.example',
      issueIdentity: async (input) => {
        const vcId = `vc:test:${issued.length + 1}`;
        issued.push({ input: input as unknown as Record<string, unknown>, vcId });
        return { id: vcId };
      },
      issueAttestations: async (input) =>
        input.capabilities.map((capability) => {
          const vcId = `att:test:${attested.length + 1}`;
          attested.push({ agentDid: input.agentDid, capability, vcId });
          return { id: vcId };
        }),
    },
    services,
    auditTrail: trail,
    host: HOST,
    didCache: { delete: (did: string) => void didCacheDeleted.push(did) },
    outboundFetch: () => outbound,
    clock: () => now.value,
    ...overrides,
  });
  const audit = captureCustodyAudit(service, trail);
  return {
    service,
    records,
    wrapped,
    keyStore,
    dids,
    services,
    audit,
    issued,
    attested,
    web,
    fetched,
    now,
    didCacheDeleted,
    context: (extra = {}) => ({ requestId: 'req_test', actor: 'admin', ...extra }),
  };
}

/** Every event of one type, as logged. */
export function events(h: Harness, type: string): Record<string, unknown>[] {
  return h.audit.events.filter((entry) => entry.event.event === type).map((entry) => entry.payload);
}
