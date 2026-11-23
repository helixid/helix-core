// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// KYA-OS story L3-H. The consent records, public facts only:
//
// - `user_keys`: one pairwise did:key per (service, service user) per consent
//   cycle. The private half is in the KeyStore (stories rule 8), never here;
//   this row keeps the DID string, which outlives the key (crypto-shredding).
// - `consent_requests`: the unsigned root grant a service submitted, until the
//   user approves or denies it on the consent page.
// - `user_consents`: what the user approved (consent type `user-signed`): the
//   grant, the consented window, the hop lifetime, and its newest hop.
//
// The service's user id is never stored: only `serviceUserRef`, a SHA-256 of
// (service DID, service user id). Same (prisma?, sqlite?) driver pattern as
// every other repository (storage/driver-registry.ts).

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../storage/sqlite.js';
import type { StorageDriverKind } from '../storage/driver-registry.js';
import { createConsentStorageDriver, type ConsentStorageDriver } from './drivers/consent.drivers.js';

export const CONSENT_REQUEST_STATUSES = ['pending', 'approved', 'denied'] as const;
export type ConsentRequestStatus = (typeof CONSENT_REQUEST_STATUSES)[number];

/** The root DelegationCredential a service submits, unsigned: SPEC.md §6.10 members a service can fill. */
export interface UnsignedRootGrant {
  invoker: string;
  invocationTarget: string;
  parentCapability: string;
  allowedAction: string[];
  caveats?: Array<Record<string, unknown>> | undefined;
  /** The end of the consented window (each hop's `validUntil` sits inside it). */
  validUntil: string;
}

/** How the page is branded as the service. */
export interface ConsentDisplay {
  serviceName?: string | undefined;
  logoUrl?: string | undefined;
  agentName?: string | undefined;
}

export interface ConsentRequestRow {
  id: string;
  serviceDid: string;
  serviceUserRef: string;
  agentDid: string;
  grant: UnsignedRootGrant;
  /** `sha256:<hex>` over the JCS of `grant`: what the page shows and the click names. */
  grantDigest: string;
  windowUntil: Date;
  /** Each hop's lifetime; null: one hop for the whole window. */
  hopLifetimeSeconds: number | null;
  display: ConsentDisplay | null;
  returnUrl: string | null;
  status: ConsentRequestStatus;
  /** SHA-256 of the page session token, set when the page is shown; null until then. */
  pageTokenHash: string | null;
  expiresAt: Date;
  createdAt: Date;
  decidedAt: Date | null;
  consentId: string | null;
}

export type NewConsentRequest = Omit<ConsentRequestRow, 'createdAt' | 'decidedAt' | 'consentId' | 'pageTokenHash' | 'status'>;
export type ConsentRequestPatch = Partial<Pick<ConsentRequestRow, 'status' | 'pageTokenHash' | 'decidedAt' | 'consentId'>>;

export interface UserKeyRow {
  did: string;
  kid: string;
  serviceDid: string;
  serviceUserRef: string;
  createdAt: Date;
  /** When the private half was destroyed; the DID string stays. */
  shreddedAt: Date | null;
}

export type NewUserKey = Omit<UserKeyRow, 'createdAt' | 'shreddedAt'>;

export type ConsentType = 'user-signed';

export interface UserConsentRow {
  id: string;
  requestId: string;
  userDid: string;
  serviceDid: string;
  serviceUserRef: string;
  agentDid: string;
  invocationTarget: string;
  allowedAction: string[];
  caveats: Array<Record<string, unknown>> | null;
  windowUntil: Date;
  hopLifetimeSeconds: number | null;
  consentType: ConsentType;
  createdAt: Date;
  withdrawnAt: Date | null;
  /** The newest hop signed under this consent. */
  latestHopId: string;
  /** The latest `validUntil` of any hop signed under this consent. */
  lastHopUntil: Date;
}

export type NewUserConsent = Omit<UserConsentRow, 'createdAt' | 'withdrawnAt'>;
export type UserConsentPatch = Partial<Pick<UserConsentRow, 'withdrawnAt' | 'latestHopId' | 'lastHopUntil'>>;

export interface UserConsentFilter {
  userDid?: string | undefined;
  serviceDid?: string | undefined;
  serviceUserRef?: string | undefined;
  agentDid?: string | undefined;
}

function driverKind(prisma?: PrismaClient, sqlite?: SqliteStore): StorageDriverKind {
  if (prisma) return 'postgres';
  if (sqlite) return 'sqlite';
  return 'memory';
}

export class ConsentRepository {
  private readonly driver: ConsentStorageDriver;

  constructor(prisma?: PrismaClient, sqlite?: SqliteStore) {
    this.driver = createConsentStorageDriver(driverKind(prisma, sqlite), { prisma, sqlite });
  }

  createRequest(row: NewConsentRequest): Promise<ConsentRequestRow> {
    return this.driver.createRequest(row);
  }

  findRequest(id: string): Promise<ConsentRequestRow | null> {
    return this.driver.findRequest(id);
  }

  /** Compare-and-set: applies `patch` only while the request is still `from`; null when it moved first. */
  transitionRequest(id: string, from: ConsentRequestStatus, patch: ConsentRequestPatch): Promise<ConsentRequestRow | null> {
    return this.driver.transitionRequest(id, from, patch);
  }

  /** Whether any consent request ever named `agentDid` (its card then leaves `responsibleParty` out). */
  hasRequestForAgent(agentDid: string): Promise<boolean> {
    return this.driver.hasRequestForAgent(agentDid);
  }

  createUserKey(row: NewUserKey): Promise<UserKeyRow> {
    return this.driver.createUserKey(row);
  }

  findUserKey(did: string): Promise<UserKeyRow | null> {
    return this.driver.findUserKey(did);
  }

  /** The unshredded key of (service, service user), newest first; null when the cycle has none. */
  findLiveUserKey(serviceDid: string, serviceUserRef: string): Promise<UserKeyRow | null> {
    return this.driver.findLiveUserKey(serviceDid, serviceUserRef);
  }

  /** Every key whose private half still exists, oldest first. */
  listLiveUserKeys(): Promise<UserKeyRow[]> {
    return this.driver.listLiveUserKeys();
  }

  /** Marks the key shredded; false when it already was. */
  markUserKeyShredded(did: string, at: Date): Promise<boolean> {
    return this.driver.markUserKeyShredded(did, at);
  }

  createConsent(row: NewUserConsent): Promise<UserConsentRow> {
    return this.driver.createConsent(row);
  }

  findConsent(id: string): Promise<UserConsentRow | null> {
    return this.driver.findConsent(id);
  }

  updateConsent(id: string, patch: UserConsentPatch): Promise<UserConsentRow> {
    return this.driver.updateConsent(id, patch);
  }

  /** Oldest first. */
  listConsents(filter: UserConsentFilter): Promise<UserConsentRow[]> {
    return this.driver.listConsents(filter);
  }
}
