// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// KYA-OS story F-3. Two repositories over the custody tables:
//
// - CustodyRepository: `custody_records` (the custody choice and onboarding
//   state of each agent, service and owner) and `custody_keys` (every key a
//   subject has had, public half only, for rotation). Public facts only.
// - WrappedKeyRepository: `wrapped_keys`, the Helix-held private keys in
//   their AES-256-GCM wrapping. Only DbKeyStore uses it (stories rule 8: no
//   code path reads a private key from a table directly).
//
// Same (prisma?, sqlite?) constructor and driver pattern as every other
// repository here (storage/driver-registry.ts).

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../storage/sqlite.js';
import type { StorageDriverKind } from '../storage/driver-registry.js';
import type { CustodySubjectType, DidHostingMode, KeyCustodyMode, KeyStoreSubjectType, PublicKeyJwk } from '../core/index.js';
import {
  createCustodyStorageDriver,
  createWrappedKeyStorageDriver,
  type CustodyStorageDriver,
  type WrappedKeyStorageDriver,
} from './drivers/custody.drivers.js';

export const CUSTODY_STATUSES = ['pending_key', 'pending_resolution', 'active'] as const;
export type CustodyStatus = (typeof CUSTODY_STATUSES)[number];

export type CustodyKeyLocation = 'self' | 'helix';
/**
 * `active`: current; `retiring`: superseded, inside its overlap window;
 * `retired`: superseded, overlap over (story C-E: it stays in the DID
 * document with `validUntil`); `revoked`: compromised (it stays with
 * `revoked`, and nothing it signed is accepted).
 */
export type CustodyKeyStatus = 'active' | 'retiring' | 'retired' | 'revoked';

export interface CustodyRecordRow {
  did: string;
  subjectType: CustodySubjectType;
  keyCustody: KeyCustodyMode;
  didHosting: DidHostingMode;
  status: CustodyStatus;
  /** Current verification-method id, `<did>#<fragment>`; null until a key is registered. */
  kid: string | null;
  name: string | null;
  ownerDid: string | null;
  scopes: string[] | null;
  /** Agents: normalized domain URLs, published as `#domain-N` LinkedDomains service entries. */
  requestedDomains: string[] | null;
  /** Agents: written on the identity credential (0 to 5). */
  maxDelegationDepth: number;
  enrollmentTokenHash: string | null;
  enrollmentExpiresAt: Date | null;
  enrollmentNonce: string | null;
  enrollmentUsedAt: Date | null;
  credentialVcId: string | null;
  activatedAt: Date | null;
  /** Own hosting: when the subject started waiting for its documents (the background re-check stops a bounded time after). */
  pendingResolutionSince: Date | null;
  /** Background re-checks made so far; sets the backoff. */
  recheckAttempts: number;
  /** When the background re-check is next due; null when none is scheduled (active, or it gave up). */
  nextRecheckAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type NewCustodyRecord = Omit<CustodyRecordRow, 'createdAt' | 'updatedAt' | 'pendingResolutionSince' | 'recheckAttempts' | 'nextRecheckAt'> &
  Partial<Pick<CustodyRecordRow, 'pendingResolutionSince' | 'recheckAttempts' | 'nextRecheckAt'>>;
export type CustodyRecordPatch = Partial<Omit<CustodyRecordRow, 'did' | 'subjectType' | 'createdAt' | 'updatedAt'>>;

export interface CustodyKeyRow {
  did: string;
  kid: string;
  location: CustodyKeyLocation;
  publicKeyJwk: PublicKeyJwk;
  status: CustodyKeyStatus;
  sequence: number;
  createdAt: Date;
  retiresAt: Date | null;
  revokedAt: Date | null;
}

export type NewCustodyKey = Omit<CustodyKeyRow, 'createdAt'>;
export type CustodyKeyPatch = Partial<Pick<CustodyKeyRow, 'status' | 'retiresAt' | 'revokedAt'>>;

export interface CustodyRecordFilter {
  subjectType?: CustodySubjectType | undefined;
  dids?: readonly string[] | undefined;
}

export interface WrappedKeyRow {
  did: string;
  kid: string;
  subjectType: KeyStoreSubjectType;
  algorithm: string;
  kekId: string;
  /** base64url; empty once shredded. */
  nonce: string;
  /** base64url of ciphertext || tag; empty once shredded. */
  ciphertext: string;
  publicKeyJwk: PublicKeyJwk;
  createdAt: Date;
  shreddedAt: Date | null;
}

export type NewWrappedKey = Omit<WrappedKeyRow, 'createdAt' | 'shreddedAt'>;

function driverKind(prisma?: PrismaClient, sqlite?: SqliteStore): StorageDriverKind {
  if (prisma) return 'postgres';
  if (sqlite) return 'sqlite';
  return 'memory';
}

export class CustodyRepository {
  private readonly driver: CustodyStorageDriver;

  constructor(prisma?: PrismaClient, sqlite?: SqliteStore) {
    this.driver = createCustodyStorageDriver(driverKind(prisma, sqlite), { prisma, sqlite });
  }

  createRecord(row: NewCustodyRecord): Promise<CustodyRecordRow> {
    return this.driver.createRecord(row);
  }

  findRecord(did: string): Promise<CustodyRecordRow | null> {
    return this.driver.findRecord(did);
  }

  findRecordByEnrollmentToken(tokenHash: string): Promise<CustodyRecordRow | null> {
    return this.driver.findRecordByEnrollmentToken(tokenHash);
  }

  updateRecord(did: string, patch: CustodyRecordPatch): Promise<CustodyRecordRow> {
    return this.driver.updateRecord(did, patch);
  }

  /** Marks the enrollment token used; false when another request used it first. */
  claimEnrollment(did: string, at: Date): Promise<boolean> {
    return this.driver.claimEnrollment(did, at);
  }

  /**
   * Status compare-and-set: applies `patch` only while the record is still in
   * `from`, and returns the updated row, or null when another request or API
   * instance moved it first. Activation goes through this, so a subject is
   * activated once.
   */
  transitionStatus(did: string, from: CustodyStatus, patch: CustodyRecordPatch): Promise<CustodyRecordRow | null> {
    return this.driver.transitionStatus(did, from, patch);
  }

  /** `pending_resolution` subjects whose background re-check is due at `now`, soonest first, at most `limit`. */
  listDueRechecks(now: Date, limit: number): Promise<CustodyRecordRow[]> {
    return this.driver.listDueRechecks(now, limit);
  }

  /**
   * Claims one due re-check: moves `nextRecheckAt` from `expected` to
   * `next.nextRecheckAt` while the subject is still `pending_resolution`.
   * False when another API instance claimed it first.
   */
  claimRecheck(did: string, expected: Date, next: { nextRecheckAt: Date | null; recheckAttempts: number }): Promise<boolean> {
    return this.driver.claimRecheck(did, expected, next);
  }

  /** Oldest first. */
  listRecords(filter: CustodyRecordFilter = {}): Promise<CustodyRecordRow[]> {
    return this.driver.listRecords(filter);
  }

  addKey(row: NewCustodyKey): Promise<CustodyKeyRow> {
    return this.driver.addKey(row);
  }

  /** In sequence order. */
  listKeys(did: string): Promise<CustodyKeyRow[]> {
    return this.driver.listKeys(did);
  }

  /** Story C-E: the subjects with a retiring key whose overlap ended by `now`, at most `limit`. */
  listRetiringDue(now: Date, limit: number): Promise<string[]> {
    return this.driver.listRetiringDue(now, limit);
  }

  updateKey(did: string, kid: string, patch: CustodyKeyPatch): Promise<CustodyKeyRow> {
    return this.driver.updateKey(did, kid, patch);
  }
}

/** Private-key rows. DbKeyStore is the only intended caller (stories rule 8). */
export class WrappedKeyRepository {
  private readonly driver: WrappedKeyStorageDriver;

  constructor(prisma?: PrismaClient, sqlite?: SqliteStore) {
    this.driver = createWrappedKeyStorageDriver(driverKind(prisma, sqlite), { prisma, sqlite });
  }

  insert(row: NewWrappedKey): Promise<WrappedKeyRow> {
    return this.driver.insert(row);
  }

  find(did: string, kid: string): Promise<WrappedKeyRow | null> {
    return this.driver.find(did, kid);
  }

  list(did: string): Promise<WrappedKeyRow[]> {
    return this.driver.list(did);
  }

  /** Empties the wrapped private key and stamps shreddedAt. False when there was nothing left to shred. */
  shred(did: string, kid: string, at: Date): Promise<boolean> {
    return this.driver.shred(did, kid, at);
  }
}
