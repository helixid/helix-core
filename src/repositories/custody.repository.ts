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
export type CustodyKeyStatus = 'active' | 'retiring' | 'revoked';

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
  enrollmentTokenHash: string | null;
  enrollmentExpiresAt: Date | null;
  enrollmentNonce: string | null;
  enrollmentUsedAt: Date | null;
  credentialVcId: string | null;
  activatedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export type NewCustodyRecord = Omit<CustodyRecordRow, 'createdAt' | 'updatedAt'>;
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
