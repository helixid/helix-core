import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../storage/sqlite.js';
import type { StorageDriverKind } from '../storage/driver-registry.js';
import { createDidKeyStorageDriver, type DidKeyStorageDriver } from './drivers/did-key.drivers.js';

/**
 * Who a custody-held key belongs to. Every private key the platform signs
 * with lives in the one `did_keys` table, whatever kind of DID it is for —
 * nobody (agent, service, issuer, user) holds their own key any more.
 */
export type DidKeySubjectType = 'agent' | 'service' | 'issuer' | 'user';

export interface DidKeyRecord {
  id: string;
  did: string;
  subjectType: DidKeySubjectType;
  encryptedPrivateKey: string;
  iv: string;
  authTag: string;
  algorithm: string;
  createdAt?: Date;
}

export interface CreateDidKeyRecordParams {
  did: string;
  subjectType: DidKeySubjectType;
  encryptedPrivateKey: string;
  iv: string;
  authTag: string;
  algorithm: string;
}

/**
 * DidKeyRepository is a thin delegator over a DidKeyStorageDriver — see
 * storage/driver-registry.ts for the pattern and
 * repositories/drivers/did.drivers.ts for the reference implementation.
 * The (prisma?, sqlite?) constructor signature matches every other
 * repository in this package on purpose — see did.repository.ts's class
 * doc comment for the full rationale.
 */
export class DidKeyRepository {
  private readonly driver: DidKeyStorageDriver;

  constructor(
    private readonly prisma?: PrismaClient,
    private readonly sqlite?: SqliteStore,
  ) {
    this.driver = createDidKeyStorageDriver(this.resolveDriverKind(), { prisma, sqlite });
  }

  private resolveDriverKind(): StorageDriverKind {
    if (this.prisma) return 'postgres';
    if (this.sqlite) return 'sqlite';
    return 'memory';
  }

  async create(data: CreateDidKeyRecordParams): Promise<DidKeyRecord> {
    return this.driver.create(data);
  }

  async findByDid(did: string): Promise<DidKeyRecord | null> {
    return this.driver.findByDid(did);
  }
}
