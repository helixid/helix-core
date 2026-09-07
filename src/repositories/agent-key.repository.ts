import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../storage/sqlite.js';
import type { StorageDriverKind } from '../storage/driver-registry.js';
import { createAgentKeyStorageDriver, type AgentKeyStorageDriver } from './drivers/agent-key.drivers.js';

export interface AgentKeyRecord {
  id: string;
  did: string;
  encryptedPrivateKey: string;
  iv: string;
  authTag: string;
  algorithm: string;
  createdAt?: Date;
}

export interface CreateAgentKeyRecordParams {
  did: string;
  encryptedPrivateKey: string;
  iv: string;
  authTag: string;
  algorithm: string;
}

/**
 * AgentKeyRepository is a thin delegator over an AgentKeyStorageDriver — see
 * storage/driver-registry.ts for the pattern and
 * repositories/drivers/did.drivers.ts for the reference implementation.
 * The (prisma?, sqlite?) constructor signature matches every other
 * repository in this package on purpose — see did.repository.ts's class
 * doc comment for the full rationale.
 */
export class AgentKeyRepository {
  private readonly driver: AgentKeyStorageDriver;

  constructor(
    private readonly prisma?: PrismaClient,
    private readonly sqlite?: SqliteStore,
  ) {
    this.driver = createAgentKeyStorageDriver(this.resolveDriverKind(), { prisma, sqlite });
  }

  private resolveDriverKind(): StorageDriverKind {
    if (this.prisma) return 'postgres';
    if (this.sqlite) return 'sqlite';
    return 'memory';
  }

  async create(data: CreateAgentKeyRecordParams): Promise<AgentKeyRecord> {
    return this.driver.create(data);
  }

  async findByDid(did: string): Promise<AgentKeyRecord | null> {
    return this.driver.findByDid(did);
  }
}
