// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// The `agents` table: one row per onboarded agent, keyed by its DID, carrying
// the name it was onboarded with, its owner-controlled visibility and what is
// known about its own onboarding credential (so a registry can filter and
// page on status without reading `vcs`). No account column: a hosted build
// attributes rows to accounts with its own link table, as for `services`.
// Enrollment tokens and challenges stay in AgentRepository.

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../storage/sqlite.js';
import type { StorageDriverKind } from '../storage/driver-registry.js';
import {
  createAgentRecordStorageDriver,
  type AgentRecordStorageDriver,
} from './drivers/agent-record.drivers.js';

export const AGENT_VISIBILITIES = ['private', 'public'] as const;
export type AgentVisibility = (typeof AGENT_VISIBILITIES)[number];

export const AGENT_STATUS_FILTERS = ['active', 'revoked', 'all'] as const;
export type AgentStatusFilter = (typeof AGENT_STATUS_FILTERS)[number];

/** An agent is revoked when its own credential is revoked or expired, or it has none. */
export type AgentStatus = 'active' | 'revoked';

export interface AgentRecord {
  did: string;
  name: string | null;
  visibility: AgentVisibility;
  visibilityChangedAt: Date | null;
  publishedAt: Date | null;
  credentialVcId: string | null;
  credentialExpiresAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface AgentCreateData {
  did: string;
  name: string | null;
  visibility: AgentVisibility;
  credentialVcId: string | null;
  credentialExpiresAt: Date | null;
  revokedAt: Date | null;
  /** Set together with a public visibility, so an agent enrolled as public is listed at once. */
  publishedAt: Date | null;
  createdAt: Date;
}

/** What the row knows about the agent's own credential. */
export interface AgentCredentialState {
  credentialVcId: string | null;
  credentialExpiresAt: Date | null;
  revokedAt: Date | null;
}

export interface PublicAgentQuery {
  /** Already trimmed and length-checked. Matches the name (case-insensitive substring) or the exact DID. */
  q?: string | undefined;
  status: AgentStatusFilter;
  /** Rows to return. Callers ask for one more than a page to learn whether another page exists. */
  limit: number;
  /** Keyset position: rows strictly after this one in (publishedAt desc, did asc) order. */
  after?: { publishedAt: Date; did: string } | undefined;
  /** The instant credential expiry is judged against. */
  now: Date;
}

/** A public row as a registry needs it. */
export interface PublicAgentRow {
  did: string;
  name: string | null;
  publishedAt: Date;
  status: AgentStatus;
}

/**
 * AgentRecordRepository is a thin delegator over an AgentRecordStorageDriver —
 * see storage/driver-registry.ts for the pattern. The (prisma?, sqlite?)
 * constructor signature matches every other repository here on purpose.
 */
export class AgentRecordRepository {
  private readonly driver: AgentRecordStorageDriver;

  constructor(
    private readonly prisma?: PrismaClient,
    private readonly sqlite?: SqliteStore,
  ) {
    this.driver = createAgentRecordStorageDriver(this.resolveDriverKind(), { prisma, sqlite });
  }

  private resolveDriverKind(): StorageDriverKind {
    if (this.prisma) return 'postgres';
    if (this.sqlite) return 'sqlite';
    return 'memory';
  }

  /** Inserts the row, or returns the one already there for this DID untouched. */
  async create(data: AgentCreateData): Promise<AgentRecord> {
    return this.driver.create(data);
  }

  async findByDid(did: string): Promise<AgentRecord | null> {
    return this.driver.findByDid(did);
  }

  /**
   * Sets the visibility and stamps the change. publishedAt is set to `at` when
   * the agent becomes public and cleared when it becomes private. Null when
   * the DID is unknown.
   */
  async setVisibility(did: string, visibility: AgentVisibility, at: Date): Promise<AgentRecord | null> {
    return this.driver.setVisibility(did, visibility, at);
  }

  async updateCredentialState(did: string, state: AgentCredentialState): Promise<void> {
    return this.driver.updateCredentialState(did, state);
  }

  /** Marks revoked the agent whose own credential this is, if any. Already-revoked rows keep their time. */
  async markRevokedByCredential(vcId: string, revokedAt: Date): Promise<void> {
    return this.driver.markRevokedByCredential(vcId, revokedAt);
  }

  /** Public agents only, selected and ordered in the query itself. */
  async listPublic(query: PublicAgentQuery): Promise<PublicAgentRow[]> {
    return this.driver.listPublic(query);
  }
}
