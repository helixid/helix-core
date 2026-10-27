// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Storage-driver implementations for AgentRepository — see
// storage/driver-registry.ts for the pattern and
// repositories/drivers/did.drivers.ts for the reference implementation.

import type { PrismaClient } from '@prisma/client';
import type { SqliteStore } from '../../storage/sqlite.js';
import { sqliteLiteral } from '../../storage/sqlite.js';
import {
  UnsupportedStorageDriverError,
  type StorageDriverDeps,
  type StorageDriverKind,
} from '../../storage/driver-registry.js';
import type {
  ChallengeRecord,
  EnrollmentTokenRecord,
} from '../agent.repository.js';

type PrismaRaw = PrismaClient & {
  $queryRawUnsafe<T = unknown>(query: string, ...values: unknown[]): Promise<T>;
};

export interface AgentStorageDriver {
  createEnrollmentToken(
    data: Omit<EnrollmentTokenRecord, 'id' | 'usedAt' | 'createdAt' | 'maxDelegationDepth'> & {
      maxDelegationDepth?: number;
    },
  ): Promise<EnrollmentTokenRecord>;
  findEnrollmentTokenByHash(tokenHash: string): Promise<EnrollmentTokenRecord | null>;
  findEnrollmentTokenById(id: string): Promise<EnrollmentTokenRecord | null>;
  burnEnrollmentTokenAtomically(tokenHash: string): Promise<boolean>;
  createChallenge(data: Omit<ChallengeRecord, 'id' | 'verifiedAt' | 'createdAt'>): Promise<ChallengeRecord>;
  findChallengeById(challengeId: string): Promise<ChallengeRecord | null>;
  markChallengeVerified(challengeId: string): Promise<ChallengeRecord>;
}

function makeId(prefix: string): string {
  return `${prefix}:${Math.random().toString(16).slice(2, 14)}`;
}

function toChallengeRecord(row: ChallengeRecord): ChallengeRecord {
  return {
    id: row.id,
    challengeId: row.challengeId,
    nonce: row.nonce,
    did: row.did,
    purpose: row.purpose,
    pendingPublicKeyHex: row.pendingPublicKeyHex,
    pendingDomains: row.pendingDomains,
    pendingDidCreateStateJson: row.pendingDidCreateStateJson,
    pendingDidCreatePayloadHex: row.pendingDidCreatePayloadHex,
    expiresAt: row.expiresAt,
    verifiedAt: row.verifiedAt,
    createdAt: row.createdAt,
    enrollmentTokenId: row.enrollmentTokenId,
  };
}

function requireChallengeRow(row: ChallengeRecord | undefined): ChallengeRecord {
  if (!row) throw new Error('Challenge query returned no rows');
  return row;
}

function requireEnrollmentTokenRow(row: EnrollmentTokenRecord | undefined): EnrollmentTokenRecord {
  if (!row) throw new Error('Enrollment token query returned no rows');
  return row;
}

function hasRealRaw(prisma: PrismaClient): boolean {
  return (
    typeof (prisma as Partial<PrismaRaw>).$queryRawUnsafe === 'function' &&
    typeof (prisma as { $connect?: unknown }).$connect === 'function'
  );
}

export class PrismaAgentStorageDriver implements AgentStorageDriver {
  constructor(private readonly prisma: PrismaClient) {}

  async createEnrollmentToken(
    data: Omit<EnrollmentTokenRecord, 'id' | 'usedAt' | 'createdAt' | 'maxDelegationDepth'> & {
      maxDelegationDepth?: number;
    },
  ): Promise<EnrollmentTokenRecord> {
    const record = (await this.prisma.enrollmentToken.create({
      data: {
        tokenHash: data.tokenHash,
        agentName: data.agentName,
        requestedScopes: data.requestedScopes,
        requestedDomains: data.requestedDomains,
        expiresAt: data.expiresAt,
      },
    })) as EnrollmentTokenRecord;
    if ((data.maxDelegationDepth ?? 0) > 0 && hasRealRaw(this.prisma)) {
      const rows = await (this.prisma as PrismaRaw).$queryRawUnsafe<EnrollmentTokenRecord[]>(
        `UPDATE "enrollment_tokens" SET "maxDelegationDepth" = $1 WHERE "id" = $2 RETURNING *`,
        data.maxDelegationDepth ?? 0,
        record.id,
      );
      return requireEnrollmentTokenRow(rows[0]);
    }
    return data.maxDelegationDepth === undefined
      ? record
      : {
          ...record,
          maxDelegationDepth: data.maxDelegationDepth ?? record.maxDelegationDepth ?? 0,
        };
  }

  async findEnrollmentTokenByHash(tokenHash: string): Promise<EnrollmentTokenRecord | null> {
    if (hasRealRaw(this.prisma)) {
      const rows = await (this.prisma as PrismaRaw).$queryRawUnsafe<EnrollmentTokenRecord[]>(
        `SELECT * FROM "enrollment_tokens" WHERE "tokenHash" = $1 LIMIT 1`,
        tokenHash,
      );
      return rows[0] ? rows[0] : null;
    }
    return this.prisma.enrollmentToken.findUnique({
      where: { tokenHash },
    }) as Promise<EnrollmentTokenRecord | null>;
  }

  async findEnrollmentTokenById(id: string): Promise<EnrollmentTokenRecord | null> {
    if (hasRealRaw(this.prisma)) {
      const rows = await (this.prisma as PrismaRaw).$queryRawUnsafe<EnrollmentTokenRecord[]>(
        `SELECT * FROM "enrollment_tokens" WHERE "id" = $1 LIMIT 1`,
        id,
      );
      return rows[0] ? rows[0] : null;
    }
    return this.prisma.enrollmentToken.findUnique({
      where: { id },
    }) as Promise<EnrollmentTokenRecord | null>;
  }

  async burnEnrollmentTokenAtomically(tokenHash: string): Promise<boolean> {
    const result = await this.prisma.enrollmentToken.updateMany({
      where: { tokenHash, usedAt: null },
      data: { usedAt: new Date() },
    });
    return result.count === 1;
  }

  async createChallenge(
    data: Omit<ChallengeRecord, 'id' | 'verifiedAt' | 'createdAt'>,
  ): Promise<ChallengeRecord> {
    const rows = await (this.prisma as PrismaRaw).$queryRawUnsafe<ChallengeRecord[]>(
      `INSERT INTO "challenges" (
        "id",
        "challengeId",
        "nonce",
        "did",
        "purpose",
        "pendingPublicKeyHex",
        "pendingDomains",
        "pendingDidCreateStateJson",
        "pendingDidCreatePayloadHex",
        "expiresAt",
        "enrollmentTokenId"
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *`,
      makeId('chdb'),
      data.challengeId,
      data.nonce,
      data.did,
      data.purpose,
      data.pendingPublicKeyHex,
      data.pendingDomains,
      data.pendingDidCreateStateJson ?? null,
      data.pendingDidCreatePayloadHex ?? null,
      data.expiresAt,
      data.enrollmentTokenId,
    );
    return toChallengeRecord(requireChallengeRow(rows[0]));
  }

  async findChallengeById(challengeId: string): Promise<ChallengeRecord | null> {
    const rows = await (this.prisma as PrismaRaw).$queryRawUnsafe<ChallengeRecord[]>(
      `SELECT * FROM "challenges" WHERE "challengeId" = $1 LIMIT 1`,
      challengeId,
    );
    return rows[0] ? toChallengeRecord(rows[0]) : null;
  }

  async markChallengeVerified(challengeId: string): Promise<ChallengeRecord> {
    const rows = await (this.prisma as PrismaRaw).$queryRawUnsafe<ChallengeRecord[]>(
      `UPDATE "challenges" SET "verifiedAt" = $1 WHERE "challengeId" = $2 RETURNING *`,
      new Date(),
      challengeId,
    );
    return toChallengeRecord(requireChallengeRow(rows[0]));
  }

}

type SqliteEnrollmentTokenRow = {
  id: string;
  token_hash: string;
  agent_name: string;
  requested_scopes: string;
  requested_domains: string;
  max_delegation_depth: number;
  expires_at: string | undefined;
  used_at: string | null;
  created_at: string;
};

type SqliteChallengeRow = {
  id: string;
  challenge_id: string;
  nonce: string;
  did: string;
  purpose: 'agent_onboarding' | 'user_verification';
  pending_public_key_hex: string | null;
  pending_domains: string | null;
  pending_did_create_state_json: string | null;
  pending_did_create_payload_hex: string | null;
  expires_at: string;
  verified_at: string | null;
  created_at: string;
  enrollment_token_id: string | null;
};

function fromEnrollmentTokenRow(
  row: SqliteEnrollmentTokenRow | undefined,
): EnrollmentTokenRecord | null {
  if (!row) return null;
  return {
    id: row.id,
    tokenHash: row.token_hash,
    agentName: row.agent_name,
    requestedScopes: row.requested_scopes,
    requestedDomains: row.requested_domains,
    maxDelegationDepth: row.max_delegation_depth,
    expiresAt: row.expires_at ? new Date(row.expires_at) : null,
    usedAt: row.used_at ? new Date(row.used_at) : null,
    createdAt: new Date(row.created_at),
  };
}

function fromChallengeRow(row: SqliteChallengeRow | undefined): ChallengeRecord | null {
  if (!row) return null;
  return {
    id: row.id,
    challengeId: row.challenge_id,
    nonce: row.nonce,
    did: row.did,
    purpose: row.purpose,
    pendingPublicKeyHex: row.pending_public_key_hex,
    pendingDomains: row.pending_domains,
    pendingDidCreateStateJson: row.pending_did_create_state_json,
    pendingDidCreatePayloadHex: row.pending_did_create_payload_hex,
    expiresAt: new Date(row.expires_at),
    verifiedAt: row.verified_at ? new Date(row.verified_at) : null,
    createdAt: new Date(row.created_at),
    enrollmentTokenId: row.enrollment_token_id,
  };
}

export class SqliteAgentStorageDriver implements AgentStorageDriver {
  constructor(private readonly sqlite: SqliteStore) {}

  async createEnrollmentToken(
    data: Omit<EnrollmentTokenRecord, 'id' | 'usedAt' | 'createdAt' | 'maxDelegationDepth'> & {
      maxDelegationDepth?: number;
    },
  ): Promise<EnrollmentTokenRecord> {
    const id = makeId('et');
    const now = new Date();
    const maxDepth = data.maxDelegationDepth ?? 0;
    this.sqlite.execute(`
      INSERT INTO enrollment_tokens (
        id, token_hash, agent_name, requested_scopes, requested_domains,
        max_delegation_depth, expires_at, used_at, created_at
      ) VALUES (
        ${sqliteLiteral(id)},
        ${sqliteLiteral(data.tokenHash)},
        ${sqliteLiteral(data.agentName)},
        ${sqliteLiteral(data.requestedScopes)},
        ${sqliteLiteral(data.requestedDomains)},
        ${sqliteLiteral(maxDepth)},
        ${sqliteLiteral(data.expiresAt)},
        NULL,
        ${sqliteLiteral(now)}
      )
    `);
    return {
      id,
      ...data,
      maxDelegationDepth: maxDepth,
      usedAt: null,
      createdAt: now,
    };
  }

  async findEnrollmentTokenByHash(tokenHash: string): Promise<EnrollmentTokenRecord | null> {
    const rows = this.sqlite.query<SqliteEnrollmentTokenRow>(`
      SELECT * FROM enrollment_tokens WHERE token_hash = ${sqliteLiteral(tokenHash)} LIMIT 1
    `);
    return fromEnrollmentTokenRow(rows[0]);
  }

  async findEnrollmentTokenById(id: string): Promise<EnrollmentTokenRecord | null> {
    const rows = this.sqlite.query<SqliteEnrollmentTokenRow>(`
      SELECT * FROM enrollment_tokens WHERE id = ${sqliteLiteral(id)} LIMIT 1
    `);
    return fromEnrollmentTokenRow(rows[0]);
  }

  async burnEnrollmentTokenAtomically(tokenHash: string): Promise<boolean> {
    const now = new Date();
    this.sqlite.execute(`
      UPDATE enrollment_tokens
      SET used_at = ${sqliteLiteral(now)}
      WHERE token_hash = ${sqliteLiteral(tokenHash)}
        AND used_at IS NULL
    `);
    const token = await this.findEnrollmentTokenByHash(tokenHash);
    return Boolean(token?.usedAt && token.usedAt.getTime() === now.getTime());
  }

  async createChallenge(
    data: Omit<ChallengeRecord, 'id' | 'verifiedAt' | 'createdAt'>,
  ): Promise<ChallengeRecord> {
    const id = makeId('chdb');
    const now = new Date();
    this.sqlite.execute(`
      INSERT INTO challenges (
        id, challenge_id, nonce, did, purpose, pending_public_key_hex,
        pending_domains, pending_did_create_state_json, pending_did_create_payload_hex,
        expires_at, verified_at, created_at, enrollment_token_id
      ) VALUES (
        ${sqliteLiteral(id)},
        ${sqliteLiteral(data.challengeId)},
        ${sqliteLiteral(data.nonce)},
        ${sqliteLiteral(data.did)},
        ${sqliteLiteral(data.purpose)},
        ${sqliteLiteral(data.pendingPublicKeyHex)},
        ${sqliteLiteral(data.pendingDomains)},
        ${sqliteLiteral(data.pendingDidCreateStateJson ?? null)},
        ${sqliteLiteral(data.pendingDidCreatePayloadHex ?? null)},
        ${sqliteLiteral(data.expiresAt)},
        NULL,
        ${sqliteLiteral(now)},
        ${sqliteLiteral(data.enrollmentTokenId)}
      )
    `);
    return {
      id,
      ...data,
      verifiedAt: null,
      createdAt: now,
    };
  }

  async findChallengeById(challengeId: string): Promise<ChallengeRecord | null> {
    const rows = this.sqlite.query<SqliteChallengeRow>(`
      SELECT * FROM challenges WHERE challenge_id = ${sqliteLiteral(challengeId)} LIMIT 1
    `);
    return fromChallengeRow(rows[0]);
  }

  async markChallengeVerified(challengeId: string): Promise<ChallengeRecord> {
    const now = new Date();
    this.sqlite.execute(`
      UPDATE challenges
      SET verified_at = ${sqliteLiteral(now)}
      WHERE challenge_id = ${sqliteLiteral(challengeId)}
    `);
    const challenge = await this.findChallengeById(challengeId);
    if (!challenge) throw new Error('Challenge not found');
    return challenge;
  }

}

export class InMemoryAgentStorageDriver implements AgentStorageDriver {
  private readonly enrollmentTokens = new Map<string, EnrollmentTokenRecord>();
  private readonly challenges = new Map<string, ChallengeRecord>();

  async createEnrollmentToken(
    data: Omit<EnrollmentTokenRecord, 'id' | 'usedAt' | 'createdAt' | 'maxDelegationDepth'> & {
      maxDelegationDepth?: number;
    },
  ): Promise<EnrollmentTokenRecord> {
    const record: EnrollmentTokenRecord = {
      id: makeId('et'),
      ...data,
      maxDelegationDepth: data.maxDelegationDepth ?? 0,
      usedAt: null,
      createdAt: new Date(),
    };
    this.enrollmentTokens.set(record.tokenHash, record);
    return record;
  }

  async findEnrollmentTokenByHash(tokenHash: string): Promise<EnrollmentTokenRecord | null> {
    return this.enrollmentTokens.get(tokenHash) ?? null;
  }

  async findEnrollmentTokenById(id: string): Promise<EnrollmentTokenRecord | null> {
    for (const token of this.enrollmentTokens.values()) {
      if (token.id === id) return token;
    }
    return null;
  }

  async burnEnrollmentTokenAtomically(tokenHash: string): Promise<boolean> {
    const token = this.enrollmentTokens.get(tokenHash);
    if (!token || token.usedAt) {
      return false;
    }
    token.usedAt = new Date();
    this.enrollmentTokens.set(tokenHash, token);
    return true;
  }

  async createChallenge(
    data: Omit<ChallengeRecord, 'id' | 'verifiedAt' | 'createdAt'>,
  ): Promise<ChallengeRecord> {
    const record: ChallengeRecord = {
      id: makeId('chdb'),
      ...data,
      verifiedAt: null,
      createdAt: new Date(),
    };
    this.challenges.set(record.challengeId, record);
    return record;
  }

  async findChallengeById(challengeId: string): Promise<ChallengeRecord | null> {
    return this.challenges.get(challengeId) ?? null;
  }

  async markChallengeVerified(challengeId: string): Promise<ChallengeRecord> {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) throw new Error('Challenge not found');
    challenge.verifiedAt = new Date();
    this.challenges.set(challengeId, challenge);
    return challenge;
  }

}

export function createAgentStorageDriver(
  kind: StorageDriverKind,
  deps: StorageDriverDeps,
): AgentStorageDriver {
  switch (kind) {
    case 'postgres':
      if (!deps.prisma) throw new Error("createAgentStorageDriver('postgres') requires deps.prisma");
      return new PrismaAgentStorageDriver(deps.prisma as PrismaClient);
    case 'sqlite':
      if (!deps.sqlite) throw new Error("createAgentStorageDriver('sqlite') requires deps.sqlite");
      return new SqliteAgentStorageDriver(deps.sqlite as SqliteStore);
    case 'memory':
      return new InMemoryAgentStorageDriver();
    default: {
      const _exhaustive: never = kind;
      throw new UnsupportedStorageDriverError('AgentRepository', _exhaustive);
    }
  }
}
