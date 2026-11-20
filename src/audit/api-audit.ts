// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import type { PrismaClient } from '@prisma/client';
import {
  AUDIT_BINDING_HELIX,
  AuditTrail,
  EvidenceEncryptor,
  TeeAuditSink,
  digestText,
  type AuditSink,
  type Config,
  type PartyRef,
} from '../core/index.js';
import type { SqliteStore } from '../storage/sqlite.js';
import { MemoryAuditStore } from './memory-store.js';
import { PrismaAuditSink } from './prisma-sink.js';
import { SqliteAuditSink } from './sqlite-sink.js';
import type { AuditEventStore } from './store.js';
import { StreamAuditSink } from './stream-sink.js';

export type ApiAuditConfig = Pick<
  Config,
  | 'AUDIT_LOG_DESTINATION'
  | 'AUDIT_LOG_PATH'
  | 'AUDIT_SOURCE_ID'
  | 'AUDIT_INCLUDE_TOOL_NAMES'
  | 'AUDIT_EVIDENCE_KEY'
  | 'AUDIT_EVIDENCE_KEY_ID'
  | 'HELIX_ISSUER_DID'
>;

/** The store for the configured storage adapter: Postgres, SQLite, or memory when neither is given. */
export function createApiAuditStore(deps: { prisma?: PrismaClient | undefined; sqlite?: SqliteStore | undefined }): AuditEventStore {
  if (deps.prisma) return new PrismaAuditSink(deps.prisma);
  if (deps.sqlite) return new SqliteAuditSink(deps.sqlite);
  return new MemoryAuditStore();
}

/** This deployment as a party: its issuer DID when it has one, else a commitment to the fixed name `helix-api`. */
export function apiPartyRef(config: Pick<ApiAuditConfig, 'HELIX_ISSUER_DID'>): PartyRef {
  if (/^did:[^\r\n]{3,}$/.test(config.HELIX_ISSUER_DID)) return { kind: 'public_did', did: config.HELIX_ISSUER_DID };
  return { kind: 'keyed_commitment', value: digestText('helix-api'), keyId: 'helix-api-tenant-v1' };
}

export interface ApiAudit {
  trail: AuditTrail;
  store: AuditEventStore;
  /** Present when AUDIT_EVIDENCE_KEY is set. */
  evidenceEncryptor?: EvidenceEncryptor;
}

/**
 * The API's own producer trail over the store (plus the stdout/file echo),
 * bound to this deployment as producer and tenant, with the evidence vault
 * when a key is configured.
 */
export function createApiAudit(config: ApiAuditConfig, store: AuditEventStore, extraSinks: AuditSink[] = []): ApiAudit {
  const sinks: AuditSink[] = [store];
  if (config.AUDIT_LOG_DESTINATION !== 'none') {
    sinks.push(new StreamAuditSink({ destination: config.AUDIT_LOG_DESTINATION, path: config.AUDIT_LOG_PATH }));
  }
  sinks.push(...extraSinks);
  const party = apiPartyRef(config);
  const evidenceEncryptor =
    config.AUDIT_EVIDENCE_KEY === undefined
      ? undefined
      : new EvidenceEncryptor({ key: config.AUDIT_EVIDENCE_KEY, keyId: config.AUDIT_EVIDENCE_KEY_ID });
  const trail = new AuditTrail({
    sink: sinks.length === 1 ? store : new TeeAuditSink(sinks),
    sourceId: config.AUDIT_SOURCE_ID,
    producer: party,
    tenantRef: party,
    binding: AUDIT_BINDING_HELIX,
    includeToolNames: config.AUDIT_INCLUDE_TOOL_NAMES,
    ...(evidenceEncryptor === undefined ? {} : { evidence: { encryptor: evidenceEncryptor, store } }),
  });
  return { trail, store, ...(evidenceEncryptor === undefined ? {} : { evidenceEncryptor }) };
}
