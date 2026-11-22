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

// The API side of KYA-OS auditability: the recorder's journal and vault on
// PostgreSQL, SQLite or memory (A-2), the operator's stream echo, the
// submission wire format, and the factory server.ts wires.
export * from './store.js';
export { PostgresAuditJournal } from './postgres-journal.js';
export { PostgresAuditEvidenceStore } from './postgres-evidence.js';
export { SqliteAuditJournal } from './sqlite-journal.js';
export { SqliteAuditEvidenceStore } from './sqlite-evidence.js';
export { MemoryAuditEvidenceStore } from './memory-evidence.js';
export { StreamAuditSink, type StreamAuditSinkOptions } from './stream-sink.js';
export {
  createApiAudit,
  createApiAuditStorage,
  createRecorderSigner,
  delegationRetentionFloor,
  apiPartyRef,
  type ApiAudit,
  type ApiAuditConfig,
  type ApiAuditStorageDeps,
  type CreateApiAuditOptions,
} from './api-audit.js';
export * from './submission.js';
