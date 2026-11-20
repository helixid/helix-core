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

// The API side of KYA-OS auditability (story A-1): stores behind the core
// `AuditSink` seam, the operator's stream echo, and the factory server.ts wires.
export * from './store.js';
export { PrismaAuditSink } from './prisma-sink.js';
export { SqliteAuditSink } from './sqlite-sink.js';
export { MemoryAuditStore } from './memory-store.js';
export { StreamAuditSink, type StreamAuditSinkOptions } from './stream-sink.js';
export { createApiAudit, createApiAuditStore, apiPartyRef, type ApiAudit, type ApiAuditConfig } from './api-audit.js';
