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

import type { AuditTrailEntry } from './types.js';

/**
 * Where an `AuditTrail` delivers each recorded event. AAP-1: the sink records
 * what it is given. Story A-2's recorder (epoch, ledger sequence, signed
 * receipt) replaces the sink behind this one method; producers never see it.
 */
export interface AuditSink {
  append(entry: AuditTrailEntry): Promise<void>;
}

/** Keeps every entry in order; for tests and local development. */
export class MemoryAuditSink implements AuditSink {
  readonly entries: AuditTrailEntry[] = [];

  async append(entry: AuditTrailEntry): Promise<void> {
    this.entries.push(entry);
  }

  /** The recorded events, oldest first. */
  get events(): AuditTrailEntry['event'][] {
    return this.entries.map((entry) => entry.event);
  }

  /** The event types recorded, oldest first. */
  get eventTypes(): string[] {
    return this.entries.map((entry) => entry.event.eventType);
  }
}

/** Delivers every entry to each sink in turn; one failing sink fails the record. */
export class TeeAuditSink implements AuditSink {
  constructor(private readonly sinks: readonly AuditSink[]) {}

  async append(entry: AuditTrailEntry): Promise<void> {
    for (const sink of this.sinks) await sink.append(entry);
  }
}
