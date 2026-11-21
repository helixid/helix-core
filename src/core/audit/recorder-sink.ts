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

import type { SignedAuditEntry } from './ledger.js';
import type { ManagedAuditRecorder } from './managed-recorder.js';
import type { AuditSink } from './sink.js';
import type { AuditTrailEntry } from './types.js';

/**
 * The sink of a producer that runs in the recorder's own process (the Helix
 * API's trail): every recorded event is submitted to the authoritative
 * recorder, and `append` resolves only once the signed receipt exists, so
 * the API's own delivery is `required`. In-process, the producer and tenant
 * are bound exactly as the event names them.
 */
export class RecorderAuditSink implements AuditSink {
  constructor(
    private readonly recorder: ManagedAuditRecorder,
    private readonly authority: string = 'helix-api',
  ) {}

  async append(entry: AuditTrailEntry): Promise<SignedAuditEntry> {
    const { event } = entry;
    return this.recorder.submit(
      { producerEvent: event, encryptedEvidence: [] },
      { producerAuthority: this.authority, tenantAuthority: this.authority, producerRef: event.source.producer, tenantRef: event.tenantRef },
    );
  }
}
