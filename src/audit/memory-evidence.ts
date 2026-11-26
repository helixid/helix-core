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

import {
  assertEvidenceMatchesRef,
  AuditEvidenceError,
  MemoryAuditRetentionStore,
  type EncryptedEvidence,
  type EvidenceRef,
} from '../core/index.js';
import type { ApiAuditEvidenceStore } from './store.js';

/** The in-memory evidence vault with holds and disposal (memory mode, tests). Ephemeral. */
export class MemoryAuditEvidenceStore extends MemoryAuditRetentionStore implements ApiAuditEvidenceStore {
  private readonly objects = new Map<string, EncryptedEvidence>();

  async putIfAbsent(object: EncryptedEvidence): Promise<EvidenceRef> {
    assertEvidenceMatchesRef(object);
    const existing = this.objects.get(object.ref.objectId) ?? (await this.evidenceState(object.ref.objectId));
    if (existing !== null && existing !== undefined) {
      if (existing.ref.ciphertextDigest !== object.ref.ciphertextDigest) {
        throw new AuditEvidenceError('Opaque evidence object id collision', { objectId: object.ref.objectId });
      }
      return existing.ref;
    }
    this.objects.set(object.ref.objectId, { ref: object.ref, ciphertext: new Uint8Array(object.ciphertext) });
    this.trackEvidence(object.ref, Date.now());
    return object.ref;
  }

  async get(objectId: string): Promise<EncryptedEvidence | null> {
    const found = this.objects.get(objectId);
    return found === undefined ? null : { ref: found.ref, ciphertext: new Uint8Array(found.ciphertext) };
  }

  async has(objectId: string): Promise<boolean> {
    return (await this.evidenceState(objectId)) !== null;
  }

  async discardUncommitted(objectId: string): Promise<void> {
    if (this.objects.delete(objectId)) await super.disposeEvidence({ ledgerId: '', objectId, disposedAt: Date.now() });
  }

  override async disposeEvidence(input: { ledgerId: string; objectId: string; disposedAt: number }): Promise<'disposed' | 'already_disposed' | 'missing'> {
    const outcome = await super.disposeEvidence(input);
    if (outcome === 'disposed') this.objects.delete(input.objectId);
    return outcome;
  }
}
