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

/**
 * Executable provider contracts (AUDITABILITY.md: "Run the provider contract
 * kit for every adapter"). `evaluateAuditJournalProviderContract` is the
 * reference kit's journal contract ported check for check from upstream
 * `src/audit/testing/provider-contracts.ts` at a4d7f61 (the spec repository
 * ships it as code, not as vendored data, so it is ported rather than
 * executed from the clone; PIN.md). Same fixtures, same six checks, same
 * names, same assertions.
 *
 * `evaluateAuditEvidenceRetentionContract` adapts the reference evidence
 * contract's three checks (exact idempotent ciphertext with defensive bytes,
 * object-id collisions refused, legal hold before irreversible disposal) to
 * Helix's split of the vault (`EvidenceStore`) and the hold store
 * (`AuditRetentionStore`).
 */

import { canonicalize } from '../crypto/jcs.js';
import { digestBytes } from './digest.js';
import type { EncryptedEvidence, EvidenceStore } from './evidence.js';
import type { AuditJournalProvider } from './journal.js';
import type { AuditLedgerRef, SignedAuditEntry } from './ledger.js';
import type { AuditRetentionStore } from './retention.js';
import type { Digest, EvidenceRef } from './types.js';

export interface AuditProviderContractCheck {
  name: string;
  passed: boolean;
  error?: unknown;
}

export interface AuditProviderContractReport {
  providerKind: 'journal' | 'evidence' | 'observer' | 'anchor' | 'outbox';
  passed: boolean;
  checks: AuditProviderContractCheck[];
}

function digest(character: string): Digest {
  return `sha256:${character.repeat(64)}`;
}

function equalJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function expectContract(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function check(checks: AuditProviderContractCheck[], name: string, execute: () => Promise<void>): Promise<void> {
  try {
    await execute();
    checks.push({ name, passed: true });
  } catch (error) {
    checks.push({ name, passed: false, error });
  }
}

function report(providerKind: AuditProviderContractReport['providerKind'], checks: AuditProviderContractCheck[]): AuditProviderContractReport {
  return { providerKind, passed: checks.every((item) => item.passed), checks };
}

export function assertAuditProviderContract(value: AuditProviderContractReport): void {
  const failures = value.checks.filter((item) => !item.passed);
  if (failures.length > 0) {
    throw new AggregateError(
      failures.map((item) => item.error),
      `${value.providerKind} provider contract failed: ${failures.map((item) => item.name).join(', ')}`,
    );
  }
}

function contractEntry(ledger: AuditLedgerRef, sequence: number, eventDigest: Digest, previousEntryDigest: Digest | null): SignedAuditEntry {
  const entryDigest = digest(((sequence + 3) % 10).toString());
  const eventId = `contract-event-${sequence}`;
  return {
    core: {
      schema: 'https://schema.kya-os.org/v1/protocol/audit/entry/v1.0.0',
      ...ledger,
      sequence: String(sequence),
      previousEntryDigest,
      recordedAt: 1_750_000_000_000 + sequence,
      recorder: { did: 'did:key:zContractRecorder', kid: 'did:key:zContractRecorder#key', alg: 'EdDSA' },
      eventDigest,
      event: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/event/v1.0.0',
        eventId,
        eventType: sequence === 0 ? 'ledger.epoch.started' : 'tool.call.completed',
        eventVersion: '1.0.0',
        binding: 'urn:kya-os:audit-binding:contract:1',
        occurredAt: 1_750_000_000_000 + sequence,
        tenantRef: { kind: 'pairwise_did', did: 'did:key:zContractTenant' },
        source: {
          producer: { kind: 'pairwise_did', did: 'did:key:zContractProducer' },
          sourceId: 'contract-source',
          sourceSequence: String(sequence),
        },
        action: { category: sequence === 0 ? 'ledger.epoch' : 'tool.call' },
        outcome: 'succeeded',
        evidence: [],
        details: sequence === 0 ? { family: 'ledger', phase: 'epoch_started' } : { family: 'tool', phase: 'completed', attempt: '1' },
        privacy: { classification: 'internal', retentionClass: 'contract' },
      },
      evidenceManifestDigest: digest('a'),
      integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
    },
    eventDigest,
    entryDigest,
    recorderReceipt: {
      core: {
        schema: 'https://schema.kya-os.org/v1/protocol/audit/receipt/v1.0.0',
        ...ledger,
        sequence: String(sequence),
        eventId,
        entryDigest,
        previousEntryDigest,
        recordedAt: 1_750_000_000_000 + sequence,
        recorder: { did: 'did:key:zContractRecorder', kid: 'did:key:zContractRecorder#key', alg: 'EdDSA' },
        integritySuite: 'KYA-AUDIT-JCS-SHA256-JWS-2026',
      },
      jws: `contract-signature-${sequence}`,
    },
  };
}

/** Framework-neutral executable contract for authoritative journal adapters. */
export async function evaluateAuditJournalProviderContract(
  createProvider: () => AuditJournalProvider | Promise<AuditJournalProvider>,
): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  const ledger = { ledgerId: 'contract-ledger', ledgerEpochId: 'epoch-1' };
  const first = contractEntry(ledger, 0, digest('1'), null);
  const second = contractEntry(ledger, 1, digest('2'), first.entryDigest);
  const third = contractEntry(ledger, 2, digest('3'), second.entryDigest);
  const idOne = digest('b');
  const idTwo = digest('c');
  const idThree = digest('d');

  await check(checks, 'declares atomic ordered capabilities', async () => {
    const provider = await createProvider();
    expectContract(provider.capabilities.atomicAppend === true, 'atomicAppend must be true');
    expectContract(provider.capabilities.orderedRead === true, 'orderedRead must be true');
    expectContract(
      provider.capabilities.durability === 'ephemeral' || provider.capabilities.durability === 'durable',
      'durability must be declared',
    );
  });

  await check(checks, 'atomically appends and rejects a stale head', async () => {
    const provider = await createProvider();
    const appended = await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    expectContract(appended.kind === 'appended', 'genesis append was not committed');
    const stale = await provider.compareAndAppend({ ledger, expectedHead: null, entry: second, idempotencyKey: idTwo });
    expectContract(stale.kind === 'head_conflict', 'stale head did not conflict');
    const head = await provider.getHead(ledger);
    expectContract(head?.entryDigest === first.entryDigest, 'stale append changed the head');
  });

  await check(checks, 'returns exact duplicates and rejects idempotency conflicts', async () => {
    const provider = await createProvider();
    await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    const duplicate = await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    expectContract(duplicate.kind === 'duplicate' && equalJson(duplicate.entry, first), 'same key and producer digest must return the original entry');
    const conflicting = { ...first, eventDigest: digest('f') };
    const conflict = await provider.compareAndAppend({ ledger, expectedHead: null, entry: conflicting, idempotencyKey: idOne });
    expectContract(conflict.kind === 'idempotency_conflict', 'changed content was not rejected');
  });

  await check(checks, 'keeps logical-ledger idempotency across epoch changes', async () => {
    const provider = await createProvider();
    await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    const nextEpoch = { ledgerId: ledger.ledgerId, ledgerEpochId: 'epoch-2' };
    const replay = contractEntry(nextEpoch, 0, first.eventDigest, null);
    const duplicate = await provider.compareAndAppend({ ledger: nextEpoch, expectedHead: null, entry: replay, idempotencyKey: idOne });
    expectContract(duplicate.kind === 'duplicate', 'epoch transition reopened idempotency scope');
  });

  await check(checks, 'scopes heads and ranges by epoch within a logical ledger', async () => {
    const provider = await createProvider();
    await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    const nextEpoch = { ledgerId: ledger.ledgerId, ledgerEpochId: 'epoch-2' };
    expectContract((await provider.getHead(nextEpoch)) === null, 'a fresh epoch inherited the previous epoch head');
    const nextGenesis = contractEntry(nextEpoch, 0, digest('7'), null);
    const appended = await provider.compareAndAppend({ ledger: nextEpoch, expectedHead: null, entry: nextGenesis, idempotencyKey: digest('8') });
    expectContract(appended.kind === 'appended', 'fresh epoch genesis append failed');
    const previousHead = await provider.getHead(ledger);
    expectContract(previousHead?.entryDigest === first.entryDigest, 'appending to a new epoch changed the previous epoch head');
    const nextHead = await provider.getHead(nextEpoch);
    expectContract(nextHead?.entryDigest === nextGenesis.entryDigest, 'the new epoch head is not scoped to its epoch');
    const nextRange: SignedAuditEntry[] = [];
    for await (const entry of provider.readRange(nextEpoch)) nextRange.push(entry);
    expectContract(nextRange.length === 1 && nextRange[0]?.entryDigest === nextGenesis.entryDigest, 'the new epoch range leaked entries from another epoch');
  });

  await check(checks, 'provides ordered stable range cursors', async () => {
    const provider = await createProvider();
    const firstResult = await provider.compareAndAppend({ ledger, expectedHead: null, entry: first, idempotencyKey: idOne });
    expectContract(firstResult.kind === 'appended', 'first append failed');
    const head = await provider.getHead(ledger);
    const secondResult = await provider.compareAndAppend({ ledger, expectedHead: head, entry: second, idempotencyKey: idTwo });
    expectContract(secondResult.kind === 'appended', 'second append failed');
    const iterator = provider.readRange(ledger)[Symbol.asyncIterator]();
    const firstRead = await iterator.next();
    const nextHead = await provider.getHead(ledger);
    await provider.compareAndAppend({ ledger, expectedHead: nextHead, entry: third, idempotencyKey: idThree });
    const remaining: SignedAuditEntry[] = [];
    for (;;) {
      const item = await iterator.next();
      if (item.done) break;
      remaining.push(item.value);
    }
    expectContract(firstRead.value?.core.sequence === '0', 'range did not start at sequence zero');
    expectContract(remaining.length === 1 && remaining[0]?.core.sequence === '1', 'range cursor was not ordered and snapshot-stable');
  });

  return report('journal', checks);
}

/** An evidence vault plus its hold store, as one retention provider. */
export interface AuditEvidenceRetentionProvider {
  vault: EvidenceStore;
  retention: AuditRetentionStore;
}

function contractEvidence(ciphertext: Uint8Array, objectId: string): EncryptedEvidence {
  const ref: EvidenceRef = {
    objectId,
    ciphertextDigest: digestBytes(ciphertext),
    mediaType: 'application/octet-stream',
    size: String(ciphertext.byteLength),
    encryption: { suite: 'A256GCM', keyId: 'contract-key-v1', nonce: 'AAAAAAAAAAAAAAAA', aadDigest: digest('e') },
  };
  return { ref, ciphertext };
}

/** The reference evidence contract's checks, over a Helix vault and hold store. */
export async function evaluateAuditEvidenceRetentionContract(
  createProvider: () => AuditEvidenceRetentionProvider | Promise<AuditEvidenceRetentionProvider>,
  options: { ledgerId?: string; objectIdPrefix?: string } = {},
): Promise<AuditProviderContractReport> {
  const checks: AuditProviderContractCheck[] = [];
  const ledgerId = options.ledgerId ?? 'contract-ledger';
  const prefix = options.objectIdPrefix ?? `evi_contract_${Date.now().toString(36)}`;
  let counter = 0;
  const nextId = (): string => `${prefix}_${(counter += 1)}`;

  await check(checks, 'stores exact ciphertext idempotently and returns defensive bytes', async () => {
    const { vault } = await createProvider();
    const evidence = contractEvidence(Uint8Array.of(1, 2, 3, 4), nextId());
    await vault.putIfAbsent(evidence);
    await vault.putIfAbsent(evidence);
    const first = await vault.get(evidence.ref.objectId);
    expectContract(first !== null && first.ciphertext[0] === 1, 'stored ciphertext was unavailable');
    first.ciphertext[0] = 255;
    const second = await vault.get(evidence.ref.objectId);
    expectContract(second?.ciphertext[0] === 1, 'provider leaked mutable ciphertext storage');
  });

  await check(checks, 'rejects opaque object identifier collisions', async () => {
    const { vault } = await createProvider();
    const objectId = nextId();
    await vault.putIfAbsent(contractEvidence(Uint8Array.of(1, 2, 3, 4), objectId));
    let rejected = false;
    try {
      await vault.putIfAbsent(contractEvidence(Uint8Array.of(5, 6, 7), objectId));
    } catch {
      rejected = true;
    }
    expectContract(rejected, 'object ID collision was accepted');
  });

  await check(checks, 'enforces legal hold before irreversible disposal', async () => {
    const { vault, retention } = await createProvider();
    const evidence = contractEvidence(Uint8Array.of(1, 2, 3, 4), nextId());
    await vault.putIfAbsent(evidence);
    const holdId = `${evidence.ref.objectId}-hold`;
    await retention.insertHold({
      holdId,
      target: { kind: 'evidence', ledgerId, objectId: evidence.ref.objectId },
      appliedAt: Date.now(),
      appliedBy: 'contract',
    });
    const held = (await retention.activeHolds(ledgerId)).some((hold) => hold.holdId === holdId);
    expectContract(held, 'applied hold is not active');
    let rejected = false;
    try {
      await retention.disposeEvidence({ ledgerId, objectId: evidence.ref.objectId, disposedAt: Date.now(), reason: 'expired' });
    } catch {
      rejected = true;
    }
    expectContract(rejected, 'held evidence was disposed');
    expectContract((await vault.get(evidence.ref.objectId)) !== null, 'a refused disposal removed the ciphertext');
    await retention.releaseHold(holdId, Date.now(), 'contract');
    expectContract(!(await retention.activeHolds(ledgerId)).some((hold) => hold.holdId === holdId), 'released hold is still active');
    const disposed = await retention.disposeEvidence({ ledgerId, objectId: evidence.ref.objectId, disposedAt: Date.now(), reason: 'expired' });
    expectContract(disposed === 'disposed', 'released evidence was not disposed');
    expectContract((await vault.get(evidence.ref.objectId)) === null, 'disposed ciphertext remains available');
    const state = await retention.evidenceState(evidence.ref.objectId);
    expectContract(
      state?.disposedAt !== undefined && canonicalize(state.ref) === canonicalize(evidence.ref),
      'disposal removed the commitment, not only the ciphertext',
    );
    expectContract(
      (await retention.disposeEvidence({ ledgerId, objectId: evidence.ref.objectId, disposedAt: Date.now(), reason: 'expired' })) === 'already_disposed',
      'disposal is not idempotent',
    );
  });

  return report('evidence', checks);
}
