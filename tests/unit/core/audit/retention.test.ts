// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Retention administration (A-2 point 6) over memory stores: holds on a
 * ledger, an entry or an object; release; disposal refused under a hold or
 * below the floor and the refusal recorded; disposal recorded per object;
 * the memory journal's remaining reads.
 */

import { describe, expect, it } from 'vitest';
import {
  AuditProtocolError,
  AuditRetentionService,
  EvidenceEncryptor,
  ManagedAuditRecorder,
  MemoryAuditJournal,
  MemoryAuditRetentionStore,
  assertNotHeld,
  evidenceAad,
  retentionSelectionDigest,
  type SignedAuditEntry,
} from '../../../../src/core/index.js';
import { MemoryAuditEvidenceStore } from '../../../../src/audit/memory-evidence.js';
import { TENANT, contextFor, producerEvent, submission, testRecorderSigner } from '../../../utils/auditLedger.js';

async function refusal(promise: Promise<unknown>): Promise<AuditProtocolError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof AuditProtocolError) return error;
    throw error;
  }
  throw new Error('expected a refusal');
}

async function setup(options: { floor?: number; now?: () => number; minimumRetentionMs?: number } = {}) {
  const journal = new MemoryAuditJournal();
  const vault = new MemoryAuditEvidenceStore();
  const recorder = new ManagedAuditRecorder({ store: journal, signer: testRecorderSigner(), evidence: vault });
  const retention = new AuditRetentionService({
    recorder,
    journal,
    retention: vault,
    delegationRetentionFloorMs: async () => options.floor ?? 0,
    policy: (ledgerId) => ({ minimumRetentionMs: ledgerId.length > 0 ? (options.minimumRetentionMs ?? 0) : 0 }),
    ...(options.now !== undefined ? { clock: options.now } : {}),
  });
  const encryptor = new EvidenceEncryptor({ key: '56'.repeat(32), keyId: 'k' });
  const objects = ['one', 'two'].map((text) => encryptor.encrypt({ plaintext: text, mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') }));
  const event = { ...producerEvent('evidence'), evidence: objects.map((o) => o.ref) };
  const entry = await recorder.submit(submission(event, { encryptedEvidence: objects }), contextFor(event));
  const ledgerId = entry.core.ledgerId;
  const target = { kind: 'entry' as const, ledgerId, ledgerEpochId: entry.core.ledgerEpochId, sequence: entry.core.sequence };
  return { journal, vault, recorder, retention, objects, entry, ledgerId, target };
}

async function eventsOf(journal: MemoryAuditJournal, ledgerId: string): Promise<Array<[string, string, string | null]>> {
  return (await journal.listEntries({ ledgerId, limit: 100 }))
    .reverse()
    .slice(2)
    .map((entry: SignedAuditEntry) => [entry.core.event.eventType, entry.core.event.outcome, entry.core.event.reason?.code ?? null]);
}

describe('AuditRetentionService', () => {
  it('refuses disposal under a ledger, entry or object hold, records each refusal, then disposes after release', async () => {
    const { journal, vault, retention, objects, ledgerId, target } = await setup();
    const holds = [
      { holdId: 'ledger-hold', target: { kind: 'ledger' as const, ledgerId } },
      { holdId: 'entry-hold', target },
      { holdId: 'object-hold', target: { kind: 'evidence' as const, ledgerId, objectId: objects[1]!.ref.objectId } },
    ];
    for (const hold of holds) await retention.applyLegalHold({ ...hold, authorizedBy: 'test' });
    expect((await retention.applyLegalHold({ ...holds[1]!, authorizedBy: 'test' })).core.event.eventType).toBe('legal_hold.applied');
    expect((await refusal(retention.applyLegalHold({ holdId: 'entry-hold', target: holds[0]!.target, authorizedBy: 'test' }))).message).toMatch(/another target/);
    for (const hold of holds) {
      expect((await refusal(retention.dispose({ target, authorizedBy: 'test' }))).code).toBe('AUDIT_EVIDENCE_LEGAL_HOLD');
      await retention.releaseLegalHold({ holdId: hold.holdId, authorizedBy: 'test' });
    }
    expect((await refusal(retention.releaseLegalHold({ holdId: 'entry-hold', authorizedBy: 'test' }))).code).toBe('AUDIT_RETENTION_REFUSED');
    const result = await retention.dispose({ target, authorizedBy: 'test' });
    expect(result.disposedObjectIds).toEqual(objects.map((o) => o.ref.objectId));
    expect(result.disposals.map((entry) => entry.core.event.details)).toEqual(
      objects.map((o) => ({ family: 'ledger', phase: 'evidence_disposed', targetEvidenceRef: o.ref })),
    );
    expect(result.command.core.event.details).toEqual({
      family: 'administration',
      phase: 'retention_executed',
      purpose: 'disposal',
      selectionDigest: retentionSelectionDigest({ target }),
    });
    for (const object of objects) expect(await vault.get(object.ref.objectId)).toBeNull();
    // Disposing again skips what is gone, and is recorded again.
    expect((await retention.dispose({ target, authorizedBy: 'test' })).skippedObjectIds).toHaveLength(2);
    const recorded = await eventsOf(journal, ledgerId);
    expect(recorded.filter(([type, outcome]) => type === 'retention.executed' && outcome === 'denied')).toHaveLength(3);
    expect(recorded.filter(([type]) => type === 'legal_hold.applied')).toHaveLength(4);
    expect(recorded.filter(([type]) => type === 'evidence.disposed')).toHaveLength(2);
  });

  it('refuses disposal below the floor, the longer of policy and delegation lifetime, and an unbounded floor always', async () => {
    let now = 1_000;
    const { retention, ledgerId, target, entry } = await setup({ floor: 500, minimumRetentionMs: 2_000, now: () => now });
    now = entry.core.recordedAt + 1_999;
    expect(await retention.retentionFloorMs(ledgerId)).toBe(2_000);
    const young = await refusal(retention.dispose({ target, authorizedBy: 'test' }));
    expect(young.details).toMatchObject({ floorMs: 2_000, ageMs: 1_999 });
    now = entry.core.recordedAt + 2_000;
    expect((await retention.dispose({ target, authorizedBy: 'test' })).disposedObjectIds).toHaveLength(2);

    const unbounded = await setup({ floor: Number.POSITIVE_INFINITY });
    expect((await refusal(unbounded.retention.dispose({ target: unbounded.target, authorizedBy: 'test' }))).details).toMatchObject({ floorMs: 'unbounded' });
    const noPolicy = new AuditRetentionService({
      recorder: unbounded.recorder,
      journal: unbounded.journal,
      retention: unbounded.vault,
      delegationRetentionFloorMs: async () => 7,
    });
    expect(await noPolicy.retentionFloorMs(unbounded.ledgerId)).toBe(7);
  });

  it('disposes a single evidence object by id, and refuses targets that do not exist', async () => {
    const { retention, vault, objects, ledgerId, target } = await setup();
    const one = await retention.dispose({ target: { kind: 'evidence', ledgerId, objectId: objects[0]!.ref.objectId }, authorizedBy: 'test' });
    expect(one.disposedObjectIds).toEqual([objects[0]!.ref.objectId]);
    expect(await vault.get(objects[1]!.ref.objectId)).not.toBeNull();
    for (const missing of [
      { kind: 'evidence' as const, ledgerId, objectId: 'evi_none' },
      { ...target, sequence: '99' },
      { ...target, sequence: 'not-a-number' },
      { ...target, ledgerEpochId: 'epoch-none' },
    ]) {
      expect((await refusal(retention.dispose({ target: missing, authorizedBy: 'test' }))).message).toMatch(/No such retention target/);
    }
    expect((await refusal(retention.applyLegalHold({ holdId: 'h', target: { kind: 'ledger', ledgerId: 'ledger-none' }, authorizedBy: 'test' }))).code).toBe('AUDIT_RETENTION_REFUSED');
    const genesis = await retention.dispose({ target: { ...target, sequence: '0' }, authorizedBy: 'test' });
    expect(genesis.disposedObjectIds).toEqual([]);
  });

  it('keeps holds and disposal state in the memory store, refusing a held object at the store too', async () => {
    const store = new MemoryAuditRetentionStore();
    const { objects } = await setup();
    store.trackEvidence(objects[0]!.ref, 5);
    store.trackEvidence(objects[0]!.ref, 9);
    expect(await store.evidenceState(objects[0]!.ref.objectId)).toEqual({ ref: objects[0]!.ref, storedAt: 5 });
    const hold = { holdId: 'h', target: { kind: 'evidence' as const, ledgerId: 'l', objectId: objects[0]!.ref.objectId }, appliedAt: 1, appliedBy: 't' };
    expect(await store.insertHold(hold)).toBe('inserted');
    expect(await store.insertHold(hold)).toBe('exists');
    await expect(store.disposeEvidence({ ledgerId: 'l', objectId: objects[0]!.ref.objectId, disposedAt: 2 })).rejects.toThrow(/legal hold/);
    expect(await store.releaseHold('none', 1, 't')).toBeNull();
    expect(await store.releaseHold('h', 3, 't')).toMatchObject({ releasedAt: 3 });
    expect(await store.getHold('none')).toBeNull();
    expect(await store.insertHold(hold)).toBe('inserted');
    expect(() => assertNotHeld([{ ...hold, target: { kind: 'ledger', ledgerId: 'l' } }], 'l', 'other')).toThrow(/legal hold/);
    expect(() => assertNotHeld([{ ...hold, releasedAt: 1 }], 'l', objects[0]!.ref.objectId)).not.toThrow();
    expect(await store.disposeEvidence({ ledgerId: 'x', objectId: 'none', disposedAt: 1 })).toBe('missing');
  });
});

describe('MemoryAuditJournal', () => {
  it('reads ranges, epochs, ledgers and listings, and refuses a seal at the wrong head', async () => {
    const { journal, ledgerId, entry } = await setup();
    const ledger = { ledgerId, ledgerEpochId: entry.core.ledgerEpochId };
    const seqs: string[] = [];
    for await (const e of journal.readRange({ ...ledger, afterSequence: '0', limit: 1 })) seqs.push(e.core.sequence);
    expect(seqs).toEqual(['1']);
    expect(await journal.listEpochs('none')).toEqual([]);
    expect(await journal.getLedger('none')).toBeNull();
    expect(await journal.findLedgerByTenant({ kind: 'public_did', did: 'did:web:nobody' })).toBeNull();
    expect(await journal.findLedgerByTenant(TENANT)).toMatchObject({ ledgerId });
    expect((await journal.ensureLedger({ ledgerId, tenantRef: TENANT, createdAt: 9 })).createdAt).not.toBe(9);
    expect(await journal.setActiveEpoch('none', null, 'x')).toBe(false);
    expect(await journal.listEntries({ eventType: 'tool.call.completed', family: 'tool', correlationId: 'call-evidence', since: new Date(0), ledgerId, limit: 5 })).toHaveLength(1);
    const head = (await journal.getHead(ledger))!;
    await expect(journal.sealEpoch({ ledger, expectedHead: { ...head, sequence: '0' }, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).rejects.toThrow(
      /not its committed head/,
    );
    await expect(journal.sealEpoch({ ledger: { ledgerId, ledgerEpochId: 'none' }, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).rejects.toThrow();
    expect(await journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).toBe('sealed');
    expect(await journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 's' })).toBe('already_sealed');
    await expect(journal.sealEpoch({ ledger, expectedHead: head, terminalDigest: head.entryDigest, reason: 'failover', successorEpochId: 't' })).rejects.toThrow(/already sealed/);
    expect(() => journal.tamperForTesting(ledger, '99', '{}')).toThrow(/no such entry/);
    journal.tamperForTesting(ledger, '1', '{}');
    const rows: string[] = [];
    for await (const row of journal.readStoredRange(ledger)) rows.push(row.entryText);
    expect(rows[1]).toBe('{}');
  });
});
