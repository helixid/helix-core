// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The managed recorder and epochs (A-2 points 1 and 5) over the memory
 * journal: per-tenant ledgers, activation (including half-finished
 * transitions and inconsistent state), the restore witness, key rotation,
 * operator transitions, and the epoch helpers.
 */

import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import {
  AuditProtocolError,
  FileRecorderWitness,
  JournalEpochTransitionGuard,
  ManagedAuditRecorder,
  MemoryAuditJournal,
  MemoryRecorderWitness,
  defaultAuditLedgerId,
  newAuditEpochId,
  terminalHeadDigest,
  witnessShowsRestore,
  type AuditEpochRecord,
  type AuditHead,
  type AuditLedgerStore,
} from '../../../../src/core/index.js';
import { TEST_RECORDER_KEYS, TENANT, contextFor, producerEvent, submission, testRecorderSigner } from '../../../utils/auditLedger.js';

const dirs: string[] = [];
afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

async function refusal(promise: Promise<unknown>): Promise<AuditProtocolError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof AuditProtocolError) return error;
    throw error;
  }
  throw new Error('expected a refusal');
}

function managed(store: AuditLedgerStore, extra: Partial<ConstructorParameters<typeof ManagedAuditRecorder>[0]> = {}): ManagedAuditRecorder {
  return new ManagedAuditRecorder({ store, signer: testRecorderSigner(), ...extra });
}

/** The memory journal with some epoch-control answers replaced. */
function overriding(base: MemoryAuditJournal, overrides: Partial<AuditLedgerStore>): AuditLedgerStore {
  return new Proxy(base, {
    get(target, property, receiver) {
      if (property in overrides) return (overrides as Record<string | symbol, unknown>)[property];
      const value = Reflect.get(target, property, receiver) as unknown;
      return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
    },
  }) as AuditLedgerStore;
}

describe('epoch helpers', () => {
  it('computes the terminal digest from the head and names epochs by index, date and a random part', () => {
    const head: AuditHead = { ledgerId: 'l', ledgerEpochId: 'e', sequence: '41', entryDigest: `sha256:${'a'.repeat(64)}` };
    expect(terminalHeadDigest(head)).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(terminalHeadDigest(head)).not.toBe(terminalHeadDigest({ ...head, sequence: '42' }));
    expect(newAuditEpochId(3, Date.UTC(2026, 10, 21))).toMatch(/^epoch-0003-20261121-[a-f0-9]{8}$/);
    expect(newAuditEpochId(3)).not.toBe(newAuditEpochId(3));
  });

  it('shows a restore when the journal is behind the witness or disagrees at the witnessed sequence', () => {
    const witnessed: AuditHead = { ledgerId: 'l', ledgerEpochId: 'e', sequence: '5', entryDigest: `sha256:${'5'.repeat(64)}` };
    expect(witnessShowsRestore(witnessed, null, null)).toBe(true);
    expect(witnessShowsRestore(witnessed, { ...witnessed, sequence: '4' }, null)).toBe(true);
    expect(witnessShowsRestore(witnessed, witnessed, witnessed.entryDigest)).toBe(false);
    expect(witnessShowsRestore(witnessed, { ...witnessed, sequence: '9', entryDigest: `sha256:${'9'.repeat(64)}` }, witnessed.entryDigest)).toBe(false);
    expect(witnessShowsRestore(witnessed, { ...witnessed, sequence: '9', entryDigest: `sha256:${'9'.repeat(64)}` }, `sha256:${'6'.repeat(64)}`)).toBe(true);
  });

  it('keeps the highest head per ledger in memory and in a file, written atomically', async () => {
    const memory = new MemoryRecorderWitness();
    const head: AuditHead = { ledgerId: 'l', ledgerEpochId: 'e1', sequence: '3', entryDigest: `sha256:${'3'.repeat(64)}` };
    await memory.record(head);
    await memory.record({ ...head, sequence: '2' });
    expect(await memory.read('l')).toEqual(head);
    await memory.record({ ...head, ledgerEpochId: 'e2', sequence: '0' });
    expect((await memory.read('l'))?.ledgerEpochId).toBe('e2');
    expect(await memory.read('none')).toBeNull();

    const dir = mkdtempSync(join(tmpdir(), 'a2-witness-'));
    dirs.push(dir);
    const path = join(dir, 'nested', 'witness.json');
    const file = new FileRecorderWitness(path);
    expect(file.durability).toBe('durable');
    expect(await file.read('l')).toBeNull();
    await Promise.all([file.record(head), file.record({ ...head, sequence: '4' }), file.record({ ...head, sequence: '1' })]);
    expect(JSON.parse(readFileSync(path, 'utf8'))).toEqual({ l: { ...head, sequence: '4' } });
    expect(await new FileRecorderWitness(path).read('l')).toMatchObject({ sequence: '4' });
    const unreadable = join(dir, 'is-a-directory');
    mkdirSync(unreadable);
    await expect(new FileRecorderWitness(unreadable).read('l')).rejects.toThrow();
  });

  it('verifies and seals a predecessor only at its committed head, idempotently', async () => {
    const journal = new MemoryAuditJournal();
    const recorder = managed(journal);
    await recorder.submit(submission(producerEvent('g1')), contextFor(producerEvent('g1')));
    const ledgerId = recorder.ledgerIdOf(TENANT);
    const [epoch] = await journal.listEpochs(ledgerId);
    const guard = new JournalEpochTransitionGuard(journal);
    const input = { ledgerId, previousEpochId: epoch!.ledgerEpochId, nextEpochId: 'next', previousTerminalCheckpointDigest: terminalHeadDigest(epoch!.head), reason: 'failover' as const };
    expect(await guard.verifyAndSeal({ ...input, previousEpochId: 'unknown' })).toBe(false);
    expect(await guard.verifyAndSeal({ ...input, previousTerminalCheckpointDigest: `sha256:${'0'.repeat(64)}` })).toBe(false);
    expect(await guard.verifyAndSeal(input)).toBe(true);
    expect(await guard.verifyAndSeal(input)).toBe(true);
    expect(await guard.verifyAndSeal({ ...input, nextEpochId: 'other' })).toBe(false);
    const racing = new JournalEpochTransitionGuard(
      overriding(new MemoryAuditJournal(), {
        listEpochs: async () => [{ ...epoch!, status: 'active' }],
        sealEpoch: async () => {
          throw new AuditProtocolError('AUDIT_JOURNAL_FAILURE', 'moved');
        },
      }),
    );
    expect(await racing.verifyAndSeal(input)).toBe(false);
    const broken = new JournalEpochTransitionGuard(
      overriding(new MemoryAuditJournal(), {
        listEpochs: async () => [{ ...epoch!, status: 'active' }],
        sealEpoch: async () => {
          throw new Error('disk');
        },
      }),
    );
    await expect(broken.verifyAndSeal(input)).rejects.toThrow('disk');
  });
});

describe('ManagedAuditRecorder', () => {
  it('keeps one ledger per tenant, and a self-hosted recorder only for its tenants', async () => {
    const journal = new MemoryAuditJournal();
    const recorder = managed(journal);
    const other = producerEvent('other', { tenantRef: { kind: 'public_did', did: 'did:web:second.example' }, producer: { kind: 'public_did', did: 'did:web:second.example' } });
    await recorder.submit(submission(producerEvent('t1')), contextFor(producerEvent('t1')));
    await recorder.submit(submission(other), contextFor(other));
    expect((await journal.listLedgers()).map((ledger) => ledger.ledgerId).sort()).toEqual([defaultAuditLedgerId(TENANT), defaultAuditLedgerId(other.tenantRef)].sort());
    expect(defaultAuditLedgerId(TENANT)).toMatch(/^ledger_[a-f0-9]{32}$/);
    expect(recorder.store).toBe(journal);

    expect(() => managed(journal, { mode: 'self-hosted' })).toThrow(/names the tenants/);
    const selfHosted = managed(journal, { mode: 'self-hosted', tenants: [TENANT] });
    expect((await refusal(selfHosted.submit(submission(other), contextFor(other)))).code).toBe('AUDIT_UNAUTHORIZED_SUBMISSION');

    const colliding = managed(new MemoryAuditJournal(), { ledgerIdFor: () => 'one-ledger' });
    await colliding.submit(submission(producerEvent('c1')), contextFor(producerEvent('c1')));
    expect((await refusal(colliding.submit(submission(other), contextFor(other)))).code).toBe('AUDIT_LEDGER_MISMATCH');
    const wrongLedger = await refusal(recorder.submit(submission(producerEvent('w'), { ledgerId: 'ledger_other' }), contextFor(producerEvent('w'))));
    expect(wrongLedger.code).toBe('AUDIT_LEDGER_MISMATCH');
    expect((await refusal(recorder.recorderFor('no-such-ledger'))).code).toBe('AUDIT_LEDGER_MISMATCH');
  });

  it('tells an observer of every producer entry, a redelivery too, and survives a throwing one', async () => {
    const seen: string[] = [];
    const recorder = managed(new MemoryAuditJournal(), { onRecorded: (entry, context) => seen.push(`${entry.core.sequence}:${context.producerAuthority}`) });
    const event = producerEvent('observed');
    const first = await recorder.submit(submission(event), contextFor(event));
    await recorder.submit(submission(event), contextFor(event));
    expect(seen).toEqual([`${first.core.sequence}:${contextFor(event).producerAuthority}`, `${first.core.sequence}:${contextFor(event).producerAuthority}`]);
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const throwing = managed(new MemoryAuditJournal(), {
      onRecorded: () => {
        throw new Error('index down');
      },
    });
    const recorded = await throwing.submit(submission(event), contextFor(event));
    expect(recorded.core.event.eventId).toBe('observed');
    expect(errors).toHaveBeenCalledWith('audit recorder: onRecorded observer failed', expect.any(Error));
    errors.mockRestore();
  });

  it('records administration events and starts every known ledger', async () => {
    const journal = new MemoryAuditJournal();
    const recorder = managed(journal);
    await recorder.submit(submission(producerEvent('s')), contextFor(producerEvent('s')));
    const ledgerId = recorder.ledgerIdOf(TENANT);
    const entry = await recorder.recordAdministration(ledgerId, {
      eventType: 'audit.exported',
      action: { category: 'audit.export' },
      outcome: 'succeeded',
      details: { family: 'administration', phase: 'exported', purpose: 'review' },
    });
    expect(entry.core.event.source.producer).toEqual({ kind: 'public_did', did: recorder.signer.ref.did });
    const restarted = managed(journal);
    await restarted.start();
    expect((await restarted.recorderFor(ledgerId)).head).toBeNull();
  });

  it('finishes a transition its predecessor was sealed for, and opens a pointer without a genesis', async () => {
    const journal = new MemoryAuditJournal();
    const first = managed(journal);
    await first.submit(submission(producerEvent('a')), contextFor(producerEvent('a')));
    const ledgerId = first.ledgerIdOf(TENANT);
    const [epoch] = await journal.listEpochs(ledgerId);
    // A recorder crashed after sealing its predecessor, before writing the successor's genesis.
    await journal.sealEpoch({ ledger: epoch!, expectedHead: epoch!.head, terminalDigest: terminalHeadDigest(epoch!.head), reason: 'retention_rollover', successorEpochId: 'epoch-successor' });
    const resumed = managed(journal);
    const entry = await resumed.submit(submission(producerEvent('b')), contextFor(producerEvent('b')));
    expect(entry.core.ledgerEpochId).toBe('epoch-successor');
    const [, genesis] = (await journal.listEpochs(ledgerId)).map((e) => e);
    expect(genesis?.ledgerEpochId).toBe('epoch-successor');

    // A ledger whose pointer was set, but whose first genesis never got written.
    const fresh = new MemoryAuditJournal();
    await fresh.ensureLedger({ ledgerId: defaultAuditLedgerId(TENANT), tenantRef: TENANT, createdAt: 1 });
    await fresh.setActiveEpoch(defaultAuditLedgerId(TENANT), null, 'epoch-pending');
    expect((await managed(fresh).submit(submission(producerEvent('c')), contextFor(producerEvent('c')))).core.ledgerEpochId).toBe('epoch-pending');
  });

  it('retries when another process set the first epoch first', async () => {
    const base = new MemoryAuditJournal();
    let raced = false;
    const store = overriding(base, {
      setActiveEpoch: async (ledgerId: string, expected: string | null, next: string) => {
        if (!raced) {
          raced = true;
          await base.setActiveEpoch(ledgerId, expected, 'epoch-winner');
          return false;
        }
        return base.setActiveEpoch(ledgerId, expected, next);
      },
    });
    const entry = await managed(store).submit(submission(producerEvent('r')), contextFor(producerEvent('r')));
    expect(entry.core.ledgerEpochId).toBe('epoch-winner');
  });

  it('refuses inconsistent ledger state instead of guessing', async () => {
    const base = new MemoryAuditJournal();
    const recorder = managed(base);
    await recorder.submit(submission(producerEvent('i')), contextFor(producerEvent('i')));
    const ledgerId = recorder.ledgerIdOf(TENANT);
    const [epoch] = await base.listEpochs(ledgerId);
    const ledger = (await base.getLedger(ledgerId))!;
    const cases: Array<Partial<AuditLedgerStore>> = [
      { getLedger: async () => ({ ...ledger, activeEpochId: null }) },
      { getLedger: async () => ({ ...ledger, activeEpochId: 'epoch-nowhere' }) },
      { listEpochs: async (): Promise<AuditEpochRecord[]> => [{ ...epoch!, status: 'sealed' }] },
    ];
    for (const overrides of cases) {
      const failure = await refusal(managed(overriding(base, overrides)).recorderFor(ledgerId));
      expect(failure.code).toBe('AUDIT_JOURNAL_FAILURE');
      expect(failure.message).toMatch(/inconsistent/);
    }
    const stuck = await refusal(managed(overriding(base, { getLedger: async () => ({ ...ledger, activeEpochId: null }), listEpochs: async () => [] })).recorderFor(ledgerId));
    expect(stuck.message).toMatch(/first epoch could not be set/);
    const noActive = await refusal(managed(overriding(base, { getLedger: async () => ({ ...ledger, activeEpochId: null }), listEpochs: async () => [] })).transition(ledgerId, 'failover'));
    expect(noActive.code).toBe('AUDIT_LEDGER_MISMATCH');
    const sealedActive = await refusal(managed(overriding(base, { listEpochs: async (): Promise<AuditEpochRecord[]> => [{ ...epoch!, status: 'sealed' }] })).transition(ledgerId, 'failover'));
    expect(sealedActive.message).toMatch(/no genesis to close/);
  });

  it('gives up a transition whose predecessor keeps moving', async () => {
    const base = new MemoryAuditJournal();
    const recorder = managed(base);
    await recorder.submit(submission(producerEvent('m')), contextFor(producerEvent('m')));
    const ledgerId = recorder.ledgerIdOf(TENANT);
    const moving = managed(
      overriding(base, {
        sealEpoch: async () => {
          throw new AuditProtocolError('AUDIT_JOURNAL_FAILURE', 'moved');
        },
      }),
    );
    expect((await refusal(moving.transition(ledgerId, 'failover'))).code).toBe('AUDIT_APPEND_CONFLICT_EXHAUSTED');
  });

  it('detects a restore from the witness: an epoch the journal lost, or another digest at the witnessed sequence', async () => {
    const journal = new MemoryAuditJournal();
    const witness = new MemoryRecorderWitness();
    const transitions: string[] = [];
    const recorder = managed(journal, { witness, onEpochTransition: (t) => transitions.push(t.reason) });
    await recorder.submit(submission(producerEvent('w1')), contextFor(producerEvent('w1')));
    await recorder.settled();
    const ledgerId = recorder.ledgerIdOf(TENANT);
    const [epoch] = await journal.listEpochs(ledgerId);

    // The witness names a sealed epoch the journal still has: no restore.
    await witness.record({ ...epoch!.head, ledgerEpochId: epoch!.ledgerEpochId });
    await managed(journal, { witness }).start();
    expect(transitions).toEqual([]);

    // The witness names an epoch the journal never saw: the journal was restored from before it.
    const lost = new MemoryRecorderWitness();
    await lost.record({ ledgerId, ledgerEpochId: 'epoch-lost', sequence: '9', entryDigest: `sha256:${'9'.repeat(64)}` });
    await managed(journal, { witness: lost, onEpochTransition: (t) => transitions.push(t.reason) }).start();
    expect(transitions).toEqual(['restore']);

    // The witness names another digest at a sequence the journal holds: a fork, also a restore.
    const [, active] = await journal.listEpochs(ledgerId);
    const forked = new MemoryRecorderWitness();
    await forked.record({ ...active!.head, entryDigest: `sha256:${'f'.repeat(64)}` });
    await managed(journal, { witness: forked, onEpochTransition: (t) => transitions.push(t.reason) }).start();
    expect(transitions).toEqual(['restore', 'restore']);
    const epochs = await journal.listEpochs(ledgerId);
    expect(epochs.map((e) => e.sealReason ?? 'active')).toEqual(['restore', 'restore', 'active']);
  });

  it('keeps a commit when the witness cannot be written, and reports it', async () => {
    const failing = { durability: 'durable' as const, read: async () => null, record: async () => { throw new Error('disk full'); } };
    const reported = vi.fn();
    const recorder = managed(new MemoryAuditJournal(), { witness: failing, onWitnessFailure: reported });
    const entry = await recorder.submit(submission(producerEvent('kept')), contextFor(producerEvent('kept')));
    expect(entry.core.sequence).toBe('1');
    await recorder.settled();
    expect(reported).toHaveBeenCalledWith(expect.objectContaining({ message: 'disk full' }));
    const logged = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const silent = managed(new MemoryAuditJournal(), { witness: failing });
    await silent.submit(submission(producerEvent('k2')), contextFor(producerEvent('k2')));
    await silent.settled();
    expect(logged).toHaveBeenCalledWith('AUDIT_WITNESS_WRITE_FAILED', expect.any(Error));
    logged.mockRestore();
  });

  it('reopens after another replica sealed the epoch, and rotates keys only at activation', async () => {
    const journal = new MemoryAuditJournal();
    const a = managed(journal);
    const b = managed(journal);
    await a.submit(submission(producerEvent('a1')), contextFor(producerEvent('a1')));
    const ledgerId = a.ledgerIdOf(TENANT);
    await b.transition(ledgerId, 'failover');
    // a still holds the sealed epoch: its next append is refused as sealed, it reopens the successor.
    const moved = await a.submit(submission(producerEvent('a2')), contextFor(producerEvent('a2')));
    expect(moved.core.ledgerEpochId).not.toBe((await journal.listEpochs(ledgerId))[0]!.ledgerEpochId);
    const rotated = managed(journal, { signer: testRecorderSigner(TEST_RECORDER_KEYS.other) });
    await rotated.start();
    expect((await journal.listEpochs(ledgerId)).at(-2)?.sealReason).toBe('key_rotation');
    expect((await refusal(a.submit(submission(producerEvent('a3')), contextFor(producerEvent('a3'))))).code).toBe('AUDIT_UNAUTHORIZED_SUBMISSION');
  });
});
