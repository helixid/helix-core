// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The authoritative recorder (A-2 point 1, 4) over the memory journal and
 * fault-injecting journals: envelope and authority checks, write-ahead
 * evidence and its compensation, genesis validation, compare-and-append
 * retries, regression detection (fail closed), and idempotency races.
 */

import { describe, expect, it, vi } from 'vitest';
import {
  AUDIT_BINDING_HELIX,
  AuditProtocolError,
  AuditRecorderService,
  EvidenceEncryptor,
  MemoryAuditJournal,
  MemoryEvidenceStore,
  auditEventDigest,
  auditReceiptPayload,
  evidenceAad,
  jwsAuditSigner,
  EnvSigner,
  verifyJws,
  didKeyPublicJwk,
  type AuditAppendResult,
  type AuditHead,
  type AuditJournalProvider,
  type AuditRecorderServiceConfig,
  type SignedAuditEntry,
} from '../../../../src/core/index.js';
import { TENANT, contextFor, producerEvent, submission, testRecorderSigner } from '../../../utils/auditLedger.js';

const ledger = { ledgerId: 'ledger-unit', ledgerEpochId: 'epoch-1' };

function config(overrides: Partial<AuditRecorderServiceConfig> = {}): AuditRecorderServiceConfig {
  return {
    ...ledger,
    tenantRef: TENANT,
    binding: AUDIT_BINDING_HELIX,
    sourceId: 'recorder',
    journal: new MemoryAuditJournal(),
    signer: testRecorderSigner(),
    clock: { now: () => 1_790_000_000_000 },
    ...overrides,
  };
}

async function refusal(promise: Promise<unknown>): Promise<AuditProtocolError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof AuditProtocolError) return error;
    throw error;
  }
  throw new Error('expected a refusal');
}

/** A journal that delegates to a memory journal, with overridable methods. */
function wrap(base: MemoryAuditJournal, overrides: Partial<AuditJournalProvider>): AuditJournalProvider {
  return {
    capabilities: base.capabilities,
    getHead: overrides.getHead ?? ((l) => base.getHead(l)),
    getByIdempotencyKey: overrides.getByIdempotencyKey ?? ((id, key) => base.getByIdempotencyKey(id, key)),
    compareAndAppend: overrides.compareAndAppend ?? ((input) => base.compareAndAppend(input)),
    readRange: overrides.readRange ?? ((query) => base.readRange(query)),
  };
}

describe('AuditRecorderService', () => {
  it('assigns sequence, predecessor, service time and a receipt the recorder key verifies', async () => {
    const signer = testRecorderSigner();
    const recorder = new AuditRecorderService(config({ signer }));
    expect(recorder.head).toBeNull();
    expect(recorder.recorder).toEqual(signer.ref);
    expect(recorder.tenantRef).toEqual(TENANT);
    const event = producerEvent('first');
    const entry = await recorder.submitAuthenticated(submission(event), contextFor(event));
    expect(entry.core).toMatchObject({ sequence: '1', recordedAt: 1_790_000_000_000, recorder: signer.ref, event });
    expect(entry.eventDigest).toBe(auditEventDigest(event));
    expect(recorder.head).toMatchObject({ sequence: '1', entryDigest: entry.entryDigest });
    const verified = verifyJws(entry.recorderReceipt.jws, didKeyPublicJwk(signer.ref.did)!, { expectedKid: signer.ref.kid });
    expect(Buffer.from(verified.payloadBytes)).toEqual(Buffer.from(auditReceiptPayload(entry.recorderReceipt.core)));
    expect(Object.isFrozen(entry.core)).toBe(true);
  });

  it('signs with any L1-C Signer whose kid becomes <did>#<fragment>', async () => {
    const signer = jwsAuditSigner(new EnvSigner({ did: 'did:web:audit.example', kid: '#recorder-1', envVar: 'K', env: { K: '4'.repeat(64) } }));
    expect(signer.ref).toEqual({ did: 'did:web:audit.example', kid: 'did:web:audit.example#recorder-1', alg: 'EdDSA' });
    expect((await signer.sign(new Uint8Array([1]))).split('.')).toHaveLength(3);
  });

  it('refuses inconsistent epoch configuration', () => {
    expect(() => new AuditRecorderService(config({ previousEpochId: 'epoch-0' }))).toThrow(/supplied together/);
    expect(() => new AuditRecorderService(config({ previousEpochId: 'epoch-0', previousTerminalCheckpointDigest: `sha256:${'1'.repeat(64)}` }))).toThrow(/verify-and-seal guard/);
  });

  it('refuses a submission whose envelope, producer, tenant or authorizer does not hold', async () => {
    const event = producerEvent('refused');
    const recorder = new AuditRecorderService(config({ authorizer: { authorize: ({ context }) => context.producerAuthority !== 'did:web:blocked.example' } }));
    expect((await refusal(recorder.submitAuthenticated(submission(event), { ...contextFor(event), producerAuthority: '' }))).code).toBe('AUDIT_UNAUTHORIZED_SUBMISSION');
    expect((await refusal(recorder.submitAuthenticated(submission(event, { ledgerId: 'other' }), contextFor(event)))).code).toBe('AUDIT_LEDGER_MISMATCH');
    const notProducer = { ...contextFor(event), producerRef: undefined, producerAuthority: 'did:web:someone-else.example' };
    expect((await refusal(recorder.submitAuthenticated(submission(event), notProducer))).message).toMatch(/producer/);
    const foreignTenant = producerEvent('foreign', { tenantRef: { kind: 'public_did', did: 'did:web:other-tenant.example' } });
    expect((await refusal(recorder.submitAuthenticated(submission(foreignTenant), contextFor(foreignTenant)))).message).toMatch(/tenant/);
    const blocked = producerEvent('blocked', { producer: { kind: 'public_did', did: 'did:web:blocked.example' } });
    expect((await refusal(recorder.submitAuthenticated(submission(blocked), contextFor(blocked)))).message).toMatch(/not authorized/);
    const keyed = producerEvent('keyed', { producer: { kind: 'keyed_commitment', value: `sha256:${'5'.repeat(64)}`, keyId: 'k' } });
    expect((await refusal(recorder.submitAuthenticated(submission(keyed), { ...contextFor(keyed), producerRef: undefined }))).code).toBe('AUDIT_UNAUTHORIZED_SUBMISSION');
  });

  it('persists submitted evidence write-ahead, exactly as the event references it, and refuses anything else', async () => {
    const encryptor = new EvidenceEncryptor({ key: 'ef'.repeat(32), keyId: 'k' });
    const object = encryptor.encrypt({ plaintext: 'x', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    const event = { ...producerEvent('with-evidence'), evidence: [object.ref] };
    const without = new AuditRecorderService(config());
    expect((await refusal(without.submitAuthenticated(submission(event, { encryptedEvidence: [object] }), contextFor(event)))).code).toBe('AUDIT_EVIDENCE_FAILURE');

    const vault = new MemoryEvidenceStore();
    const has = async (objectId: string): Promise<boolean> => (await vault.get(objectId)) !== null;
    const recorder = new AuditRecorderService(config({ evidence: { has, putIfAbsent: (o) => vault.putIfAbsent(o) } }));
    expect((await refusal(recorder.submitAuthenticated(submission(event, { encryptedEvidence: [object, object] }), contextFor(event)))).message).toMatch(/unique frozen event reference/);
    const otherRef = { ...object, ref: { ...object.ref, mediaType: 'text/other' } };
    expect((await refusal(recorder.submitAuthenticated(submission(event, { encryptedEvidence: [otherRef] }), contextFor(event)))).code).toBe('AUDIT_EVIDENCE_FAILURE');
    const entry = await recorder.submitAuthenticated(submission(event, { encryptedEvidence: [object] }), contextFor(event));
    expect(entry.core.event.evidence).toEqual([object.ref]);
    expect(await vault.get(object.ref.objectId)).not.toBeNull();

    const broken = new AuditRecorderService(config({ evidence: { has: async () => false, putIfAbsent: async () => { throw new Error('disk full'); } } }));
    const persisted = await refusal(broken.submitAuthenticated(submission(event, { encryptedEvidence: [object] }), contextFor(event)));
    expect(persisted.message).toMatch(/could not be persisted/);
  });

  it('discards only the evidence a failed append newly stored, never shared or committed objects', async () => {
    const encryptor = new EvidenceEncryptor({ key: '12'.repeat(32), keyId: 'k' });
    const fresh = encryptor.encrypt({ plaintext: 'new', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    const existing = encryptor.encrypt({ plaintext: 'old', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    const stored = new Set<string>([existing.ref.objectId]);
    const discarded: string[] = [];
    const evidence = {
      has: async (id: string) => stored.has(id),
      putIfAbsent: async (o: { ref: { objectId: string } }) => void stored.add(o.ref.objectId),
      discardUncommitted: async (id: string) => void discarded.push(id),
    };
    const base = new MemoryAuditJournal();
    let fail = false;
    const journal = wrap(base, {
      compareAndAppend: async (input) => {
        if (fail) throw new Error('connection reset');
        return base.compareAndAppend(input);
      },
    });
    const recorder = new AuditRecorderService(config({ journal, evidence }));
    await recorder.open();
    fail = true;
    const event = { ...producerEvent('fails'), evidence: [fresh.ref, existing.ref] };
    const failure = await refusal(recorder.submitAuthenticated(submission(event, { encryptedEvidence: [fresh, existing] }), contextFor(event)));
    expect(failure.code).toBe('AUDIT_JOURNAL_FAILURE');
    expect(discarded).toEqual([fresh.ref.objectId]);

    // Two submissions holding one new object at once: neither discards it.
    const shared = encryptor.encrypt({ plaintext: 'shared', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    const one = { ...producerEvent('one'), evidence: [shared.ref] };
    const two = { ...producerEvent('two'), evidence: [shared.ref] };
    await Promise.all([
      refusal(recorder.submitAuthenticated(submission(one, { encryptedEvidence: [shared] }), contextFor(one))),
      refusal(recorder.submitAuthenticated(submission(two, { encryptedEvidence: [shared] }), contextFor(two))),
    ]);
    expect(discarded).toEqual([fresh.ref.objectId]);
  });

  it('keeps an orphan when the identity was committed meanwhile, or the discard itself fails', async () => {
    const encryptor = new EvidenceEncryptor({ key: '34'.repeat(32), keyId: 'k' });
    const object = encryptor.encrypt({ plaintext: 'x', mediaType: 'text/plain', aad: evidenceAad(TENANT, 'p') });
    const event = { ...producerEvent('orphan'), evidence: [object.ref] };
    const base = new MemoryAuditJournal();
    const genuine = await new AuditRecorderService(config({ journal: base })).submitAuthenticated(submission(producerEvent('genuine')), contextFor(producerEvent('genuine')));
    let committedMeanwhile = false;
    const journal = wrap(base, {
      // The append commits, then the connection drops before the answer arrives.
      compareAndAppend: async () => {
        committedMeanwhile = true;
        throw new Error('timeout after commit');
      },
      getByIdempotencyKey: async (id, key) => (committedMeanwhile ? genuine : base.getByIdempotencyKey(id, key)),
    });
    const discard = vi.fn(async () => undefined);
    const recorder = new AuditRecorderService(config({ journal, evidence: { has: async () => false, putIfAbsent: async () => undefined, discardUncommitted: discard } }));
    await refusal(recorder.submitAuthenticated(submission(event, { encryptedEvidence: [object] }), contextFor(event)));
    expect(discard).not.toHaveBeenCalled();

    const failing = vi.fn(async () => {
      throw new Error('vault down');
    });
    const plain = wrap(base, { compareAndAppend: async () => { throw new Error('socket'); } });
    const second = new AuditRecorderService(config({ journal: plain, evidence: { has: async () => false, putIfAbsent: async () => undefined, discardUncommitted: failing } }));
    expect((await refusal(second.submitAuthenticated(submission(event, { encryptedEvidence: [object] }), contextFor(event)))).code).toBe('AUDIT_JOURNAL_FAILURE');
    expect(failing).toHaveBeenCalledTimes(1);
  });

  it('refuses an existing genesis that does not match its configuration, or a head without genesis', async () => {
    const journal = new MemoryAuditJournal();
    await new AuditRecorderService(config({ journal })).open();
    const other = new AuditRecorderService(config({ journal, signer: testRecorderSigner('9'.repeat(64)) }));
    const mismatch = await refusal(other.open());
    expect(mismatch.code).toBe('AUDIT_JOURNAL_FAILURE');
    expect(mismatch.message).toMatch(/genesis does not match/);
    const headless = new AuditRecorderService(
      config({ journal: wrap(new MemoryAuditJournal(), { getHead: async () => ({ ...ledger, sequence: '3', entryDigest: `sha256:${'1'.repeat(64)}` }) }) }),
    );
    expect((await refusal(headless.open())).message).toMatch(/without genesis/);
  });

  it('refuses a successor epoch whose predecessor cannot be verified and sealed, recording failover by default', async () => {
    const verifyAndSeal = vi.fn(async () => false);
    const recorder = new AuditRecorderService(
      config({ previousEpochId: 'epoch-0', previousTerminalCheckpointDigest: `sha256:${'1'.repeat(64)}`, epochTransitionGuard: { verifyAndSeal } }),
    );
    expect((await refusal(recorder.open())).code).toBe('AUDIT_INVALID_CONFIGURATION');
    expect(verifyAndSeal).toHaveBeenCalledWith(expect.objectContaining({ reason: 'failover', nextEpochId: 'epoch-1' }));
  });

  it('retries a head conflict against a replica that moved, and gives up only after its budget', async () => {
    const journal = new MemoryAuditJournal();
    const a = new AuditRecorderService(config({ journal }));
    const b = new AuditRecorderService(config({ journal }));
    const events = Array.from({ length: 20 }, (_, i) => producerEvent(`replica-${i}`));
    const entries = await Promise.all(events.map((event, i) => (i % 2 === 0 ? a : b).submitAuthenticated(submission(event), contextFor(event))));
    expect(entries.map((entry) => Number(entry.core.sequence)).sort((x, y) => x - y)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));

    const base = new MemoryAuditJournal();
    await new AuditRecorderService(config({ journal: base })).open();
    let moved = 0;
    const moving = wrap(base, {
      compareAndAppend: async (): Promise<AuditAppendResult> => {
        moved += 1;
        return { kind: 'head_conflict', actualHead: { ...ledger, sequence: String(moved), entryDigest: `sha256:${String(moved % 10).repeat(64)}` } };
      },
    });
    const exhausted = new AuditRecorderService(config({ journal: moving, maxAppendConflicts: 2 }));
    expect((await refusal(exhausted.submitAuthenticated(submission(producerEvent('x')), contextFor(producerEvent('x'))))).code).toBe('AUDIT_APPEND_CONFLICT_EXHAUSTED');
  });

  it('fails closed on a conflict that does not advance the head, a head below its commits, or a fork at a sequence it saw', async () => {
    const base = new MemoryAuditJournal();
    const recorder = new AuditRecorderService(config({ journal: base }));
    await recorder.submitAuthenticated(submission(producerEvent('a')), contextFor(producerEvent('a')));
    const head = (await base.getHead(ledger))!;

    const stuck = new AuditRecorderService(config({ journal: wrap(base, { compareAndAppend: async () => ({ kind: 'head_conflict', actualHead: head }) }) }));
    await stuck.open();
    expect((await refusal(stuck.submitAuthenticated(submission(producerEvent('b')), contextFor(producerEvent('b'))))).message).toMatch(/without advancing/);

    let behind: AuditHead | null = { ...head, sequence: '0' };
    const rewinding = wrap(base, { compareAndAppend: async () => ({ kind: 'head_conflict', actualHead: behind }) });
    const committedRecorder = new AuditRecorderService(config({ journal: base }));
    await committedRecorder.submitAuthenticated(submission(producerEvent('c')), contextFor(producerEvent('c')));
    Object.assign(committedRecorder as unknown as { config: AuditRecorderServiceConfig }, { config: { ...config({ journal: rewinding }) } });
    expect((await refusal(committedRecorder.submitAuthenticated(submission(producerEvent('d')), contextFor(producerEvent('d'))))).message).toMatch(/moved behind/);
    behind = null;
    expect((await refusal(committedRecorder.submitAuthenticated(submission(producerEvent('e')), contextFor(producerEvent('e'))))).message).toMatch(/moved behind/);

    // A different digest at the sequence the journal already reported: a fork.
    const current = (await base.getHead(ledger))!;
    let calls = 0;
    const forking = wrap(base, {
      getHead: async () => ({ ...current, sequence: '0', entryDigest: `sha256:${'0'.repeat(64)}` }),
      compareAndAppend: async (): Promise<AuditAppendResult> => {
        calls += 1;
        return {
          kind: 'head_conflict',
          actualHead: calls === 1 ? current : { ...current, entryDigest: `sha256:${'f'.repeat(64)}` },
        };
      },
    });
    const observer = new AuditRecorderService(config({ journal: forking }));
    (observer as unknown as { genesis: SignedAuditEntry }).genesis = {} as SignedAuditEntry;
    expect((await refusal(observer.submitAuthenticated(submission(producerEvent('f')), contextFor(producerEvent('f'))))).message).toMatch(/moved behind/);
  });

  it('wraps a journal that throws as AUDIT_JOURNAL_FAILURE, but passes sealed-epoch and authority refusals through', async () => {
    const base = new MemoryAuditJournal();
    await new AuditRecorderService(config({ journal: base })).open();
    const cases: Array<[unknown, string]> = [
      [new Error('socket'), 'AUDIT_JOURNAL_FAILURE'],
      [new AuditProtocolError('AUDIT_EPOCH_MISMATCH', 'sealed'), 'AUDIT_EPOCH_MISMATCH'],
      [new AuditProtocolError('AUDIT_UNAUTHORIZED_SUBMISSION', 'authority'), 'AUDIT_UNAUTHORIZED_SUBMISSION'],
    ];
    for (const [thrown, code] of cases) {
      const recorder = new AuditRecorderService(config({ journal: wrap(base, { compareAndAppend: async () => { throw thrown; } }) }));
      expect((await refusal(recorder.submitAuthenticated(submission(producerEvent(code)), contextFor(producerEvent(code))))).code).toBe(code);
    }
  });

  it('resolves idempotency races to the original entry, or to an event-id conflict', async () => {
    const base = new MemoryAuditJournal();
    const original = new AuditRecorderService(config({ journal: base }));
    const event = producerEvent('raced');
    const first = await original.submitAuthenticated(submission(event), contextFor(event));
    // The first lookup misses (the race), the second (inside the append) finds it.
    let misses = 1;
    const racing = wrap(base, {
      getByIdempotencyKey: async (id, key) => (misses-- > 0 ? null : base.getByIdempotencyKey(id, key)),
    });
    const late = new AuditRecorderService(config({ journal: racing }));
    expect(await late.submitAuthenticated(submission(event), contextFor(event))).toEqual(first);
    // The append itself answers duplicate / idempotency_conflict.
    const answering = (result: AuditAppendResult): AuditJournalProvider => wrap(base, { getByIdempotencyKey: async () => null, compareAndAppend: async () => result });
    const dup = new AuditRecorderService(config({ journal: answering({ kind: 'duplicate', entry: first }) }));
    expect(await dup.submitAuthenticated(submission(event), contextFor(event))).toEqual(first);
    const conflict = new AuditRecorderService(config({ journal: answering({ kind: 'idempotency_conflict', existing: first }) }));
    const changed = producerEvent('raced', { outcome: 'failed' });
    expect((await refusal(conflict.submitAuthenticated(submission(changed), contextFor(changed)))).code).toBe('AUDIT_EVENT_ID_CONFLICT');
  });

  it('settles a cold-start genesis race between replicas on epoch configuration', async () => {
    const journal = new MemoryAuditJournal();
    const replicas = [new AuditRecorderService(config({ journal })), new AuditRecorderService(config({ journal, clock: { now: () => 1_790_000_000_999 } }))];
    const [a, b] = await Promise.all(replicas.map((recorder) => recorder.open()));
    expect(a).toEqual(b);
    // A genesis raced in by another replica between the head read and the append.
    const base = new MemoryAuditJournal();
    const winner = new AuditRecorderService(config({ journal: base }));
    const won = await winner.open();
    let reads = 0;
    const late = new AuditRecorderService(
      config({
        journal: wrap(base, {
          getHead: async (l) => (reads++ < 1 ? null : base.getHead(l)),
          getByIdempotencyKey: async (id, key) => (reads < 2 ? null : base.getByIdempotencyKey(id, key)),
        }),
      }),
    );
    expect(await late.open()).toEqual(won);
  });

  it('refuses a producer event in the genesis position and a genesis past it', async () => {
    const base = new MemoryAuditJournal();
    const recorder = new AuditRecorderService(config({ journal: wrap(base, { getHead: async () => null }) }));
    (recorder as unknown as { genesis: unknown }).genesis = {};
    expect((await refusal(recorder.submitAuthenticated(submission(producerEvent('g')), contextFor(producerEvent('g'))))).message).toMatch(/cannot replace genesis/);
  });

  it('records its own administration events under its own DID and source', async () => {
    const recorder = new AuditRecorderService(config());
    const event = recorder.ownEvent({
      eventId: 'admin-1',
      eventType: 'audit.accessed',
      occurredAt: 1,
      action: { category: 'audit.access' },
      outcome: 'succeeded',
      details: { family: 'administration', phase: 'accessed', purpose: 'review' },
      privacy: { classification: 'internal', retentionClass: 'integrity-ledger' },
    });
    expect(event.source).toEqual({ producer: { kind: 'public_did', did: recorder.recorder.did }, sourceId: 'recorder' });
    const entry = await recorder.recordOwnEvent(event);
    expect(entry.core.sequence).toBe('1');
  });
});
