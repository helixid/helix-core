// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The verify walk (L3-F point 5): every break reason at the entry it
 * concerns, the epoch chain (root, forks, unreachable epochs, commitments),
 * key pinning and resolution; and the ledger helpers it relies on.
 */

import { describe, expect, it } from 'vitest';
import {
  AuditRecorderService,
  AUDIT_BINDING_HELIX,
  ManagedAuditRecorder,
  MemoryAuditJournal,
  auditReceiptPayload,
  buildAuditReceiptCore,
  canonicalize,
  collectAuditEvidenceRefs,
  didKeyPublicJwk,
  digestAuditEntry,
  parseAuditEntryCore,
  parseSignedAuditEntry,
  signedAuditEntryIssue,
  signerRefOf,
  verifyAuditLedger,
  type AuditLedgerEpochSource,
  type AuditProducerEvent,
  type EvidenceRef,
  type SignedAuditEntry,
  type StoredAuditEntry,
} from '../../../../src/core/index.js';
import { TENANT, contextFor, producerEvent, submission, testRecorderSigner } from '../../../utils/auditLedger.js';

async function ledgerOf(count: number): Promise<{ journal: MemoryAuditJournal; ledgerId: string; recorder: ManagedAuditRecorder }> {
  const journal = new MemoryAuditJournal();
  const recorder = new ManagedAuditRecorder({ store: journal, signer: testRecorderSigner() });
  for (let i = 1; i <= count; i += 1) await recorder.submit(submission(producerEvent(`v-${i}`)), contextFor(producerEvent(`v-${i}`)));
  return { journal, ledgerId: recorder.ledgerIdOf(TENANT), recorder };
}

async function storedRows(journal: MemoryAuditJournal, ledgerId: string, epochIndex = 0): Promise<StoredAuditEntry[]> {
  const epoch = (await journal.listEpochs(ledgerId))[epochIndex]!;
  const rows: StoredAuditEntry[] = [];
  for await (const row of journal.readStoredRange(epoch)) rows.push(row);
  return rows;
}

async function sourcesOf(journal: MemoryAuditJournal, ledgerId: string): Promise<AuditLedgerEpochSource[]> {
  return (await journal.listEpochs(ledgerId)).map((epoch) => ({ ledgerEpochId: epoch.ledgerEpochId, read: () => journal.readStoredRange(epoch), storedHead: epoch.head }));
}

/** Re-signs an altered entry with the recorder key: only what the test changed is wrong. */
async function resigned(entry: SignedAuditEntry, change: (copy: SignedAuditEntry) => void): Promise<SignedAuditEntry> {
  const copy = structuredClone(entry);
  change(copy);
  copy.entryDigest = digestAuditEntry(copy.core);
  copy.recorderReceipt.core = buildAuditReceiptCore(copy.core, copy.entryDigest);
  copy.recorderReceipt.jws = await testRecorderSigner().sign(auditReceiptPayload(copy.recorderReceipt.core));
  return copy;
}

function rowOf(entry: SignedAuditEntry): StoredAuditEntry {
  return {
    ledgerId: entry.core.ledgerId,
    ledgerEpochId: entry.core.ledgerEpochId,
    sequence: entry.core.sequence,
    entryDigest: entry.entryDigest,
    eventDigest: entry.eventDigest,
    previousEntryDigest: entry.core.previousEntryDigest,
    entryText: canonicalize(entry),
  };
}

describe('verifyAuditLedger', () => {
  it('verifies an untouched ledger, warning when recorder keys are not pinned', async () => {
    const { journal, ledgerId, recorder } = await ledgerOf(3);
    const unpinned = await verifyAuditLedger({ ledgerId, epochs: await sourcesOf(journal, ledgerId) });
    expect(unpinned).toMatchObject({ ok: true, entriesVerified: 4 });
    expect(unpinned.warnings[0]).toMatch(/not pinned/);
    const pinned = await verifyAuditLedger({ ledgerId, epochs: await sourcesOf(journal, ledgerId), trustedRecorders: [recorder.signer.ref.kid] });
    expect(pinned.warnings).toEqual([]);
    expect(pinned.epochs[0]).toMatchObject({ entries: 4, previousEpochId: null, transitionReason: null });
    expect(await verifyAuditLedger({ ledgerId, epochs: [] })).toMatchObject({ ok: true, entriesVerified: 0 });
  });

  const tamperCases: Array<{ name: string; at: string; reason: string; alter: (rows: StoredAuditEntry[]) => Promise<StoredAuditEntry[]> | StoredAuditEntry[] }> = [
    { name: 'text that is not JSON', at: '2', reason: 'entry_unreadable', alter: (rows) => rows.map((r) => (r.sequence === '2' ? { ...r, entryText: '{' } : r)) },
    {
      name: 'text that is not a signed entry',
      at: '2',
      reason: 'entry_schema_invalid',
      alter: (rows) => rows.map((r) => (r.sequence === '2' ? { ...r, entryText: JSON.stringify({ ...JSON.parse(r.entryText), extra: 1 }) } : r)),
    },
    { name: 'a column', at: '1', reason: 'stored_columns_mismatch', alter: (rows) => rows.map((r) => (r.sequence === '1' ? { ...r, eventDigest: `sha256:${'0'.repeat(64)}` } : r)) },
    { name: 'a missing entry', at: '3', reason: 'sequence_gap', alter: (rows) => rows.filter((r) => r.sequence !== '2') },
    {
      name: 'the evidence manifest digest',
      at: '2',
      reason: 'evidence_manifest_mismatch',
      alter: (rows) =>
        rows.map((r) => {
          if (r.sequence !== '2') return r;
          const entry = JSON.parse(r.entryText) as SignedAuditEntry;
          entry.core.evidenceManifestDigest = `sha256:${'0'.repeat(64)}`;
          return { ...r, entryText: canonicalize(entry) };
        }),
    },
    {
      name: 'a predecessor link re-signed by the recorder key (a fork)',
      at: '2',
      reason: 'predecessor_mismatch',
      alter: async (rows) =>
        Promise.all(
          rows.map(async (r) => {
            if (r.sequence !== '2') return r;
            return rowOf(await resigned(JSON.parse(r.entryText) as SignedAuditEntry, (copy) => void (copy.core.previousEntryDigest = `sha256:${'a'.repeat(64)}`)));
          }),
        ),
    },
    {
      name: 'a genesis replaced by a signed non-genesis',
      at: '0',
      reason: 'genesis_invalid',
      alter: async (rows) =>
        Promise.all(
          rows.map(async (r) => {
            if (r.sequence !== '0') return r;
            return rowOf(
              await resigned(JSON.parse(r.entryText) as SignedAuditEntry, (copy) => {
                copy.core.event = { ...copy.core.event, eventType: 'audit.accessed', details: { family: 'administration', phase: 'accessed' } };
                copy.core.eventDigest = `sha256:${'0'.repeat(64)}`;
                copy.eventDigest = copy.core.eventDigest;
              }),
            );
          }),
        ),
    },
  ];

  for (const testCase of tamperCases) {
    it(`breaks at sequence ${testCase.at} for ${testCase.name}`, async () => {
      const { journal, ledgerId } = await ledgerOf(3);
      const [epoch] = await journal.listEpochs(ledgerId);
      const rows = await testCase.alter(await storedRows(journal, ledgerId));
      const result = await verifyAuditLedger({ ledgerId, epochs: [{ ledgerEpochId: epoch!.ledgerEpochId, read: () => rows }] });
      expect(result.ok).toBe(false);
      if (testCase.reason === 'genesis_invalid') {
        expect(['genesis_invalid', 'event_digest_mismatch']).toContain(result.brokenLink?.reason);
      } else {
        expect(result.brokenLink).toMatchObject({ ledgerEpochId: epoch!.ledgerEpochId, sequence: testCase.at, reason: testCase.reason });
      }
    });
  }

  it('breaks at a genesis that is a signed entry of another kind, with its digests consistent', async () => {
    const { journal, ledgerId } = await ledgerOf(1);
    const rows = await storedRows(journal, ledgerId);
    const genesis = JSON.parse(rows[0]!.entryText) as SignedAuditEntry;
    const producer = JSON.parse(rows[1]!.entryText) as SignedAuditEntry;
    const forged = await resigned(genesis, (copy) => {
      copy.core.event = producer.core.event;
      copy.core.eventDigest = producer.core.eventDigest;
      copy.eventDigest = producer.eventDigest;
      copy.core.evidenceManifestDigest = producer.core.evidenceManifestDigest;
    });
    const result = await verifyAuditLedger({ ledgerId, epochs: [{ ledgerEpochId: genesis.core.ledgerEpochId, read: () => [rowOf(forged)] }] });
    expect(result.brokenLink).toMatchObject({ sequence: '0', reason: 'genesis_invalid' });
  });

  it('breaks on another ledger\'s entry, a recorder change inside an epoch, an unpinned or unresolvable recorder', async () => {
    const { journal, ledgerId } = await ledgerOf(2);
    const [epoch] = await journal.listEpochs(ledgerId);
    const rows = await storedRows(journal, ledgerId);
    expect((await verifyAuditLedger({ ledgerId: 'other-ledger', epochs: [{ ledgerEpochId: epoch!.ledgerEpochId, read: () => rows }] })).brokenLink?.reason).toBe(
      'ledger_mismatch',
    );
    const second = JSON.parse(rows[1]!.entryText) as SignedAuditEntry;
    const otherSigner = testRecorderSigner('7'.repeat(64));
    const foreign = structuredClone(second);
    foreign.core.recorder = otherSigner.ref;
    foreign.entryDigest = digestAuditEntry(foreign.core);
    foreign.recorderReceipt.core = buildAuditReceiptCore(foreign.core, foreign.entryDigest);
    foreign.recorderReceipt.jws = await otherSigner.sign(auditReceiptPayload(foreign.recorderReceipt.core));
    const swapped = [rows[0]!, rowOf(foreign), ...rows.slice(2)];
    expect((await verifyAuditLedger({ ledgerId, epochs: [{ ledgerEpochId: epoch!.ledgerEpochId, read: () => swapped }] })).brokenLink).toMatchObject({
      sequence: '1',
      reason: 'recorder_changed_within_epoch',
    });
    expect((await verifyAuditLedger({ ledgerId, epochs: await sourcesOf(journal, ledgerId), trustedRecorders: ['did:key:zSomeoneElse'] })).brokenLink).toMatchObject({
      sequence: '0',
      reason: 'recorder_untrusted',
    });
    expect((await verifyAuditLedger({ ledgerId, epochs: await sourcesOf(journal, ledgerId), resolveRecorderKey: () => null })).brokenLink).toMatchObject({
      sequence: '0',
      reason: 'recorder_key_unresolved',
    });
    const wrongKey = didKeyPublicJwk(otherSigner.ref.did)!;
    expect((await verifyAuditLedger({ ledgerId, epochs: await sourcesOf(journal, ledgerId), resolveRecorderKey: async () => wrongKey })).brokenLink?.reason).toBe(
      'receipt_signature_invalid',
    );
  });

  it('breaks on a receipt whose signature text was altered even where the bytes decode the same', async () => {
    const { journal, ledgerId } = await ledgerOf(1);
    const [epoch] = await journal.listEpochs(ledgerId);
    const rows = await storedRows(journal, ledgerId);
    const entry = JSON.parse(rows[1]!.entryText) as SignedAuditEntry;
    const [header, payload, signature] = entry.recorderReceipt.jws.split('.') as [string, string, string];
    // 64 bytes in 86 characters: the last character carries 4 spare bits, so a sibling character decodes to the same bytes.
    const last = signature.at(-1)!;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const sibling = alphabet[(alphabet.indexOf(last) & ~0b1111) | ((alphabet.indexOf(last) + 1) & 0b1111)]!;
    expect(Buffer.from(`${signature.slice(0, -1)}${sibling}`, 'base64url')).toEqual(Buffer.from(signature, 'base64url'));
    for (const jws of [`${header}.${payload}.${signature.slice(0, -1)}${sibling}`, `${header}.${payload}`, `${header}.${payload}.${signature}=`]) {
      const altered = rowOf({ ...entry, recorderReceipt: { ...entry.recorderReceipt, jws } });
      const result = await verifyAuditLedger({ ledgerId, epochs: [{ ledgerEpochId: epoch!.ledgerEpochId, read: () => [rows[0]!, altered] }] });
      expect(result.brokenLink).toMatchObject({ sequence: '1', reason: 'receipt_signature_invalid' });
    }
  });

  it('breaks on an empty epoch and a stored head that is not the last entry', async () => {
    const { journal, ledgerId } = await ledgerOf(2);
    const [epoch] = await journal.listEpochs(ledgerId);
    expect((await verifyAuditLedger({ ledgerId, epochs: [{ ledgerEpochId: 'empty', read: () => [] }] })).brokenLink).toMatchObject({ sequence: null, reason: 'epoch_empty' });
    const rows = await storedRows(journal, ledgerId);
    const result = await verifyAuditLedger({ ledgerId, epochs: [{ ledgerEpochId: epoch!.ledgerEpochId, read: () => rows.slice(0, 2), storedHead: epoch!.head }] });
    expect(result.brokenLink).toMatchObject({ sequence: '2', reason: 'head_mismatch' });
  });

  it('walks epochs by their genesis commitments, and breaks on a second root, a fork, an unreachable epoch or a wrong commitment', async () => {
    const { journal, ledgerId, recorder } = await ledgerOf(1);
    await recorder.transition(ledgerId, 'failover');
    await recorder.submit(submission(producerEvent('after')), contextFor(producerEvent('after')));
    await recorder.transition(ledgerId, 'retention_rollover');
    const sources = await sourcesOf(journal, ledgerId);
    const walked = await verifyAuditLedger({ ledgerId, epochs: [...sources].reverse() });
    expect(walked.ok).toBe(true);
    expect(walked.epochs.map((epoch) => epoch.transitionReason)).toEqual([null, 'failover', 'retention_rollover']);

    expect((await verifyAuditLedger({ ledgerId, epochs: [sources[0]!, { ...sources[0]!, ledgerEpochId: 'copy' }] })).brokenLink?.reason).toBe('epoch_chain_broken');
    expect((await verifyAuditLedger({ ledgerId, epochs: [sources[1]!, sources[2]!] })).brokenLink).toMatchObject({ reason: 'epoch_chain_broken', sequence: '0' });
    const fork = await verifyAuditLedger({ ledgerId, epochs: [sources[0]!, sources[1]!, { ...sources[1]!, ledgerEpochId: 'twin' }] });
    expect(fork.brokenLink?.message).toMatch(/fork/);
    const unreachable = await verifyAuditLedger({ ledgerId, epochs: [sources[0]!, sources[2]!] });
    expect(unreachable.brokenLink?.message).toMatch(/never reaches/);
    const unreadableGenesis = await verifyAuditLedger({ ledgerId, epochs: [{ ledgerEpochId: 'bad', read: () => [{ ledgerId, ledgerEpochId: 'bad', sequence: '0', entryDigest: 'x', eventDigest: 'x', previousEntryDigest: null, entryText: '{' }] }] });
    expect(unreadableGenesis.brokenLink?.reason).toBe('entry_unreadable');

    // A successor genesis committing another terminal digest, signed by a recorder whose guard let it through.
    const lying = new AuditRecorderService({
      ledgerId,
      ledgerEpochId: 'epoch-lying',
      tenantRef: TENANT,
      binding: AUDIT_BINDING_HELIX,
      sourceId: 'helix-audit-recorder',
      journal,
      signer: testRecorderSigner(),
      clock: { now: () => 1 },
      previousEpochId: sources[2]!.ledgerEpochId,
      previousTerminalCheckpointDigest: `sha256:${'0'.repeat(64)}`,
      epochTransitionGuard: { verifyAndSeal: async () => true },
    });
    await lying.open();
    const withLie = await sourcesOf(journal, ledgerId);
    const broken = await verifyAuditLedger({ ledgerId, epochs: withLie });
    expect(broken.brokenLink).toMatchObject({ ledgerEpochId: 'epoch-lying', sequence: '0', reason: 'epoch_commitment_mismatch' });
    // A root genesis that names a predecessor is not a root.
    const fakeRoot = await verifyAuditLedger({ ledgerId, epochs: [withLie.at(-1)!] });
    expect(fakeRoot.brokenLink?.message).toMatch(/No epoch is the ledger root/);
  });

  it('propagates a storage failure instead of reporting a broken link', async () => {
    const failing: AuditLedgerEpochSource = {
      ledgerEpochId: 'e',
      read: () => ({
        [Symbol.asyncIterator]: () => ({ next: async () => Promise.reject(new Error('connection lost')) }),
      }),
    };
    await expect(verifyAuditLedger({ ledgerId: 'l', epochs: [failing] })).rejects.toThrow('connection lost');
  });
});

describe('ledger helpers', () => {
  it('resolves only Ed25519 did:key DIDs offline', () => {
    const signer = testRecorderSigner();
    expect(didKeyPublicJwk(signer.ref.did)).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
    expect(didKeyPublicJwk('did:web:audit.example')).toBeNull();
    expect(didKeyPublicJwk('did:key:z111')).toBeNull();
    expect(didKeyPublicJwk('did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169')).toBeNull();
    expect(signerRefOf({ did: 'did:web:a', kid: '#k' })).toEqual({ did: 'did:web:a', kid: 'did:web:a#k', alg: 'EdDSA' });
  });

  it('parses entries strictly', async () => {
    const { journal, ledgerId } = await ledgerOf(1);
    const [row] = (await storedRows(journal, ledgerId)).slice(1);
    const entry = JSON.parse(row!.entryText) as SignedAuditEntry;
    expect(parseSignedAuditEntry(entry)).toEqual(entry);
    expect(parseAuditEntryCore(entry.core)).toEqual(entry.core);
    expect(() => parseSignedAuditEntry({ ...entry, extra: true })).toThrow(/Signed audit entry is invalid at \$/);
    expect(() => parseAuditEntryCore({ ...entry.core, sequence: '01' })).toThrow(/sequence/);
    expect(signedAuditEntryIssue(entry)).toBeUndefined();
    expect(signedAuditEntryIssue({})).toMatch(/core/);
  });

  it('collects every evidence reference an event carries', () => {
    const ref = (objectId: string): EvidenceRef => ({
      objectId,
      ciphertextDigest: `sha256:${'1'.repeat(64)}`,
      mediaType: 'text/plain',
      size: '1',
      encryption: { suite: 'A256GCM', keyId: 'k', nonce: 'n', aadDigest: `sha256:${'2'.repeat(64)}` },
    });
    const party = (objectId: string) => ({ kind: 'evidence_ref' as const, ref: ref(objectId) });
    const base = producerEvent('refs');
    const event: AuditProducerEvent = {
      ...base,
      tenantRef: party('tenant'),
      source: { ...base.source, producer: party('producer') },
      session: { ref: party('session') },
      actor: party('actor'),
      responsibleParty: party('responsible'),
      resource: party('resource'),
      proof: ref('proof'),
      evidence: [ref('evidence')],
      action: { category: 'tool.call', detailRef: ref('action') },
      reason: { code: 'x', detailRef: ref('reason') },
      authorization: { source: 'policy', decision: 'allowed', statusEvidence: [ref('status')] },
    };
    expect(collectAuditEvidenceRefs(event).map((r) => r.objectId)).toEqual([
      'tenant',
      'producer',
      'session',
      'actor',
      'responsible',
      'resource',
      'proof',
      'evidence',
      'action',
      'reason',
      'status',
    ]);
    const delegation = { ...base, eventType: 'delegation.revoked' as const, details: { family: 'delegation' as const, phase: 'revoked' as const, delegationRef: 'd', statusEvidence: [ref('d')] } };
    expect(collectAuditEvidenceRefs(delegation).map((r) => r.objectId)).toEqual(['d']);
    const delegationBare = { ...delegation, details: { family: 'delegation' as const, phase: 'revoked' as const, delegationRef: 'd' } };
    expect(collectAuditEvidenceRefs(delegationBare)).toEqual([]);
    const ledger = { ...base, eventType: 'evidence.disposed' as const, details: { family: 'ledger' as const, phase: 'evidence_disposed' as const, targetEvidenceRef: ref('t') } };
    expect(collectAuditEvidenceRefs(ledger).map((r) => r.objectId)).toEqual(['t']);
  });
});
