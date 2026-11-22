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
 * The verify command's engine (story L3-F point 5, `helix-audit verify`):
 * walks a ledger epoch by epoch, from the genesis that names no predecessor
 * through each successor whose genesis commits the previous epoch id and
 * terminal digest, and within each epoch checks every entry: its stored
 * text parses as a signed entry, the indexed columns agree with it, the
 * sequence is the next one, the event, evidence-manifest and entry digests
 * recompute, the receipt core is the one the entry implies, the recorder is
 * the epoch's one authority (and a trusted one when keys are pinned), the
 * receipt signature verifies, and the predecessor digest is the previous
 * entry's. It stops at the first broken link and says where and why.
 *
 * It reads only what it is given (entries, pinned recorder keys); it never
 * asks a Helix database anything on its own, so an auditor can run it on an
 * export.
 */

import { base58btcDecode } from '../crypto/vp.js';
import { verifyJws, publicKeyHexToJwk, type Ed25519PublicJwk } from '../crypto/jws.js';
import { auditEventDigest } from './digest.js';
import { terminalHeadDigest } from './epochs.js';
import type { StoredAuditEntry } from './journal.js';
import {
  auditReceiptPayload,
  buildAuditReceiptCore,
  digestAuditEntry,
  digestAuditEvidenceManifest,
  sameCanonical,
  signedAuditEntryIssue,
  type AuditHead,
  type SignedAuditEntry,
} from './ledger.js';
import type { Digest, SignerRef } from './types.js';

export const AUDIT_LEDGER_BREAK_REASONS = [
  'entry_unreadable',
  'entry_schema_invalid',
  'stored_columns_mismatch',
  'ledger_mismatch',
  'sequence_gap',
  'event_digest_mismatch',
  'evidence_manifest_mismatch',
  'entry_digest_mismatch',
  'receipt_core_mismatch',
  'recorder_changed_within_epoch',
  'recorder_untrusted',
  'recorder_key_unresolved',
  'receipt_signature_invalid',
  'predecessor_mismatch',
  'genesis_invalid',
  'epoch_commitment_mismatch',
  'epoch_chain_broken',
  'epoch_empty',
  'head_mismatch',
] as const;

export type AuditLedgerBreakReason = (typeof AUDIT_LEDGER_BREAK_REASONS)[number];

export interface AuditLedgerBrokenLink {
  ledgerId: string;
  ledgerEpochId: string;
  /** The entry the break is at; null for an epoch-level break (an empty epoch). */
  sequence: string | null;
  reason: AuditLedgerBreakReason;
  message: string;
}

export interface AuditLedgerEpochSummary {
  ledgerEpochId: string;
  entries: number;
  head: AuditHead | null;
  /** Terminal digest computed from the verified head (what a successor genesis must commit). */
  terminalDigest: Digest | null;
  recorder: SignerRef | null;
  previousEpochId: string | null;
  transitionReason: string | null;
}

export interface AuditLedgerVerification {
  ok: boolean;
  ledgerId: string;
  epochs: AuditLedgerEpochSummary[];
  entriesVerified: number;
  brokenLink?: AuditLedgerBrokenLink;
  warnings: string[];
}

/** One epoch as storage (or an export) holds it. `read` may be called more than once. */
export interface AuditLedgerEpochSource {
  ledgerEpochId: string;
  read(): AsyncIterable<StoredAuditEntry> | Iterable<StoredAuditEntry>;
  /** The stored head row, when storage keeps one; checked against the last entry. */
  storedHead?: { sequence: string; entryDigest: string } | null;
}

export interface VerifyAuditLedgerOptions {
  ledgerId: string;
  epochs: AuditLedgerEpochSource[];
  /**
   * Recorder keys pinned out of band (DIDs or full kids). When given, a
   * recorder not listed is a broken link; when absent, the recorders the
   * ledger names are used and a warning says so.
   */
  trustedRecorders?: string[];
  /** Resolves a recorder's public key; default: did:key, offline. */
  resolveRecorderKey?: (signer: SignerRef) => Promise<Ed25519PublicJwk | null> | Ed25519PublicJwk | null;
}

class Broken extends Error {
  constructor(readonly link: AuditLedgerBrokenLink) {
    super(link.message);
  }
}

/** The Ed25519 key of a `did:key` (multicodec 0xed01), or null for anything else. */
export function didKeyPublicJwk(did: string): Ed25519PublicJwk | null {
  const match = /^did:key:(z[1-9A-HJ-NP-Za-km-z]+)$/.exec(did);
  if (match === null) return null;
  try {
    const bytes = base58btcDecode(match[1]!.slice(1));
    if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) return null;
    return publicKeyHexToJwk(Buffer.from(bytes.slice(2)).toString('hex'));
  } catch {
    return null;
  }
}

async function* iterate(source: AsyncIterable<StoredAuditEntry> | Iterable<StoredAuditEntry>): AsyncIterable<StoredAuditEntry> {
  for await (const item of source) yield item;
}

interface GenesisInfo {
  epoch: AuditLedgerEpochSource;
  previousEpochId: string | null;
}

async function readGenesisInfo(epoch: AuditLedgerEpochSource): Promise<GenesisInfo> {
  for await (const stored of iterate(epoch.read())) {
    try {
      const details = (JSON.parse(stored.entryText) as SignedAuditEntry).core.event.details;
      return { epoch, previousEpochId: details.family === 'ledger' && typeof details.previousEpochId === 'string' ? details.previousEpochId : null };
    } catch {
      return { epoch, previousEpochId: null };
    }
  }
  return { epoch, previousEpochId: null };
}

/**
 * The epochs in chain order: the root (a genesis with no predecessor), then
 * each epoch whose genesis names the one before. A second root, a fork (two
 * successors of one epoch) or an epoch the chain never reaches is a break.
 */
async function orderEpochs(ledgerId: string, epochs: AuditLedgerEpochSource[]): Promise<AuditLedgerEpochSource[]> {
  const infos = await Promise.all(epochs.map(readGenesisInfo));
  const roots = infos.filter((info) => info.previousEpochId === null);
  if (roots.length !== 1) {
    const second = roots[1] ?? infos[0];
    if (second === undefined) return [];
    throw new Broken({
      ledgerId,
      ledgerEpochId: second.epoch.ledgerEpochId,
      sequence: '0',
      reason: 'epoch_chain_broken',
      message: roots.length === 0 ? 'No epoch is the ledger root (every genesis names a predecessor)' : 'A second epoch claims to be the ledger root',
    });
  }
  const ordered = [roots[0]!.epoch];
  const remaining = infos.filter((info) => info !== roots[0]);
  for (;;) {
    const last = ordered.at(-1)!.ledgerEpochId;
    const successors = remaining.filter((info) => info.previousEpochId === last);
    if (successors.length > 1) {
      throw new Broken({
        ledgerId,
        ledgerEpochId: successors[1]!.epoch.ledgerEpochId,
        sequence: '0',
        reason: 'epoch_chain_broken',
        message: `Two epochs claim to succeed ${last} (a fork)`,
      });
    }
    if (successors.length === 0) break;
    ordered.push(successors[0]!.epoch);
    remaining.splice(remaining.indexOf(successors[0]!), 1);
  }
  if (remaining.length > 0) {
    throw new Broken({
      ledgerId,
      ledgerEpochId: remaining[0]!.epoch.ledgerEpochId,
      sequence: '0',
      reason: 'epoch_chain_broken',
      message: `The epoch chain never reaches this epoch (its genesis names ${remaining[0]!.previousEpochId})`,
    });
  }
  return ordered;
}

/** Every segment of a compact JWS is canonical base64url (re-encoding its bytes gives the same text). */
function canonicalJws(jws: string): boolean {
  const segments = jws.split('.');
  return segments.length === 3 && segments.every((segment) => /^[A-Za-z0-9_-]*$/.test(segment) && Buffer.from(segment, 'base64url').toString('base64url') === segment);
}

/**
 * The receipt's JWS verifies under the recorder key over exactly the receipt
 * core's RFC 8785 bytes, and its text is canonical: a variant that decodes to
 * the same bytes (spare bits in a last character) is still an altered receipt.
 */
function receiptSignatureHolds(entry: SignedAuditEntry, jwk: Ed25519PublicJwk): boolean {
  if (!canonicalJws(entry.recorderReceipt.jws)) return false;
  try {
    const verified = verifyJws(entry.recorderReceipt.jws, jwk, { expectedKid: entry.core.recorder.kid, expectedDid: entry.core.recorder.did });
    return Buffer.from(verified.payloadBytes).equals(Buffer.from(auditReceiptPayload(entry.recorderReceipt.core)));
  } catch {
    return false;
  }
}

function trusted(signer: SignerRef, pins: string[] | undefined): boolean {
  return pins === undefined || pins.includes(signer.did) || pins.includes(signer.kid);
}

/** Walks the ledger and reports the first broken link, if any. */
export async function verifyAuditLedger(options: VerifyAuditLedgerOptions): Promise<AuditLedgerVerification> {
  const { ledgerId } = options;
  const resolveKey = options.resolveRecorderKey ?? ((signer: SignerRef): Ed25519PublicJwk | null => didKeyPublicJwk(signer.did));
  const keyCache = new Map<string, Ed25519PublicJwk | null>();
  const summaries: AuditLedgerEpochSummary[] = [];
  const warnings: string[] = [];
  if (options.trustedRecorders === undefined) {
    warnings.push('Recorder keys are not pinned: receipts were checked against the recorders the ledger itself names. Pin them with trustedRecorders.');
  }
  let entriesVerified = 0;

  try {
    const ordered = await orderEpochs(ledgerId, options.epochs);
    let previous: AuditLedgerEpochSummary | null = null;
    for (const epoch of ordered) {
      const summary: AuditLedgerEpochSummary = {
        ledgerEpochId: epoch.ledgerEpochId,
        entries: 0,
        head: null,
        terminalDigest: null,
        recorder: null,
        previousEpochId: null,
        transitionReason: null,
      };
      const brk = (sequence: string | null, reason: AuditLedgerBreakReason, message: string): Broken =>
        new Broken({ ledgerId, ledgerEpochId: epoch.ledgerEpochId, sequence, reason, message });

      let expected = 0n;
      let previousDigest: string | null = null;
      for await (const stored of iterate(epoch.read())) {
        const at = stored.sequence;
        let raw: unknown;
        try {
          raw = JSON.parse(stored.entryText);
        } catch {
          throw brk(at, 'entry_unreadable', 'The stored entry is not JSON');
        }
        const issue = signedAuditEntryIssue(raw);
        if (issue !== undefined) throw brk(at, 'entry_schema_invalid', `The stored entry is not a signed audit entry (${issue})`);
        const entry = raw as SignedAuditEntry;
        const core = entry.core;
        if (
          stored.sequence !== core.sequence ||
          stored.entryDigest !== entry.entryDigest ||
          stored.eventDigest !== entry.eventDigest ||
          stored.previousEntryDigest !== core.previousEntryDigest ||
          stored.ledgerId !== core.ledgerId ||
          stored.ledgerEpochId !== core.ledgerEpochId
        ) {
          throw brk(at, 'stored_columns_mismatch', 'The stored index columns disagree with the stored entry');
        }
        if (core.ledgerId !== ledgerId || core.ledgerEpochId !== epoch.ledgerEpochId) {
          throw brk(at, 'ledger_mismatch', 'The entry names another ledger or epoch');
        }
        if (core.sequence !== expected.toString()) {
          throw brk(at, 'sequence_gap', `Expected sequence ${expected.toString()}, found ${core.sequence}`);
        }
        const eventDigest = auditEventDigest(core.event);
        if (eventDigest !== core.eventDigest || eventDigest !== entry.eventDigest) {
          throw brk(at, 'event_digest_mismatch', 'The event does not hash to the digest the entry carries');
        }
        if (digestAuditEvidenceManifest(core.event) !== core.evidenceManifestDigest) {
          throw brk(at, 'evidence_manifest_mismatch', 'The evidence manifest does not hash to the digest the entry carries');
        }
        const entryDigest = digestAuditEntry(core);
        if (entryDigest !== entry.entryDigest) throw brk(at, 'entry_digest_mismatch', 'The entry core does not hash to its entry digest');
        if (!sameCanonical(entry.recorderReceipt.core, buildAuditReceiptCore(core, entryDigest))) {
          throw brk(at, 'receipt_core_mismatch', 'The receipt does not describe this entry');
        }
        if (summary.recorder === null) summary.recorder = core.recorder;
        else if (!sameCanonical(summary.recorder, core.recorder)) {
          throw brk(at, 'recorder_changed_within_epoch', 'Another recorder signed inside this epoch');
        }
        if (!trusted(core.recorder, options.trustedRecorders)) throw brk(at, 'recorder_untrusted', `Recorder ${core.recorder.kid} is not pinned`);
        if (!keyCache.has(core.recorder.kid)) keyCache.set(core.recorder.kid, (await resolveKey(core.recorder)) ?? null);
        const jwk = keyCache.get(core.recorder.kid)!;
        if (jwk === null) throw brk(at, 'recorder_key_unresolved', `No public key for recorder ${core.recorder.kid}`);
        if (!receiptSignatureHolds(entry, jwk)) throw brk(at, 'receipt_signature_invalid', 'The recorder receipt signature does not verify');
        if (core.previousEntryDigest !== previousDigest) {
          throw brk(at, 'predecessor_mismatch', 'The predecessor digest is not the previous entry\'s digest');
        }
        if (expected === 0n) {
          const details = core.event.details;
          const producer = core.event.source.producer;
          if (
            core.event.eventType !== 'ledger.epoch.started' ||
            details.family !== 'ledger' ||
            details.phase !== 'epoch_started' ||
            producer.kind !== 'public_did' ||
            producer.did !== core.recorder.did
          ) {
            throw brk(at, 'genesis_invalid', 'The first entry of an epoch is not a genesis signed by its recorder');
          }
          summary.previousEpochId = details.previousEpochId ?? null;
          summary.transitionReason = core.event.reason?.code ?? null;
          const committedId = details.previousEpochId ?? null;
          const committedDigest = details.previousTerminalCheckpointDigest ?? null;
          if (previous === null ? committedId !== null || committedDigest !== null : committedId !== previous.ledgerEpochId || committedDigest !== previous.terminalDigest) {
            throw brk(at, 'epoch_commitment_mismatch', 'The genesis does not commit the previous epoch id and its terminal digest');
          }
        }
        previousDigest = entry.entryDigest;
        summary.head = { ledgerId, ledgerEpochId: epoch.ledgerEpochId, sequence: core.sequence, entryDigest: entry.entryDigest };
        summary.entries += 1;
        entriesVerified += 1;
        expected += 1n;
      }
      if (summary.head === null) throw brk(null, 'epoch_empty', 'The epoch has no genesis');
      if (epoch.storedHead != null && (epoch.storedHead.sequence !== summary.head.sequence || epoch.storedHead.entryDigest !== summary.head.entryDigest)) {
        throw brk(epoch.storedHead.sequence, 'head_mismatch', 'The stored head is not the last stored entry (entries were removed or the head was moved)');
      }
      summary.terminalDigest = terminalHeadDigest(summary.head);
      summaries.push(summary);
      previous = summary;
    }
    return { ok: true, ledgerId, epochs: summaries, entriesVerified, warnings };
  } catch (error) {
    if (!(error instanceof Broken)) throw error;
    return { ok: false, ledgerId, epochs: summaries, entriesVerified, brokenLink: error.link, warnings };
  }
}
