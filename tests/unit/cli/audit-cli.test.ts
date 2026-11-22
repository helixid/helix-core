// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/** `helix-audit` (L3-F point 5): sources, exports, output and exit codes. */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import { ManagedAuditRecorder, type AuditLedgerVerification } from '../../../src/core/index.js';
import { SqliteAuditJournal } from '../../../src/audit/sqlite-journal.js';
import { runAuditCli, verifyAuditLedgerExport, type AuditLedgerExport } from '../../../src/cli/audit.js';
import { SqliteStore } from '../../../src/storage/sqlite.js';
import { TENANT, contextFor, producerEvent, submission, testRecorderSigner } from '../../utils/auditLedger.js';

const dir = mkdtempSync(join(tmpdir(), 'helix-audit-cli-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function io() {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (line: string) => out.push(line), err: (line: string) => err.push(line) }, out, err };
}

async function sqliteLedger(name: string): Promise<{ path: string; ledgerId: string; sqlite: SqliteStore }> {
  const path = join(dir, `${name}.sqlite`);
  const sqlite = new SqliteStore(path);
  const recorder = new ManagedAuditRecorder({ store: new SqliteAuditJournal(sqlite), signer: testRecorderSigner() });
  for (const id of ['a', 'b']) await recorder.submit(submission(producerEvent(id)), contextFor(producerEvent(id)));
  return { path, ledgerId: recorder.ledgerIdOf(TENANT), sqlite };
}

describe('helix-audit', () => {
  it('lists, exports and verifies a SQLite ledger, and the export verifies offline', async () => {
    const { path, ledgerId } = await sqliteLedger('ok');
    const listed = io();
    expect(await runAuditCli(['ledgers', '--sqlite', path], listed.io)).toBe(0);
    expect(listed.out).toEqual([ledgerId]);

    const verified = io();
    expect(await runAuditCli(['verify', '--ledger', ledgerId, '--sqlite', path, '--trusted-recorder', testRecorderSigner().ref.did], verified.io)).toBe(0);
    expect(verified.out[0]).toBe(`ledger ${ledgerId}: OK, 1 epoch(s), 3 entries verified`);
    expect(verified.out[1]).toMatch(/epoch epoch-0001-\d{8}-[a-f0-9]{8}: 3 entries, head 2, root, recorder did:key:/);
    expect(verified.err).toEqual([]);

    const exported = io();
    expect(await runAuditCli(['export', '--ledger', ledgerId, '--sqlite', path], exported.io)).toBe(0);
    const file = join(dir, 'export.json');
    writeFileSync(file, exported.out[0]!);
    const data = JSON.parse(exported.out[0]!) as AuditLedgerExport;
    expect(data).toMatchObject({ format: 'helix-audit-ledger-export/v1', ledgerId });
    const offline = io();
    expect(await runAuditCli(['verify', '--ledger', ledgerId, '--file', file, '--json'], offline.io)).toBe(0);
    expect((JSON.parse(offline.out.join('\n')) as AuditLedgerVerification).ok).toBe(true);
    const fileLedgers = io();
    expect(await runAuditCli(['ledgers', '--file', file], fileLedgers.io)).toBe(0);
    expect(fileLedgers.out).toEqual([ledgerId]);
    expect((await verifyAuditLedgerExport(data, [testRecorderSigner().ref.did])).warnings).toEqual([]);
  });

  it('reports the first broken link with exit code 1, and an empty epoch without a sequence', async () => {
    const { path, ledgerId, sqlite } = await sqliteLedger('broken');
    sqlite.execute('DROP TRIGGER audit_journal_entries_no_update');
    const [row] = sqlite.query<{ entry: string }>(`SELECT entry FROM audit_journal_entries WHERE sequence = 1`);
    const entry = JSON.parse(row!.entry) as { core: { event: { outcome: string } } };
    entry.core.event.outcome = 'denied';
    sqlite.write(`UPDATE audit_journal_entries SET entry = ? WHERE sequence = 1`, JSON.stringify(entry));
    const broken = io();
    expect(await runAuditCli(['verify', '--ledger', ledgerId, '--sqlite', path], broken.io)).toBe(1);
    expect(broken.out[0]).toMatch(new RegExp(`^ledger ${ledgerId}: BROKEN at epoch epoch-\\S+ sequence 1: event_digest_mismatch: `));
    expect(broken.out[1]).toBe('  1 entries verified before the break');
    expect(broken.err[0]).toMatch(/^warning: Recorder keys are not pinned/);

    const file = join(dir, 'empty.json');
    writeFileSync(file, JSON.stringify({ format: 'helix-audit-ledger-export/v1', ledgerId: 'l', epochs: [{ ledgerEpochId: 'e', storedHead: null, entries: [] }] }));
    const empty = io();
    expect(await runAuditCli(['verify', '--ledger', 'l', '--file', file], empty.io)).toBe(1);
    expect(empty.out[0]).toBe('ledger l: BROKEN at epoch e: epoch_empty: The epoch has no genesis');
  });

  it('exits 2 with the usage for bad arguments and sources, and with the cause for failures', async () => {
    const usage: string[][] = [
      [],
      ['nonsense'],
      ['verify', '--bogus'],
      ['verify', '--ledger'],
      ['verify', '--ledger', 'l'],
      ['verify', '--ledger', 'l', '--sqlite', 'a', '--file', 'b'],
      ['verify', '--file', join(dir, 'export.json')],
      ['verify', '--ledger', 'l', '--api', 'http://api.test'],
    ];
    for (const argv of usage) {
      const run = io();
      expect(await runAuditCli(argv, run.io), argv.join(' ')).toBe(2);
      expect(run.err[0]).toMatch(/^helix-audit: /);
      expect(run.err[0]).toContain('usage:');
    }
    const notExport = join(dir, 'not-export.json');
    writeFileSync(notExport, '{"format":"other"}');
    const wrongFormat = io();
    expect(await runAuditCli(['verify', '--ledger', 'l', '--file', notExport], wrongFormat.io)).toBe(2);
    expect(wrongFormat.err[0]).toMatch(/is not a helix-audit export/);
    const otherLedger = io();
    expect(await runAuditCli(['verify', '--ledger', 'someone-else', '--file', join(dir, 'empty.json')], otherLedger.io)).toBe(2);
    expect(otherLedger.err[0]).toMatch(/exports ledger l, not someone-else/);
    const missing = io();
    expect(await runAuditCli(['verify', '--ledger', 'l', '--file', join(dir, 'missing.json')], missing.io)).toBe(2);
    expect(missing.err[0]).toMatch(/ENOENT/);
    expect(missing.err[0]).not.toContain('usage:');
    const { path } = await sqliteLedger('unknown');
    const unknown = io();
    expect(await runAuditCli(['verify', '--ledger', 'no-such-ledger', '--sqlite', path], unknown.io)).toBe(2);
    expect(unknown.err[0]).toMatch(/no ledger no-such-ledger/);
    const listedJson = io();
    expect(await runAuditCli(['ledgers', '--sqlite', path, '--json'], listedJson.io)).toBe(0);
    expect(JSON.parse(listedJson.out[0]!)).toHaveLength(1);
  });

  it('writes to the console by default', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(await runAuditCli([])).toBe(2);
    expect(error).toHaveBeenCalledWith(expect.stringContaining('usage:'));
    error.mockRestore();
  });
});
