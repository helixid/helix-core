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
 * `helix-audit`: the ledger verify command (story L3-F point 5) and export.
 *
 *   helix-audit verify  --ledger <id> <source> [--trusted-recorder <did|kid>]... [--json]
 *   helix-audit export  --ledger <id> <source>            (prints an export file)
 *   helix-audit ledgers <source> [--json]
 *
 * <source> is one of:
 *   --database-url <postgres url>     the journal tables, read directly
 *   --sqlite <path>                   a self-hosted SQLite file
 *   --file <export.json>              an export (`helix-audit export`), offline
 *   --api <url> --admin-key <key>     a Helix API's export endpoints, verified here
 *
 * `verify` walks the ledger epoch by epoch and reports the first broken link.
 * Exit 0: the ledger verifies; 1: a broken link; 2: usage, configuration or
 * input failure.
 */

import { readFile } from 'node:fs/promises';
import pg from 'pg';
import {
  verifyAuditLedger,
  type AuditLedgerEpochSource,
  type AuditLedgerStore,
  type AuditLedgerVerification,
  type StoredAuditEntry,
} from '../core/index.js';
import { PostgresAuditJournal } from '../audit/postgres-journal.js';
import { SqliteAuditJournal } from '../audit/sqlite-journal.js';
import { SqliteStore } from '../storage/sqlite.js';

export interface AuditCliIo {
  out(line: string): void;
  err(line: string): void;
  fetch?: typeof fetch;
}

/** The export file `helix-audit export` writes and `--file` reads. */
export interface AuditLedgerExport {
  format: 'helix-audit-ledger-export/v1';
  ledgerId: string;
  epochs: Array<{ ledgerEpochId: string; storedHead: { sequence: string; entryDigest: string } | null; entries: StoredAuditEntry[] }>;
}

interface Args {
  command: string | undefined;
  ledger?: string;
  databaseUrl?: string;
  sqlite?: string;
  file?: string;
  api?: string;
  adminKey?: string;
  trusted: string[];
  json: boolean;
}

class UsageError extends Error {}

const USAGE = `usage:
  helix-audit verify  --ledger <id> <source> [--trusted-recorder <did|kid>]... [--json]
  helix-audit export  --ledger <id> <source>
  helix-audit ledgers <source> [--json]
source: --database-url <url> | --sqlite <path> | --file <export.json> | --api <url> --admin-key <key>`;

function parseArgs(argv: readonly string[]): Args {
  const args: Args = { command: argv[0], trusted: [], json: false };
  for (let i = 1; i < argv.length; i += 1) {
    const flag = argv[i]!;
    const value = (): string => {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) throw new UsageError(`${flag} needs a value`);
      i += 1;
      return next;
    };
    switch (flag) {
      case '--ledger':
        args.ledger = value();
        break;
      case '--database-url':
        args.databaseUrl = value();
        break;
      case '--sqlite':
        args.sqlite = value();
        break;
      case '--file':
        args.file = value();
        break;
      case '--api':
        args.api = value();
        break;
      case '--admin-key':
        args.adminKey = value();
        break;
      case '--trusted-recorder':
        args.trusted.push(value());
        break;
      case '--json':
        args.json = true;
        break;
      default:
        throw new UsageError(`unknown argument ${flag}`);
    }
  }
  return args;
}

interface Source {
  ledgers(): Promise<string[]>;
  export(ledgerId: string): Promise<AuditLedgerExport>;
  close(): Promise<void>;
}

async function collect<T>(iterable: AsyncIterable<T>): Promise<T[]> {
  const items: T[] = [];
  for await (const item of iterable) items.push(item);
  return items;
}

function journalSource(journal: AuditLedgerStore, close: () => Promise<void>): Source {
  return {
    ledgers: async () => (await journal.listLedgers()).map((ledger) => ledger.ledgerId),
    export: async (ledgerId): Promise<AuditLedgerExport> => {
      const epochs = await journal.listEpochs(ledgerId);
      if (epochs.length === 0) throw new UsageError(`no ledger ${ledgerId} in this source`);
      return {
        format: 'helix-audit-ledger-export/v1',
        ledgerId,
        epochs: await Promise.all(
          epochs.map(async (epoch) => ({
            ledgerEpochId: epoch.ledgerEpochId,
            storedHead: { sequence: epoch.head.sequence, entryDigest: epoch.head.entryDigest },
            entries: await collect(journal.readStoredRange(epoch)),
          })),
        ),
      };
    },
    close,
  };
}

function fileSource(path: string): Source {
  let loaded: Promise<AuditLedgerExport> | undefined;
  const load = (): Promise<AuditLedgerExport> =>
    (loaded ??= readFile(path, 'utf8').then((text) => {
      const parsed = JSON.parse(text) as AuditLedgerExport;
      if (parsed.format !== 'helix-audit-ledger-export/v1' || !Array.isArray(parsed.epochs)) throw new UsageError(`${path} is not a helix-audit export`);
      return parsed;
    }));
  return {
    ledgers: async () => [(await load()).ledgerId],
    export: async (ledgerId): Promise<AuditLedgerExport> => {
      const data = await load();
      if (data.ledgerId !== ledgerId) throw new UsageError(`${path} exports ledger ${data.ledgerId}, not ${ledgerId}`);
      return data;
    },
    close: async () => undefined,
  };
}

function apiSource(base: string, adminKey: string, doFetch: typeof fetch): Source {
  const root = base.replace(/\/+$/, '');
  const get = async <T>(path: string): Promise<T> => {
    const res = await doFetch(`${root}${path}`, { headers: { 'x-admin-api-key': adminKey } });
    if (!res.ok) throw new UsageError(`GET ${path} answered ${res.status}`);
    return (await res.json()) as T;
  };
  return {
    ledgers: async () => (await get<Array<{ ledgerId: string }>>('/v1/audit/ledgers')).map((ledger) => ledger.ledgerId),
    export: async (ledgerId): Promise<AuditLedgerExport> => {
      const ledger = await get<{ epochs: Array<{ ledgerEpochId: string; head: { sequence: string; entryDigest: string } }> }>(
        `/v1/audit/ledgers/${encodeURIComponent(ledgerId)}/epochs`,
      );
      return {
        format: 'helix-audit-ledger-export/v1',
        ledgerId,
        epochs: await Promise.all(
          ledger.epochs.map(async (epoch) => ({
            ledgerEpochId: epoch.ledgerEpochId,
            storedHead: { sequence: epoch.head.sequence, entryDigest: epoch.head.entryDigest },
            entries: await get<StoredAuditEntry[]>(
              `/v1/audit/ledgers/${encodeURIComponent(ledgerId)}/epochs/${encodeURIComponent(epoch.ledgerEpochId)}/entries`,
            ),
          })),
        ),
      };
    },
    close: async () => undefined,
  };
}

function openSource(args: Args, io: AuditCliIo): Source {
  const chosen = [args.databaseUrl, args.sqlite, args.file, args.api].filter((value) => value !== undefined);
  if (chosen.length !== 1) throw new UsageError('give exactly one source');
  if (args.databaseUrl !== undefined) {
    const pool = new pg.Pool({ connectionString: args.databaseUrl, max: 2 });
    return journalSource(new PostgresAuditJournal(pool), () => pool.end());
  }
  if (args.sqlite !== undefined) return journalSource(new SqliteAuditJournal(new SqliteStore(args.sqlite)), async () => undefined);
  if (args.file !== undefined) return fileSource(args.file);
  if (args.adminKey === undefined) throw new UsageError('--api needs --admin-key');
  return apiSource(args.api!, args.adminKey, io.fetch ?? fetch);
}

/** Verifies one exported ledger. */
export function verifyAuditLedgerExport(data: AuditLedgerExport, trustedRecorders?: string[]): Promise<AuditLedgerVerification> {
  const epochs: AuditLedgerEpochSource[] = data.epochs.map((epoch) => ({
    ledgerEpochId: epoch.ledgerEpochId,
    read: () => epoch.entries,
    storedHead: epoch.storedHead,
  }));
  return verifyAuditLedger({ ledgerId: data.ledgerId, epochs, ...(trustedRecorders !== undefined ? { trustedRecorders } : {}) });
}

function printVerification(result: AuditLedgerVerification, io: AuditCliIo): void {
  if (result.ok) io.out(`ledger ${result.ledgerId}: OK, ${result.epochs.length} epoch(s), ${result.entriesVerified} entries verified`);
  else {
    const link = result.brokenLink!;
    io.out(
      `ledger ${result.ledgerId}: BROKEN at epoch ${link.ledgerEpochId}${link.sequence !== null ? ` sequence ${link.sequence}` : ''}: ${link.reason}: ${link.message}`,
    );
    io.out(`  ${result.entriesVerified} entries verified before the break`);
  }
  for (const epoch of result.epochs) {
    const from = epoch.previousEpochId === null ? 'root' : `after ${epoch.previousEpochId} (${epoch.transitionReason ?? 'transition'})`;
    io.out(`  epoch ${epoch.ledgerEpochId}: ${epoch.entries} entries, head ${epoch.head?.sequence ?? '-'}, ${from}, recorder ${epoch.recorder?.kid ?? '-'}`);
  }
  for (const warning of result.warnings) io.err(`warning: ${warning}`);
}

/** Runs one command; resolves with the exit code. */
export async function runAuditCli(argv: readonly string[], io: AuditCliIo = { out: console.log, err: console.error }): Promise<number> {
  let source: Source | undefined;
  try {
    const args = parseArgs(argv);
    if (args.command !== 'verify' && args.command !== 'export' && args.command !== 'ledgers') throw new UsageError(`unknown command ${args.command ?? ''}`);
    source = openSource(args, io);
    if (args.command === 'ledgers') {
      const ledgers = await source.ledgers();
      if (args.json) io.out(JSON.stringify(ledgers));
      else for (const ledger of ledgers) io.out(ledger);
      return 0;
    }
    if (args.ledger === undefined) throw new UsageError(`${args.command} needs --ledger`);
    const data = await source.export(args.ledger);
    if (args.command === 'export') {
      io.out(JSON.stringify(data));
      return 0;
    }
    const result = await verifyAuditLedgerExport(data, args.trusted.length > 0 ? args.trusted : undefined);
    if (args.json) io.out(JSON.stringify(result, null, 2));
    else printVerification(result, io);
    return result.ok ? 0 : 1;
  } catch (error) {
    io.err(error instanceof UsageError ? `helix-audit: ${error.message}\n${USAGE}` : `helix-audit: ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  } finally {
    await source?.close();
  }
}
