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

import { mkdirSync } from 'node:fs';
import { appendFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { AuditSink, AuditTrailEntry } from '../core/index.js';

export interface StreamAuditSinkOptions {
  /** `stdout`, `file`, `both` or `none` (AUDIT_LOG_DESTINATION). */
  destination: 'stdout' | 'file' | 'both' | 'none';
  /** AUDIT_LOG_PATH; default `./data/audit.log`. */
  path?: string | undefined;
  /** Injectable for tests. */
  write?: (line: string) => void;
  appendToFile?: (path: string, line: string) => Promise<void>;
}

/**
 * Echoes each recorded event as one line, `{"eventDigest", "event"}` with the
 * event in canonical form, to stdout and/or an append-only file. A file
 * failure is reported on stderr and never fails the record: the database
 * store is the record, this is the operator's tail.
 */
export class StreamAuditSink implements AuditSink {
  private readonly write: (line: string) => void;
  private readonly appendToFile: (path: string, line: string) => Promise<void>;

  constructor(private readonly options: StreamAuditSinkOptions) {
    this.write = options.write ?? ((line): void => console.log(line));
    this.appendToFile =
      options.appendToFile ??
      (async (path, line): Promise<void> => {
        mkdirSync(dirname(path), { recursive: true });
        await appendFile(path, line, 'utf8');
      });
  }

  async append(entry: AuditTrailEntry): Promise<void> {
    const line = `{"eventDigest":"${entry.eventDigest}","event":${entry.canonical}}`;
    const { destination } = this.options;
    if (destination === 'stdout' || destination === 'both') this.write(line);
    if (destination === 'file' || destination === 'both') {
      try {
        await this.appendToFile(this.options.path ?? './data/audit.log', `${line}\n`);
      } catch (error) {
        console.error('FAILED_TO_WRITE_AUDIT_LOG_FILE', error instanceof Error ? error.message : String(error));
      }
    }
  }
}
