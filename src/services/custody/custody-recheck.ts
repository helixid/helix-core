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
 * KYA-OS story F-3: the timer behind the background re-check of own-hosted
 * subjects waiting for their documents (`CustodyService.recheckPending`).
 * Every `tickSeconds` it runs one re-check, never two at once in this
 * process; the per-subject backoff, the batch and host limits, the cutoff
 * and the guard against several API instances are in `recheckPending`.
 */

import type { CustodyRecheckRun, CustodyRecheckSettings, OnboardingResult } from './custody.service.js';

/** The re-check schedule from the `CUSTODY_RECHECK_*` config. */
export function custodyRecheckSettings(config: {
  CUSTODY_RECHECK_INITIAL_INTERVAL_SECONDS: number;
  CUSTODY_RECHECK_MAX_INTERVAL_SECONDS: number;
  CUSTODY_RECHECK_GIVE_UP_AFTER_SECONDS: number;
  CUSTODY_RECHECK_BATCH_SIZE: number;
}): CustodyRecheckSettings {
  return {
    initialIntervalSeconds: config.CUSTODY_RECHECK_INITIAL_INTERVAL_SECONDS,
    maxIntervalSeconds: config.CUSTODY_RECHECK_MAX_INTERVAL_SECONDS,
    giveUpAfterSeconds: config.CUSTODY_RECHECK_GIVE_UP_AFTER_SECONDS,
    batchSize: config.CUSTODY_RECHECK_BATCH_SIZE,
  };
}

export interface CustodyRecheckTarget {
  recheckPending(onActivated?: (result: OnboardingResult, requestId: string) => Promise<void> | void): Promise<CustodyRecheckRun>;
}

export interface CustodyRecheckSchedulerOptions {
  tickSeconds: number;
  /** What the hosted build does after an activation (account links), as its activate route does. */
  onActivated?: ((result: OnboardingResult, requestId: string) => Promise<void> | void) | undefined;
  log?: { info(object: object, message: string): void; error(object: object, message: string): void } | undefined;
}

export class CustodyRecheckScheduler {
  private timer: ReturnType<typeof setInterval> | undefined;
  private running: Promise<CustodyRecheckRun | undefined> | undefined;

  constructor(
    private readonly target: CustodyRecheckTarget,
    private readonly options: CustodyRecheckSchedulerOptions,
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.runOnce(), this.options.tickSeconds * 1000);
    // Never keeps the process alive on its own.
    this.timer.unref?.();
  }

  /** One run now, unless one is already running in this process. Errors are logged, never thrown. */
  runOnce(): Promise<CustodyRecheckRun | undefined> {
    if (this.running) return this.running;
    this.running = this.target
      .recheckPending(this.options.onActivated)
      .then((run) => {
        if (run.checked.length > 0 || run.stopped.length > 0) {
          this.options.log?.info({ checked: run.checked.length, activated: run.activated.map((result) => result.did), stopped: run.stopped }, 'custody re-check run');
        }
        return run;
      })
      .catch((error: unknown) => {
        this.options.log?.error({ err: error }, 'custody re-check run failed');
        return undefined;
      })
      .finally(() => {
        this.running = undefined;
      });
    return this.running;
  }

  /** Stops the timer and waits for a run in progress. */
  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running;
  }
}
