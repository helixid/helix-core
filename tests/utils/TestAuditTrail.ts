// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

import { AuditTrail, MemoryAuditSink, type AuditProducerEvent, type AuditTrailOptions } from '../../src/core/index.js';

/**
 * An `AuditTrail` over an in-memory sink for service tests: `sink.events`
 * holds every recorded event oldest first, `sink.eventTypes` their types.
 */
export class TestAuditTrail extends AuditTrail {
  readonly memorySink: MemoryAuditSink;

  constructor(options: Partial<Omit<AuditTrailOptions, 'sink'>> = {}) {
    const sink = new MemoryAuditSink();
    super({
      sink,
      sourceId: 'test-api',
      producer: { kind: 'public_did', did: 'did:hedera:testnet:helixissuer' },
      tenantRef: { kind: 'keyed_commitment', value: `sha256:${'0'.repeat(64)}`, keyId: 'test-tenant' },
      ...options,
    });
    this.memorySink = sink;
  }

  get events(): AuditProducerEvent[] {
    return this.memorySink.events;
  }

  get eventTypes(): string[] {
    return this.memorySink.eventTypes;
  }

  /** The recorded events of one type, oldest first. */
  ofType(eventType: AuditProducerEvent['eventType']): AuditProducerEvent[] {
    return this.memorySink.events.filter((event) => event.eventType === eventType);
  }

  /** Lets fire-and-forget `record()` calls settle before asserting. */
  async flush(): Promise<void> {
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
  }

  clear(): void {
    this.memorySink.entries.length = 0;
  }
}
