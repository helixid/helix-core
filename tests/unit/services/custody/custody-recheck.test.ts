// Copyright 2026 DgVerse LLP
// KYA-OS story F-3: own-hosted subjects waiting for their documents
// (pending_resolution) are re-checked in the background, with backoff, for a
// bounded time, safely across several API instances.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuditEvents, ConfigSchema, CustodyStateInvalidError } from '../../../../src/core/index.js';
import { CustodyRecheckScheduler, custodyRecheckSettings } from '../../../../src/services/custody/custody-recheck.js';
import { DEFAULT_RECHECK_SETTINGS, RECHECK_ACTOR, type CustodyRecheckRun, type OnboardingResult } from '../../../../src/services/custody/custody.service.js';
import { events, harness, type Harness } from './harness.js';

const MINUTE = 60 * 1000;

async function pendingAgent(h: Harness, path: string, host = 'owner.example'): Promise<OnboardingResult> {
  const did = `did:web:${host}:agents:${path}`;
  const created = await h.service.createAgent({ name: path, keyCustody: 'helix', didHosting: 'own', did }, h.context());
  expect(created.status).toBe('pending_resolution');
  return created;
}

function publish(h: Harness, created: OnboardingResult): void {
  h.web.set(created.documents!.didDocumentUrl, created.documents!.didDocument);
  h.web.set(created.documents!.cardUrl, created.documents!.card);
}

function later(h: Harness, ms: number): void {
  h.now.value = new Date(h.now.value.getTime() + ms);
}

describe('CustodyService.recheckPending', () => {
  it('schedules the first check, backs off while the documents are not live, and activates once they are, audited as system', async () => {
    const h = harness();
    const created = await pendingAgent(h, 'a');
    const start = h.now.value.getTime();
    expect((await h.records.findRecord(created.did))).toMatchObject({ recheckAttempts: 0, nextRecheckAt: new Date(start + 2 * MINUTE), pendingResolutionSince: new Date(start) });

    // Not due yet: nothing is read.
    expect(await h.service.recheckPending()).toEqual({ checked: [], activated: [], stopped: [], deferred: [] });
    expect(h.fetched).toEqual([]);

    later(h, 2 * MINUTE);
    expect((await h.service.recheckPending()).checked).toEqual([created.did]);
    expect(await h.records.findRecord(created.did)).toMatchObject({ status: 'pending_resolution', recheckAttempts: 1, nextRecheckAt: new Date(start + 6 * MINUTE) });
    later(h, 4 * MINUTE);
    await h.service.recheckPending();
    expect(await h.records.findRecord(created.did)).toMatchObject({ recheckAttempts: 2, nextRecheckAt: new Date(start + 14 * MINUTE) });

    publish(h, created);
    later(h, 8 * MINUTE);
    const onActivated = vi.fn();
    const run = await h.service.recheckPending(onActivated);
    expect(run.activated).toEqual([expect.objectContaining({ did: created.did, status: 'active', vcId: 'vc:test:1' })]);
    expect(onActivated).toHaveBeenCalledWith(expect.objectContaining({ did: created.did, status: 'active' }), expect.stringMatching(/^custody-recheck:[0-9a-f]{16}$/));
    expect(await h.records.findRecord(created.did)).toMatchObject({ status: 'active', nextRecheckAt: null, credentialVcId: 'vc:test:1' });
    const requestId = onActivated.mock.calls[0]![1] as string;
    expect(events(h, AuditEvents.CUSTODY_ACTIVATED)).toEqual([expect.objectContaining({ actor: RECHECK_ACTOR, did: created.did, resolution: 'verified', requestId })]);
    expect(events(h, AuditEvents.AGENT_ONBOARDED)).toEqual([expect.objectContaining({ agentDid: created.did, requestId })]);
    // Active: never re-checked again; manual activation now says so.
    later(h, 60 * MINUTE);
    expect((await h.service.recheckPending()).checked).toEqual([]);
    await expect(h.service.activate(created.did, h.context())).rejects.toThrow(CustodyStateInvalidError);
  });

  it('caps the wait between checks, and stops a bounded time after the subject started waiting; manual activation still works', async () => {
    const h = harness({ recheck: { initialIntervalSeconds: 60, maxIntervalSeconds: 300, giveUpAfterSeconds: 3600, batchSize: undefined } });
    const created = await pendingAgent(h, 'slow');
    const waits: number[] = [];
    for (let i = 0; i < 6; i += 1) {
      const due = (await h.records.findRecord(created.did))!.nextRecheckAt!;
      h.now.value = due;
      await h.service.recheckPending();
      waits.push(((await h.records.findRecord(created.did))!.nextRecheckAt!.getTime() - due.getTime()) / 1000);
    }
    expect(waits).toEqual([120, 240, 300, 300, 300, 300]);

    h.now.value = new Date((await h.records.findRecord(created.did))!.pendingResolutionSince!.getTime() + 3600 * 1000);
    const fetchedBefore = h.fetched.length;
    expect(await h.service.recheckPending()).toMatchObject({ checked: [], stopped: [created.did] });
    expect(h.fetched.length).toBe(fetchedBefore);
    expect(await h.records.findRecord(created.did)).toMatchObject({ status: 'pending_resolution', nextRecheckAt: null });
    later(h, 24 * 60 * MINUTE);
    expect(await h.service.recheckPending()).toEqual({ checked: [], activated: [], stopped: [], deferred: [] });

    publish(h, created);
    expect(await h.service.activate(created.did, h.context())).toMatchObject({ status: 'active' });
    expect(events(h, AuditEvents.CUSTODY_ACTIVATED)).toEqual([expect.objectContaining({ actor: 'admin' })]);
  });

  it('reads one subject per owner host per run and at most batchSize subjects, leaving the rest due', async () => {
    const h = harness();
    const a = await pendingAgent(h, 'one');
    const b = await pendingAgent(h, 'two');
    const c = await pendingAgent(h, 'three', 'other.example');
    later(h, 2 * MINUTE);
    expect(await h.service.recheckPending()).toMatchObject({ checked: [c.did, a.did], deferred: [b.did] });
    expect(await h.service.recheckPending()).toMatchObject({ checked: [b.did], deferred: [] });
    expect(h.fetched.filter((url) => url.endsWith('did.json'))).toEqual([
      'https://other.example/agents/three/did.json',
      'https://owner.example/agents/one/did.json',
      'https://owner.example/agents/two/did.json',
    ]);

    const small = harness({ recheck: { batchSize: 1 } });
    const d = await pendingAgent(small, 'four', 'other.example');
    await pendingAgent(small, 'five');
    later(small, 2 * MINUTE);
    expect(await small.service.recheckPending()).toMatchObject({ checked: [d.did], deferred: [] });
  });

  it('two API instances on one database activate a subject once, and issue one credential', async () => {
    const h = harness();
    const other = harness({ records: h.records, keyStore: h.keyStore, didRepository: h.dids });
    const created = await pendingAgent(h, 'shared');
    publish(h, created);
    publish(other, created);
    later(h, 2 * MINUTE);
    other.now.value = h.now.value;
    const runs = await Promise.all([h.service.recheckPending(), other.service.recheckPending()]);
    expect(runs.flatMap((run) => run.activated).map((result) => result.did)).toEqual([created.did]);
    expect(runs.flatMap((run) => run.checked)).toEqual([created.did]);
    expect(runs.flatMap((run) => run.deferred)).toEqual([created.did]);
    expect([...h.issued, ...other.issued]).toHaveLength(1);
    expect([...events(h, AuditEvents.CUSTODY_ACTIVATED), ...events(other, AuditEvents.CUSTODY_ACTIVATED)]).toHaveLength(1);
  });

  it('a manual "Check and activate" racing the background re-check activates once', async () => {
    const h = harness();
    const other = harness({ records: h.records, keyStore: h.keyStore, didRepository: h.dids });
    const created = await pendingAgent(h, 'race');
    publish(h, created);
    publish(other, created);
    later(h, 2 * MINUTE);
    other.now.value = h.now.value;
    const [manual, background] = await Promise.allSettled([h.service.activate(created.did, h.context()), other.service.recheckPending()]);
    const manualWon = manual.status === 'fulfilled';
    expect(background.status).toBe('fulfilled');
    expect((background as PromiseFulfilledResult<CustodyRecheckRun>).value.activated).toHaveLength(manualWon ? 0 : 1);
    if (!manualWon) expect((manual as PromiseRejectedResult).reason).toBeInstanceOf(CustodyStateInvalidError);
    expect([...h.issued, ...other.issued]).toHaveLength(1);
    expect((await h.records.findRecord(created.did))!.status).toBe('active');
  });

  it('puts the subject back to waiting when its credential cannot be issued, so a later check or a manual activation can still activate it', async () => {
    let fail = true;
    const h = harness();
    const failing = harness({
      records: h.records,
      keyStore: h.keyStore,
      didRepository: h.dids,
      credentials: {
        issueVC: async () => {
          if (fail) throw new Error('issuer down');
          return { vcId: 'vc:late', vc: {} };
        },
        revokeVC: async () => ({}),
      },
    });
    const created = await pendingAgent(h, 'flaky');
    publish(failing, created);
    later(failing, 2 * MINUTE);
    const scheduled = (await h.records.findRecord(created.did))!.nextRecheckAt;
    await expect(failing.service.activate(created.did, failing.context())).rejects.toThrow('issuer down');
    expect(await h.records.findRecord(created.did)).toMatchObject({ status: 'pending_resolution', activatedAt: null, nextRecheckAt: scheduled });
    await expect(failing.service.recheckPending()).rejects.toThrow('issuer down');
    fail = false;
    expect(await failing.service.activate(created.did, failing.context())).toMatchObject({ status: 'active', vcId: 'vc:late' });
  });

  it('skips a subject with no current key or a DID it cannot read, and carries on with the others', async () => {
    const h = harness();
    const good = await pendingAgent(h, 'good');
    publish(h, good);
    const base = { subjectType: 'agent' as const, keyCustody: 'helix' as const, didHosting: 'own' as const, status: 'pending_resolution' as const, name: null, ownerDid: null, scopes: null, requestedDomains: null, maxDelegationDepth: 0, enrollmentTokenHash: null, enrollmentExpiresAt: null, enrollmentNonce: null, enrollmentUsedAt: null, credentialVcId: null, activatedAt: null, pendingResolutionSince: h.now.value, nextRecheckAt: h.now.value };
    await h.records.createRecord({ ...base, did: 'did:example:nokey', kid: null });
    await h.records.createRecord({ ...base, did: 'did:example:odd', kid: 'did:example:odd#key-1' });
    await h.records.addKey({ did: 'did:example:odd', kid: 'did:example:odd#key-1', location: 'helix', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, status: 'active', sequence: 1, retiresAt: null, revokedAt: null });
    later(h, 2 * MINUTE);
    const run = await h.service.recheckPending();
    expect(run.checked).toEqual(expect.arrayContaining(['did:example:nokey', 'did:example:odd', good.did]));
    expect(run.activated.map((result) => result.did)).toEqual([good.did]);
    expect(await h.records.findRecord('did:example:odd')).toMatchObject({ status: 'pending_resolution', recheckAttempts: 1 });
  });

  it('defaults', () => {
    expect(DEFAULT_RECHECK_SETTINGS).toEqual({ initialIntervalSeconds: 120, maxIntervalSeconds: 3600, giveUpAfterSeconds: 259200, batchSize: 20 });
  });
});

describe('the CUSTODY_RECHECK_* config', () => {
  it('parses with defaults, and maps onto the service settings', () => {
    const shape = ConfigSchema.shape;
    expect(shape.CUSTODY_RECHECK_ENABLED.parse(undefined)).toBe(true);
    expect(shape.CUSTODY_RECHECK_ENABLED.parse('false')).toBe(false);
    expect(() => shape.CUSTODY_RECHECK_ENABLED.parse('no')).toThrow();
    expect(shape.CUSTODY_RECHECK_TICK_SECONDS.parse(undefined)).toBe(60);
    expect(() => shape.CUSTODY_RECHECK_TICK_SECONDS.parse('1')).toThrow();
    expect(
      custodyRecheckSettings({
        CUSTODY_RECHECK_INITIAL_INTERVAL_SECONDS: shape.CUSTODY_RECHECK_INITIAL_INTERVAL_SECONDS.parse(undefined),
        CUSTODY_RECHECK_MAX_INTERVAL_SECONDS: shape.CUSTODY_RECHECK_MAX_INTERVAL_SECONDS.parse(undefined),
        CUSTODY_RECHECK_GIVE_UP_AFTER_SECONDS: shape.CUSTODY_RECHECK_GIVE_UP_AFTER_SECONDS.parse(undefined),
        CUSTODY_RECHECK_BATCH_SIZE: shape.CUSTODY_RECHECK_BATCH_SIZE.parse('5'),
      }),
    ).toEqual({ ...DEFAULT_RECHECK_SETTINGS, batchSize: 5 });
  });
});

describe('CustodyRecheckScheduler', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const emptyRun = (): CustodyRecheckRun => ({ checked: [], activated: [], stopped: [], deferred: [] });

  it('runs every tick, never two runs at once, logs runs that did something, and stops', async () => {
    vi.useFakeTimers();
    let release: () => void = () => undefined;
    const calls: unknown[] = [];
    const target = {
      recheckPending: vi.fn(async (onActivated?: unknown) => {
        calls.push(onActivated);
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return { ...emptyRun(), checked: ['did:web:o:a'], activated: [{ did: 'did:web:o:a' } as OnboardingResult] };
      }),
    };
    const log = { info: vi.fn(), error: vi.fn() };
    const onActivated = vi.fn();
    const scheduler = new CustodyRecheckScheduler(target, { tickSeconds: 30, onActivated, log });
    scheduler.start();
    scheduler.start();
    await vi.advanceTimersByTimeAsync(30_000);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(target.recheckPending).toHaveBeenCalledTimes(1);
    expect(calls).toEqual([onActivated]);
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(log.info).toHaveBeenCalledWith({ checked: 1, activated: ['did:web:o:a'], stopped: [] }, 'custody re-check run');
    await vi.advanceTimersByTimeAsync(30_000);
    expect(target.recheckPending).toHaveBeenCalledTimes(2);
    const stopping = scheduler.stop();
    release();
    await stopping;
    await vi.advanceTimersByTimeAsync(120_000);
    expect(target.recheckPending).toHaveBeenCalledTimes(2);
  });

  it('logs a failed run and keeps going; quiet runs are not logged', async () => {
    const target = { recheckPending: vi.fn().mockRejectedValueOnce(new Error('db down')).mockResolvedValue(emptyRun()) };
    const log = { info: vi.fn(), error: vi.fn() };
    const scheduler = new CustodyRecheckScheduler(target, { tickSeconds: 60, log });
    expect(await scheduler.runOnce()).toBeUndefined();
    expect(log.error).toHaveBeenCalledWith({ err: expect.any(Error) }, 'custody re-check run failed');
    expect(await scheduler.runOnce()).toEqual(emptyRun());
    expect(log.info).not.toHaveBeenCalled();
    await new CustodyRecheckScheduler(target, { tickSeconds: 60 }).runOnce();
    await scheduler.stop();
  });
});
