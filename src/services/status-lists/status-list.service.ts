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
 * Signed per-issuer status lists (KYA-OS story L3-C points 1 and 5).
 *
 * `StatusListPublisher` keeps one W3C Bitstring Status List v1.0 per issuer
 * DID, served at `<API>/v1/status-list/<listId>`, each signed by that
 * issuer's own Signer (`DataIntegrityProof`, `eddsa-jcs-2022`) with
 * `validFrom`/`validUntil` set, so a verifier can compute freshness. A list
 * is republished on change (a served version whose bits differ from the
 * stored ones is never served) and before expiry (a version with less than
 * `refreshBeforeSeconds` left is re-signed on read, and `startRefresh()`
 * re-signs the lists it knows ahead of time).
 *
 * Signers: the Helix issuer, and every DID whose key Helix holds go through
 * `signerFor` (the KeyStore; stories rule 8). An issuer whose key stays with
 * it (self-custody) signs its own list: it reads the unsigned list from
 * `unsignedList()`, signs it, and hands it back to `submitSigned()`, which
 * accepts it only when its proof verifies under the issuer's
 * `assertionMethod` key and its bits are the stored ones. Until such an
 * issuer has signed the current bits, its list is not served (503), so its
 * credentials read as revoked everywhere: fail closed, never a stale "clear".
 *
 * `StatusListService` is the credential side: an entry on the issuing DID's
 * list for each new credential, and revocation that sets every affected bit
 * and marks every record in one transaction, republishes each affected list,
 * writes one audit event per credential and only then emits one revocation
 * signal per credential (so a verifier that refetches on the signal reads
 * the new bits).
 */

import {
  DEFAULT_STATUS_LIST_ID,
  ErrorCode,
  HelixError,
  bareEncodedList,
  buildStatusListCredential,
  createStatusList,
  issuerOfStatusListId,
  multibaseEncodedList,
  statusListIdFor,
  unsignedStatusListCredential,
  verifyDataIntegrity,
  type BitstringStatusEntry,
  type DidResolver,
  type AuditTrail,
  type SignedStatusListCredential,
  type Signer,
  type StatusListCredential,
} from '../../core/index.js';
import { credentialRevoked, recordAudit, revocationSignalFailed, statusListPublished } from '../revocation/audit.js';
import type { ICache } from '../../cache/ICache.js';
import { NoopCache } from '../../cache/NoopCache.js';
import type { RevokeVcItem, VcRepository, VCRecord } from '../../repositories/vc.repository.js';

/** Bits per list: SPEC.md §6.7 (indexes 0 to 131071). */
export const STATUS_LIST_LENGTH = 131072;
export const DEFAULT_LIST_TTL_SECONDS = 3600;
export const DEFAULT_REFRESH_BEFORE_SECONDS = 300;

export type StatusListRepository = Pick<VcRepository, 'findStatusListById' | 'createStatusList' | 'claimNextIndex' | 'revokeVcs' | 'findByVcId'>;

export interface StatusListPublisherOptions {
  repo: StatusListRepository;
  helixIssuerDid: string;
  /** The API's public base URL; lists are served at `<apiBaseUrl>/v1/status-list/<listId>`. */
  apiBaseUrl: string;
  /** The Signer of an issuer DID whose key Helix holds, or undefined for a self-custody issuer. */
  signerFor: (issuerDid: string) => Promise<Signer | undefined>;
  /** How an issuer DID resolves, for the proof of a list it signed itself. */
  resolveDid: DidResolver;
  /** `validUntil - validFrom` of every list Helix signs; default 3600 s. */
  listTtlSeconds?: number | undefined;
  /** Re-sign a list with less than this left; default 300 s. */
  refreshBeforeSeconds?: number | undefined;
  /** Where issuer-signed lists are kept, shared by every API instance (Redis); default this process only. */
  signedCache?: ICache<string> | undefined;
  /** A-1's typed trail: one `configuration.changed` per list newly signed. */
  audit?: AuditTrail | undefined;
  /** Milliseconds since the epoch; default `Date.now`. */
  clock?: (() => number) | undefined;
}

interface Published {
  credential: SignedStatusListCredential;
  /** The bare bits the credential carries, compared with the stored ones on every read. */
  encodedList: string;
  validUntilMs: number;
}

const iso = (ms: number): string => new Date(ms).toISOString();

export class StatusListPublisher {
  readonly helixIssuerDid: string;
  readonly listTtlSeconds: number;
  readonly refreshBeforeSeconds: number;
  readonly #options: StatusListPublisherOptions;
  readonly #clock: () => number;
  readonly #published = new Map<string, Published>();
  readonly #signedCache: ICache<string>;
  #timer: ReturnType<typeof setInterval> | undefined;

  constructor(options: StatusListPublisherOptions) {
    this.#options = options;
    this.helixIssuerDid = options.helixIssuerDid;
    this.listTtlSeconds = options.listTtlSeconds ?? DEFAULT_LIST_TTL_SECONDS;
    this.refreshBeforeSeconds = options.refreshBeforeSeconds ?? DEFAULT_REFRESH_BEFORE_SECONDS;
    if (!(this.listTtlSeconds > this.refreshBeforeSeconds) || !(this.refreshBeforeSeconds >= 0)) {
      throw new Error('StatusListPublisher: listTtlSeconds must exceed refreshBeforeSeconds, which must be non-negative');
    }
    this.#clock = options.clock ?? Date.now;
    this.#signedCache = options.signedCache ?? new NoopCache<string>();
  }

  listIdFor(issuerDid: string): string {
    return statusListIdFor(issuerDid, this.helixIssuerDid);
  }

  issuerOf(listId: string): string | undefined {
    return issuerOfStatusListId(listId, this.helixIssuerDid);
  }

  urlFor(listId: string): string {
    return `${this.#options.apiBaseUrl}/v1/status-list/${listId}`;
  }

  /** The list id a `statusListCredential` URL names when it is one of this deployment's lists. */
  listIdOfUrl(url: string): string | undefined {
    const prefix = `${this.#options.apiBaseUrl}/v1/status-list/`;
    if (!url.startsWith(prefix)) return undefined;
    const listId = url.slice(prefix.length);
    return this.issuerOf(listId) === undefined ? undefined : listId;
  }

  /** The stored list, created empty the first time an issuer needs one. */
  async ensureList(listId: string): Promise<{ encodedList: string; nextIndex: number }> {
    const existing = await this.#options.repo.findStatusListById(listId);
    if (existing) return existing;
    const created = await this.#options.repo.createStatusList(listId, createStatusList(STATUS_LIST_LENGTH));
    return created;
  }

  /** A fresh entry on `issuerDid`'s own list. */
  async claimEntry(issuerDid: string): Promise<{ statusListCredentialUrl: string; statusListIndex: number }> {
    const listId = this.listIdFor(issuerDid);
    const list = await this.ensureList(listId);
    if (list.nextIndex >= STATUS_LIST_LENGTH) {
      throw new HelixError(ErrorCode.STATUS_LIST_INDEX_EXHAUSTED, `The status list of ${issuerDid} is full`, 503);
    }
    const { claimedIndex } = await this.#options.repo.claimNextIndex(listId);
    return { statusListCredentialUrl: this.urlFor(listId), statusListIndex: claimedIndex };
  }

  #window(): { validFrom: string; validUntil: string } {
    // Whole seconds: the window a verifier reads is the one the issuer meant, on every clock.
    const now = Math.floor(this.#clock() / 1000) * 1000;
    return { validFrom: iso(now), validUntil: iso(now + this.listTtlSeconds * 1000) };
  }

  #servable(published: Published | undefined, encodedList: string): published is Published {
    return published !== undefined && published.encodedList === encodedList && published.validUntilMs - this.#clock() > this.refreshBeforeSeconds * 1000;
  }

  async #cachedSigned(listId: string): Promise<Published | undefined> {
    const raw = await this.#signedCache.get(listId);
    if (raw === null || raw === undefined) return undefined;
    try {
      return JSON.parse(raw) as Published;
    } catch {
      return undefined;
    }
  }

  /**
   * The signed list to serve: the version published, re-signed when the
   * stored bits changed or it nears its end. 404 for no such list; 503
   * while a self-custody issuer has not signed the current bits.
   */
  async getSigned(listId: string): Promise<SignedStatusListCredential> {
    const issuer = this.issuerOf(listId);
    const stored = issuer === undefined ? null : await this.#options.repo.findStatusListById(listId);
    if (issuer === undefined || !stored) {
      throw new HelixError(ErrorCode.STATUS_LIST_NOT_FOUND, 'Status list not found', 404);
    }
    const current = this.#published.get(listId);
    if (this.#servable(current, stored.encodedList)) return current.credential;
    const signer = await this.#options.signerFor(issuer);
    if (signer !== undefined) return (await this.#sign(listId, issuer, stored.encodedList, signer)).credential;
    // A self-custody issuer: only a version it signed over these very bits, still inside its window.
    const submitted = await this.#cachedSigned(listId);
    if (submitted !== undefined && submitted.encodedList === stored.encodedList && submitted.validUntilMs > this.#clock()) {
      this.#published.set(listId, submitted);
      return submitted.credential;
    }
    throw new HelixError(ErrorCode.STATUS_LIST_UNSIGNED, `The status list of ${issuer} awaits its issuer's signature over its current bits`, 503);
  }

  async #sign(listId: string, issuer: string, encodedList: string, signer: Signer): Promise<Published> {
    const credential = await buildStatusListCredential({ id: this.urlFor(listId), issuer, encodedList, ...this.#window() }, signer);
    const published: Published = { credential, encodedList, validUntilMs: Date.parse(credential.validUntil) };
    this.#published.set(listId, published);
    recordAudit(this.#options.audit, statusListPublished(issuer, 'published'));
    return published;
  }

  /**
   * Re-signs `listId` now (after its bits changed), when Helix holds its
   * issuer's key. Returns false for a self-custody issuer, whose list waits
   * for its own signature.
   */
  async publish(listId: string): Promise<boolean> {
    const issuer = this.issuerOf(listId);
    if (issuer === undefined) return false;
    const stored = await this.#options.repo.findStatusListById(listId);
    if (!stored) return false;
    const signer = await this.#options.signerFor(issuer);
    if (signer === undefined) return false;
    await this.#sign(listId, issuer, stored.encodedList, signer);
    return true;
  }

  /** The list as it stands, unsigned, with a fresh window: what a self-custody issuer signs. */
  async unsignedList(listId: string): Promise<StatusListCredential & { validUntil: string }> {
    const issuer = this.issuerOf(listId);
    const stored = issuer === undefined ? null : await this.#options.repo.findStatusListById(listId);
    if (issuer === undefined || !stored) throw new HelixError(ErrorCode.STATUS_LIST_NOT_FOUND, 'Status list not found', 404);
    return unsignedStatusListCredential({ id: this.urlFor(listId), issuer, encodedList: stored.encodedList, ...this.#window() });
  }

  /**
   * A list its self-custody issuer signed: accepted when it is this list
   * (id, issuer, type, purpose), carries exactly the stored bits, states a
   * window that has begun, has not ended and is no longer than
   * `listTtlSeconds` plus a minute, and its proof verifies under the
   * issuer's `assertionMethod` key.
   */
  async submitSigned(listId: string, value: unknown): Promise<SignedStatusListCredential> {
    const issuer = this.issuerOf(listId);
    const stored = issuer === undefined ? null : await this.#options.repo.findStatusListById(listId);
    if (issuer === undefined || !stored) throw new HelixError(ErrorCode.STATUS_LIST_NOT_FOUND, 'Status list not found', 404);
    const refuse = (message: string): never => {
      throw new HelixError(ErrorCode.VALIDATION_ERROR, `status list refused: ${message}`, 400);
    };
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return refuse('not a JSON object');
    const list = value as Partial<SignedStatusListCredential>;
    if (list.id !== this.urlFor(listId)) refuse(`id must be ${this.urlFor(listId)}`);
    if (list.issuer !== issuer) refuse(`issuer must be ${issuer}`);
    if (!Array.isArray(list.type) || !list.type.includes('BitstringStatusListCredential') || list.credentialSubject?.type !== 'BitstringStatusList') {
      refuse('not a Bitstring Status List v1.0 credential');
    }
    if (list.credentialSubject?.statusPurpose !== 'revocation') refuse('statusPurpose must be revocation');
    if (typeof list.credentialSubject?.encodedList !== 'string' || bareEncodedList(list.credentialSubject.encodedList) !== bareEncodedList(stored.encodedList)) {
      refuse('encodedList is not the list as it stands');
    }
    const from = Date.parse(String(list.validFrom));
    const until = Date.parse(String(list.validUntil));
    const now = this.#clock();
    if (Number.isNaN(from) || Number.isNaN(until)) return refuse('validFrom and validUntil must be date-times');
    if (from > now + 120_000 || until <= now) refuse('the list is outside the window it states');
    if (until - from > (this.listTtlSeconds + 60) * 1000) refuse(`the window is longer than ${this.listTtlSeconds} s`);
    const verdict = await verifyDataIntegrity(list as Record<string, unknown>, this.#options.resolveDid);
    if (!verdict.ok) refuse(`${verdict.reason}: ${verdict.message}`);
    const published: Published = { credential: list as SignedStatusListCredential, encodedList: stored.encodedList, validUntilMs: until };
    this.#published.set(listId, published);
    await this.#signedCache.set(listId, JSON.stringify(published), Math.max(1, Math.ceil((until - now) / 1000)));
    recordAudit(this.#options.audit, statusListPublished(issuer, 'submitted'));
    return published.credential;
  }

  /** Re-signs, every `intervalMs`, each list this process published that nears its end: republished before expiry. */
  startRefresh(intervalMs = 60_000): void {
    if (this.#timer !== undefined) return;
    this.#timer = setInterval(() => void this.refreshDue(), intervalMs);
    this.#timer.unref?.();
  }

  stopRefresh(): void {
    if (this.#timer !== undefined) clearInterval(this.#timer);
    this.#timer = undefined;
  }

  /** Re-signs the published lists that near their end; returns the ids re-signed. */
  async refreshDue(): Promise<string[]> {
    const due = [...this.#published.entries()].filter(([, published]) => published.validUntilMs - this.#clock() <= this.refreshBeforeSeconds * 1000);
    const refreshed: string[] = [];
    for (const [listId] of due) {
      try {
        if (await this.publish(listId)) refreshed.push(listId);
      } catch {
        // A list that cannot be re-signed now is re-signed on its next read.
      }
    }
    return refreshed;
  }
}

/** What a revocation emits per credential, after the bits are published. */
export interface RevocationSignalSink {
  publish(credentialId: string): Promise<unknown>;
}

export interface RevokeContext {
  requestId: string;
  /** The DID that asked (a signed revocation request's signer), for the audit trail. */
  revoker?: string | undefined;
  /** The credential the revocation was asked for, when this one is a descendant revoked by cascade. */
  cascadeFrom?: string | undefined;
}

/**
 * The credential side of the per-issuer lists: entries for new credentials
 * and revocation (implements F-1's `CredentialStatusStore`).
 */
export class StatusListService {
  readonly publisher: StatusListPublisher;
  readonly #repo: StatusListRepository;
  readonly #audit: AuditTrail | undefined;
  #signals: RevocationSignalSink | undefined;

  constructor(options: { publisher: StatusListPublisher; repo: StatusListRepository; audit: AuditTrail | undefined; signals?: RevocationSignalSink | undefined }) {
    this.publisher = options.publisher;
    this.#repo = options.repo;
    this.#audit = options.audit;
    this.#signals = options.signals;
  }

  /** Connects the revocation signal (constructed after this service in the server's wiring). */
  setSignals(signals: RevocationSignalSink | undefined): void {
    this.#signals = signals;
  }

  /** An entry on the issuing DID's own list (default the Helix issuer's). */
  async claimStatusListEntry(issuerDid?: string): Promise<{ statusListCredentialUrl: string; statusListIndex: number }> {
    return this.publisher.claimEntry(issuerDid ?? this.publisher.helixIssuerDid);
  }

  /** A `BitstringStatusListEntry` on the issuing DID's list, as a credential carries it. */
  async statusEntryFor(issuerDid: string): Promise<BitstringStatusEntry> {
    const entry = await this.claimStatusListEntry(issuerDid);
    return {
      id: `${entry.statusListCredentialUrl}#${entry.statusListIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: entry.statusListIndex.toString(),
      statusListCredential: entry.statusListCredentialUrl,
    };
  }

  /** Revokes one credential (no cascade): F-1's `CredentialStatusStore.revokeVC`. */
  async revokeVC(vcId: string, requestId: string): Promise<{ vcId: string; revoked: true; revokedAt: string }> {
    const [record] = await this.revokeMany([vcId], { requestId });
    return { vcId, revoked: true, revokedAt: (record?.revokedAt ?? new Date()).toISOString() };
  }

  /** The bit of a credential record on one of this deployment's lists, or none (a credential on another party's list). */
  bitOf(record: VCRecord): { listId: string; index: number } | undefined {
    const vc = (typeof record.vcJson === 'string' ? JSON.parse(record.vcJson) : record.vcJson) as { credentialStatus?: Partial<BitstringStatusEntry> };
    const status = vc?.credentialStatus;
    if (typeof status?.statusListCredential !== 'string') return undefined;
    const listId = this.publisher.listIdOfUrl(status.statusListCredential);
    const index = Number(status.statusListIndex);
    if (listId === undefined || !/^[0-9]+$/.test(String(status.statusListIndex)) || !Number.isSafeInteger(index) || index >= STATUS_LIST_LENGTH) return undefined;
    return { listId, index };
  }

  /**
   * Revokes `vcIds` (the first is the one asked for; the rest its
   * descendants) atomically, republishes each affected list, writes one
   * audit event per credential, then emits one signal per credential. The
   * first must exist and be active; descendants already revoked are skipped.
   */
  async revokeMany(vcIds: readonly string[], context: RevokeContext & { cascade?: boolean }): Promise<VCRecord[]> {
    const items: RevokeVcItem[] = [];
    const records: VCRecord[] = [];
    for (const [position, vcId] of vcIds.entries()) {
      const record = await this.#repo.findByVcId(vcId);
      if (!record) {
        if (position === 0) throw new HelixError(ErrorCode.VC_NOT_FOUND, 'Credential not found', 404);
        continue;
      }
      if (record.revokedAt) {
        if (position === 0) throw new HelixError(ErrorCode.VC_ALREADY_REVOKED, 'Credential already revoked', 409);
        continue;
      }
      const bit = this.bitOf(record);
      items.push({ vcId, ...(bit === undefined ? {} : bit) });
      records.push(record);
    }
    for (const listId of new Set(items.flatMap((item) => (item.listId === undefined ? [] : [item.listId])))) await this.publisher.ensureList(listId);
    const revoked = await this.#repo.revokeVcs(items);
    // The bits first: a verifier that refetches on the signal must read them.
    for (const listId of new Set(items.flatMap((item) => (item.listId === undefined ? [] : [item.listId])))) {
      await this.publisher.publish(listId);
    }
    for (const [position, record] of records.entries()) {
      const cascadeFrom = context.cascadeFrom ?? (position > 0 ? vcIds[0] : undefined);
      recordAudit(this.#audit, credentialRevoked({ requestId: context.requestId, vcId: record.vcId, subjectDid: record.subjectDid, revoker: context.revoker, cascadeFrom }));
    }
    for (const record of records) {
      try {
        await this.#signals?.publish(record.vcId);
      } catch (error) {
        console.error('REVOCATION_SIGNAL_FAILED', record.vcId, (error as Error).message);
        recordAudit(this.#audit, revocationSignalFailed({ vcId: record.vcId, correlationId: context.requestId, stage: 'emit' }));
      }
    }
    return revoked;
  }

  /** The list as served (signed), for the public route. */
  getSigned(listId: string): Promise<SignedStatusListCredential> {
    return this.publisher.getSigned(listId);
  }
}

export { DEFAULT_STATUS_LIST_ID, multibaseEncodedList };
