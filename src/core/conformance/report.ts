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
 * The conformance report (KYA-OS story F-3 point 5).
 *
 * KYA-OS SPEC §4.5: an implementation that holds agent keys is
 * non-conformant. Helix offers full custody as a labelled option, so the
 * report splits Helix's agents, services and owners in two:
 *
 * - the claim set: self-custody subjects (`keyCustody: self`), which carry
 *   the implementation's Core and Card claims;
 * - the excluded list: custodial subjects (`keyCustody: helix`), labelled
 *   `custody: helix` and never part of any Core or Card claim. Verifiers
 *   still accept their proofs, since a key is a key; the label is about what
 *   Helix may claim, not about whether the proofs hold.
 *
 * Pure: the caller supplies the subjects (from Helix's custody records) and
 * the implementation's claims; nothing here reads a database.
 */

import {
  CUSTODY_LABEL_HELIX,
  CUSTODY_LABEL_SELF,
  custodyLabel,
  isConformantCustody,
  type CustodyLabel,
  type CustodySubjectType,
  type DidHostingMode,
  type KeyCustodyMode,
} from '../custody/choice.js';

/** The spec pin every report names (stories rule 5). */
export const KYA_OS_SPEC_PIN = Object.freeze({
  repository: 'decentralized-identity/kya-os-mcp',
  commit: 'a4d7f61',
  conformanceSuite: '1.10.0',
});

export const CUSTODY_EXCLUSION_REASON =
  'KYA-OS SPEC §4.5: Helix holds this key, so the implementation is non-conformant for it; it is excluded from every Core and Card claim. Verifiers still accept its proofs.';

export const CONFORMANCE_REPORT_NOTE =
  'Self-custody agents, services and owners are the conformant tier and carry the claims below. Custodial ones (custody: helix) are listed apart and excluded from every Core or Card claim (KYA-OS SPEC §4.5); verifiers still accept their proofs, since a key is a key.';

/** One claim the implementation makes: a KYA-OS profile (`core`, `card`, `audit`) at a level. */
export interface ConformanceClaim {
  profile: string;
  level: string;
}

export interface ConformanceImplementation {
  name: string;
  version: string;
  claims: readonly ConformanceClaim[];
}

/** What the report needs to know about one agent, service or owner. */
export interface ConformanceSubject {
  did: string;
  subjectType: CustodySubjectType;
  keyCustody: KeyCustodyMode;
  didHosting: DidHostingMode;
  name?: string | null | undefined;
  /** Only `active` subjects are in the claim set; the others are listed as pending. */
  status?: string | undefined;
}

export interface ConformanceReportEntry {
  did: string;
  subjectType: CustodySubjectType;
  name: string | null;
  keyCustody: KeyCustodyMode;
  didHosting: DidHostingMode;
  label: CustodyLabel;
  status: string;
}

export interface ClaimSetEntry extends ConformanceReportEntry {
  label: typeof CUSTODY_LABEL_SELF;
  claims: ConformanceClaim[];
}

export interface ExcludedEntry extends ConformanceReportEntry {
  label: typeof CUSTODY_LABEL_HELIX;
  reason: string;
}

export interface ConformanceReport {
  generatedAt: string;
  spec: typeof KYA_OS_SPEC_PIN;
  implementation: { name: string; version: string; claims: ConformanceClaim[] };
  note: string;
  claimSet: ClaimSetEntry[];
  excluded: ExcludedEntry[];
  pending: ConformanceReportEntry[];
  summary: { subjects: number; inClaimSet: number; excluded: number; pending: number };
}

export interface BuildConformanceReportInput {
  implementation: ConformanceImplementation;
  subjects: readonly ConformanceSubject[];
  /** Default: now. */
  generatedAt?: Date | undefined;
}

function entryOf(subject: ConformanceSubject): ConformanceReportEntry {
  return {
    did: subject.did,
    subjectType: subject.subjectType,
    name: subject.name ?? null,
    keyCustody: subject.keyCustody,
    didHosting: subject.didHosting,
    label: custodyLabel(subject.keyCustody),
    status: subject.status ?? 'active',
  };
}

function byDid(a: { did: string }, b: { did: string }): number {
  return a.did < b.did ? -1 : a.did > b.did ? 1 : 0;
}

/**
 * The report: self-custody active subjects in the claim set with the
 * implementation's claims, every custodial subject excluded with
 * `custody: helix`, self-custody subjects not yet active listed as pending.
 * Entries are sorted by DID so two reports over the same records are equal.
 */
export function buildConformanceReport(input: BuildConformanceReportInput): ConformanceReport {
  const claims = input.implementation.claims.map((claim) => ({ profile: claim.profile, level: claim.level }));
  const claimSet: ClaimSetEntry[] = [];
  const excluded: ExcludedEntry[] = [];
  const pending: ConformanceReportEntry[] = [];
  const seen = new Set<string>();
  for (const subject of input.subjects) {
    if (seen.has(subject.did)) continue;
    seen.add(subject.did);
    const entry = entryOf(subject);
    if (!isConformantCustody(subject.keyCustody)) {
      excluded.push({ ...entry, label: CUSTODY_LABEL_HELIX, reason: CUSTODY_EXCLUSION_REASON });
    } else if (entry.status === 'active') {
      claimSet.push({ ...entry, label: CUSTODY_LABEL_SELF, claims: claims.map((claim) => ({ ...claim })) });
    } else {
      pending.push(entry);
    }
  }
  claimSet.sort(byDid);
  excluded.sort(byDid);
  pending.sort(byDid);
  return {
    generatedAt: (input.generatedAt ?? new Date()).toISOString(),
    spec: KYA_OS_SPEC_PIN,
    implementation: { name: input.implementation.name, version: input.implementation.version, claims },
    note: CONFORMANCE_REPORT_NOTE,
    claimSet,
    excluded,
    pending,
    summary: { subjects: seen.size, inClaimSet: claimSet.length, excluded: excluded.length, pending: pending.length },
  };
}

/** Whether a DID is in a report's claim set: what a claim about that subject may rest on. */
export function isInClaimSet(report: ConformanceReport, did: string): boolean {
  return report.claimSet.some((entry) => entry.did === did);
}
