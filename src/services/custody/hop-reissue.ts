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
 * The hop-reissue seam of a custody change (KYA-OS story F-3 point 6).
 *
 * Changing custody is a key rotation: delegation hops are bound to a `kid`
 * (story C-E point 4), so the agent's leaf hops must be reissued bound to
 * the new one. The hops themselves are story F-1's (`DelegationCredential`)
 * and the reissue protocol is story C-E's (`reissueHopsForKid`), neither of
 * which is on this base. F-3 calls this seam on every custody change and
 * reports what it returned; the default says plainly that nothing was
 * reissued yet. C-E replaces it with the real `reissueHopsForKid`.
 */

export interface HopReissueInput {
  did: string;
  oldKid: string;
  newKid: string;
  requestId: string;
}

export interface HopReissueResult {
  /** Hops reissued bound to the new kid. */
  reissued: number;
  /** True while hop reissue is not implemented (stories F-1 and C-E). */
  pending: boolean;
  note?: string | undefined;
}

export interface HopReissuer {
  reissueHopsForKid(input: HopReissueInput): Promise<HopReissueResult>;
}

export const HOP_REISSUE_PENDING_NOTE =
  'Hop reissue on rotation is story C-E (delegation hops are story F-1); F-3 calls this seam on every custody change.';

/** The default until C-E: reissues nothing and says so. */
export const pendingHopReissuer: HopReissuer = {
  async reissueHopsForKid(): Promise<HopReissueResult> {
    return { reissued: 0, pending: true, note: HOP_REISSUE_PENDING_NOTE };
  },
};
