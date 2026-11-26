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
 * Delegation hops bound to a key (KYA-OS story C-E point 4; F-3 point 6).
 *
 * A hop names its delegate by DID, so the hop format (SPEC.md §6.10) says
 * nothing about keys. Helix binds each hop it issued to the delegate's key
 * that was current when it was issued: a key is current from its own
 * creation until the next key's, so the binding is read off the key
 * timeline (`BoundWindow`) and never stored twice.
 *
 * On rotation the agent's leaf hops bound to the old kid are reissued by
 * their issuers, bound to the new kid (same parent, target, actions,
 * caveats and expiry; a new id and status entry). Issuers whose key Helix
 * holds (the Helix issuer, custodial accounts, agents and services) sign
 * through the KeyStore; a self-custody issuer's hops are reported so its
 * SDK reissues them. When the overlap ends the old-kid hops that were
 * reissued expire (revoked through the status lists); a compromised kid's
 * hops are revoked at once, with every hop below them.
 */

/** The instants a key was current: from its creation to the next key's (open when it is still current). */
export interface BoundWindow {
  from: Date;
  until: Date | null;
}

export interface HopReissueInput {
  did: string;
  oldKid: string;
  newKid: string;
  requestId: string;
  /** When `oldKid` was current: the hops issued in this window are bound to it. Default: every hop of `did`. */
  bound?: BoundWindow | undefined;
}

/** A hop Helix cannot reissue: its issuer holds its own key and reissues it through its SDK. */
export interface PendingIssuerHop {
  hopId: string;
  issuer: string;
}

export interface HopReissueResult {
  /** Hops reissued bound to the new kid. */
  reissued: number;
  /** True only for the placeholder reissuer that reissues nothing. */
  pending: boolean;
  /** Old hop id to the new hop id, for every hop reissued. */
  reissuedHops?: Record<string, string> | undefined;
  /** Hops whose issuer reissues them through its SDK (story C-E point 4). */
  pendingIssuers?: PendingIssuerHop[] | undefined;
  note?: string | undefined;
}

export interface KidHopsInput {
  did: string;
  kid: string;
  requestId: string;
  /** When `kid` was current; default every hop of `did`. */
  bound?: BoundWindow | undefined;
}

export interface HopReissuer {
  reissueHopsForKid(input: HopReissueInput): Promise<HopReissueResult>;
  /** The overlap of `kid` ended: its reissued hops expire. Resolves to the hop ids revoked. */
  expireHopsForKid?(input: KidHopsInput): Promise<string[]>;
  /** `kid` is compromised: every hop bound to it is revoked with its descendants. Resolves to the hop ids revoked. */
  revokeHopsForKid?(input: KidHopsInput): Promise<string[]>;
}

export const HOP_REISSUE_PENDING_NOTE = 'No hop reissuer is attached: no delegation hop was reissued for the new key.';

/** The placeholder when no credential service is attached: reissues nothing and says so. */
export const pendingHopReissuer: HopReissuer = {
  async reissueHopsForKid(): Promise<HopReissueResult> {
    return { reissued: 0, pending: true, note: HOP_REISSUE_PENDING_NOTE };
  },
};
