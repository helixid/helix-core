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
 * The one outbound read seam of the verify path (KYA-OS story C-A): the DID
 * resolver, the Entity Card resolver and the status-list fetch all read
 * through `getOutboundFetch()`, a SafeFetch by default. Tests and local
 * stacks replace it with `setOutboundFetch`; a `fetch`-compatible function
 * (one that returns a `Response`) satisfies the shape.
 *
 * The default SafeFetch is strict unless `HELIX_OUTBOUND_DEVELOPMENT=1` is
 * set, or `NODE_ENV` is `development` or `test`: those admit http and
 * loopback or private addresses, which the local stacks' did:web DIDs
 * (`did:web:localhost%3A3000:…`, `DID_WEB_LOOPBACK_RESOLVE_HOST`) need.
 */

import { createSafeFetch, type SafeFetchInit } from './safe-fetch.js';

/** What a resolver needs from a read: `Response` and `SafeFetchResponse` both qualify. */
export interface OutboundResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type OutboundFetch = (url: string, init?: SafeFetchInit) => Promise<OutboundResponse>;

let configured: OutboundFetch | undefined;
let fallback: OutboundFetch | undefined;

/** Whether the default SafeFetch admits http and non-public addresses (local stacks only). */
export function outboundDevelopmentMode(env: NodeJS.ProcessEnv = process.env): boolean {
  if (env['HELIX_OUTBOUND_DEVELOPMENT'] === '1') return true;
  if (env['HELIX_OUTBOUND_DEVELOPMENT'] === '0') return false;
  return env['NODE_ENV'] === 'development' || env['NODE_ENV'] === 'test';
}

export function getOutboundFetch(): OutboundFetch {
  if (configured) return configured;
  fallback ??= createSafeFetch({ development: outboundDevelopmentMode() });
  return fallback;
}

/** Replaces the outbound read for every resolver in this process; `undefined` restores the default. */
export function setOutboundFetch(fetchLike: OutboundFetch | undefined): void {
  configured = fetchLike;
}
