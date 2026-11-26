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

import * as ed25519 from "@noble/ed25519";
import { derivePublicKey, normalizeEd25519PrivateKey } from "./keys.js";

/**
 * Whoever holds an Ed25519 private key and signs with it (KYA-OS story L1-C).
 *
 * Signing code in helix-core never reads a private key itself: it hands the
 * bytes to a Signer the caller supplies and uses whatever comes back. The
 * key stays wherever the Signer keeps it (an environment secret today; PEM,
 * wallet, WebCrypto and KMS adapters are phase 4), so no API request and no
 * core function ever carries private key material (self-custody invariant,
 * rule 7 of the KYA-OS stories).
 */
export interface Signer {
  /** DID of the key's controller. The JWS `kid` is `<did>#<kid>`. */
  readonly did: string;
  /** Verification-method fragment, without the `#` (for example `key-1`). */
  readonly kid: string;
  /** Raw Ed25519 signature (64 bytes) over `data`. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface EnvSignerOptions {
  did: string;
  /**
   * Verification-method fragment or the full id the DID document publishes
   * (`<did>#key-1`), so a did:web agent announces exactly the `kid` its
   * document lists. Default: `defaultKidFragment(did)`, the multibase value
   * for a did:key, else `key-1`.
   */
  kid?: string;
  /** Name of the variable holding the private key. Default `HELIX_SIGNING_KEY`. */
  envVar?: string;
  /** Where to read it from. Default `process.env`. */
  env?: Readonly<Record<string, string | undefined>>;
}

export const DEFAULT_SIGNING_KEY_ENV_VAR = "HELIX_SIGNING_KEY";
export const DEFAULT_KID_FRAGMENT = "key-1";

const DID_KEY_PREFIX = "did:key:";

/**
 * The verification-method fragment a DID's signer names when the caller gives
 * none. A did:key document defines exactly one method, `did:key:z…#z…` (the
 * multibase value repeated), so a did:key signs as that; `key-1`, which
 * `buildDIDDocument` publishes for did:web and other DIDs, does not exist in
 * a did:key document and a verifier refuses it.
 */
export function defaultKidFragment(did: string): string {
  if (did.startsWith(DID_KEY_PREFIX) && did.length > DID_KEY_PREFIX.length) {
    return did.slice(DID_KEY_PREFIX.length);
  }
  return DEFAULT_KID_FRAGMENT;
}

/**
 * The only Signer for now: an Ed25519 private key (raw 32-byte hex or PKCS8
 * DER seed hex, as `HELIX_SIGNING_KEY` already is) read from an environment
 * variable at every `sign()` call. The instance itself never holds the key,
 * so serialising or logging a Signer leaks nothing.
 */
export class EnvSigner implements Signer {
  readonly did: string;
  readonly kid: string;
  // ES private fields: never enumerable, so serialising or logging the
  // signer shows the DID and kid and nothing of where the key lives.
  readonly #envVar: string;
  readonly #env: Readonly<Record<string, string | undefined>>;

  constructor(options: EnvSignerOptions) {
    if (!options.did.startsWith("did:")) {
      throw new Error("EnvSigner: did must be a DID");
    }
    // The fragment alone (`key-1`, `#key-1`) or the full verification-method
    // id the DID document publishes (`<did>#key-1`), which must be this DID's.
    let kid = options.kid ?? defaultKidFragment(options.did);
    if (kid.startsWith(`${options.did}#`)) kid = kid.slice(options.did.length + 1);
    kid = kid.replace(/^#/, "");
    if (kid.length === 0 || kid.includes("#")) {
      throw new Error(
        "EnvSigner: kid must be a verification-method fragment of this DID",
      );
    }
    this.did = options.did;
    this.kid = kid;
    this.#envVar = options.envVar ?? DEFAULT_SIGNING_KEY_ENV_VAR;
    this.#env = options.env ?? process.env;
  }

  /** `<did>#<kid>`, what the JWS header carries. */
  get verificationMethodId(): string {
    return `${this.did}#${this.kid}`;
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(data, this.secret());
  }

  publicKeyHex(): string {
    return derivePublicKey(Buffer.from(this.secret()).toString("hex"));
  }

  private secret(): Uint8Array {
    const value = this.#env[this.#envVar];
    if (value === undefined || value.trim() === "") {
      throw new Error(
        `EnvSigner: environment variable ${this.#envVar} is not set`,
      );
    }
    return normalizeEd25519PrivateKey(value);
  }
}
