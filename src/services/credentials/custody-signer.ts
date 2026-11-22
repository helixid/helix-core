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

import { signData, type Signer } from '../../core/index.js';
import type { EncryptedKeyMaterial, IKeyCustody } from '../key-custody/key-custody.js';

/**
 * A {@link Signer} over a key Helix holds in custody (a custodial agent or a
 * service): the plaintext key exists only inside `keyCustody.signWith` for
 * the one signature (stories rule 8, Helix-held keys go through the key
 * store only). The signer itself carries the DID and the encrypted record.
 */
export class CustodySigner implements Signer {
  readonly did: string;
  readonly kid: string;
  // ES private fields: never enumerable, so serialising or logging the
  // signer shows the DID and kid and neither the encrypted record nor the
  // custody (whose master key must never leave it).
  readonly #encrypted: EncryptedKeyMaterial;
  readonly #keyCustody: IKeyCustody;

  constructor(did: string, encrypted: EncryptedKeyMaterial, keyCustody: IKeyCustody, kid = 'key-1') {
    this.did = did;
    this.kid = kid;
    this.#encrypted = encrypted;
    this.#keyCustody = keyCustody;
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const hex = await this.#keyCustody.signWith(this.#encrypted, (privateKeyHex) => signData(data, privateKeyHex));
    return new Uint8Array(Buffer.from(hex, 'hex'));
  }
}
