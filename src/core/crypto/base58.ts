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
 * base58btc, the Bitcoin alphabet, as did:key and multibase `z` use it
 * (KYA-OS conformance Core L1.9): every leading zero byte is one leading
 * `1`, the rest is the big number in base 58, so `[0]` is `1`, `[0, 0, 1]`
 * is `112`, and empty is empty. Decoding accepts the alphabet only.
 */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const INDEX = new Map<string, number>([...ALPHABET].map((char, i) => [char, i]));

export function isBase58btc(value: string): boolean {
  for (const char of value) {
    if (!INDEX.has(char)) return false;
  }
  return true;
}

export function encodeBase58btc(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  let n = 0n;
  for (let i = zeros; i < bytes.length; i += 1) n = n * 256n + BigInt(bytes[i]!);
  let digits = '';
  while (n > 0n) {
    digits = ALPHABET[Number(n % 58n)] + digits;
    n /= 58n;
  }
  return ALPHABET[0]!.repeat(zeros) + digits;
}

export function decodeBase58btc(value: string): Uint8Array {
  let zeros = 0;
  while (zeros < value.length && value[zeros] === ALPHABET[0]) zeros += 1;
  let n = 0n;
  for (let i = zeros; i < value.length; i += 1) {
    const digit = INDEX.get(value[i]!);
    if (digit === undefined) throw new Error(`Invalid base58 character: ${value[i]}`);
    n = n * 58n + BigInt(digit);
  }
  const rest: number[] = [];
  while (n > 0n) {
    rest.unshift(Number(n % 256n));
    n /= 256n;
  }
  return new Uint8Array([...new Array<number>(zeros).fill(0), ...rest]);
}
