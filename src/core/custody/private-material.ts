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
 * The self-custody invariant on the Helix side (stories rule 7, story F-3):
 * a request that registers a client-held key carries the public half and
 * nothing else. These names only ever carry private material; a body that
 * has one anywhere is refused before anything is read from it.
 */

export const PRIVATE_KEY_MATERIAL_MEMBERS: ReadonlySet<string> = new Set([
  'd',
  'privateKey',
  'privateKeyHex',
  'privateKeyJwk',
  'privateKeyMultibase',
  'private_key',
  'secretKey',
  'seed',
  'secret',
]);

/** The path of the first private-material member anywhere in `value`, or undefined. */
export function findPrivateKeyMaterial(value: unknown, path = ''): string | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  for (const [name, member] of Object.entries(value as Record<string, unknown>)) {
    const here = path ? `${path}.${name}` : name;
    if (PRIVATE_KEY_MATERIAL_MEMBERS.has(name)) return here;
    const nested = findPrivateKeyMaterial(member, here);
    if (nested !== undefined) return nested;
  }
  return undefined;
}
