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

import { gzipSync, gunzipSync } from 'node:zlib';
import { signDataIntegrity } from '../credentials/data-integrity.js';
import type { DataIntegrityProof } from '../credentials/types.js';
import type { Signer } from '../crypto/signer.js';

export { StatusListCredentialSchema } from './schema.js';

/** W3C VC 2.0 context: a Bitstring Status List v1.0 credential is a VC 2.0 credential. */
export const STATUS_LIST_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

/**
 * A W3C Bitstring Status List v1.0 credential (KYA-OS story L3-C point 1):
 * one per issuer DID, `validFrom`/`validUntil` set so a verifier can compute
 * freshness, signed by that issuer with a `DataIntegrityProof`
 * (`eddsa-jcs-2022`).
 */
export interface StatusListCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil?: string;
  credentialSubject: {
    id: string;
    type: 'BitstringStatusList';
    statusPurpose: 'revocation';
    encodedList: string;
  };
  proof?: DataIntegrityProof;
}

export type SignedStatusListCredential = StatusListCredential & { validUntil: string; proof: DataIntegrityProof };

/**
 * Encodes a buffer to a base64url string.
 */
function base64urlEncode(buffer: Buffer): string {
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Decodes a base64url string to a buffer.
 */
function base64urlDecode(str: string): Buffer {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64');
}

/**
 * Creates a new status list bitstring (W3C Bitstring Status List).
 * Default size: 131072 bits (16KB uncompressed).
 */
export function createStatusList(size: number = 131072): string {
  const buffer = Buffer.alloc(Math.ceil(size / 8), 0);
  const compressed = gzipSync(buffer);
  return base64urlEncode(compressed);
}

/**
 * Flips a bit in the encoded status list.
 * 0 = valid, 1 = revoked.
 */
export function setBit(encodedList: string, index: number, value: 0 | 1): string {
  const compressed = base64urlDecode(encodedList);
  const buffer = gunzipSync(compressed);

  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;

  const byte = buffer[byteIndex];
  if (byte === undefined) throw new Error('Status list index out of bounds');

  if (value === 1) {
    buffer[byteIndex] = byte | (1 << (7 - bitIndex));
  } else {
    buffer[byteIndex] = byte & ~(1 << (7 - bitIndex));
  }

  const newCompressed = gzipSync(buffer);
  return base64urlEncode(newCompressed);
}

/**
 * Reads a bit from the encoded status list.
 */
export function getBit(encodedList: string, index: number): 0 | 1 {
  const compressed = base64urlDecode(encodedList);
  const buffer = gunzipSync(compressed);

  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;

  const byte = buffer[byteIndex];
  if (byte === undefined) throw new Error('Status list index out of bounds');

  const bit = (byte >> (7 - bitIndex)) & 1;
  return bit === 1 ? 1 : 0;
}

/**
 * Returns the bit capacity of an encoded status list.
 */
export function getStatusListLength(encodedList: string): number {
  const compressed = base64urlDecode(encodedList);
  const buffer = gunzipSync(compressed);
  return buffer.length * 8;
}

export interface StatusListCredentialInput {
  /** The URL the list is served at: its `id`, byte for byte what credentials name as `statusListCredential`. */
  id: string;
  /** The issuer DID: the one whose credentials the list covers, and its signer. */
  issuer: string;
  /** GZIP + base64url bitstring (multibase `u` prefix added when missing). */
  encodedList: string;
  validFrom: string;
  validUntil: string;
}

/** The encoded list with the multibase base64url `u` prefix Bitstring Status List v1.0 requires. */
export function multibaseEncodedList(encodedList: string): string {
  return encodedList.startsWith('u') ? encodedList : `u${encodedList}`;
}

/** The bare base64url payload of an encoded list, with or without its multibase `u`. */
export function bareEncodedList(encodedList: string): string {
  return encodedList.startsWith('u') ? encodedList.slice(1) : encodedList;
}

/**
 * The signed W3C Bitstring Status List v1.0 credential of one issuer
 * (story L3-C point 1): `validFrom` and `validUntil` set, signed by
 * `signer`, whose DID must be `issuer`.
 */
export async function buildStatusListCredential(input: StatusListCredentialInput, signer: Signer): Promise<SignedStatusListCredential> {
  if (Date.parse(input.validUntil) <= Date.parse(input.validFrom)) {
    throw new Error('buildStatusListCredential: validUntil must be after validFrom');
  }
  const unsigned = unsignedStatusListCredential(input);
  return (await signDataIntegrity(unsigned as unknown as Record<string, unknown>, signer, { created: input.validFrom })) as unknown as SignedStatusListCredential;
}

/** The same credential before its proof: what a self-custody issuer signs itself (story L3-C, issuers without a Helix-held key). */
export function unsignedStatusListCredential(input: StatusListCredentialInput): StatusListCredential & { validUntil: string } {
  return {
    '@context': [STATUS_LIST_CONTEXT],
    id: input.id,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: input.issuer,
    validFrom: input.validFrom,
    validUntil: input.validUntil,
    credentialSubject: {
      id: `${input.id}#list`,
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList: multibaseEncodedList(input.encodedList),
    },
  };
}

/** The list id of the platform list legacy credentials and the Helix issuer use. */
export const DEFAULT_STATUS_LIST_ID = 'helix-status-list-1';
const ISSUER_LIST_PREFIX = 'iss-';

/**
 * The list id of an issuer's list: one list per issuer DID. The Helix
 * issuer keeps the platform list; every other issuer's id carries its DID,
 * base64url-encoded, so the id alone names whose list it is.
 */
export function statusListIdFor(issuerDid: string, helixIssuerDid: string): string {
  if (issuerDid === helixIssuerDid) return DEFAULT_STATUS_LIST_ID;
  return `${ISSUER_LIST_PREFIX}${Buffer.from(issuerDid, 'utf8').toString('base64url')}`;
}

/** The issuer DID a list id names, or undefined for an id that names none. */
export function issuerOfStatusListId(listId: string, helixIssuerDid: string): string | undefined {
  if (listId === DEFAULT_STATUS_LIST_ID) return helixIssuerDid;
  if (!listId.startsWith(ISSUER_LIST_PREFIX)) return undefined;
  const encoded = listId.slice(ISSUER_LIST_PREFIX.length);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return undefined;
  const did = Buffer.from(encoded, 'base64url').toString('utf8');
  return did.startsWith('did:') && Buffer.from(did, 'utf8').toString('base64url') === encoded ? did : undefined;
}
