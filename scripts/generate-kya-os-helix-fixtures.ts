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
 * Generates `fixtures/kya-os-helix/*.json`: the Helix-made fixture set for the
 * KYA-OS profile (stories rule 6). One file per primitive, generated straight
 * from helix-core's implementation and checked in; helix-core, helix-sdk-py
 * and e2e-playwright assert byte-for-byte equality against them, so there is
 * exactly one place these values live.
 *
 * Today: `jcs.json` (L1-B) — sample JSON values with their RFC 8785 canonical
 * form and `sha256:<hex>` hash. Later stories add their own files here.
 *
 * Run: pnpm generate:kya-os-helix
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalize, hashJson } from '../src/core/crypto/jcs.js';

const OUT_DIR = fileURLToPath(new URL('../fixtures/kya-os-helix/', import.meta.url));
mkdirSync(OUT_DIR, { recursive: true });

interface JcsCase {
  name: string;
  input: unknown;
}

const jcsCases: JcsCase[] = [
  { name: 'empty_object', input: {} },
  { name: 'empty_array', input: [] },
  { name: 'scalars', input: [null, true, false, 0, -1, 42, 'text', ''] },
  { name: 'flat_object_unordered_keys', input: { zeta: 1, alpha: 2, mid: 3, Alpha: 4, _under: 5, '10': 6, '9': 7 } },
  {
    name: 'nested_key_order',
    input: {
      outer: { z: { y: [{ b: 2, a: 1 }, { d: 4, c: 3 }], x: null }, a: { deep: true, arr: [3, 1, 2] } },
      top: 'value',
      '': 'empty key',
    },
  },
  {
    name: 'utf16_key_order_rfc8785_3_2_3',
    input: {
      '\u20ac': 'Euro Sign',
      '\r': 'Carriage Return',
      '\ufb33': 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '\ud83d\ude00': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      '\u00f6': 'Latin Small Letter O With Diaeresis',
    },
  },
  {
    name: 'unicode_escapes',
    input: {
      controls: '\u0000\u0001\u001f',
      named: '\b\f\n\r\t',
      quote_backslash_solidus: '"\\/',
      del_and_line_separators: '\u007f\u2028\u2029',
      bmp: 'h\u00e9llo w\u00f6rld \u4f60\u597d \ufb33',
      non_bmp: '\ud83d\udd11\u2728\ud834\udd1e',
      combining: 'e\u0301 a\u030a',
    },
  },
  {
    name: 'rfc8785_appendix_sample',
    input: {
      numbers: [333333333.33333329, 4.5, 2e-3, 0.000000000000000000000000001],
      string: '\u20ac$\u000f\u000aA\u0027\u0042\u0022\u005c\\\u0022\u002f',
      literals: [null, true, false],
    },
  },
  {
    name: 'floats',
    input: [
      -0,
      0.1,
      0.1 + 0.2,
      1e-7,
      1e-5,
      0.000001,
      5e-324,
      2.220446049250313e-16,
      -2.5,
      123.456,
      49.99,
      0.875,
      1e21 / 1e6,
      1234567890123456.7,
      100,
      9007199254740991,
      -9007199254740991,
    ],
  },
  {
    name: 'mcp_tool_call_covered_request',
    input: {
      method: 'tools/call',
      params: { name: 'lookup_order', arguments: { orderId: 'ord-42', includeItems: true, limit: 25, price: 19.99 } },
    },
  },
  {
    name: 'mcp_tool_call_response_body',
    input: [
      { type: 'text', text: 'Order ord-42: 2 items, total 39.98' },
      { type: 'resource', resource: { uri: 'helix://orders/ord-42', mimeType: 'application/json', text: '{"id":"ord-42"}' } },
    ],
  },
  {
    name: 'l2_proof_meta',
    input: {
      responseHash: 'sha256:4bcfa5d788673d0a2a796d22b0ad28bbb482ec087770cd870d6a8ce2e90ec142',
      requestHash: 'sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7',
      sessionId: 'kyaos_01HZX',
      audience: 'did:web:service.example.com',
      nonce: 'b6VZmm9hXn-otOETBkvlvQ',
      ts: 1750000000,
      kid: 'did:key:z6MkqQrYYzmMhjiBtLF8b6HofyGM9s2GffDF3BSsGEpBpczT#z6MkqQrYYzmMhjiBtLF8b6HofyGM9s2GffDF3BSsGEpBpczT',
      did: 'did:key:z6MkqQrYYzmMhjiBtLF8b6HofyGM9s2GffDF3BSsGEpBpczT',
    },
  },
  {
    name: 'delegation_credential_unsigned',
    input: {
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/zcap/v1'],
      type: ['VerifiableCredential', 'DelegationCredential'],
      id: 'urn:uuid:5b3c7e0a-1f2d-4c8e-9a6b-0d1e2f3a4b5c',
      issuer: 'did:web:helix.example.com:agents:parent',
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: '2026-01-02T00:00:00Z',
      credentialSubject: {
        id: 'did:web:helix.example.com:agents:child',
        invoker: 'did:web:helix.example.com:agents:child',
        parentCapability: 'urn:uuid:root-consent',
        invocationTarget: 'https://service.example.com/mcp',
        allowedAction: ['read:orders', 'read:catalog'],
        caveats: [{ type: 'MaxCalls', max: 100 }],
      },
      credentialStatus: {
        type: 'BitstringStatusListEntry',
        statusPurpose: 'revocation',
        statusListIndex: '94567',
        statusListCredential: 'https://helix.example.com/status/3',
      },
    },
  },
  {
    name: 'status_list_credential_unsigned',
    input: {
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
      id: 'https://helix.example.com/status/3',
      type: ['VerifiableCredential', 'StatusList2021Credential'],
      issuer: 'did:web:helix.example.com',
      issuanceDate: '2026-01-01T00:00:00Z',
      credentialSubject: {
        id: 'https://helix.example.com/status/3#list',
        type: 'StatusList2021',
        statusPurpose: 'revocation',
        encodedList: 'H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA',
      },
    },
  },
];

const jcsFile = {
  generated_from: 'helix-core',
  generator: 'scripts/generate-kya-os-helix-fixtures.ts',
  note:
    'RFC 8785 canonical form and KYA-OS sha256:<hex> hash of sample JSON values, from src/core/crypto/jcs.ts. ' +
    'helix-sdk-py and e2e-playwright assert byte-for-byte equality against this file; regenerate with ' +
    '`pnpm generate:kya-os-helix` whenever jcs.ts changes, never hand-edit.',
  vectors: jcsCases.map(({ name, input }) => ({ name, input, canonical: canonicalize(input), hash: hashJson(input) })),
};

writeFileSync(`${OUT_DIR}jcs.json`, JSON.stringify(jcsFile, null, 2) + '\n', 'utf8');
console.log(`wrote fixtures/kya-os-helix/jcs.json (${jcsFile.vectors.length} vectors)`);
