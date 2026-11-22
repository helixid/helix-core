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
 * Cross-language agent-key fixtures (KYA-OS story L1-A, stories rule 6):
 * generated once from helix-core's own implementation, checked in at
 * fixtures/kya-os-helix/did.json, and consumed byte for byte by helix-core,
 * helix-sdk-js, helix-sdk-py and e2e-playwright. For each test key: the
 * seed, the public key, its JWK, its did:key, its did:web document with the
 * verification-method id that is the agent's `kid`, the registration body
 * the SDK sends (public JWK only), and what resolving either DID must give.
 * Plus base58btc vectors (L1.9) and malformed did:key cases.
 *
 * Run: pnpm generate:did-fixtures
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  encodeBase58btc,
  buildDidDocument,
  derivePublicKey,
  didKeyDocument,
  didKeyFromPublicKey,
  publicKeyBytesToJwk,
  publicKeyToMultibaseOf,
  resolveDidKey,
  verificationMethodId,
  type AgentDidDocument,
  type PublicKeyJwk,
} from '../src/core/index.js';

export interface DidFixtureKey {
  /** The 32-byte Ed25519 seed, what EnvSigner reads from the environment. Test key only. */
  private_key_hex: string;
  public_key_hex: string;
  public_key_jwk: PublicKeyJwk;
  public_key_multibase: string;
  did_key: string;
  did_web: string;
  kid_fragment: string;
  /** `<did_web>#<kid_fragment>`: the verification-method id and the JWS `kid`. */
  kid: string;
  did_web_document: AgentDidDocument;
  did_key_document: AgentDidDocument;
  /** The body of POST /v1/agents/{did}/keys: the public JWK and the kid, nothing else. */
  registration_body: { publicKeyJwk: PublicKeyJwk; kid: string };
  /** What resolveDid gives for did_web and for did_key: the same raw key and JWK. */
  resolved: {
    raw_key_hex: string;
    jwk: PublicKeyJwk;
    did_web_kid: string;
    did_key_kid: string;
  };
}

export interface Base58Vector {
  bytes_hex: string;
  base58btc: string;
}

export interface DidKeyRejection {
  name: string;
  did: string;
  reason: string;
}

export interface DidFixtures {
  generated_from: string;
  generator: string;
  note: string;
  keys: { agent: DidFixtureKey; other: DidFixtureKey };
  base58btc: Base58Vector[];
  did_key_rejections: DidKeyRejection[];
}

const AGENT_SEED = Array.from({ length: 32 }, (_, i) => (0x41 + i).toString(16).padStart(2, '0')).join('');
const OTHER_SEED = Array.from({ length: 32 }, (_, i) => (0xa0 - i).toString(16).padStart(2, '0')).join('');

function fixtureKey(privateKeyHex: string, didWeb: string, kidFragment: string): DidFixtureKey {
  const publicKeyHex = derivePublicKey(privateKeyHex);
  const publicKey = new Uint8Array(Buffer.from(publicKeyHex, 'hex'));
  const publicKeyJwk = publicKeyBytesToJwk(publicKey);
  const didKey = didKeyFromPublicKey(publicKey);
  const kid = verificationMethodId(didWeb, kidFragment);
  const didWebDocument = buildDidDocument({ did: didWeb, publicKeyJwk, kid: kidFragment, alsoKnownAs: [didKey] });
  const fromDidKey = resolveDidKey(didKey);
  return {
    private_key_hex: privateKeyHex,
    public_key_hex: publicKeyHex,
    public_key_jwk: publicKeyJwk,
    public_key_multibase: publicKeyToMultibaseOf(publicKey),
    did_key: didKey,
    did_web: didWeb,
    kid_fragment: kidFragment,
    kid,
    did_web_document: didWebDocument,
    did_key_document: didKeyDocument(didKey),
    registration_body: { publicKeyJwk, kid: kidFragment },
    resolved: {
      raw_key_hex: Buffer.from(fromDidKey.rawKey).toString('hex'),
      jwk: { kty: 'OKP', crv: 'Ed25519', x: fromDidKey.jwk.x },
      did_web_kid: kid,
      did_key_kid: fromDidKey.kid,
    },
  };
}

export function buildDidFixtures(): DidFixtures {
  const agent = fixtureKey(AGENT_SEED, 'did:web:agents.helix.test:agents:fixture-agent', 'key-1');
  const other = fixtureKey(OTHER_SEED, 'did:web:other.helix.test', 'kya-os-2026');

  const base58Cases = ['', '00', '000102', '0000ff', '61', '626262', '636363', '48656c6c6f', '73696d706c792061206c6f6e6720737472696e67', '00eb15231dfceb60925886b67d065299925915aeb172c06647', 'ffffffff', `ed01${agent.public_key_hex}`, `ed01${'2a'.repeat(32)}`];
  const base58btc = base58Cases.map((hex) => ({
    bytes_hex: hex,
    base58btc: encodeBase58btc(new Uint8Array(Buffer.from(hex, 'hex'))),
  }));

  const did_key_rejections: DidKeyRejection[] = [
    { name: 'not_multibase_z', did: `did:key:${agent.did_key.slice('did:key:z'.length)}`, reason: 'no multibase z prefix' },
    { name: 'invalid_base58', did: 'did:key:z6MkNOTVALIDbase58!!!!', reason: 'characters outside the base58btc alphabet' },
    { name: 'wrong_multicodec', did: `did:key:${'z'}${encodeBase58btc(new Uint8Array(Buffer.from(`ec01${agent.public_key_hex}`, 'hex')))}`, reason: 'multicodec is not 0xed01 (Ed25519)' },
    { name: 'truncated_key', did: `did:key:z${encodeBase58btc(new Uint8Array(Buffer.from(`ed01${agent.public_key_hex.slice(0, 62)}`, 'hex')))}`, reason: 'fewer than 32 key bytes' },
    { name: 'empty', did: 'did:key:z', reason: 'nothing after the multibase prefix' },
    { name: 'did_web', did: agent.did_web, reason: 'not did:key' },
  ];

  return {
    generated_from: 'helix-core',
    generator: 'scripts/generate-did-fixtures.ts',
    note: 'KYA-OS story L1-A. Regenerate (pnpm generate:did-fixtures) whenever src/core/did/* or the key helpers change; helix-core, helix-sdk-js, helix-sdk-py and e2e-playwright assert byte-for-byte against this file. Test keys only; never real secrets.',
    keys: { agent, other },
    base58btc,
    did_key_rejections,
  };
}

export function serializeDidFixtures(fixtures: DidFixtures): string {
  return `${JSON.stringify(fixtures, null, 2)}\n`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const outDir = fileURLToPath(new URL('../fixtures/kya-os-helix/', import.meta.url));
  mkdirSync(outDir, { recursive: true });
  const fixtures = buildDidFixtures();
  writeFileSync(`${outDir}did.json`, serializeDidFixtures(fixtures));
  // eslint-disable-next-line no-console
  console.log(`wrote fixtures/kya-os-helix/did.json (${Object.keys(fixtures.keys).length} keys, ${fixtures.base58btc.length} base58 vectors)`);
}
