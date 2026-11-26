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
 * Cross-language JWS fixtures (KYA-OS story L1-C, stories rule 6): generated
 * once from helix-core's `signJws`, checked in at fixtures/kya-os-helix/jws.json,
 * and consumed byte for byte by helix-core, helix-sdk-py and e2e-playwright.
 *
 * Run: pnpm generate:jws-fixtures
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as ed25519 from "@noble/ed25519";
import {
  EnvSigner,
  JwsReasons,
  base64UrlEncode,
  buildDIDDocument,
  derivePublicKey,
  publicKeyHexToJwk,
  signJws,
  type DIDDocument,
  type Ed25519PublicJwk,
  type JwsPayload,
} from "../src/core/index.js";

export interface JwsFixtureKey {
  private_key_hex: string;
  public_key_hex: string;
  did: string;
  kid_fragment: string;
  kid: string;
  public_key_jwk: Ed25519PublicJwk;
  did_document: DIDDocument;
}

export interface JwsFixtureVector {
  name: string;
  signer: "signer" | "other";
  /** `{json}`: signed as JSON.stringify of it; `{text}`: UTF-8; `{bytes_hex}`: raw bytes. */
  payload: { json: unknown } | { text: string } | { bytes_hex: string };
  header_extra?: Record<string, unknown>;
  header: Record<string, unknown>;
  jws: string;
}

export interface JwsFixtureRejection {
  name: string;
  jws: string;
  /** Which fixture key to verify against; `kid` says whether its JWK carries a kid. */
  verify_with: { key: "signer" | "other"; kid: boolean };
  expected_did?: string;
  reason: string;
  /**
   * What `verifyJwsByKid` with the fixture DID documents refuses it for, when
   * it differs; null when the kid path verifies (it resolves the right key).
   */
  by_kid_reason?: string | null;
}

export interface JwsFixtures {
  generated_from: string;
  generator: string;
  note: string;
  keys: { signer: JwsFixtureKey; other: JwsFixtureKey };
  vectors: JwsFixtureVector[];
  rejections: JwsFixtureRejection[];
}

const SIGNER_SEED = Array.from({ length: 32 }, (_, i) =>
  (i + 1).toString(16).padStart(2, "0"),
).join("");
const OTHER_SEED = Array.from({ length: 32 }, (_, i) =>
  (i + 33).toString(16).padStart(2, "0"),
).join("");

function fixtureKey(privateKeyHex: string, did: string): JwsFixtureKey {
  const publicKeyHex = derivePublicKey(privateKeyHex);
  const kid = `${did}#key-1`;
  return {
    private_key_hex: privateKeyHex,
    public_key_hex: publicKeyHex,
    did,
    kid_fragment: "key-1",
    kid,
    public_key_jwk: publicKeyHexToJwk(publicKeyHex, kid),
    did_document: buildDIDDocument(did, publicKeyHex),
  };
}

function signerFor(key: JwsFixtureKey): EnvSigner {
  return new EnvSigner({
    did: key.did,
    kid: key.kid_fragment,
    envVar: "FIXTURE_KEY",
    env: { FIXTURE_KEY: key.private_key_hex },
  });
}

/** A JWS with whatever header and segments the case needs, signed by a real key. */
function rawJws(
  headerJson: string,
  payloadJson: string,
  privateKeyHex: string,
): string {
  const signingInput = `${base64UrlEncode(headerJson)}.${base64UrlEncode(payloadJson)}`;
  const signature = ed25519.sign(
    Buffer.from(signingInput, "utf8"),
    Buffer.from(privateKeyHex, "hex"),
  );
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

function decodeHeader(jws: string): Record<string, unknown> {
  return JSON.parse(
    Buffer.from(jws.split(".")[0]!, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
}

export async function buildJwsFixtures(): Promise<JwsFixtures> {
  const signer = fixtureKey(SIGNER_SEED, "did:web:signer.helix.test");
  const other = fixtureKey(OTHER_SEED, "did:web:other.helix.test");
  const keys = { signer, other };

  const cases: {
    name: string;
    signer: "signer" | "other";
    payload: JwsFixtureVector["payload"];
    header_extra?: Record<string, unknown>;
  }[] = [
    {
      name: "json_object",
      signer: "signer",
      payload: {
        json: {
          iss: signer.did,
          sub: "agent-1",
          n: 42,
          ok: true,
          nested: { list: [1, 2, 3], none: null },
        },
      },
    },
    {
      name: "json_object_unicode",
      signer: "signer",
      payload: { json: { msg: "héllo wörld 你好 🎉", quote: 'say "hi"\\now' } },
    },
    {
      name: "json_array",
      signer: "signer",
      payload: { json: ["a", 1, false] },
    },
    { name: "text", signer: "signer", payload: { text: "plain text payload" } },
    { name: "empty_json_object", signer: "signer", payload: { json: {} } },
    { name: "bytes", signer: "signer", payload: { bytes_hex: "00ff10203040" } },
    {
      name: "other_key",
      signer: "other",
      payload: { json: { iss: other.did, purpose: "second key" } },
    },
    {
      name: "extra_header_typ",
      signer: "signer",
      payload: { json: { iss: signer.did, jti: "session-1" } },
      header_extra: { typ: "JWT", crv: "Ed25519" },
    },
    {
      name: "kya_os_proof_shape",
      signer: "signer",
      payload: {
        json: {
          aud: "did:web:server.example.com",
          iss: signer.did,
          nonce: "b6VZmm9hXn-otOETBkvlvQ",
          requestHash:
            "sha256:c8f3d59959c9247211de8c76b94ef17f0c279f09362350ced67f69ecdb89d6c7",
          sessionId: "sess_fixture",
          sub: signer.did,
          ts: 1750000000,
        },
      },
    },
  ];

  const vectors: JwsFixtureVector[] = [];
  for (const c of cases) {
    const key = keys[c.signer];
    const payload: JwsPayload =
      "json" in c.payload
        ? (c.payload.json as JwsPayload)
        : "text" in c.payload
          ? c.payload.text
          : new Uint8Array(Buffer.from(c.payload.bytes_hex, "hex"));
    const jws = await signJws(
      payload,
      signerFor(key),
      c.header_extra ? { header: c.header_extra } : {},
    );
    vectors.push({
      name: c.name,
      signer: c.signer,
      payload: c.payload,
      ...(c.header_extra ? { header_extra: c.header_extra } : {}),
      header: decodeHeader(jws),
      jws,
    });
  }

  const claims = JSON.stringify({ iss: signer.did, sub: "agent-1" });
  const good = await signJws(
    JSON.parse(claims) as Record<string, unknown>,
    signerFor(signer),
  );
  const [h, p, s] = good.split(".") as [string, string, string];
  const headerWith = (members: Record<string, unknown>): string =>
    JSON.stringify(members);

  const rejections: JwsFixtureRejection[] = [
    {
      name: "alg_rs256",
      jws: rawJws(
        headerWith({ alg: "RS256", kid: signer.kid }),
        claims,
        signer.private_key_hex,
      ),
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.ALG_UNSUPPORTED,
    },
    {
      name: "alg_none",
      jws: rawJws(
        headerWith({ alg: "none", kid: signer.kid }),
        claims,
        signer.private_key_hex,
      ),
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.ALG_UNSUPPORTED,
    },
    {
      name: "alg_missing",
      jws: rawJws(
        headerWith({ kid: signer.kid }),
        claims,
        signer.private_key_hex,
      ),
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.ALG_UNSUPPORTED,
    },
    {
      name: "kid_missing",
      jws: rawJws(headerWith({ alg: "EdDSA" }), claims, signer.private_key_hex),
      verify_with: { key: "signer", kid: false },
      reason: JwsReasons.KID_MISSING,
    },
    {
      name: "kid_not_a_did",
      jws: rawJws(
        headerWith({ alg: "EdDSA", kid: "key-1" }),
        claims,
        signer.private_key_hex,
      ),
      verify_with: { key: "signer", kid: false },
      reason: JwsReasons.KID_MALFORMED,
    },
    {
      name: "kid_without_fragment",
      jws: rawJws(
        headerWith({ alg: "EdDSA", kid: signer.did }),
        claims,
        signer.private_key_hex,
      ),
      verify_with: { key: "signer", kid: false },
      reason: JwsReasons.KID_MALFORMED,
    },
    {
      name: "kid_of_other_did_than_iss",
      jws: rawJws(
        headerWith({ alg: "EdDSA", kid: other.kid }),
        claims,
        signer.private_key_hex,
      ),
      verify_with: { key: "signer", kid: false },
      reason: JwsReasons.KID_DID_MISMATCH,
      by_kid_reason: JwsReasons.KID_DID_MISMATCH,
    },
    {
      name: "kid_of_other_did_than_expected",
      jws: rawJws(
        headerWith({ alg: "EdDSA", kid: other.kid }),
        JSON.stringify({ sub: "no iss" }),
        other.private_key_hex,
      ),
      verify_with: { key: "other", kid: false },
      expected_did: signer.did,
      reason: JwsReasons.KID_DID_MISMATCH,
      by_kid_reason: JwsReasons.KID_DID_MISMATCH,
    },
    {
      name: "kid_not_the_given_key",
      jws: rawJws(
        headerWith({ alg: "EdDSA", kid: `${signer.did}#key-2` }),
        claims,
        signer.private_key_hex,
      ),
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.KID_MISMATCH,
      by_kid_reason: JwsReasons.KEY_NOT_FOUND,
    },
    {
      name: "wrong_key",
      jws: good,
      verify_with: { key: "other", kid: false },
      reason: JwsReasons.SIGNATURE_INVALID,
      by_kid_reason: null,
    },
    {
      name: "signature_tampered",
      jws: `${h}.${p}.${s.slice(0, -2)}${s.endsWith("AA") ? "BB" : "AA"}`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.SIGNATURE_INVALID,
    },
    {
      name: "payload_tampered",
      jws: `${h}.${base64UrlEncode(JSON.stringify({ iss: signer.did, sub: "agent-2" }))}.${s}`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.SIGNATURE_INVALID,
    },
    {
      name: "signature_padded",
      jws: `${h}.${p}.${s}=`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.MALFORMED,
    },
    {
      name: "signature_base64_alphabet",
      jws: `${h}.${p}.${s.replace(/-/g, "+").replace(/_/g, "/")}${s.includes("-") || s.includes("_") ? "" : "+"}`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.MALFORMED,
    },
    {
      name: "payload_with_white_space",
      jws: `${h}.${p} .${s}`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.MALFORMED,
    },
    {
      name: "two_segments",
      jws: `${h}.${p}`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.MALFORMED,
    },
    {
      name: "four_segments",
      jws: `${h}.${p}.${s}.${s}`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.MALFORMED,
    },
    {
      name: "empty_signature",
      jws: `${h}.${p}.`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.MALFORMED,
    },
    {
      name: "header_not_json",
      jws: `${base64UrlEncode("not json")}.${p}.${s}`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.HEADER_INVALID,
    },
    {
      name: "header_json_array",
      jws: `${base64UrlEncode("[]")}.${p}.${s}`,
      verify_with: { key: "signer", kid: true },
      reason: JwsReasons.HEADER_INVALID,
    },
  ];

  return {
    generated_from: "helix-core",
    generator: "scripts/generate-jws-fixtures.ts",
    note: "KYA-OS story L1-C. Regenerate (pnpm generate:jws-fixtures) whenever src/core/crypto/jws.ts or signer.ts change; helix-core, helix-sdk-py and e2e-playwright assert byte-for-byte against this file. Test keys only; never real secrets.",
    keys,
    vectors,
    rejections,
  };
}

export function serializeJwsFixtures(fixtures: JwsFixtures): string {
  return `${JSON.stringify(fixtures, null, 2)}\n`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const outDir = fileURLToPath(
    new URL("../fixtures/kya-os-helix/", import.meta.url),
  );
  mkdirSync(outDir, { recursive: true });
  const fixtures = await buildJwsFixtures();
  writeFileSync(`${outDir}jws.json`, serializeJwsFixtures(fixtures));
  // eslint-disable-next-line no-console
  console.log(
    `wrote fixtures/kya-os-helix/jws.json (${fixtures.vectors.length} vectors, ${fixtures.rejections.length} rejections)`,
  );
}
