// Copyright 2026 DgVerse LLP
// KYA-OS story L1-C: the cross-language JWS fixture set (stories rule 6).
// Regenerates fixtures/kya-os-helix/jws.json from source and fails on drift,
// then verifies every vector and rejection against the checked-in file.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  EnvSigner,
  InvalidJWSError,
  publicKeyHexToJwk,
  signJws,
  verifyJws,
  verifyJwsByKid,
  type DidResolver,
  type Ed25519PublicJwk,
  type JwsPayload,
} from "../../../src/core/index.js";
import {
  buildJwsFixtures,
  serializeJwsFixtures,
  type JwsFixtures,
} from "../../../scripts/generate-jws-fixtures.js";

const FIXTURE_PATH = fileURLToPath(
  new URL("../../../fixtures/kya-os-helix/jws.json", import.meta.url),
);
const checkedIn = readFileSync(FIXTURE_PATH, "utf8");
const fixtures = JSON.parse(checkedIn) as JwsFixtures;

const resolver: DidResolver = async (did) =>
  Object.values(fixtures.keys).find((key) => key.did === did)?.did_document ??
  null;

function jwkFor(key: "signer" | "other", withKid: boolean): Ed25519PublicJwk {
  const fixture = fixtures.keys[key];
  return publicKeyHexToJwk(
    fixture.public_key_hex,
    withKid ? fixture.kid : undefined,
  );
}

async function reasonOf(
  run: () => Promise<unknown> | unknown,
): Promise<string> {
  try {
    await run();
  } catch (error) {
    if (error instanceof InvalidJWSError) return error.reason;
    throw error;
  }
  throw new Error("expected a refusal");
}

describe("fixtures/kya-os-helix/jws.json", () => {
  it("is exactly what the generator produces from current source (regenerate with pnpm generate:jws-fixtures)", async () => {
    expect(serializeJwsFixtures(await buildJwsFixtures())).toBe(checkedIn);
  });

  it("records the test keys consistently", () => {
    for (const key of Object.values(fixtures.keys)) {
      expect(key.kid).toBe(`${key.did}#${key.kid_fragment}`);
      expect(key.public_key_jwk).toEqual(
        publicKeyHexToJwk(key.public_key_hex, key.kid),
      );
      expect(key.did_document.id).toBe(key.did);
      expect(key.did_document.assertionMethod).toContain(key.kid);
    }
  });

  for (const vector of fixtures.vectors) {
    it(`vector ${vector.name}: re-signing gives the same bytes and it verifies by JWK and by kid`, async () => {
      const key = fixtures.keys[vector.signer];
      const signer = new EnvSigner({
        did: key.did,
        kid: key.kid_fragment,
        envVar: "K",
        env: { K: key.private_key_hex },
      });
      const payload: JwsPayload =
        "json" in vector.payload
          ? (vector.payload.json as JwsPayload)
          : "text" in vector.payload
            ? vector.payload.text
            : new Uint8Array(Buffer.from(vector.payload.bytes_hex, "hex"));
      const signed = await signJws(
        payload,
        signer,
        vector.header_extra ? { header: vector.header_extra } : {},
      );
      expect(signed).toBe(vector.jws);

      const byJwk = verifyJws(vector.jws, jwkFor(vector.signer, true));
      expect(byJwk.header).toEqual(vector.header);
      expect(byJwk.did).toBe(key.did);
      const byKid = await verifyJwsByKid(vector.jws, resolver);
      expect(byKid.payloadBytes).toEqual(byJwk.payloadBytes);
      if ("json" in vector.payload)
        expect(byKid.payload).toEqual(vector.payload.json);
      if ("text" in vector.payload)
        expect(Buffer.from(byKid.payloadBytes).toString("utf8")).toBe(
          vector.payload.text,
        );
      if ("bytes_hex" in vector.payload)
        expect(Buffer.from(byKid.payloadBytes).toString("hex")).toBe(
          vector.payload.bytes_hex,
        );
    });
  }

  for (const rejection of fixtures.rejections) {
    it(`rejection ${rejection.name}: refused for ${rejection.reason}`, async () => {
      const options =
        rejection.expected_did === undefined
          ? {}
          : { expectedDid: rejection.expected_did };
      const jwk = jwkFor(rejection.verify_with.key, rejection.verify_with.kid);
      expect(await reasonOf(() => verifyJws(rejection.jws, jwk, options))).toBe(
        rejection.reason,
      );
      if (rejection.by_kid_reason === null) {
        expect(
          (await verifyJwsByKid(rejection.jws, resolver, options)).did,
        ).toBe(fixtures.keys.signer.did);
      } else {
        expect(
          await reasonOf(() =>
            verifyJwsByKid(rejection.jws, resolver, options),
          ),
        ).toBe(rejection.by_kid_reason ?? rejection.reason);
      }
    });
  }
});
