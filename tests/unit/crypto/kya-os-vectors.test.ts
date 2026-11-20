// Copyright 2026 DgVerse LLP
// KYA-OS conformance vectors for Core L1.3 to L1.5 (story L1-C), vendored
// from decentralized-identity/kya-os-mcp at a4d7f61 (suite 1.10.0) under
// fixtures/kya-os/ with the upstream path layout.
//
// signed-proof.json: every vector's JWS is read with verifyJws against the
// vector's publicKeyJwk. The ones the suite refuses at the JWS layer (segment
// reading, alg, kid, key, signature) must be refused here; the rest are valid
// JWS that the suite refuses for reasons above this story (timestamp, meta
// and hash binding, delegation chain), which L2-A takes up.
//
// signed-proof-key-relationship.json: verifyJwsByKid with the vector's
// didDocuments as the resolver.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  InvalidJWSError,
  JwsReasons,
  verifyJws,
  verifyJwsByKid,
  type Ed25519PublicJwk,
  type JwsDidDocument,
} from "../../../src/core/index.js";

const VENDORED = fileURLToPath(
  new URL("../../../fixtures/kya-os/", import.meta.url),
);

interface Vector<I> {
  id: string;
  expected: "pass" | "fail";
  reason: string;
  input: I;
}

interface VectorFile<I> {
  version: string;
  category: string;
  vectors: Vector<I>[];
}

interface SignedProofInput {
  proof: { jws: string; meta: { did: string; kid: string } };
  publicKeyJwk: Ed25519PublicJwk;
}

interface KeyRelationshipInput {
  proof: { jws: string; meta: { did: string; kid: string } };
  didDocuments: Record<string, JwsDidDocument>;
  keyId?: string;
}

function load<I>(name: string): VectorFile<I> {
  return JSON.parse(
    readFileSync(`${VENDORED}conformance/vectors/${name}`, "utf8"),
  ) as VectorFile<I>;
}

function refusal(run: () => unknown): string | undefined {
  try {
    run();
    return undefined;
  } catch (error) {
    if (error instanceof InvalidJWSError) return error.reason;
    throw error;
  }
}

async function refusalAsync(
  promise: Promise<unknown>,
): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    if (error instanceof InvalidJWSError) return error.reason;
    throw error;
  }
}

/** Fail vectors whose refusal is the JWS layer's (L1.3 to L1.5), with the reason verifyJws gives. */
const JWS_LAYER_REFUSALS: Record<string, string> = {
  "signed-proof/tampered-signature": JwsReasons.SIGNATURE_INVALID,
  // The unrelated key's JWK carries its own kid, so the kid check refuses it before the signature does.
  "signed-proof/wrong-key": JwsReasons.KID_MISMATCH,
  "signed-proof/delegation-proof-signature-stray-character":
    JwsReasons.MALFORMED,
  "signed-proof/delegation-proof-signature-stray-characters":
    JwsReasons.MALFORMED,
  "signed-proof/delegation-proof-signature-base64": JwsReasons.MALFORMED,
  "signed-proof/delegation-proof-signature-white-space": JwsReasons.MALFORMED,
  "signed-proof/delegation-proof-signature-padded": JwsReasons.MALFORMED,
  "signed-proof/delegation-proof-fourth-segment": JwsReasons.MALFORMED,
  "signed-proof/delegation-proof-header-non-ascii": JwsReasons.MALFORMED,
  "signed-proof/delegation-proof-header-algorithm": JwsReasons.ALG_UNSUPPORTED,
  "signed-proof/delegation-proof-header-key": JwsReasons.KID_MISMATCH,
  "signed-proof/delegation-proof-signer-of-another-did":
    JwsReasons.KID_DID_MISMATCH,
};

describe("vendored suite", () => {
  it("matches the pinned SUITE-MANIFEST hashes for the files this story vendors", () => {
    const manifest = JSON.parse(
      readFileSync(`${VENDORED}conformance/SUITE-MANIFEST.json`, "utf8"),
    ) as {
      suiteVersion: string;
      files: [string, string][];
    };
    expect(manifest.suiteVersion).toBe("1.10.0");
    for (const name of [
      "signed-proof.json",
      "signed-proof-key-relationship.json",
    ]) {
      const pinned = manifest.files.find(([file]) => file === name)?.[1];
      const actual = createHash("sha256")
        .update(readFileSync(`${VENDORED}conformance/vectors/${name}`))
        .digest("hex");
      expect(actual, name).toBe(pinned);
    }
  });
});

describe("signed-proof vectors through verifyJws (L1.3 to L1.5)", () => {
  const file = load<SignedProofInput>("signed-proof.json");

  it("is the 1.10.0 signed-proof category", () => {
    expect(file.version).toBe("1.10.0");
    expect(file.category).toBe("signed-proof");
    for (const id of Object.keys(JWS_LAYER_REFUSALS)) {
      expect(
        file.vectors.map((v) => v.id),
        id,
      ).toContain(id);
    }
  });

  for (const vector of file.vectors) {
    const { jws, meta } = vector.input.proof;
    const jwk = vector.input.publicKeyJwk;
    const jwsLayer = JWS_LAYER_REFUSALS[vector.id];

    if (vector.expected === "pass") {
      it(`${vector.id} (pass): verifies against publicKeyJwk, kid names meta.did`, () => {
        const result = verifyJws(jws, jwk, {
          expectedKid: meta.kid,
          expectedDid: meta.did,
        });
        expect(result.header.alg).toBe("EdDSA");
        expect(result.kid).toBe(meta.kid);
        expect(result.did).toBe(meta.did);
        expect((result.payload as { iss: string }).iss).toBe(meta.did);
      });
    } else if (jwsLayer !== undefined) {
      it(`${vector.id} (fail at the JWS layer): refused for ${jwsLayer}`, () => {
        expect(
          refusal(() =>
            verifyJws(jws, jwk, {
              expectedKid: meta.kid,
              expectedDid: meta.did,
            }),
          ),
        ).toBe(jwsLayer);
      });
    } else {
      it(`${vector.id} (fail above the JWS layer): the JWS itself verifies; the suite's reason is for the L2 proof verifier`, () => {
        expect(
          refusal(() =>
            verifyJws(jws, jwk, {
              expectedKid: meta.kid,
              expectedDid: meta.did,
            }),
          ),
        ).toBeUndefined();
      });
    }
  }
});

describe("signed-proof-key-relationship vectors through verifyJwsByKid", () => {
  const file = load<KeyRelationshipInput>("signed-proof-key-relationship.json");

  it("is the 1.10.0 key-relationship file", () => {
    expect(file.version).toBe("1.10.0");
    expect(file.vectors).toHaveLength(10);
  });

  for (const vector of file.vectors) {
    const { jws, meta } = vector.input.proof;
    const resolver = async (did: string): Promise<JwsDidDocument | null> =>
      vector.input.didDocuments[did] ?? null;

    if (vector.input.keyId === undefined) {
      // The suite's two no-kid vectors ask what a verifier does when the proof
      // names no key and it must pick the first assertion entry. Under L1-C a
      // JWS without kid is refused outright, so the only question left is the
      // header's own kid, which names #assert in both: a defined, listed,
      // self-controlled key, so both verify.
      it(`${vector.id} (no keyId; kid is mandatory here, so the header kid selects the key): verifies`, async () => {
        const result = await verifyJwsByKid(jws, resolver, {
          expectedDid: meta.did,
        });
        expect(result.kid).toBe(meta.kid);
      });
      continue;
    }

    if (vector.expected === "pass") {
      it(`${vector.id} (pass): ${vector.reason}`, async () => {
        const result = await verifyJwsByKid(jws, resolver, {
          expectedKid: vector.input.keyId,
          expectedDid: meta.did,
        });
        expect(result.did).toBe(meta.did);
      });
    } else {
      it(`${vector.id} (fail): ${vector.reason}`, async () => {
        expect(
          await refusalAsync(
            verifyJwsByKid(jws, resolver, {
              expectedKid: vector.input.keyId,
              expectedDid: meta.did,
            }),
          ),
        ).toBeDefined();
      });
    }
  }
});
