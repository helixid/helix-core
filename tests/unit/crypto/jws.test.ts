// Copyright 2026 DgVerse LLP
// KYA-OS story L1-C: EdDSA compact JWS sign and verify (Core L1.3 to L1.5).

import * as ed25519 from "@noble/ed25519";
import { describe, expect, it } from "vitest";
import {
  EnvSigner,
  InvalidJWSError,
  JwsReasons,
  base64UrlDecodeStrict,
  base64UrlEncode,
  buildDIDDocument,
  derivePublicKey,
  generateKeyPair,
  publicKeyHexToJwk,
  publicKeyToMultibase,
  readJwsHeader,
  selectAssertionMethod,
  signJws,
  verificationMethodToJwk,
  verifyJws,
  verifyJwsByKid,
  type DidResolver,
  type JwsDidDocument,
  type JwsVerificationMethod,
  type Signer,
} from "../../../src/core/index.js";
import { base58btcEncode } from "../../../src/core/crypto/vp.js";

const DID = "did:web:agent.helix.test";
const keys = generateKeyPair();
const otherKeys = generateKeyPair();
const env = { TEST_SIGNING_KEY: keys.privateKey };
const signer = new EnvSigner({ did: DID, envVar: "TEST_SIGNING_KEY", env });
const jwk = publicKeyHexToJwk(keys.publicKey);
const document = buildDIDDocument(DID, keys.publicKey);
const resolver: DidResolver = async (did) => (did === DID ? document : null);

function refusal(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof InvalidJWSError) return error.reason;
    throw error;
  }
  throw new Error("expected a refusal");
}

async function refusalAsync(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof InvalidJWSError) return error.reason;
    throw error;
  }
  throw new Error("expected a refusal");
}

function decodeSegment(segment: string): string {
  return Buffer.from(segment, "base64url").toString("utf8");
}

function rawJws(
  header: Record<string, unknown>,
  payload: string,
  privateKeyHex: string,
): string {
  const input = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(payload)}`;
  const signature = ed25519.sign(
    Buffer.from(input, "utf8"),
    Buffer.from(privateKeyHex, "hex"),
  );
  return `${input}.${base64UrlEncode(signature)}`;
}

describe("signJws (L1.3, L1.5)", () => {
  it("produces header.payload.signature with alg EdDSA and kid <did>#<fragment>, in that order", async () => {
    const jws = await signJws({ iss: DID, n: 1 }, signer);
    const [h, p, s] = jws.split(".") as [string, string, string];
    expect(decodeSegment(h)).toBe(`{"alg":"EdDSA","kid":"${DID}#key-1"}`);
    expect(decodeSegment(p)).toBe(`{"iss":"${DID}","n":1}`);
    expect(base64UrlDecodeStrict(s)).toHaveLength(64);
    expect(jws).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it("signs strings as UTF-8 and bytes as given", async () => {
    const text = await signJws("plain", signer);
    expect(decodeSegment(text.split(".")[1]!)).toBe("plain");
    const bytes = await signJws(new Uint8Array([0, 255, 16]), signer);
    expect(Buffer.from(bytes.split(".")[1]!, "base64url")).toEqual(
      Buffer.from([0, 255, 16]),
    );
    expect(verifyJws(bytes, jwk).payload).toBeUndefined();
  });

  it("appends extra header members after alg and kid and never lets them override either", async () => {
    const jws = await signJws({ a: 1 }, signer, {
      header: { typ: "JWT", alg: "HS256", kid: "nope" },
    });
    expect(decodeSegment(jws.split(".")[0]!)).toBe(
      `{"alg":"EdDSA","kid":"${DID}#key-1","typ":"JWT"}`,
    );
  });

  it("accepts a signer kid written with a leading #", async () => {
    const hashSigner: Signer = {
      did: DID,
      kid: "#key-1",
      sign: (d) => signer.sign(d),
    };
    expect(readJwsHeader(await signJws({ a: 1 }, hashSigner)).kid).toBe(
      `${DID}#key-1`,
    );
  });

  it("refuses a signer without a DID or with a malformed fragment", async () => {
    const noDid: Signer = {
      did: "agent",
      kid: "key-1",
      sign: (d) => signer.sign(d),
    };
    expect(await refusalAsync(signJws({}, noDid))).toBe(
      JwsReasons.KID_MALFORMED,
    );
    const badKid: Signer = {
      did: DID,
      kid: "a#b",
      sign: (d) => signer.sign(d),
    };
    expect(await refusalAsync(signJws({}, badKid))).toBe(
      JwsReasons.KID_MALFORMED,
    );
    const empty: Signer = { did: DID, kid: "#", sign: (d) => signer.sign(d) };
    expect(await refusalAsync(signJws({}, empty))).toBe(
      JwsReasons.KID_MALFORMED,
    );
  });

  it("refuses a signer that returns something other than a 64-byte signature", async () => {
    const short: Signer = {
      did: DID,
      kid: "key-1",
      sign: async () => new Uint8Array(10),
    };
    expect(await refusalAsync(signJws({}, short))).toBe(
      JwsReasons.SIGNATURE_INVALID,
    );
    const notBytes = {
      did: DID,
      kid: "key-1",
      sign: async () => "sig",
    } as unknown as Signer;
    expect(await refusalAsync(signJws({}, notBytes))).toBe(
      JwsReasons.SIGNATURE_INVALID,
    );
  });

  it("self-custody invariant: core only ever hands bytes to the Signer; the key never appears anywhere", async () => {
    const seen: Uint8Array[] = [];
    const spy: Signer = {
      did: DID,
      kid: "key-1",
      sign: async (data) => {
        seen.push(data);
        return signer.sign(data);
      },
    };
    const jws = await signJws({ iss: DID }, spy);
    expect(seen).toHaveLength(1);
    expect(Buffer.from(seen[0]!).toString("utf8")).toBe(
      jws.split(".").slice(0, 2).join("."),
    );
    const leaks = [
      keys.privateKey,
      base64UrlEncode(Buffer.from(keys.privateKey, "hex")),
    ];
    for (const leak of leaks) {
      expect(jws).not.toContain(leak);
      expect(JSON.stringify(signer)).not.toContain(leak);
      expect(JSON.stringify(spy)).not.toContain(leak);
    }
    expect(Object.keys(signer)).toEqual(["did", "kid"]);
  });
});

describe("verifyJws (L1.4)", () => {
  it("verifies a JWS signed through the Signer against the public JWK and returns the parsed payload", async () => {
    const jws = await signJws({ iss: DID, sub: "x" }, signer);
    const result = verifyJws(jws, jwk);
    expect(result).toMatchObject({
      kid: `${DID}#key-1`,
      did: DID,
      payload: { iss: DID, sub: "x" },
    });
    expect(result.header).toEqual({ alg: "EdDSA", kid: `${DID}#key-1` });
    expect(Buffer.from(result.payloadBytes).toString("utf8")).toBe(
      `{"iss":"${DID}","sub":"x"}`,
    );
  });

  it("accepts a JWK that carries the matching kid and refuses one that carries another", async () => {
    const jws = await signJws({}, signer);
    expect(
      verifyJws(jws, publicKeyHexToJwk(keys.publicKey, `${DID}#key-1`)).did,
    ).toBe(DID);
    expect(
      refusal(() =>
        verifyJws(jws, publicKeyHexToJwk(keys.publicKey, `${DID}#key-2`)),
      ),
    ).toBe(JwsReasons.KID_MISMATCH);
    expect(
      refusal(() => verifyJws(jws, jwk, { expectedKid: `${DID}#key-2` })),
    ).toBe(JwsReasons.KID_MISMATCH);
    expect(verifyJws(jws, jwk, { expectedKid: `${DID}#key-1` }).kid).toBe(
      `${DID}#key-1`,
    );
  });

  it("refuses any alg but EdDSA", () => {
    for (const alg of ["HS256", "RS256", "ES256", "none", "eddsa", undefined]) {
      const header =
        alg === undefined
          ? { kid: `${DID}#key-1` }
          : { alg, kid: `${DID}#key-1` };
      expect(
        refusal(() => verifyJws(rawJws(header, "{}", keys.privateKey), jwk)),
      ).toBe(JwsReasons.ALG_UNSUPPORTED);
    }
  });

  it("refuses a missing, null, non-string or malformed kid", () => {
    expect(
      refusal(() =>
        verifyJws(rawJws({ alg: "EdDSA" }, "{}", keys.privateKey), jwk),
      ),
    ).toBe(JwsReasons.KID_MISSING);
    expect(
      refusal(() =>
        verifyJws(
          rawJws({ alg: "EdDSA", kid: null }, "{}", keys.privateKey),
          jwk,
        ),
      ),
    ).toBe(JwsReasons.KID_MISSING);
    expect(
      refusal(() =>
        verifyJws(rawJws({ alg: "EdDSA", kid: 7 }, "{}", keys.privateKey), jwk),
      ),
    ).toBe(JwsReasons.KID_MALFORMED);
    for (const kid of [
      "key-1",
      "#key-1",
      DID,
      `${DID}#`,
      "did:#x",
      "http://x#y",
    ]) {
      expect(
        refusal(() =>
          verifyJws(rawJws({ alg: "EdDSA", kid }, "{}", keys.privateKey), jwk),
        ),
        kid,
      ).toBe(JwsReasons.KID_MALFORMED);
    }
  });

  it("refuses a kid whose DID differs from the claimed signer: the iss claim or expectedDid", async () => {
    const otherKid = rawJws(
      { alg: "EdDSA", kid: "did:web:other.test#key-1" },
      JSON.stringify({ iss: DID }),
      keys.privateKey,
    );
    expect(refusal(() => verifyJws(otherKid, jwk))).toBe(
      JwsReasons.KID_DID_MISMATCH,
    );
    const jws = await signJws({ sub: "no iss claim" }, signer);
    expect(
      refusal(() => verifyJws(jws, jwk, { expectedDid: "did:web:other.test" })),
    ).toBe(JwsReasons.KID_DID_MISMATCH);
    expect(verifyJws(jws, jwk, { expectedDid: DID }).did).toBe(DID);
    const issNotString = await signJws({ iss: 5 }, signer);
    expect(verifyJws(issNotString, jwk).payload).toEqual({ iss: 5 });
    expect(verifyJws(await signJws(["iss"], signer), jwk).payload).toEqual([
      "iss",
    ]);
  });

  it("refuses a bad signature, a tampered payload and the wrong key", async () => {
    const jws = await signJws({ iss: DID }, signer);
    const [h, p, s] = jws.split(".") as [string, string, string];
    expect(
      refusal(() => verifyJws(jws, publicKeyHexToJwk(otherKeys.publicKey))),
    ).toBe(JwsReasons.SIGNATURE_INVALID);
    expect(
      refusal(() =>
        verifyJws(
          `${h}.${base64UrlEncode(`{"iss":"${DID}","sub":"tampered"}`)}.${s}`,
          jwk,
        ),
      ),
    ).toBe(JwsReasons.SIGNATURE_INVALID);
    const flipped = `${s.startsWith("A") ? "B" : "A"}${s.slice(1)}`;
    expect(refusal(() => verifyJws(`${h}.${p}.${flipped}`, jwk))).toBe(
      JwsReasons.SIGNATURE_INVALID,
    );
    expect(
      refusal(() =>
        verifyJws(`${h}.${p}.${base64UrlEncode(new Uint8Array(10))}`, jwk),
      ),
    ).toBe(JwsReasons.SIGNATURE_INVALID);
    // 64 bytes that are not a canonical signature make noble throw; that is a refusal, not a crash.
    expect(
      refusal(() =>
        verifyJws(
          `${h}.${p}.${base64UrlEncode(new Uint8Array(64).fill(255))}`,
          jwk,
        ),
      ),
    ).toBe(JwsReasons.SIGNATURE_INVALID);
  });

  it("reads segments strictly: three non-empty base64url segments, nothing looser", async () => {
    const jws = await signJws({ iss: DID }, signer);
    const [h, p, s] = jws.split(".") as [string, string, string];
    const malformed = [
      `${h}.${p}`,
      `${h}.${p}.${s}.${s}`,
      `.${p}.${s}`,
      `${h}..${s}`,
      `${h}.${p}.`,
      `${h}.${p}.${s}=`,
      `${h}.${p}.${s}==`,
      `${h}.${p}. ${s}`,
      `${h}.${p}.${s}\n`,
      `${h}.${p}.${s.replace(/[A-Za-z0-9_-]$/, "+")}`,
      `${h}.${p}.${s}é`,
      `${h}.${p}.${s}A`.slice(
        0,
        h.length + p.length + 2 + (s.length - (s.length % 4)) + 1,
      ),
    ];
    for (const value of malformed) {
      expect(
        refusal(() => verifyJws(value, jwk)),
        JSON.stringify(value),
      ).toBe(JwsReasons.MALFORMED);
    }
    expect(refusal(() => verifyJws(42 as unknown as string, jwk))).toBe(
      JwsReasons.MALFORMED,
    );
    expect(
      refusal(() => verifyJws(`${base64UrlEncode("nope")}.${p}.${s}`, jwk)),
    ).toBe(JwsReasons.HEADER_INVALID);
    expect(
      refusal(() => verifyJws(`${base64UrlEncode("[1]")}.${p}.${s}`, jwk)),
    ).toBe(JwsReasons.HEADER_INVALID);
    expect(
      refusal(() => verifyJws(`${base64UrlEncode("null")}.${p}.${s}`, jwk)),
    ).toBe(JwsReasons.HEADER_INVALID);
  });

  it("refuses a key that is not a strict Ed25519 public JWK", async () => {
    const jws = await signJws({}, signer);
    const bad = [
      null,
      "key",
      { kty: "EC", crv: "P-256", x: jwk.x },
      { kty: "OKP", crv: "X25519", x: jwk.x },
      { kty: "OKP", crv: "Ed25519" },
      { kty: "OKP", crv: "Ed25519", x: `${jwk.x}=` },
      { kty: "OKP", crv: "Ed25519", x: jwk.x.slice(0, 10) },
      { kty: "OKP", crv: "Ed25519", x: jwk.x, kid: 5 },
    ];
    for (const candidate of bad) {
      expect(
        refusal(() => verifyJws(jws, candidate as never)),
        JSON.stringify(candidate),
      ).toBe(JwsReasons.JWK_INVALID);
    }
  });

  it("exposes the reason on the error object and as details", async () => {
    const jws = await signJws({}, signer);
    try {
      verifyJws(jws, publicKeyHexToJwk(otherKeys.publicKey));
      throw new Error("unreachable");
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidJWSError);
      const refused = error as InvalidJWSError;
      expect(refused.code).toBe("JWS_INVALID");
      expect(refused.name).toBe("InvalidJWSError");
      expect(refused.details).toEqual({ reason: JwsReasons.SIGNATURE_INVALID });
      expect(new InvalidJWSError("x").message).toBe("JWS is invalid");
    }
  });
});

describe("verifyJwsByKid", () => {
  it("resolves the kid DID, picks the assertion method and verifies", async () => {
    const jws = await signJws({ iss: DID, sub: "x" }, signer);
    const result = await verifyJwsByKid(jws, resolver);
    expect(result.payload).toEqual({ iss: DID, sub: "x" });
    expect(result.did).toBe(DID);
  });

  it("never touches storage: only the injected resolver is called, once, with the kid DID", async () => {
    const calls: string[] = [];
    const jws = await signJws({ iss: DID }, signer);
    await verifyJwsByKid(jws, async (did) => {
      calls.push(did);
      return document;
    });
    expect(calls).toEqual([DID]);
  });

  it("refuses before resolving when the kid DID is not the expected signer", async () => {
    let resolved = false;
    const jws = await signJws({}, signer);
    const reason = await refusalAsync(
      verifyJwsByKid(
        jws,
        async () => {
          resolved = true;
          return document;
        },
        { expectedDid: "did:web:other.test" },
      ),
    );
    expect(reason).toBe(JwsReasons.KID_DID_MISMATCH);
    expect(resolved).toBe(false);
  });

  it("refuses a malformed JWS without resolving", async () => {
    expect(await refusalAsync(verifyJwsByKid("a.b", resolver))).toBe(
      JwsReasons.MALFORMED,
    );
    const noKid = rawJws({ alg: "EdDSA" }, "{}", keys.privateKey);
    expect(await refusalAsync(verifyJwsByKid(noKid, resolver))).toBe(
      JwsReasons.KID_MISSING,
    );
  });

  it("refuses when the DID does not resolve, or resolves to another document", async () => {
    const jws = await signJws({}, signer);
    expect(await refusalAsync(verifyJwsByKid(jws, async () => null))).toBe(
      JwsReasons.DID_UNRESOLVED,
    );
    expect(await refusalAsync(verifyJwsByKid(jws, async () => undefined))).toBe(
      JwsReasons.DID_UNRESOLVED,
    );
    const foreign = buildDIDDocument("did:web:other.test", keys.publicKey);
    expect(await refusalAsync(verifyJwsByKid(jws, async () => foreign))).toBe(
      JwsReasons.DID_DOCUMENT_MISMATCH,
    );
    expect(
      await refusalAsync(verifyJwsByKid(jws, async () => "doc" as never)),
    ).toBe(JwsReasons.DID_DOCUMENT_MISMATCH);
  });

  it("refuses a key the document does not define, lists only for authentication, defines twice, or another DID controls", async () => {
    const jws = await signJws({}, signer);
    const method = document.verificationMethod[0]!;
    const cases: { name: string; doc: JwsDidDocument; reason: string }[] = [
      {
        name: "not defined",
        doc: { id: DID, verificationMethod: [], assertionMethod: [method.id] },
        reason: JwsReasons.KEY_NOT_FOUND,
      },
      {
        name: "no arrays at all",
        doc: { id: DID },
        reason: JwsReasons.KEY_NOT_FOUND,
      },
      {
        name: "arrays not arrays",
        doc: {
          id: DID,
          verificationMethod: "x" as never,
          assertionMethod: "y" as never,
        },
        reason: JwsReasons.KEY_NOT_FOUND,
      },
      {
        name: "authentication only",
        doc: {
          id: DID,
          verificationMethod: [method],
          authentication: [method.id],
        },
        reason: JwsReasons.KEY_NOT_ASSERTION,
      },
      {
        name: "unlisted",
        doc: { id: DID, verificationMethod: [method], assertionMethod: [] },
        reason: JwsReasons.KEY_NOT_ASSERTION,
      },
      {
        name: "duplicate",
        doc: {
          id: DID,
          verificationMethod: [method],
          assertionMethod: [method],
        },
        reason: JwsReasons.KEY_AMBIGUOUS,
      },
      {
        name: "defined twice",
        doc: {
          id: DID,
          verificationMethod: [method, method],
          assertionMethod: [method.id],
        },
        reason: JwsReasons.KEY_AMBIGUOUS,
      },
      {
        name: "foreign controller",
        doc: {
          id: DID,
          verificationMethod: [{ ...method, controller: "did:web:other.test" }],
          assertionMethod: [method.id],
        },
        reason: JwsReasons.KEY_FOREIGN_CONTROLLER,
      },
      {
        name: "no key material",
        doc: {
          id: DID,
          verificationMethod: [
            {
              id: method.id,
              type: "Ed25519VerificationKey2020",
              controller: DID,
            },
          ],
          assertionMethod: [method.id],
        },
        reason: JwsReasons.KEY_UNSUPPORTED,
      },
      {
        name: "wrong key",
        doc: buildDIDDocument(DID, otherKeys.publicKey),
        reason: JwsReasons.SIGNATURE_INVALID,
      },
    ];
    for (const c of cases) {
      expect(
        await refusalAsync(verifyJwsByKid(jws, async () => c.doc)),
        c.name,
      ).toBe(c.reason);
    }
  });

  it("accepts relative ids, embedded assertion methods, and a null entry among the methods", async () => {
    const jws = await signJws({}, signer);
    const method = document.verificationMethod[0]!;
    const relative: JwsDidDocument = {
      id: DID,
      verificationMethod: [null as never, { ...method, id: "#key-1" }],
      assertionMethod: ["#key-1"],
    };
    expect((await verifyJwsByKid(jws, async () => relative)).did).toBe(DID);
    const embedded: JwsDidDocument = {
      id: DID,
      assertionMethod: [null as never, "did:web:x#y", method],
    };
    expect((await verifyJwsByKid(jws, async () => embedded)).did).toBe(DID);
  });
});

describe("verification method key forms", () => {
  const method = (
    extra: Partial<JwsVerificationMethod>,
  ): JwsVerificationMethod => ({
    id: `${DID}#key-1`,
    type: "Ed25519VerificationKey2020",
    controller: DID,
    ...extra,
  });

  it("reads publicKeyJwk, publicKeyMultibase and publicKeyBase58", () => {
    const expected = {
      kty: "OKP",
      crv: "Ed25519",
      x: jwk.x,
      kid: `${DID}#key-1`,
    };
    expect(
      verificationMethodToJwk(
        method({ publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: jwk.x } }),
      ),
    ).toEqual(expected);
    expect(
      verificationMethodToJwk(
        method({ publicKeyMultibase: publicKeyToMultibase(keys.publicKey) }),
      ),
    ).toEqual(expected);
    expect(
      verificationMethodToJwk(
        method({
          publicKeyBase58: base58btcEncode(Buffer.from(keys.publicKey, "hex")),
        }),
      ),
    ).toEqual(expected);
  });

  it("refuses an invalid JWK, an undecodable multibase or base58 value, and a method without key material", () => {
    expect(
      refusal(() =>
        verificationMethodToJwk(
          method({ publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "bad=" } }),
        ),
      ),
    ).toBe(JwsReasons.JWK_INVALID);
    expect(
      refusal(() =>
        verificationMethodToJwk(method({ publicKeyMultibase: "f00" })),
      ),
    ).toBe(JwsReasons.KEY_UNSUPPORTED);
    expect(
      refusal(() =>
        verificationMethodToJwk(method({ publicKeyBase58: "0OIl" })),
      ),
    ).toBe(JwsReasons.KEY_UNSUPPORTED);
    expect(refusal(() => verificationMethodToJwk(method({})))).toBe(
      JwsReasons.KEY_UNSUPPORTED,
    );
  });

  it("selectAssertionMethod is exported for callers that resolve documents themselves", () => {
    expect(selectAssertionMethod(document, DID, `${DID}#key-1`)).toBe(
      document.verificationMethod[0],
    );
  });
});

describe("base64url helpers and header reading", () => {
  it("encodes without padding and decodes only the strict form", () => {
    expect(base64UrlEncode("hi")).toBe("aGk");
    expect(base64UrlEncode(new Uint8Array([250, 251, 252]))).toBe("-vv8");
    expect(Buffer.from(base64UrlDecodeStrict("aGk")!).toString()).toBe("hi");
    expect(base64UrlDecodeStrict("")).toEqual(new Uint8Array(0));
    for (const bad of ["aGk=", "a", "aGk ", "a+b/", "ü", "aGkaa"]) {
      expect(base64UrlDecodeStrict(bad), bad).toBeUndefined();
    }
  });

  it("readJwsHeader returns the header without verifying", async () => {
    const jws = await signJws({}, signer, { header: { typ: "JWT" } });
    expect(readJwsHeader(jws)).toEqual({
      alg: "EdDSA",
      kid: `${DID}#key-1`,
      typ: "JWT",
    });
  });

  it("publicKeyHexToJwk round-trips the key", () => {
    expect(Buffer.from(base64UrlDecodeStrict(jwk.x)!).toString("hex")).toBe(
      keys.publicKey,
    );
    expect(publicKeyHexToJwk(keys.publicKey, "k")).toEqual({
      kty: "OKP",
      crv: "Ed25519",
      x: jwk.x,
      kid: "k",
    });
  });
});

describe("EnvSigner", () => {
  it("reads the key from the environment at sign time and derives the public key", async () => {
    const dynamic: Record<string, string | undefined> = {};
    const lazy = new EnvSigner({
      did: DID,
      kid: "#key-9",
      envVar: "LATER",
      env: dynamic,
    });
    expect(lazy.kid).toBe("key-9");
    expect(lazy.verificationMethodId).toBe(`${DID}#key-9`);
    await expect(lazy.sign(new Uint8Array(1))).rejects.toThrow(
      "LATER is not set",
    );
    dynamic["LATER"] = "  ";
    await expect(lazy.sign(new Uint8Array(1))).rejects.toThrow(
      "LATER is not set",
    );
    dynamic["LATER"] = keys.privateKey;
    expect(lazy.publicKeyHex()).toBe(derivePublicKey(keys.privateKey));
    const jws = await signJws({ iss: DID }, lazy);
    expect(verifyJws(jws, jwk).kid).toBe(`${DID}#key-9`);
    dynamic["LATER"] = "not-a-key";
    await expect(lazy.sign(new Uint8Array(1))).rejects.toThrow(
      "Ed25519 private key",
    );
  });

  it("defaults to HELIX_SIGNING_KEY in process.env and kid key-1", async () => {
    const previous = process.env["HELIX_SIGNING_KEY"];
    process.env["HELIX_SIGNING_KEY"] = keys.privateKey;
    try {
      const fromProcess = new EnvSigner({ did: DID });
      expect(fromProcess.kid).toBe("key-1");
      expect(verifyJws(await signJws({}, fromProcess), jwk).did).toBe(DID);
    } finally {
      if (previous === undefined) delete process.env["HELIX_SIGNING_KEY"];
      else process.env["HELIX_SIGNING_KEY"] = previous;
    }
  });

  it("accepts a PKCS8 DER seed as HELIX_SIGNING_KEY already does", async () => {
    const der = new EnvSigner({
      did: DID,
      envVar: "K",
      env: { K: `302e020100300506032b657004220420${keys.privateKey}` },
    });
    expect(verifyJws(await signJws({}, der), jwk).did).toBe(DID);
  });

  it("refuses a non-DID or a malformed kid at construction", () => {
    expect(() => new EnvSigner({ did: "agent", env })).toThrow("must be a DID");
    expect(() => new EnvSigner({ did: DID, kid: "a#b", env })).toThrow(
      "fragment",
    );
    expect(() => new EnvSigner({ did: DID, kid: "#", env })).toThrow(
      "fragment",
    );
  });
});
