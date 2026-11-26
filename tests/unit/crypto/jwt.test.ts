// Copyright 2026 DgVerse LLP
// KYA-OS story L1-C: the session JWT is issued through signJws and carries kid.

import { describe, expect, it } from "vitest";
import {
  EnvSigner,
  InvalidJWTError,
  JWTExpiredError,
  base64UrlEncode,
  buildDIDDocument,
  decodeJWTUnsafe,
  generateKeyPair,
  issueJWT,
  readJwsHeader,
  verifyJWT,
  verifyJwsByKid,
  type HelixJWTPayload,
} from "../../../src/core/index.js";

const ISSUER = "did:hedera:testnet:helixissuer";
const keys = generateKeyPair();
const signer = new EnvSigner({
  did: ISSUER,
  envVar: "HELIX_SIGNING_KEY",
  env: { HELIX_SIGNING_KEY: keys.privateKey },
});
const now = Math.floor(Date.now() / 1000);

function claims(overrides: Partial<HelixJWTPayload> = {}): HelixJWTPayload {
  return {
    iss: ISSUER,
    sub: "did:web:agent.test",
    iat: now,
    exp: now + 600,
    jti: "jwt:1",
    userDid: "did:web:user.test",
    targetService: "did:web:service.test",
    scopes: ["read:orders"],
    vpId: "vp:1",
    ...overrides,
  };
}

describe("issueJWT", () => {
  it("signs through the Signer and carries alg, kid, typ and crv in the header", async () => {
    const token = await issueJWT(claims(), signer);
    expect(readJwsHeader(token)).toEqual({
      alg: "EdDSA",
      kid: `${ISSUER}#key-1`,
      typ: "JWT",
      crv: "Ed25519",
    });
    expect(verifyJWT(token, keys.publicKey)).toEqual(claims());
  });

  it("verifies through verifyJwsByKid with the issuer DID document", async () => {
    const token = await issueJWT(claims(), signer);
    const document = buildDIDDocument(ISSUER, keys.publicKey);
    const result = await verifyJwsByKid(token, async (did) =>
      did === ISSUER ? document : null,
    );
    expect(result.kid).toBe(`${ISSUER}#key-1`);
    expect(result.payload).toEqual(claims());
  });

  it("validates the claims before signing", async () => {
    await expect(issueJWT({ ...claims(), exp: -1 }, signer)).rejects.toThrow();
  });
});

describe("verifyJWT", () => {
  it("refuses a token without kid (issued before L1-C), a wrong key, a tampered payload and a foreign alg", async () => {
    const token = await issueJWT(claims(), signer);
    const [h, p, s] = token.split(".") as [string, string, string];
    const legacyHeader = base64UrlEncode(
      JSON.stringify({ alg: "EdDSA", typ: "JWT", crv: "Ed25519" }),
    );
    expect(() =>
      verifyJWT(`${legacyHeader}.${p}.${s}`, keys.publicKey),
    ).toThrow(InvalidJWTError);
    expect(() => verifyJWT(token, generateKeyPair().publicKey)).toThrow(
      "JWT is invalid: JWS signature does not verify",
    );
    expect(() =>
      verifyJWT(
        `${h}.${base64UrlEncode(JSON.stringify(claims({ scopes: ["admin"] })))}.${s}`,
        keys.publicKey,
      ),
    ).toThrow(InvalidJWTError);
    const hs256 = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    expect(() => verifyJWT(`${hs256}.${p}.${s}`, keys.publicKey)).toThrow(
      "JWT header is not supported",
    );
    const notJwt = base64UrlEncode(
      JSON.stringify({ alg: "EdDSA", kid: `${ISSUER}#key-1` }),
    );
    expect(() => verifyJWT(`${notJwt}.${p}.${s}`, keys.publicKey)).toThrow(
      "JWT header is not supported",
    );
  });

  it("refuses malformed tokens with InvalidJWTError", () => {
    expect(() => verifyJWT("a.b", keys.publicKey)).toThrow(
      "JWT must contain header, payload, and signature",
    );
    expect(() =>
      verifyJWT(`${base64UrlEncode("x")}.b.c`, keys.publicKey),
    ).toThrow("JWT header is invalid JSON");
    expect(() =>
      decodeJWTUnsafe(`a.${base64UrlEncode('{"iss":1}')}.c`),
    ).toThrow("JWT payload has invalid Helix claims");
  });

  it("refuses an expired token", async () => {
    const token = await issueJWT(
      claims({ iat: now - 1200, exp: now - 600 }),
      signer,
    );
    expect(() => verifyJWT(token, keys.publicKey)).toThrow(JWTExpiredError);
    expect(decodeJWTUnsafe(token).exp).toBe(now - 600);
  });
});
