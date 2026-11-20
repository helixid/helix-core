import { HelixJWTPayloadSchema, type HelixJWTPayload } from "../schemas/jwt.js";
import {
  InvalidJWSError,
  InvalidJWTError,
  JWTExpiredError,
} from "../errors/HelixError.js";
import { publicKeyHexToJwk, signJws, verifyJws } from "./jws.js";
import type { Signer } from "./signer.js";

/**
 * Session JWT (returned by POST /v1/vp/verify with session: true, checked by
 * SDKs against GET /v1/sessions/public-key). Since KYA-OS story L1-C it is a
 * plain EdDSA compact JWS from `signJws`, so the protected header carries
 * `kid` (`<issuer did>#<fragment>`) and verifies through `verifyJwsByKid` as
 * well as through this module. `typ` and `crv` stay in the header for the
 * SDK verifiers that already check them.
 */
const JWT_EXTRA_HEADER = { typ: "JWT", crv: "Ed25519" } as const;

function parseJsonPart(part: string, label: string): unknown {
  try {
    return JSON.parse(
      Buffer.from(part, "base64url").toString("utf8"),
    ) as unknown;
  } catch {
    throw new InvalidJWTError(`JWT ${label} is invalid JSON`);
  }
}

function splitToken(token: string): [string, string, string] {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new InvalidJWTError(
      "JWT must contain header, payload, and signature",
    );
  }
  return parts as [string, string, string];
}

export async function issueJWT(
  payload: HelixJWTPayload,
  signer: Signer,
): Promise<string> {
  const parsed = HelixJWTPayloadSchema.parse(payload);
  return signJws(parsed, signer, { header: JWT_EXTRA_HEADER });
}

export function decodeJWTUnsafe(token: string): HelixJWTPayload {
  const [, payloadPart] = splitToken(token);
  const parsed = HelixJWTPayloadSchema.safeParse(
    parseJsonPart(payloadPart, "payload"),
  );
  if (!parsed.success) {
    throw new InvalidJWTError("JWT payload has invalid Helix claims");
  }
  return parsed.data;
}

export function verifyJWT(
  token: string,
  publicKeyHex: string,
): HelixJWTPayload {
  const [headerPart] = splitToken(token);
  const header = parseJsonPart(headerPart, "header") as Record<string, unknown>;
  if (header["alg"] !== "EdDSA" || header["typ"] !== "JWT") {
    throw new InvalidJWTError("JWT header is not supported");
  }

  try {
    verifyJws(token, publicKeyHexToJwk(publicKeyHex));
  } catch (error) {
    /* v8 ignore next */
    if (!(error instanceof InvalidJWSError)) throw error;
    throw new InvalidJWTError(`JWT is invalid: ${error.message}`);
  }

  const payload = decodeJWTUnsafe(token);
  if (payload.exp <= Math.floor(Date.now() / 1000)) {
    throw new JWTExpiredError();
  }
  return payload;
}
