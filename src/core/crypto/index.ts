export * from './did.js';
export * from './signer.js';
export * from './jws.js';
export {
  generateKeyPair,
  derivePublicKey,
  publicKeyToMultibase,
  multibaseToPublicKeyHex,
  signData,
  verifySignature as verifySignatureSync,
  type KeyPair,
} from './keys.js';
export {
  base58btcDecode,
  base58btcEncode,
  hashCanonicalPayload,
  signBytes,
  toCanonicalJson,
  verifySignature,
} from './vp.js';
export * from './jwt.js';
export { CanonicalJsonError, canonicalize, hashJson } from './jcs.js';
export { decodeBase58btc, encodeBase58btc, isBase58btc } from './base58.js';
