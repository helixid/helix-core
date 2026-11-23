import {
  base58btcDecode,
  base58btcEncode,
  hashCanonicalPayload,
  signBytes,
  verifySignature,
} from './crypto/vp.js';
import { extractPublicKeyFromDIDDocument, type DIDDocument } from './crypto/did.js';
import type { Signer } from './crypto/signer.js';

/**
 * Who signs a credential or presentation: a raw private key (the pre-KYA-OS
 * custodial keys in did_keys), or a Signer (KYA-OS story F-3: a Helix-held
 * KeyStore key, which never hands its private half out).
 */
export type SigningKeyMaterial = { did: string; privateKeyHex: string } | { did: string; signer: Signer };

/** The verification method a proof names for `wallet`: `<did>#key-1` for a raw key, `<did>#<signer.kid>` for a Signer. */
export function verificationMethodOfKey(wallet: SigningKeyMaterial): string {
  return 'signer' in wallet ? `${wallet.did}#${wallet.signer.kid.replace(/^#/, '')}` : `${wallet.did}#key-1`;
}

/** The raw private key or the Signer of `wallet`, as createEd25519Proof takes it. */
export function proofKeyOf(wallet: SigningKeyMaterial): string | Signer {
  return 'signer' in wallet ? wallet.signer : wallet.privateKeyHex;
}

export interface LinkedDataProof {
  type: 'Ed25519Signature2020';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
}

export async function createEd25519Proof(
  payload: Record<string, unknown>,
  /** A raw private key (hex), or a Signer: the same signature over the same bytes either way. */
  key: string | Signer,
  verificationMethod: string,
  /** Test-only: overrides `created` instead of `new Date()`, for deterministic golden vectors. */
  createdAt?: Date,
): Promise<LinkedDataProof> {
  const digest = hashCanonicalPayload(payload);
  let signatureHex: string;
  if (typeof key === 'string') {
    signatureHex = await signBytes(digest, key);
  } else {
    const signature = await key.sign(digest);
    if (!(signature instanceof Uint8Array) || signature.length !== 64) {
      throw new Error('createEd25519Proof: the signer did not return a 64-byte Ed25519 signature');
    }
    signatureHex = Buffer.from(signature).toString('hex');
  }
  return {
    type: 'Ed25519Signature2020',
    created: (createdAt ?? new Date()).toISOString(),
    verificationMethod,
    proofPurpose: 'assertionMethod',
    proofValue: base58btcEncode(Buffer.from(signatureHex, 'hex')),
  };
}

export async function verifyEd25519Proof(
  payload: Record<string, unknown>,
  proof: { proofValue: string },
  didDocument: DIDDocument,
): Promise<boolean> {
  const verifyProofValue = async (proofValue: string): Promise<boolean> => verifySignature(
    hashCanonicalPayload(payload),
    Buffer.from(base58btcDecode(proofValue)).toString('hex'),
    extractPublicKeyFromDIDDocument(didDocument),
  );

  try {
    if (await verifyProofValue(proof.proofValue)) return true;
  } catch {
    // Retry below for multibase-prefixed values.
  }
  if (proof.proofValue.startsWith('z')) {
    try {
      return await verifyProofValue(proof.proofValue.slice(1));
    } catch {
      return false;
    }
  }
  return false;
}
