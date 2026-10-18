import { randomBytes, randomUUID } from 'node:crypto';
import { createEd25519Proof } from './proof.js';
import { VPInvalidStructureError } from './errors/HelixError.js';
import type { SignedVC } from './schemas/vc.js';
import type { SignedVP } from './schemas/vp.js';

export interface VPBuilderOptions {
  /**
   * Exactly one agent-authority VC, plus any number of consent grants. A
   * user's consent to one service may be spread over several grants (each
   * consent screen with a different scope set issues its own), and the VP
   * carries all of them: the verifier takes the union of their scopes.
   */
  credentials: SignedVC[];
  holderDid: string;
  targetService: string;
  /** DID or plain email string; when absent, `delegatedBy` is omitted from the payload entirely. */
  userDid?: string;
}

/**
 * Test-only override hooks for `VPBuilder.sign()`. Never used in production
 * call sites: omitting these preserves the existing random `id`/`nonce`/
 * `expirationDate` behavior exactly. These exist so golden-vector generators
 * (and SDK ports of this file) can produce deterministic, byte-for-byte
 * reproducible signed VPs for cross-language fixture testing.
 */
export interface VPBuilderSignOverrides {
  /** Overrides the `vp:helix:<uuid>` id instead of calling randomUUID(). */
  id?: string;
  /** Overrides the hex nonce instead of calling randomBytes(32). */
  nonce?: string;
  /** Overrides the computed expiration instead of Date.now() + 5min. */
  expiresAt?: Date;
  /** Overrides the proof's `created` timestamp instead of `new Date()`. */
  proofCreatedAt?: Date;
}

function isAgentAuthorityType(vc: SignedVC): boolean {
  return Array.isArray(vc.type) && vc.type.includes('HelixAgentCredential');
}

function isGrantType(vc: SignedVC): boolean {
  return Array.isArray(vc.type) && vc.type.includes('DelegationGrantCredential');
}

export class VPBuilder {
  constructor(private readonly options: VPBuilderOptions) {
    const credentials = options.credentials;
    if (!Array.isArray(credentials) || credentials.length < 1) {
      throw new VPInvalidStructureError('VP must carry at least one credential');
    }
    const agentEntries = credentials.filter(isAgentAuthorityType);
    const grantEntries = credentials.filter(isGrantType);
    if (agentEntries.length !== 1 || agentEntries.length + grantEntries.length !== credentials.length) {
      throw new VPInvalidStructureError(
        'VP credential array must contain exactly one agent-authority credential, and otherwise only consent grants',
      );
    }
  }

  async sign(
    privateKeyHex: string,
    verificationMethodId: string,
    overrides?: VPBuilderSignOverrides,
  ): Promise<SignedVP> {
    const expiresAt = overrides?.expiresAt ?? new Date(Date.now() + 5 * 60 * 1000);
    const payload = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      id: overrides?.id ?? `vp:helix:${randomUUID()}`,
      holder: this.options.holderDid,
      verifiableCredential: this.options.credentials,
      nonce: overrides?.nonce ?? randomBytes(32).toString('hex'),
      expirationDate: expiresAt.toISOString(),
      // "No user" is one semantic state with one wire shape: the key is absent,
      // never serialized as null/undefined.
      ...(this.options.userDid !== undefined ? { delegatedBy: this.options.userDid } : {}),
      targetService: this.options.targetService,
    };

    return {
      ...payload,
      proof: await createEd25519Proof(payload, privateKeyHex, verificationMethodId, overrides?.proofCreatedAt),
    };
  }
}
