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

/** KYA-OS story F-3: the refusals of the custody choice, the KeyStore and custodial signing. */

import { HelixError } from '../errors/HelixError.js';

/** A custody choice or account preference that is not one of the allowed modes. */
export class CustodyChoiceInvalidError extends HelixError {
  constructor(message: string) {
    super('CUSTODY_CHOICE_INVALID', message, 400);
  }
}

/** No custody record for this agent, service or owner. */
export class CustodySubjectNotFoundError extends HelixError {
  constructor(did: string) {
    super('CUSTODY_SUBJECT_NOT_FOUND', `No custody record for ${did}`, 404, { did });
  }
}

/** The operation does not fit the subject's custody state (for example activating an active agent). */
export class CustodyStateInvalidError extends HelixError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('CUSTODY_STATE_INVALID', message, 409, details);
  }
}

/**
 * Helix signs only for subjects whose key it holds (`keyCustody: helix`).
 * A self-custody subject's key never reaches Helix, so there is nothing to
 * sign with, and signing for it would break the self-custody invariant.
 */
export class CustodialSigningRefusedError extends HelixError {
  constructor(did: string, reason: string) {
    super('CUSTODIAL_SIGNING_REFUSED', `Helix does not sign for ${did}: ${reason}`, 409, { did, reason });
  }
}

/**
 * Helix does not sign for a subject that has been revoked: its identity
 * credential is revoked or its DID is deactivated. A verifier would refuse
 * whatever Helix signed anyway; refusing here keeps a revoked agent from
 * producing fresh proofs at all.
 */
export class AgentRevokedError extends HelixError {
  constructor(did: string, reason: string) {
    super('AGENT_REVOKED', `Helix does not sign for ${did}: ${reason}`, 403, { did, reason });
  }
}

/** The enrollment or rotation proof of possession of the new key did not verify. */
export class EnrollmentProofInvalidError extends HelixError {
  constructor(message: string) {
    super('ENROLLMENT_PROOF_INVALID', message, 400);
  }
}

/**
 * An own-hosted did:web did not resolve from the owner's domain, or what it
 * serves does not list the registered key, so the subject is not activated.
 */
export class DidDocumentUnresolvedError extends HelixError {
  constructor(did: string, reason: string, details?: Record<string, unknown>) {
    super('DID_DOCUMENT_UNRESOLVED', `${did} does not resolve to the registered documents: ${reason}`, 422, {
      did,
      reason,
      ...details,
    });
  }
}

export class KeyStoreKeyNotFoundError extends HelixError {
  constructor(kid: string) {
    super('KEY_STORE_KEY_NOT_FOUND', `The key store holds no key ${kid}`, 404, { kid });
  }
}

/** The key was shredded: its private half is gone for good. */
export class KeyStoreKeyShreddedError extends HelixError {
  constructor(kid: string) {
    super('KEY_STORE_KEY_SHREDDED', `Key ${kid} was shredded and can no longer sign`, 410, { kid });
  }
}

/** The key store is not configured (no key-encryption key) or cannot reach its storage. */
export class KeyStoreUnavailableError extends HelixError {
  constructor(message: string) {
    super('KEY_STORE_UNAVAILABLE', message, 503);
  }
}
