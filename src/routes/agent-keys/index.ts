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

import type { FastifyPluginAsync } from 'fastify';
import {
  AdminAuthRequiredError,
  DIDDeactivatedError,
  DIDNotFoundError,
  HelixError,
  ValidationError,
  buildDidDocument,
  didKeyFromPublicKey,
  evictDIDCache,
  isDidWeb,
  publicKeyJwkBytes,
  verificationMethodId,
  type AgentDidDocument,
} from '../../core/index.js';

/**
 * POST /agents/:did/keys (KYA-OS story L1-A): an agent operator registers
 * the public half of a key the SDK generated client side. The body is a
 * public JWK and nothing else; any private material (`d`, or any member a
 * public OKP JWK does not have) is refused with 400 before anything is
 * stored. Helix stores the public key against the agent by republishing
 * the agent's did:web document with it as the one verification method,
 * `<did>#<key-id>`, which is the `kid` every JWS the agent emits carries.
 *
 * Gated like POST /agents/:did/vp: OSS has no credential narrower than the
 * admin key. The hosted build layers its account scoping on top.
 */

export interface AgentKeyRouteOptions {
  didRepository: {
    findDidById(did: string): Promise<{ didDocument: unknown; deactivatedAt?: Date | null } | null>;
    updateDidDocument(
      did: string,
      didDocument: unknown,
      update: { updateType: string; hederaTransactionId: string; payload: unknown },
    ): Promise<unknown>;
  };
  /** The DID service's document cache, dropped so local verifiers see the new key at once. */
  didCache?: { delete(did: string): Promise<unknown> | unknown } | undefined;
  adminApiKey?: string | undefined;
}

export interface RegisterAgentKeyBody {
  publicKeyJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string; kid?: string };
  /** Verification-method fragment or full id. Default `key-1`. */
  kid?: string;
}

export interface RegisterAgentKeyResult {
  did: string;
  kid: string;
  didKey: string;
  didDocument: AgentDidDocument;
}

export const AGENT_KEY_UPDATE_TYPE = 'register_agent_key';

const BODY_MEMBERS = new Set(['publicKeyJwk', 'kid']);
/** Names that only ever carry private material; refused wherever they appear in the body. */
const PRIVATE_MATERIAL_MEMBERS = new Set(['d', 'privateKey', 'privateKeyHex', 'private_key', 'seed', 'secret']);

function findPrivateMaterial(value: unknown, path: string): string | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  for (const [name, member] of Object.entries(value as Record<string, unknown>)) {
    const here = path ? `${path}.${name}` : name;
    if (PRIVATE_MATERIAL_MEMBERS.has(name)) return here;
    const nested = findPrivateMaterial(member, here);
    if (nested !== undefined) return nested;
  }
  return undefined;
}

/** The body, checked: a public JWK (kty, crv, x, optional kid) and an optional kid, nothing else. */
export function readRegisterAgentKeyBody(body: unknown): { publicKey: Uint8Array; kid: string | undefined } {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new ValidationError('Request body must be a JSON object with publicKeyJwk');
  }
  const members = body as Record<string, unknown>;
  const privateMaterial = findPrivateMaterial(members, '');
  if (privateMaterial !== undefined) {
    throw new ValidationError(
      `Request carries private key material (${privateMaterial}); only the public JWK is accepted`,
    );
  }
  const foreign = Object.keys(members).filter((name) => !BODY_MEMBERS.has(name));
  if (foreign.length > 0) {
    throw new ValidationError(`Request carries unexpected members (${foreign.join(', ')})`);
  }
  if (members['kid'] !== undefined && (typeof members['kid'] !== 'string' || members['kid'].length === 0)) {
    throw new ValidationError('kid must be a non-empty string');
  }
  const publicKey = publicKeyJwkBytes(members['publicKeyJwk']);
  const jwkKid = (members['publicKeyJwk'] as { kid?: string }).kid;
  const kid = (members['kid'] as string | undefined) ?? jwkKid;
  return { publicKey, kid };
}

const agentKeyRoutes: FastifyPluginAsync<AgentKeyRouteOptions> = async (fastify, options) => {
  function requireAdmin(request: { headers: Record<string, string | string[] | undefined> }): void {
    const submitted = request.headers['x-admin-api-key'];
    const submittedKey = Array.isArray(submitted) ? submitted[0] : submitted;
    if (!options.adminApiKey || submittedKey !== options.adminApiKey) {
      throw new AdminAuthRequiredError();
    }
  }

  fastify.post<{ Params: { did: string } }>('/agents/:did/keys', async (request, reply) => {
    try {
      requireAdmin(request);
      const did = request.params.did;
      if (!isDidWeb(did)) {
        throw new ValidationError('Only a did:web agent publishes a key document');
      }
      const { publicKey, kid } = readRegisterAgentKeyBody(request.body);

      const record = await options.didRepository.findDidById(did);
      if (!record) throw new DIDNotFoundError(did);
      if (record.deactivatedAt) throw new DIDDeactivatedError(did);

      const previous = record.didDocument as { service?: unknown[] } | null;
      const didKey = didKeyFromPublicKey(publicKey);
      const didDocument = buildDidDocument({
        did,
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKey).toString('base64url') },
        kid: verificationMethodId(did, kid),
        alsoKnownAs: [didKey],
        ...(Array.isArray(previous?.service) ? { service: previous.service } : {}),
      });
      const verificationMethod = didDocument.verificationMethod[0]!;

      await options.didRepository.updateDidDocument(did, didDocument, {
        updateType: AGENT_KEY_UPDATE_TYPE,
        hederaTransactionId: '',
        payload: { kid: verificationMethod.id, publicKeyJwk: verificationMethod.publicKeyJwk, didKey },
      });
      evictDIDCache(did);
      await options.didCache?.delete(did);

      const result: RegisterAgentKeyResult = { did, kid: verificationMethod.id, didKey, didDocument };
      return reply.code(201).send(result);
    } catch (error) {
      if (error instanceof HelixError) {
        return reply
          .code(error.httpStatus)
          .send({ error: { code: error.code, message: error.message, requestId: request.id } });
      }
      throw error;
    }
  });
};

export default agentKeyRoutes;
