import type { FastifyPluginAsync } from 'fastify';
import { didWebFor, sameDid, type DIDDocument } from '../../core/index.js';

interface DidWebRouteOptions {
  issuerDid: string;
  didDomain: string;
  didRepository: {
    findDidById(did: string): Promise<{ didDocument: unknown; deactivatedAt?: Date | null } | null>;
  };
}

/**
 * The Helix issuer's own did:web document at `/.well-known/did.json`
 * (`did:web:<DID_DOMAIN>`). Only a did:web issuer of this domain is served
 * there: with `DID_METHOD=key` (or hedera) the issuer is not a did:web, so the
 * path claims no did:web id and answers 404. Agents, services and accounts
 * (`/agents/<hex>/did.json`, `/services/<hex>/did.json`,
 * `/accounts/<hex>/did.json`, with their `card.json`) are served by
 * `routes/entity-card`.
 */
const didWebRoutes: FastifyPluginAsync<DidWebRouteOptions> = async (fastify, options) => {
  let hostDid: string | undefined;
  try {
    hostDid = options.didDomain ? didWebFor(options.didDomain) : undefined;
  } catch {
    hostDid = undefined;
  }
  const servesIssuer = hostDid !== undefined && sameDid(options.issuerDid, hostDid);

  fastify.get('/.well-known/did.json', async (_request, reply) => {
    const issuer = servesIssuer ? await options.didRepository.findDidById(options.issuerDid) : null;
    if (!issuer) {
      return reply.code(404).send({
        error: {
          code: 'DID_NOT_FOUND',
          message: 'Issuer DID document is not available.',
        },
      });
    }

    return reply
      .type('application/json')
      .header('Cache-Control', 'public, max-age=3600')
      .send(issuer.didDocument as DIDDocument);
  });
};

export default didWebRoutes;
