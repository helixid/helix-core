import type { FastifyPluginAsync } from 'fastify';
import type { DIDDocument } from '../../core/index.js';

interface DidWebRouteOptions {
  issuerDid: string;
  didDomain: string;
  didRepository: {
    findDidById(did: string): Promise<{ didDocument: unknown; deactivatedAt?: Date | null } | null>;
  };
}

const didWebRoutes: FastifyPluginAsync<DidWebRouteOptions> = async (fastify, options) => {
  fastify.get('/.well-known/did.json', async (_request, reply) => {
    const issuer = await options.didRepository.findDidById(options.issuerDid);
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

  // Agent/user DIDs minted with DID_METHOD=web (see DIDService.createDID)
  // are `did:web:<domain>:agents:<slug>`, which per the did:web spec
  // resolves to <domain>/agents/<slug>/did.json.
  fastify.get<{ Params: { slug: string } }>('/agents/:slug/did.json', async (request, reply) => {
    const did = `did:web:${options.didDomain}:agents:${request.params.slug}`;
    const record = await options.didRepository.findDidById(did);
    if (!record) {
      return reply.code(404).send({
        error: {
          code: 'DID_NOT_FOUND',
          message: 'DID document is not available.',
        },
      });
    }
    if (record.deactivatedAt) {
      return reply.code(410).send({
        error: {
          code: 'DID_DEACTIVATED',
          message: 'DID is deactivated.',
        },
      });
    }

    return reply
      .type('application/json')
      .header('Cache-Control', 'public, max-age=3600')
      .send(record.didDocument as DIDDocument);
  });

  // Service DIDs (DIDService.createDID with subjectType 'service') are
  // `did:web:<domain>:services:<slug>` -> <domain>/services/<slug>/did.json.
  fastify.get<{ Params: { slug: string } }>('/services/:slug/did.json', async (request, reply) => {
    const did = `did:web:${options.didDomain}:services:${request.params.slug}`;
    const record = await options.didRepository.findDidById(did);
    if (!record) {
      return reply.code(404).send({
        error: {
          code: 'DID_NOT_FOUND',
          message: 'DID document is not available.',
        },
      });
    }
    if (record.deactivatedAt) {
      return reply.code(410).send({
        error: {
          code: 'DID_DEACTIVATED',
          message: 'DID is deactivated.',
        },
      });
    }

    return reply
      .type('application/json')
      .header('Cache-Control', 'public, max-age=3600')
      .send(record.didDocument as DIDDocument);
  });
};

export default didWebRoutes;
