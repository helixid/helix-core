// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * Public DID resolution for the keys of revokers and of issuers that sign
 * their own status lists (KYA-OS story L3-C): never this server's database
 * (stories rule 4), only what anyone can resolve.
 *
 * A did:key has one key, and two names for it are in use: the W3C did:key
 * method id `<did>#<fingerprint>`, which KYA-OS parties and the SDK sign
 * with, and Helix's `<did>#key-1`, which keys Helix holds sign with. The
 * document this resolver returns lists the key under both, so a request
 * signed under either verifies; it is still the one key of the DID.
 */

import type { DIDDocument, DidResolver } from '../../core/index.js';

export function publicDidResolver(resolve: (did: string) => Promise<DIDDocument>): DidResolver {
  return async (did) => {
    const document = await resolve(did);
    if (!did.startsWith('did:key:')) return document as unknown as Awaited<ReturnType<DidResolver>>;
    const fingerprint = did.slice('did:key:'.length);
    const standardId = `${did}#${fingerprint}`;
    const [first] = document.verificationMethod ?? [];
    if (first === undefined || document.verificationMethod.some((method) => method.id === standardId)) {
      return document as unknown as Awaited<ReturnType<DidResolver>>;
    }
    return {
      ...document,
      verificationMethod: [...document.verificationMethod, { ...first, id: standardId }],
      assertionMethod: [...(document.assertionMethod ?? []), standardId],
      authentication: [...(document.authentication ?? []), standardId],
    } as unknown as Awaited<ReturnType<DidResolver>>;
  };
}
