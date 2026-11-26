// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import { buildDIDDocument, didKeyDocument, type DIDDocument } from '../../src/core/index.js';

/**
 * The document a verifier resolves for `did`: a did:key's own W3C document
 * (`did:key:z…#z…`, the method its signer names by default), else the
 * `#key-1` document `buildDIDDocument` publishes.
 */
export function testDidDocument(did: string, publicKeyHex: string): DIDDocument {
  return did.startsWith('did:key:') ? (didKeyDocument(did) as unknown as DIDDocument) : buildDIDDocument(did, publicKeyHex);
}
