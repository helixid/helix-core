/**
 * The DID document of a fixture did:key, W3C style: its one verification
 * method is `did:key:z…#z…` (the multibase value as the fragment), the id a
 * did:key resolver derives and what `defaultKidFragment` signs with (F-1-New's
 * kid fix). TEST ONLY: used by the fixture generators.
 */
import { buildDIDDocument, type DIDDocument } from '../src/core/index.js';
import { defaultKidFragment } from '../src/core/crypto/signer.js';

export function didKeyKid(did: string): string {
  return `${did}#${defaultKidFragment(did)}`;
}

export function didKeyDocument(did: string, publicKeyHex: string): DIDDocument {
  const legacy = `${did}#key-1`;
  const kid = didKeyKid(did);
  const document = buildDIDDocument(did, publicKeyHex);
  return {
    ...document,
    verificationMethod: document.verificationMethod.map((method) => ({ ...method, id: method.id === legacy ? kid : method.id })),
    authentication: (document.authentication ?? []).map((ref) => (ref === legacy ? kid : ref)),
    assertionMethod: (document.assertionMethod ?? []).map((ref) => (ref === legacy ? kid : ref)),
  } as DIDDocument;
}
