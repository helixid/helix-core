# Golden vectors

These fixtures are the cross-language contract for the small set of crypto
primitives that every SDK must implement **locally** rather than call the API
for: canonical JSON, hashing and Ed25519 signing. They
are generated once from `helix-core`'s own implementation — never
hand-written or re-derived from a spec — and every SDK asserts byte-for-byte
equality against them.

## Files

| File                 | Covers                                                          |
| -------------------- | ---------------------------------------------------------------- |
| `canonical-json.json`| `toCanonicalJson` / `hashCanonicalPayload` over representative and edge-case payloads (nested objects, arrays, unicode, numeric edge cases). |
| `signing.json`       | `signData` / `verifySignature` over the same payload set, using a fixed (non-secret, test-only) keypair. |
| `vp-builder.json`    | Frozen: full `VPBuilder.sign()` output of the retired VP path. KYA-OS story F-2 removed `VPBuilder` from helix-core, so this file is no longer regenerated; it stays for the SDK suites that still read it until they retire their own VP code. |

## Regenerating

```bash
pnpm generate:golden-vectors
```

Regenerate whenever `helix-core/src/crypto/vp.ts`, `crypto/keys.ts` or
`proof.ts` change, and commit the resulting diff in the
same PR as the source change. Do not hand-edit these files — they're
generated output.

## Who enforces this

- **`helix-core`**: `tests/unit/golden-vectors.test.ts` re-derives every
  vector from current source and fails if it drifts from what's committed
  here — this is what catches "changed the crypto, forgot to regenerate."
- **`helix-sdk-js`**: no longer tests `vp-builder.json`; `VPBuilder` and
  its vector test were removed with the Helix VP (KYA-OS story C-C).
- **`helix-sdk-py`** (once it exists): same pattern, its own
  implementation, same fixture files.

Every consumer loads these files directly rather than hand-copying values
into its own test source, so there is exactly one place these numbers live.
