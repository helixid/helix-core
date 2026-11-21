# Local verifier fixtures (KYA-OS story F-2)

One fixture set drives both local verifiers, `@helixid/sdk-js`'s
`kyaos.verifier.verify` and helix-sdk-py's `helix_sdk.verifier.verify`
(stories rule 6). The cases are built from helix-core's credential builders,
judged by the JavaScript reference verifier, and checked in. Every consumer
must come to the recorded verdict for every case: `ok`, `level`,
`effectiveScopes`, `reasons` (in order) and `chainSummary`.

| File | Covers |
| --- | --- |
| `environment.json` | TEST-ONLY keys (derived from labels; never reuse), their did:key documents, the status lists (live, stale, cached, wrong purpose, foreign issuer, wrong id, bare bits) and the Entity Cards the cases use. |
| `valid.json` | Accepted calls: two-hop and single-hop chains, catalog narrowing, a proof alone, no card, a card from the `resolveCard` seam, the legacy `org.kya-os/proof@1` profile, a bare capability (L1), a cached status read (L2), trusted-issuer lists in both modes, `cnf` fusion, a revoked attestation (demotion, not refusal). |
| `proof.json` | The request proof: tampered signature and request, `_meta` tampering (free), wrong audience, expired, created in the future, lifetime over 60 s, inverted window, within skew, `kid`/`did` mismatch, forged principal, unpublished key, key not in the DID document, malformed proofs, missing proof or request, ES256, the `cnf` cases. |
| `chain.json` | Every attenuation failure (broadened action, dropped or widened caveat, changed currency or unknown caveat, extended `validUntil`, broken parent or continuity, target drift), wrong resource, resource owner, root parent, expired and not-yet-valid hops, malformed and unsigned hops, tampered and foreign hop proofs, leaf invoker mismatch, untrusted root, undelegated action, `responsibleParty` mismatch, card refusals, over-long chain, lowered bound, empty chain, a failed chain with no fallback. |
| `status.json` | Revoked leaf and root (cascade), stale, unavailable and throwing lists, purpose, issuer and id mismatches, a bare-bits read, an out-of-range index, the missing status seam. |
| `seams.json` | Replayed nonce, missing or failing nonce store, missing `resolveDidKeys` (`did_membership_unverifiable`), failing key listing, missing, unknown and failing DID resolver, missing clock, every seam missing at once. |

Each case gives `input` (`proof`, `chain`, `request`, `card`), `seams` (how the
harness builds each seam from `environment.json`: `documents`, `missing`,
`throws`, ...), `options` (the verifier's options, camelCase), `now` (the
fixed clock, epoch ms) and `expected`. The harness that turns `seams` into
functions is the same in every consumer: helix-core's generator
(`scripts/gen-fixtures.ts`, `fixtureSeams`), helix-sdk-js
(`tests/unit/kyaos/verifier/harness.ts`) and helix-sdk-py
(`tests/verifier_harness.py`).

## Regenerating

```bash
pnpm generate:verifier-fixtures
```

Regenerate whenever the verifier in helix-sdk-js or a credential builder here
changes, and commit the diff in the same PR. Do not hand-edit.
`tests/unit/kya-os/verifier-fixtures.test.ts` fails when the checked-in files
drift from what the generator produces.

## Who reads them

- helix-core: `tests/unit/kya-os/verifier-fixtures.test.ts`, `tests/unit/routes/verify.test.ts`.
- helix-sdk-js: `helix-sdk-js/tests/unit/kyaos/verifier/fixtures.test.ts`, `mcp-middleware/tests/middleware.test.ts` (sibling checkout or `HELIX_CORE_FIXTURES_DIR`).
- helix-sdk-py: `tests/test_verifier.py` (sibling checkout or `HELIX_CORE_FIXTURES_DIR`).
- e2e-playwright: `tests/suite/kya-os/f-2-local-verifier.spec.ts`, both languages over every case.
