# KYA-OS Helix fixtures

Cross-language fixtures for the KYA-OS primitives Helix implements in more
than one language (stories rule 6). Generated once from helix-core and
checked in; helix-core, helix-sdk-py and e2e-playwright assert byte for byte
against them. Never hand-edit.

| File       | Story | Covers                                                                                   | Regenerate                   |
| ---------- | ----- | ---------------------------------------------------------------------------------------- | ---------------------------- |
| `jws.json` | L1-C  | `signJws` / `verifyJws` / `verifyJwsByKid`: test keys, DID documents, payloads, expected compact JWS, and the rejection cases with their reason codes. | `pnpm generate:jws-fixtures` |

Consumers:

- helix-core: `tests/unit/crypto/jws-fixtures.test.ts` regenerates the file
  from source and fails on drift, then verifies every vector and rejection.
- helix-sdk-py: `tests/test_jws.py` reads the sibling checkout's copy
  (`../helix-core/fixtures/kya-os-helix/jws.json`), or the directory named by
  `HELIX_CORE_FIXTURES_DIR`.
- e2e-playwright: `tests/suite/kya-os/l1-c-jws.spec.ts` signs and verifies
  across the JS and Python SDKs with these keys.

The KYA-OS conformance vectors themselves live next door in `fixtures/kya-os/`,
vendored from `decentralized-identity/kya-os-mcp` at the pinned commit.
