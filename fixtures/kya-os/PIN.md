# KYA-OS conformance suite, vendored

Source: https://github.com/decentralized-identity/kya-os-mcp

| Field | Value |
| --- | --- |
| Commit | `a4d7f61` (Merge pull request #322, `fix/gate-reports-configured-resolver-throw`) |
| Suite version | 1.10.0 |
| Vector set hash | `sha256:6dd5e3dd0526b0fb7e7e3ea9e76b63a3acd0651aeb36ee03ea1f820bb15ebed0` |
| Vector count | 164 |
| Reference package | `@kya-os/mcp` 1.23.0 (per `conformance/SUITE-MANIFEST.json`) |

## What is here

The data files of the suite, byte for byte, at the same paths as upstream:

- `conformance/vectors/*.json`: the 14 vector files, one category each.
- `conformance/SUITE-MANIFEST.json`: upstream's own manifest (per-file SHA-256, vector set hash).
- `conformance/unseen-code-points.json`: data the `signed-proof` and `delegation-chain` vectors refer to.
- `schemas/*.json` and `schemas/README.md`: the JSON schemas.
- `CONFORMANCE.md`: the conformance requirements document (Core, Entity Card and Audit ladders).

Upstream's TypeScript and Python harness code (`conformance/*.ts`, `conformance/*.py`,
`conformance/suite-hash.mjs`) is not vendored: Helix runs the vectors through its own
implementations, and nothing from the clone is executed.

## Vector set hash

Recipe from upstream `conformance/suite-hash.mjs`: SHA-256 of each vector file's raw bytes,
`[filename, hex]` pairs sorted by filename, RFC 8785 canonical form of that array, then
`sha256:` plus the SHA-256 hex of it. Recomputed independently at vendoring time; it equals
the value above and the value in `SUITE-MANIFEST.json`.

## Moving the pin

Moving the pin is its own change (stories rule 5): re-clone at the new commit, replace every
file here, recompute the hash, update this file and `SUITE-MANIFEST.json`, and re-run every
story's vector tests.
