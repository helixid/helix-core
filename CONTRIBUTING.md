# Contributing to `@helixid/core`

`@helixid/core` is the cryptographic and schema layer beneath every other
HelixID component — credential verification, DID resolution, delegation-chain
validation, and revocation all bottom out here.

**This is the highest-stakes repository in the org.** A change here ripples
through every SDK, every middleware, and every deployment. Expect stricter
review and a higher test bar than you would meet elsewhere.

> **New to HelixID?** Read
> [docs.helixid.dev](https://docs.helixid.dev) first — it covers the concepts
> (DIDs, verifiable credentials, the two-issuer model, delegation, revocation)
> that the rest of this document assumes. This file is the authoritative
> process for *this* repository; the docs site is the orientation.

---

## Open-Source Scope

This repository is Apache-2.0 and public. It holds the verification primitives
that everything else depends on, so the bar for correctness is high and the
appetite for surface-area growth is low.

Changes that alter verification semantics, delegation rules, or revocation
behaviour need a written rationale and a second maintainer review. If you are
unsure whether something qualifies, open an issue before writing code.

---

## Ways to Contribute

1. **DID method resolvers** — additional DID methods, following the existing
   resolver interface.
2. **Spec conformance** — W3C VC 2.0, DID 1.0, and StatusList conformance gaps,
   ideally with a failing test vector.
3. **Test vectors** — golden vectors for edge cases we do not yet cover
   (`pnpm generate:golden-vectors`).
4. **Bug reports** with a minimal reproduction. For anything touching crypto, a
   failing test is worth more than a description.

---

## Before You Start

**Open a Discussion or Issue first** for any non-trivial change. Trivial means: typos, obviously incorrect code, a missing test for existing behavior, a small doc improvement. Anything else — new features, new dependencies, API changes, performance optimizations that change behavior, new packages — needs a design sketch and sign-off from a maintainer before a PR lands.

This saves time on both sides. A rejected PR after two weeks of work is a worse outcome than a fifteen-minute design conversation.

---

## Development Setup

### Prerequisites

- Node.js `^20.19.0 || >=22.12.0` — note 20.0–20.18 will **not** work
- pnpm ≥ 9 (`corepack enable` — the repo pins `pnpm@9.15.2` via `packageManager`)
- Git

### Clone and Bootstrap

```bash
git clone https://github.com/helixid/helix-core.git
cd helix-core
pnpm install
pnpm build          # runs `prisma generate` then tsc
```

`pnpm build` is also wired to `prepare`, so a plain `pnpm install` builds too.

### Run Tests

```bash
pnpm test           # the default suite, live tests excluded, with coverage
pnpm test:non-live  # same without coverage — fastest inner loop
pnpm test:unit      # tests/unit only
pnpm test:security  # tests/security — run this for anything crypto-adjacent
pnpm test:live      # live tests only; needs configured infrastructure
pnpm lint
pnpm typecheck
```

Run `pnpm test:security` before opening any PR that touches verification, key
handling, or delegation.

### Database

This repository carries a Prisma schema. After changing it:

```bash
pnpm db:generate    # regenerate the client
pnpm db:migrate     # create a migration locally
```

---

## Repository Structure

```
helix-core/
├── src/          # the published package
├── prisma/       # schema and migrations
├── tests/        # unit, security, and live suites
├── e2e/          # end-to-end package
├── fixtures/     # golden vectors and test fixtures
├── patches/      # pnpm patches for upstream dependencies
├── scripts/      # maintenance and vector generation
└── docs/         # design notes
```

The rest of the system lives in separate repositories under the same org — see
[Project Structure](https://docs.helixid.dev/get-started/project-structure).

---

## Branching and Commits

### Branch Names

```
<type>/<short-kebab-description>

feat/did-web-resolver
fix/statuslist-cache-invalidation
docs/delegation-tutorial
```

### Conventional Commits (required)

We use [Conventional Commits](https://www.conventionalcommits.org/). The release tooling parses commit messages to generate changelogs and bump versions.

```
<type>(<scope>): <summary>

[optional body]

[optional footer(s)]
```

Allowed types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`, `revert`.

Scope is the package or area: `core`, `api`, `sdk-js`, `mcp`, `langchain`, `cli`, `docs`.

Examples:

```
feat(sdk): add did:web resolver with HTTPS pinning

fix(api): invalidate status-list cache after credential revocation

perf(sdk): avoid re-parsing JWS on repeated verification

BREAKING CHANGE: verifyPresentation now returns DelegationChain,
not string[]. Migration: use result.delegationChain.dids.
```

**Breaking changes** must include a `BREAKING CHANGE:` footer and a migration note in the PR description.

### Sign Your Commits (DCO)

Every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/). We deliberately use DCO instead of a CLA — it's a lightweight attestation with no corporate-legal review tax. By signing off, you affirm that you have the right to submit the work under Apache 2.0.

```bash
git commit -s -m "feat(sdk): add did:web resolver"
```

This appends a `Signed-off-by: Your Name <your.email@example.com>` line. Our CI rejects PRs missing DCO on any commit. If you forget, rebase with `git rebase --signoff`.

---

## Pull Requests

### Before Opening a PR

- [ ] Rebase on the latest `main`
- [ ] Run `pnpm lint && pnpm test && pnpm build` locally and pass
- [ ] Add or update tests — no untested code merges
- [ ] Update docs if you changed public API
- [ ] Add a changeset (`pnpm changeset`) if your change is user-visible
- [ ] Every commit is DCO-signed

### PR Description

Use this template — it mirrors what reviewers and release notes need:

```markdown
## What
<short summary of the change>

## Why
<motivation, linked issue, relevant context>

## How
<implementation approach, trade-offs considered, alternatives rejected>

## Testing
<how you verified this works — unit, integration, manual scenarios>

## Risk & Rollback
<what could break, how to revert if this ships bad>

## Breaking Changes
<none | description + migration path>

Closes #<issue>
```

### Review Expectations

- Two maintainer approvals required for changes in `helix-core` or `helix-sdk-js`
- One maintainer approval for everything else
- Reviewers respond within 3 business days — if silent longer, ping in Discussions
- We squash-merge by default; commit history on `main` is one commit per PR

### Merging

Only maintainers merge. Do not merge your own PR even if you have permissions.

---

## Coding Standards

### TypeScript

- `strict` mode. No `any` in exported signatures; justify it in a comment anywhere else.
- Public API changes need doc comments and a changeset.
- Prefer explicit return types on exported functions.

### Tooling

- ESLint + Prettier are enforced in CI. Run `pnpm format` before pushing.

### Cryptography and Security-Sensitive Code

This is the repository where that rule bites hardest:

- Never hand-roll primitives. Use the vetted libraries already in the dependency tree.
- Constant-time comparison for anything secret-dependent.
- Changes to verification, delegation-chain walking, or revocation require a
  second maintainer review and a threat-model note in the PR.
- New verification behaviour needs a golden vector, not just a unit test.

### Testing

- Unit tests: `tests/unit/`. Security-relevant behaviour: `tests/security/`.
- Target ≥ 85% line coverage for new code. Lower is acceptable with justification.
- A bug fix should come with the test that would have caught it.

---

## Security Disclosure

**Do not open public issues for security vulnerabilities.** Use one of:

- Email `hello@dgverse.in`
- [GitHub Security Advisory](https://github.com/helixid/helix-core/security/advisories/new) (private)

We acknowledge within 48 hours, triage within 7 business days, and practice coordinated disclosure with a default 90-day embargo. Full scope, safe-harbor terms, and response policy: [`SECURITY.md`](SECURITY.md).

---

## Release Process

`@helixid/core` is published to npm as a **public package** and is versioned
with [changesets](https://github.com/changesets/changesets).

```bash
pnpm changeset          # describe your change; commit the generated file
pnpm changeset version  # maintainers: bump versions and write changelogs
pnpm release            # maintainers: publish
```

Publishing runs from `.github/workflows/release.yml`. Contributors only need the
first command.

---

## Community and Code of Conduct

- **Discussions:** [github.com/helixid/helixid/discussions](https://github.com/helixid/helixid/discussions) — design questions, use cases, show-and-tell
- **Issues:** [github.com/helixid/helixid/issues](https://github.com/helixid/helixid/issues) — bugs and concrete feature requests
- **Security:** `hello@dgverse.in`
- **General contact:** `hello@dgverse.in`

We follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Short version: be respectful, assume good faith, keep technical debate on technical merits, and escalate conduct concerns to `hello@dgverse.in`.

---

## Licensing of Contributions

Contributions are licensed under [Apache License 2.0](LICENSE), same as the project. DCO sign-off on each commit is the full legal attestation — no CLA, no separate agreement, no surprise relicensing. See the DCO section above.

---

## Quick Reference

| Task | Command |
|---|---|
| Install deps | `pnpm install` |
| Build | `pnpm build` |
| Test (default) | `pnpm test` |
| Test (fast loop) | `pnpm test:non-live` |
| Security tests | `pnpm test:security` |
| Lint | `pnpm lint` |
| Typecheck | `pnpm typecheck` |
| Format | `pnpm format` |
| Add a changeset | `pnpm changeset` |
