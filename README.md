# @helixid/core

Fastify HTTP API primitives for Helix ID — self-hostable, stateful operations across four boundaries. Consumed by both `helix-server-enterprise` and `github.com/helixid/helixid` (the OSS self-hosted server) as a real dependency, not copied into either.

## Documentation

Full documentation is at **[docs.helixid.dev](https://docs.helixid.dev)** — concepts,
guides, and reference. This README covers only what is specific to this repository.

| | |
|---|---|
| **Start here** | [Introduction](https://docs.helixid.dev/) |
| **Concepts** | [The Trust Stack](https://docs.helixid.dev/concepts/trust-stack) · [Two-Issuer Model](https://docs.helixid.dev/concepts/two-issuer-model) · [Delegation](https://docs.helixid.dev/concepts/delegation) · [Revocation](https://docs.helixid.dev/concepts/revocation) |
| **Get started** | [Quick Start](https://docs.helixid.dev/get-started/quick-start) · [Installation & Modes](https://docs.helixid.dev/get-started/installation-and-modes) |
| **Contributing** | [How to Contribute](https://docs.helixid.dev/contributing/how-to-contribute) · [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| **Security** | [Reporting a Vulnerability](https://docs.helixid.dev/security/reporting-a-vulnerability) · [`SECURITY.md`](SECURITY.md) |

---

## Quick Start (local, no Docker)

The fastest working setup skips Postgres and Hedera entirely: SQLite
self-initializes its own schema on first run (no migration step), and
`did:key` needs no DNS-reachable domain, so there's nothing else to stand
up first.

### 1. Install

```bash
pnpm install
```

This repo's own `pnpm install` still needs read access to the (currently
private) `helixid/helix-sdk-js` repo, via the `@helixid/sdk-js`
devDependency used by dev/e2e tooling — unrelated to DID method choice,
and not something a consumer installing `@helixid/core` from npm ever
hits (devDependencies aren't installed transitively).

`@helixid/did-hedera` is not a dependency of `@helixid/core` at all, not
even an optional one — `did:key` and `did:web` never touch it, and
`DID_METHOD=hedera` only works if you separately run
`npm install @helixid/did-hedera` (published on npm; see "Using
did:hedera" below). Leaving it out of the manifest keeps every other
install method free of Hedera's SDK weight, and free of pulling the old,
retired `@helixid/core` in transitively (`@helixid/did-hedera` itself
still depends on that package at `^0.1.5`).

### 2. Configure

Only two variables have no default and must be set:
`HELIX_SIGNING_KEY` and `HELIX_ADMIN_API_KEY`. Everything below is the
full set worth setting for local dev — write it to `helix-api/.env`
(loaded automatically; see `src/loadEnv.ts`):

```bash
NODE_ENV=development
PORT=3000
HELIX_STORAGE_ADAPTER=sqlite
HELIX_SQLITE_PATH=./data/helixid.sqlite
API_BASE_URL=http://localhost:3000
DID_METHOD=key
HELIX_ISSUER_DID=did:key:z6MkgHKqmKyCQroyo3RVx3gM1LXwUNwzZkynmsqwhYNqNjdn
HELIX_SIGNING_KEY=11deb8f4b8f2e1c0a9d7c6b5a4938271605f4e3d2c1b0a998877665544332211
HELIX_ADMIN_API_KEY=dev-admin-key-change-in-production
```

`HELIX_ISSUER_DID` and `HELIX_SIGNING_KEY` must be a matched pair — the
DID is not derived from the key automatically, so if you generate your
own key instead of reusing the sample above, derive its `did:key` first
(e.g. via the SDK's `keys.derivePublicKey` / `publicKeyToMultibase`, or
the CLI) and put the result in `HELIX_ISSUER_DID`. A mismatched pair
doesn't fail at startup — every VP verification fails later instead, with
`VC_SIGNATURE_INVALID`, since the API ends up resolving the wrong public
key for its own issuer DID.

`HELIX_ADMIN_API_KEY` just needs to be ≥16 characters; the value above is
a placeholder, not a real credential — change it for anything beyond a
throwaway local run.

### 3. Run

```bash
cd helix-api
npm run dev
```

Confirm it's up:

```bash
curl http://localhost:3000/health
```

Reset to a clean slate: delete `helix-api/data/helixid.sqlite*` and restart.

**Troubleshooting:** if `npm run dev` fails on `better-sqlite3` with a
`NODE_MODULE_VERSION` / `ERR_DLOPEN_FAILED` error, its native binary was
built against a different Node version than the one currently active
(easy to hit after switching Node versions, or if `pnpm install` ran
under a different version than you're running now). Fix: `cd
node_modules/.pnpm/better-sqlite3@*/node_modules/better-sqlite3 && npx
node-gyp rebuild` from the repo root, then retry.

## Using did:hedera

`did:key` and `did:web` work out of the box. `DID_METHOD=hedera` anchors
DIDs on the Hedera network instead, and needs one extra package plus a
funded Hedera account:

```bash
npm install @helixid/did-hedera
```

Then set (validated at startup — missing any of these with
`DID_METHOD=hedera` fails fast rather than failing later at request time):

```bash
DID_METHOD=hedera
HEDERA_NETWORK=testnet
HEDERA_OPERATOR_ID=0.0.xxxxx
HEDERA_OPERATOR_KEY=<operator private key>
HELIX_ISSUER_DID=did:hedera:testnet:<...>
```

`scripts/setup-hedera.ts --create-issuer-did` (in the consuming server
repo) generates the signing key and derives a matching `HELIX_ISSUER_DID`
for you, writing both into `.env`.

If `@helixid/did-hedera` isn't installed, both DID creation
(`createHederaClient`) and resolution of existing `did:hedera:...` DIDs
(`did-resolver`'s `resolveDID`) fail with an explicit error naming the
missing package, rather than an obscure module-not-found stack trace.

## Boundaries

| Boundary | Routes | Description |
|---|---|---|
| B1 | `/did/*` | DID lifecycle and DID resolution |
| B2 | `/vc/*` | VC issuance, revocation, renewal, status list |
| B3 | `/vp/*` | VP template generation, verification, vpId lifecycle |
| B4 | `/agent/*` | Agent onboarding, user DID, challenge-response |

## Scripts

```bash
npm run dev          # Start with tsx watch (hot reload)
npm run build        # Compile TypeScript
npm run start        # Run compiled output
npm run test         # Run all tests with coverage
npm run test:security # Run security tests only
```

## Architecture

- Routes call Services only — never Repositories directly
- Services call Repositories for data access
- Boundaries communicate through internal service interfaces only (§7 of constitution)
- DID and status flows are isolated behind the service boundary so the API can evolve independently

---

## The HelixID ecosystem

| Repository | What it is |
|---|---|
| [helixid](https://github.com/helixid/helixid) | HelixID API — the issuer and verifier service |
| **helix-core** — you are here | `@helixid/core` — crypto, schemas, resolver, verification primitives |
| [helix-sdk-js](https://github.com/helixid/helix-sdk-js) | JS/TS SDK, CLI, LangChain + MCP middleware, consent widget |
| [helix-sdk-py](https://github.com/helixid/helix-sdk-py) | `helixid-sdk-py` — the Python SDK |
| [helix-console](https://github.com/helixid/helix-console) | Operator Console SPA |
| [helix-wiki](https://github.com/helixid/helix-wiki) | Source for [docs.helixid.dev](https://docs.helixid.dev) |

---
