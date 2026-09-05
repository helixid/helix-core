# helix-api

Fastify HTTP API for Helix ID — self-hostable, stateful operations across four boundaries.

## Quick Start (local, no Docker)

The fastest working setup skips Postgres and Hedera entirely: SQLite
self-initializes its own schema on first run (no migration step), and
`did:key` needs no DNS-reachable domain, so there's nothing else to stand
up first.

### 1. Install

```bash
pnpm install
```

`helix-api` depends on `@helixid/did-hedera`, pulled as a git dependency
from the (currently private) `helixid/helix-sdk-js` repo. If `pnpm
install` fails trying to fetch it, you need read access to that repo —
this isn't optional even in `did:key` mode, since it's an install-time
dependency regardless of which DID method you run with.

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
