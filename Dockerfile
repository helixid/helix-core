# helix-api production image. helix-api *is* this repo now (no more
# nested helix-api/ subdirectory -- see docs/decisions.md for why), so this
# builds the workspace root package directly.
#
# @helixid/did-hedera is declared as a pnpm git dependency
# (github:helixid/helix-sdk-js#path:did-hedera, see pnpm-workspace.yaml's
# allowBuilds), but that repo is currently *private* -- this image has no
# git credentials for it, so a plain `pnpm install` can't fetch it here
# (the same reason each example's node.Dockerfile vendors its sibling
# packages instead of installing them from git).
#
# TODO(helixid/helix-sdk-js visibility): once helix-sdk-js is public, delete
# the vendoring below, restore `context: ../..` / `dockerfile: Dockerfile`
# in both examples' docker-compose.yml, and go back to a plain
# `pnpm install --filter @helixid/api`.
#
# Build context: the parent directory containing all four split repos.
FROM node:24.15.0-alpine AS builder

WORKDIR /app
RUN corepack enable
# better-sqlite3 and argon2 have native (node-gyp) build steps.
RUN apk add --no-cache python3 make g++ git

COPY helix-server/package.json helix-server/pnpm-lock.yaml helix-server/pnpm-workspace.yaml helix-server/tsconfig.base.json ./
# pnpm-workspace.yaml's globs (examples/*, examples, e2e) need a package.json
# present for every matching directory or pnpm's workspace scan complains --
# we don't need to build any of these for the api image, just satisfy it.
# Only "name" is kept: the real files declare sibling-repo file:/git: deps
# (e2e-consent-demo, e2e-consent-demo-hosted, e2e-travel-concierge,
# e2e-travel-concierge-hosted) that pnpm would otherwise try to resolve
# during its whole-workspace scan, even under --filter @helixid/api.
COPY helix-server/e2e/package.json ./e2e/
COPY helix-server/examples/package.json ./examples/
COPY helix-server/examples/e2e-consent-demo/package.json ./examples/e2e-consent-demo/
COPY helix-server/examples/e2e-consent-demo-hosted/package.json ./examples/e2e-consent-demo-hosted/
COPY helix-server/examples/e2e-travel-concierge/package.json ./examples/e2e-travel-concierge/
COPY helix-server/examples/e2e-travel-concierge-hosted/package.json ./examples/e2e-travel-concierge-hosted/
COPY helix-server/examples/framework-middleware/package.json ./examples/framework-middleware/
RUN for f in e2e/package.json examples/package.json examples/e2e-consent-demo/package.json examples/e2e-consent-demo-hosted/package.json examples/e2e-travel-concierge/package.json examples/e2e-travel-concierge-hosted/package.json examples/framework-middleware/package.json; do \
      node -e "const j = require('./$f'); require('fs').writeFileSync('$f', JSON.stringify({ name: j.name, version: j.version, private: true }, null, 2));"; \
    done

# Vendored, pre-built @helixid/did-hedera (built via `pnpm --filter
# @helixid/did-hedera build` in the helix-sdk-js repo). Only dist/ +
# package.json are needed -- helix-api resolves it via "main"/"exports".
COPY helix-sdk-js/did-hedera/dist helix-sdk-js/did-hedera/dist
COPY helix-sdk-js/did-hedera/package.json helix-sdk-js/did-hedera/package.json
RUN node -e "const f = 'helix-sdk-js/did-hedera/package.json'; const j = require('./' + f); delete j.scripts; require('fs').writeFileSync(f, JSON.stringify(j, null, 2));" \
 && npm pkg set "dependencies.@helixid/did-hedera=file:/app/helix-sdk-js/did-hedera" \
 && npm pkg delete "devDependencies.@helixid/sdk-js"

RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --no-frozen-lockfile

COPY helix-server/src src
COPY helix-server/tests tests
COPY helix-server/prisma prisma
COPY helix-server/tsconfig.json helix-server/tsconfig.build.json helix-server/vitest.config.ts helix-server/prisma.config.ts ./
COPY helix-server/package.json ./
# The COPY above brings back the real (unpatched) package.json, clobbering
# the in-place edit from above -- re-apply it, since the build step below
# reads package.json fresh rather than reusing the earlier in-memory patch.
RUN npm pkg set "dependencies.@helixid/did-hedera=file:/app/helix-sdk-js/did-hedera" \
 && npm pkg delete "devDependencies.@helixid/sdk-js"

RUN pnpm run build

# `pnpm deploy` (isolate prod-only deps into a self-contained directory,
# dropping workspace symlinks) is unreliable once the deployed package
# *is* the workspace root itself: its --prod output still listed
# devDependencies in package.json, and re-running `prisma generate`
# against that output failed to resolve @prisma/client even though the
# symlink was actually present -- some part of `pnpm deploy`'s dependency
# re-resolution behaves differently for the root package than for a
# nested one. Simpler and reliable: carry this /app checkout's own
# node_modules forward as-is -- it already has a correctly generated
# Prisma client (from the build step above) and every prod dependency
# resolved, at the cost of also carrying devDependencies into the image
# (no lean prod-only reinstall). Revisit if image size becomes a real
# concern; correctness over leanness for now.

FROM node:24.15.0-alpine AS runner

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/prisma ./prisma

EXPOSE 3000

CMD ["node", "dist/server.js"]
