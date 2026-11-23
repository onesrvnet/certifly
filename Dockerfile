# syntax=docker/dockerfile:1

FROM oven/bun:1 AS build
WORKDIR /app
COPY package.json bun.lock ./
COPY packages/core/package.json packages/core/
COPY packages/db/package.json packages/db/
COPY packages/keyvault/package.json packages/keyvault/
COPY packages/pki/package.json packages/pki/
COPY packages/shared/package.json packages/shared/
RUN bun install --frozen-lockfile --ignore-scripts
COPY . .
# No database credentials here: NuxtHub bundles the generated migrations into the output
# (.output/server/db/migrations) and the server applies them when it starts.
RUN bunx nuxt build

FROM node:24-alpine AS runtime
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000
WORKDIR /app
COPY --from=build --chown=node:node /app/.output ./.output
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD wget -qO- http://127.0.0.1:3000/_health || exit 1
CMD ["node", ".output/server/index.mjs"]
