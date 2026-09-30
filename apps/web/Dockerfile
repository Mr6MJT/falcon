# Orvex/Falcon web image — Next.js. NEXT_PUBLIC_API_BASE is baked at build time, so it must
# be the PUBLIC API URL the browser will call (e.g. https://falcon.example.com/api).
# pnpm is pinned to 9.x to match the lockfile (lockfileVersion 9.0); a bare `corepack enable`
# pulls the latest pnpm (12+), which errors on ignored dependency build scripts.
FROM node:22-slim AS build
WORKDIR /app
RUN npm install -g pnpm@9
COPY apps/web/package.json apps/web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY apps/web ./
ARG NEXT_PUBLIC_API_BASE=http://localhost:8071
ENV NEXT_PUBLIC_API_BASE=$NEXT_PUBLIC_API_BASE
RUN pnpm build

FROM node:22-slim
WORKDIR /app
RUN npm install -g pnpm@9
ENV NODE_ENV=production
COPY --from=build /app ./
EXPOSE 3000
CMD ["pnpm", "start", "-p", "3000", "-H", "0.0.0.0"]
