# syntax=docker/dockerfile:1
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY --from=build /app/dist ./dist
# Circuit artifacts (3.0 MB wasm + 810 KB zkey) so the agent can generate
# real Groth16 policy proofs. They are public platform files.
COPY circuits ./circuits
# NEVER bake AGENT_SECRET into the image. Set it at runtime, e.g.:
#   fly secrets set AGENT_SECRET=<redacted>
ENV PORT=3000
EXPOSE 3000
CMD ["node", "dist/index.js"]
