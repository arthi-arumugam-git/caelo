# syntax=docker/dockerfile:1
#
# Caelo: free, local developer security scanner.
# By Irth Labs. https://caelo.sh
#
# The image is built from this repo, so it matches the tagged source exactly.
# With no arguments the image starts the MCP server over stdio, so MCP clients
# and catalogs can run it directly:
#
#   docker run --rm -i -v "$PWD:/scan" ghcr.io/arthi-arumugam-git/caelo
#
# Pass a folder to run the one-shot CLI scan instead (mount it at /scan):
#
#   docker run --rm -v "$PWD:/scan" ghcr.io/arthi-arumugam-git/caelo /scan

FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5

# The CLI lives here, kept separate from the code it scans (mounted at /scan).
WORKDIR /app

# Install production dependencies first so this layer caches across source edits.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

# Copy the same files the published npm package ships.
COPY bin ./bin
COPY lib ./lib
COPY README.md LICENSE ./

# Caelo only reads files, so run as the built-in unprivileged node user.
USER node

# A CLI scan runs against whatever is mounted at /scan.
WORKDIR /scan

# Default (no args) starts the stdio MCP server; pass /scan (or any path) for the CLI.
ENTRYPOINT ["node", "/app/bin/caelo.js"]
CMD ["--mcp"]
