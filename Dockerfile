# syntax=docker/dockerfile:1
#
# Caelo: free, local security scanner for apps built with AI coding tools.
# By Irth Labs. https://caelo.sh
#
# The image is built from this repo, so it matches the tagged source exactly.
# Scan a folder by mounting it at /scan:
#
#   docker run --rm -v "$PWD:/scan" ghcr.io/arthi-arumugam-git/caelo /scan
#
# Run the MCP server over stdio instead:
#
#   docker run --rm -i -v "$PWD:/scan" ghcr.io/arthi-arumugam-git/caelo --mcp

FROM node:20-alpine

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

# Scans run against whatever is mounted at /scan.
WORKDIR /scan

ENTRYPOINT ["node", "/app/bin/caelo.js"]
CMD ["/scan"]
