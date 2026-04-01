FROM node:20-alpine

LABEL maintainer="CREDEBL"
LABEL description="Offline-capable verification adapter with SQLite-backed issuer cache and context proxy"

WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++

# Create directories
RUN mkdir -p /app/cache /app/contexts /app/templates

# Copy package.json and install dependencies
COPY package.json .
RUN npm install --production

# Copy adapters
COPY adapter.js .
COPY offline-adapter.js .
COPY context-proxy.js .

# Copy cached JSON-LD contexts
COPY contexts/ /app/contexts/

# Copy JSON-XT templates
COPY templates/ /app/templates/

# Environment variables with defaults
ENV ADAPTER_PORT=8085
ENV CONTEXT_PROXY_PORT=8086
ENV CREDEBL_AGENT_URL=http://localhost:8004
ENV CREDEBL_API_KEY=supersecret-that-too-16chars
ENV UPSTREAM_VERIFY_SERVICE=http://verify-service:8080
ENV POLYGON_RPC_URL=https://rpc-amoy.polygon.technology
ENV CACHE_FILE=/app/cache/issuer-cache.json
ENV CACHE_DB=/app/cache/issuer-cache.db
ENV CACHE_TTL_MS=604800000
ENV CONTEXTS_DIR=/app/contexts

# Use offline adapter by default
ENV USE_OFFLINE_ADAPTER=true
ENV RUN_CONTEXT_PROXY=true

EXPOSE 8085 8086

# Volume for persistent cache (SQLite database)
VOLUME /app/cache

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8085/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Start script - runs context proxy in background and main adapter
CMD ["sh", "-c", "if [ \"$RUN_CONTEXT_PROXY\" = \"true\" ]; then node context-proxy.js & fi; if [ \"$USE_OFFLINE_ADAPTER\" = \"true\" ]; then node offline-adapter.js; else node adapter.js; fi"]
