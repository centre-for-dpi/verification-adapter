# CREDEBL Inji Adapter

A Node.js service that sits between [Inji Verify](https://docs.mosip.io/inji/inji-verify) and multiple W3C Verifiable Credential verification backends. It auto-detects credential formats (JSON-LD, JSON-XT, PixelPass QR), routes to the appropriate backend based on issuer DID method and proof type, and supports offline verification using cached issuer keys.

## Features

- **Multi-backend routing** -- inspects the credential's issuer DID method and proof type to route to either a [CREDEBL](https://docs.credebl.id/docs) agent (credo-ts) or the Inji Verify Service
- **Format auto-detection** -- accepts raw JSON-LD credentials, [JSON-XT](https://www.npmjs.com/package/jsonxt) compressed URIs, and [@mosip/pixelpass](https://www.npmjs.com/package/@mosip/pixelpass) base45+zlib-encoded QR data
- **Offline verification** -- caches issuer DID documents and public keys in SQLite, performs local Ed25519/secp256k1 signature verification when upstream services are unreachable
- **JSON-LD context proxy** -- serves cached W3C and security JSON-LD contexts locally so credential processing doesn't depend on external context servers

## Architecture

```txt
Inji Verify UI  ──▶  NGINX Proxy  ──▶  Verification Adapter (:8085)
                                            │
                               ┌────────────┴────────────┐
                               ▼                         ▼
                        CREDEBL Agent              Inji Verify Service
                     (did:polygon,indy,          (did:web,key,jwk +
                      sov,peer + secp256k1)       Ed25519,RSA,JWS)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed data flow diagrams.

## Quick Start

### Prerequisites

- Node.js >= 18
- A running [CREDEBL](https://docs.credebl.id/docs) agent instance (for `did:polygon` and other credo-ts-supported credentials)
- Inji Verify Service (for `did:web`/`did:key`/`did:jwk` with standard proof types)

### Local

```bash
npm install

# Online-only adapter (routes to backends)
node adapter.js

# Offline-capable adapter (recommended -- adds SQLite issuer cache + auto online/offline failover)
node offline-adapter.js
```

### Docker

```bash
docker build -t credebl/verification-adapter .
docker run -p 8085:8085 \
  -e CREDEBL_AGENT_URL=http://host.docker.internal:8004 \
  -e CREDEBL_API_KEY=supersecret-that-too-16chars \
  -v adapter-cache:/app/cache \
  credebl/verification-adapter
```

### Docker Compose

```bash
docker compose up -d
```

The compose file expects an external `docker-deployment_default` network (the CREDEBL stack network).

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `ADAPTER_PORT` | `8085` | Port the adapter listens on |
| `CREDEBL_AGENT_URL` | `http://localhost:8004` | CREDEBL agent base URL |
| `CREDEBL_API_KEY` | `supersecret-that-too-16chars` | API key for the CREDEBL agent `/agent/token` endpoint |
| `UPSTREAM_VERIFY_SERVICE` | `http://verify-service:8080` | Inji Verify Service URL |
| `POLYGON_RPC_URL` | `https://rpc-amoy.polygon.technology` | Polygon RPC endpoint for direct DID resolution |
| `CACHE_DB` | `./cache/issuer-cache.db` | SQLite database path for the issuer cache |
| `CACHE_TTL_MS` | `604800000` (7 days) | Cache entry time-to-live in milliseconds |
| `CONTEXT_PROXY_PORT` | `8086` | JSON-LD context proxy port |
| `CONTEXTS_DIR` | `./contexts` | Directory containing cached JSON-LD context files |
| `USE_OFFLINE_ADAPTER` | `true` | Docker: use `offline-adapter.js` instead of `adapter.js` |
| `RUN_CONTEXT_PROXY` | `true` | Docker: start `context-proxy.js` alongside the adapter |

## API

### Verification

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/v1/verify/vc-verification` | Verify a credential (Inji Verify v1 compatible) |
| `POST` | `/v1/verify/vc-verification/v2` | Verify a credential (v2 format with per-check results) |
| `POST` | `/verify-offline` | Force offline verification using local cache only |

The verification endpoint accepts multiple input formats in the request body:

- **JSON** -- `{ "verifiableCredentials": [vc] }`, `{ "credential": vc }`, `{ "verifiableCredential": vc }`, or a raw credential object (has `@context`)
- **JSON-XT URI** -- a `jxt:...` string, either as `text/plain` body or inside a JSON field
- **PixelPass QR data** -- base45-encoded string (auto-detected and decoded via `@mosip/pixelpass`)

These can be nested: PixelPass data may decode to a JSON-XT URI, which in turn expands to a full JSON-LD credential.

**Example:**

```bash
curl -X POST http://localhost:8085/v1/verify/vc-verification \
  -H 'Content-Type: application/json' \
  -d '{
    "verifiableCredentials": [{
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiableCredential"],
      "issuer": "did:polygon:0xD3A288...",
      "credentialSubject": { ... },
      "proof": { ... }
    }]
  }'
```

**Response:**

```json
{
  "verificationStatus": "SUCCESS",
  "online": true,
  "backend": "credebl-agent",
  "vc": { "...decoded credential..." },
  "verifiableCredential": { "...decoded credential..." }
}
```

### Cache & Sync (offline-adapter only)

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/sync` | Pre-cache issuer DID document(s) for offline use |
| `GET` | `/cache` | View cache statistics and cached issuers |
| `GET` | `/templates` | Retrieve loaded JSON-XT templates |

```bash
# Pre-cache issuers while online
curl -X POST http://localhost:8085/sync \
  -H 'Content-Type: application/json' \
  -d '{"dids": ["did:polygon:0xD3A288e4cCeb5ADE57c5B674475d6728Af3bD9Fd"]}'
```

### Health

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Health check with connectivity and cache status |

## Routing Logic

The adapter inspects each credential's issuer DID method and proof type to pick a backend:

| Condition | Backend |
| --- | --- |
| `did:polygon`, `did:indy`, `did:sov`, `did:peer` | CREDEBL Agent |
| Proof type `EcdsaSecp256k1Signature2019` | CREDEBL Agent |
| `did:web`/`did:key`/`did:jwk` with `Ed25519Signature2018`, `RsaSignature2018`, or `JsonWebSignature2020` | Inji Verify Service |
| Unknown DID method or proof type | Inji Verify Service (fallback) |

## Offline Mode

The offline-capable adapter (`offline-adapter.js`) automatically switches modes based on connectivity:

1. **Connectivity monitoring** -- pings CREDEBL Agent and Inji Verify Service every 30s
2. **Issuer cache** -- SQLite database (WAL mode) stores DID documents and extracted public keys with configurable TTL
3. **Local signature verification** -- uses Node.js `crypto` for Ed25519 and secp256k1 signatures
4. **Trusted issuer fallback** -- when full cryptographic verification isn't possible offline (e.g., `Ed25519Signature2020` requires JSON-LD canonicalization), falls back to structural validation against the cached issuer
5. **`did:key` self-resolution** -- `did:key` DIDs encode their public key directly, so they never require network access
6. **Legacy migration** -- automatically migrates from a JSON file cache to SQLite on first run

Pre-cache issuers using `POST /sync` while online so their credentials can be verified offline later.

## Project Structure

```txt
├── adapter.js                 # Online-only adapter
├── offline-adapter.js         # Offline-capable adapter with SQLite cache
├── context-proxy.js           # JSON-LD context proxy server (port 8086)
├── contexts/                  # Cached JSON-LD context files
│   ├── credentials-v1.json    #   W3C Verifiable Credentials v1
│   ├── did-v1.json            #   DID Core v1
│   ├── ed25519-2020.jsonld    #   Ed25519Signature2020 suite
│   ├── security-v2.json       #   Security Vocabulary v2
│   └── security-v3.json       #   Security Vocabulary v3
├── templates/
│   └── jsonxt-templates.json  # JSON-XT templates (educ:1, empl:1)
├── Dockerfile
├── docker-compose.yml
├── ARCHITECTURE.md
└── package.json
```

## Dependencies

| Package | Purpose |
| --- | --- |
| [`@mosip/pixelpass`](https://www.npmjs.com/package/@mosip/pixelpass) | Decode PixelPass QR data (base45 + zlib decompression) |
| [`jsonxt`](https://www.npmjs.com/package/jsonxt) | Decode JSON-XT compressed credential URIs |
| [`better-sqlite3`](https://www.npmjs.com/package/better-sqlite3) | SQLite database for offline issuer key cache |

## License

Apache-2.0
