# Verification Adapter

A backend-agnostic verification adapter that sits between any credential verification UI and any W3C-compliant verifier backend, with standards-compliant offline cryptographic verification. Adding a new backend (CREDEBL, walt.id, Inji Verify, or custom) is a JSON config change — no code modification.

## Why it matters

Verification adapters in CREDEBL, walt.id, and MOSIP stacks are coupled to their respective backend APIs — hardcoded endpoints, auth flows, request formats, and DID method routing. When the deployment target changes, the adapter must be rewritten. This adapter treats backends as configuration: a `Backend` interface and `backends.json` file let operators add, remove, or re-prioritise verifier backends without rebuilding the binary.

Offline verification uses URDNA2015 JSON-LD canonicalization with the W3C Data Integrity two-hash pattern (`SHA256(canon(proofOpts)) || SHA256(canon(doc))`), enabling cryptographic signature verification without network access to any backend.

## What it does

| Capability | Detail |
| --- | --- |
| Online verification | Routes credentials to the correct backend by DID method, with per-backend auth, request wrapping, and response parsing |
| Offline verification | Caches issuer public keys via `/sync`, verifies Ed25519 and RSA signatures locally using URDNA2015 canonicalization |
| Backend routing | `BackendRegistry.Select(didMethod)` — config-driven, priority-ordered |
| Input decoding | PixelPass (Base45 + zlib), JSON-XT template expansion, raw JSON-LD |
| DID resolution | did:key (local), did:web (HTTPS), did:polygon (Ethereum RPC) |
| Proof types | Ed25519Signature2018/2020, EcdsaSecp256k1Signature2019, RsaSignature2018, DataIntegrityProof/eddsa-rdfc-2022 |

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/verify/vc-verification` | Verify credential (auto online/offline) |
| POST | `/verify-offline` | Force offline verification |
| POST | `/sync` | Cache issuer DID(s) for offline use |
| GET | `/cache` | Cache statistics |
| GET | `/templates` | JSON-XT templates |
| GET | `/health` | Per-backend connectivity status |

## Backend configuration

Backends are declared in a JSON file (set `BACKENDS_CONFIG` env var). Without a config file, the adapter falls back to CREDEBL + Inji Verify defaults from legacy env vars.

```json
{
  "backends": [
    {
      "name": "inji-verify",
      "url": "http://inji-verify-service:8080",
      "verifyPath": "/v1/verify/vc-verification",
      "healthPath": "/v1/verify/actuator/health",
      "contentType": "application/vc+ld+json",
      "didMethods": ["did:web", "did:key", "did:jwk"],
      "successField": "verificationStatus",
      "successValue": "SUCCESS"
    },
    {
      "name": "waltid-verifier",
      "url": "http://waltid:7003",
      "verifyPath": "/openid4vc/verify",
      "healthPath": "/health",
      "didMethods": ["did:jwk", "did:web", "did:key"],
      "wrapField": "vp_token",
      "successField": "verified"
    }
  ]
}
```

Each entry declares its own auth (`tokenPath`, `apiKey`), request format (`wrapField`, `wrapArray`, `contentType`), response parsing (`successField`, `successValue`), and optional DID resolution (`resolvePath`, `resolveDocField`). Backends are selected in registration order.

## Running

```bash
# Local
go run .

# With backends config
BACKENDS_CONFIG=./backends.json go run .

# Docker
docker compose -f docker-compose.test.yml up --build
./test/smoke.sh
```

The test compose starts the adapter with `mosipid/inji-verify-service:0.16.0` and `waltid/verifier-api:0.18.2`.

### Testing with CREDEBL

CREDEBL is 14+ NestJS microservices (NATS, Redis, PostgreSQL, agent-provisioning, credo-controller, etc.) and has no single Docker image. To test with CREDEBL:

1. Start the full CREDEBL stack from its own docker-compose (`install/docker-deployment/` or [credebl/platform](https://github.com/credebl/platform)).
2. Ensure the Credo agent is provisioned and listening on port 8004.
3. The adapter's `backends.json` already includes a `credebl-agent` entry pointing to `http://host.docker.internal:8004`. On Linux Docker (no `host.docker.internal`), use `http://172.17.0.1:8004` or add `extra_hosts: ["host.docker.internal:host-gateway"]` to the adapter service in docker-compose.
4. Credentials with `did:polygon`, `did:indy`, `did:sov`, or `did:peer` issuers will route to the CREDEBL agent. Other DID methods route to Inji Verify or walt.id.

When the CREDEBL agent is unreachable, the adapter falls back to offline verification for those DID methods (CRYPTOGRAPHIC if the issuer is cached, TRUSTED_ISSUER otherwise).

## Testing issuance → verification

The `test/issue-and-verify` tool generates an Ed25519 keypair, derives a `did:key`, signs a credential with URDNA2015, and verifies it through all three paths:

```bash
cd test/issue-and-verify && go run .
```

Output:

```txt
Direct Inji:     SUCCESS
Adapter→Inji:    SUCCESS (backend: inji-verify)
Adapter offline:  SUCCESS (level: CRYPTOGRAPHIC)
```

Credentials from credissuer.com (Ed25519Signature2020) and Inji Certify (RsaSignature2018) verify through the adapter. Walt.id's `issuer-api:0.18.2` issues `jwt_vc_json` format natively; for `ldp_vc` credentials, sign with json-gold using the walt.id-onboarded keypair.

## Testing offline verification

`POST /verify-offline` forces offline mode regardless of backend connectivity. The adapter looks up the issuer's cached public key in SQLite and verifies the signature locally using URDNA2015 canonicalization.

**Prerequisite:** sync the issuer while online so the public key is cached:

```bash
curl -X POST http://localhost:8085/sync \
  -H "Content-Type: application/json" \
  -d '{"did": "did:web:did.credissuer.com:d2bd3fa6-48d4-4f30-8be5-83f4c48fa088"}'
```

Then verify offline:

```bash
curl -X POST http://localhost:8085/verify-offline \
  -H "Content-Type: application/json" \
  -d @credential.json
```

### True air-gap test

To simulate a fully disconnected environment, run the adapter with `--network none`:

```bash
# Copy the SQLite cache from the running adapter
docker cp adapter:/app/cache/issuer-cache.db /tmp/issuer-cache.db

# Run with no network
docker run --rm --network none \
  -v /tmp/issuer-cache.db:/app/cache/issuer-cache.db \
  adapter-standalone-adapter
```

### Offline verification levels by network state

| Scenario | Result | Why |
| --- | --- | --- |
| `/verify-offline` with network | CRYPTOGRAPHIC | json-gold fetches `@context` URLs over HTTP, canonicalizes, verifies signature |
| `/verify-offline` after restart, with network | CRYPTOGRAPHIC | json-gold re-fetches contexts (no persistent context cache) |
| `--network none` (true air-gap) | TRUSTED_ISSUER | Context fetch fails → canonicalization fails → falls back to structural check |

json-gold's `DefaultDocumentLoader` does not bundle W3C contexts — it always fetches over HTTP. In a true air-gap, canonicalization fails for any credential whose `@context` URLs are not reachable, and the adapter falls back to `TRUSTED_ISSUER` (issuer DID matches cache, proof structure valid, but no cryptographic signature check).

For CRYPTOGRAPHIC verification in a true air-gap, the adapter would need pre-cached JSON-LD contexts — either embedded in the binary or loaded from a local file at startup. This is what the WASM module with embedded contexts solved (archived to `~/Projects/2026/adapter-wasm-archive/`), and what Inji Verify's `LocalDocumentLoader` does internally.

## Why Inji Verify rejects some cross-platform credentials and how the adapter handles it

### Content-Type

Inji Verify's `/vc-verification` endpoint passes `@RequestBody String vc` directly to the MOSIP `vcverifier-jar`. When the body is `{"verifiableCredentials": [cred]}` with `Content-Type: application/json`, the library receives the wrapper object as the credential string and fails to parse it. The fix: send the raw credential as the body with `Content-Type: application/vc+ld+json`. The adapter's Inji backend preset does this automatically.

### Unknown types without @context

Inji uses Titanium JSON-LD for context expansion. Custom credential types (e.g. `UniversityDegree`) without an `@context` definition cause `INVALID_LOCAL_CONTEXT`. Adding `{"@vocab": "https://example.org/vocab#"}` to the `@context` array gives unknown terms a fallback IRI.

### Canonicalization output across implementations

All three URDNA2015 implementations produce **identical N-Quads** for the same input document:

| Implementation | Language | Used by |
| --- | --- | --- |
| json-gold | Go | This adapter (signing + offline verification) |
| Titanium JSON-LD + rdf-urdna | Java | Inji Verify (online verification) |
| @digitalbazaar/jsonld (WASM via Javy/wazero) | JS in WASM | archived |

The divergence that causes verification failures is not in the URDNA2015 algorithm. It is in **what gets canonicalized** (Content-Type causing the wrong string to be parsed) and **what terms are expandable** (missing `@vocab` for custom types). When these are handled correctly, json-gold-signed credentials verify in Inji Verify without modification.

### SD-JWT

The adapter passes SD-JWT credentials (`Content-Type: application/vc+sd-jwt`) through to backends as raw strings — no JSON-LD canonicalization involved. The token body (including trailing `~`) is forwarded with the original content type preserved.

**Working flow:** Inji Verify 0.16.0's SD-JWT verifier (`SdJwtVerifier` in `vcverifier-jar:1.6.0`) resolves the issuer's public key exclusively from the `x5c` claim in the JWT header — an X.509 certificate chain, not a DID. It does not call the `PublicKeyResolverFactory` that the LDP verifier uses for `did:key`/`did:web` resolution. This means:

| Issuer key source | SD-JWT verification |
| --- | --- |
| `x5c` in JWT header (X.509 cert) | **Works** |
| `kid` referencing a DID | Does not work (no DID resolution in SD-JWT path) |

To issue an SD-JWT that Inji Verify accepts: generate an Ed25519 keypair, create a self-signed X.509 certificate, include it in the JWT header as `x5c`, and sign with EdDSA. The trailing `~` is required even with no selective disclosures. Tested end-to-end with `mosipid/inji-verify-service:0.16.0`.

## References

- [W3C RDF Dataset Canonicalization](https://www.w3.org/TR/rdf-canon/)
- [W3C Verifiable Credentials Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
- [Node.js Adapter (original but tightly coupled to CREDBL)](./nodejs-credebl-inji-adapter/)
- [Architecture Documentation](./verification-adapter/ARCHITECTURE.md)
