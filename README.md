# Verification Adapter

A backend-agnostic verification adapter that sits between any credential verification UI and any W3C-compliant verifier backend, with standards-compliant offline cryptographic verification. Adding a new backend (CREDEBL, walt.id, Inji Verify, or custom) is a JSON config change — no code modification.

## Why it matters

Verification adapters in CREDEBL, walt.id, and MOSIP stacks are coupled to their respective backend APIs — hardcoded endpoints, auth flows, request formats, and DID method routing. When the deployment target changes, the adapter must be rewritten. This adapter treats backends as configuration: a `Backend` interface and `backends.json` file let operators add, remove, or re-prioritise verifier backends without rebuilding the binary.

Offline verification uses URDNA2015 JSON-LD canonicalization with the W3C Data Integrity two-hash pattern (`SHA256(canon(proofOpts)) || SHA256(canon(doc))`), enabling cryptographic signature verification without network access to any backend.

## What it does

| Capability | Detail |
| --- | --- |
| VC Data Model | W3C VCDM 1.1 (`https://www.w3.org/2018/credentials/v1`) and 2.0 (`https://www.w3.org/ns/credentials/v2`) |
| Credential formats | LDP_VC (JSON-LD with proof), SD-JWT (`vc+sd-jwt` with x5c), JWT_VC_JSON (via OID4VP) |
| Online verification | Routes credentials to the correct backend by DID method, with per-backend auth, request wrapping, and response parsing |
| Offline verification | Caches issuer public keys via `/sync`, verifies Ed25519 and RSA signatures locally using URDNA2015 canonicalization |
| Backend routing | `BackendRegistry.Select(didMethod)` — config-driven, priority-ordered |
| Input decoding | PixelPass (Base45 + zlib), JSON-XT template expansion, raw JSON-LD |
| DID resolution | did:key (local), did:web (HTTPS), did:polygon (Ethereum RPC) |
| Proof types | Ed25519Signature2018/2020, EcdsaSecp256k1Signature2019, RsaSignature2018, DataIntegrityProof/eddsa-rdfc-2022 |

### W3C VC Data Model support

Both VCDM 1.1 and 2.0 credentials are handled. The adapter does not enforce a specific data model version — it passes the credential's `@context` array to the canonicalizer and backend as-is. Differences between versions are handled by the JSON-LD context definitions, not adapter logic.

| | VCDM 1.1 | VCDM 2.0 |
| --- | --- | --- |
| Context URL | `https://www.w3.org/2018/credentials/v1` | `https://www.w3.org/ns/credentials/v2` |
| Date fields | `issuanceDate`, `expirationDate` | `validFrom`, `validUntil` |
| Online (Inji Verify) | Tested, works | Supported by Inji's `LdpValidator` |
| Online (CREDEBL Agent) | Tested, works | Supported |
| Offline (CRYPTOGRAPHIC) | Tested end-to-end | Works (json-gold fetches v2 context) |
| Issuer field | String or `{id, name}` object — adapter extracts DID from both | Same |

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

# Docker (adapter + Inji Verify + walt.id)
docker compose -f docker-compose.test.yml up --build
./test/smoke.sh

# Docker with Inji Certify issuance (adds Certify v0.14.0 + Postgres + nginx)
docker network create mosip_network 2>/dev/null
docker compose -f docker-compose.test.yml -f docker-compose.certify-test.yml up --build
```

The test compose starts the adapter with `mosipid/inji-verify-service:0.16.0` and `waltid/verifier-api:0.18.2`. The Certify overlay adds `injistack/inji-certify-with-plugins:0.14.0` for credential issuance testing.

### Testing with CREDEBL

CREDEBL is 14+ NestJS microservices (NATS, Redis, PostgreSQL, agent-provisioning, credo-controller, etc.) and has no single Docker image. To test with CREDEBL:

1. Start the full CREDEBL stack from its own docker-compose (`install/docker-deployment/` or [credebl/platform](https://github.com/credebl/platform)).
2. Ensure the Credo agent is provisioned and listening on port 8004.
3. The adapter's `backends.json` already includes a `credebl-agent` entry pointing to `http://host.docker.internal:8004`. On Linux Docker (no `host.docker.internal`), use `http://172.17.0.1:8004` or add `extra_hosts: ["host.docker.internal:host-gateway"]` to the adapter service in docker-compose.
4. Credentials with `did:polygon`, `did:indy`, `did:sov`, or `did:peer` issuers will route to the CREDEBL agent. Other DID methods route to Inji Verify or walt.id.

When the CREDEBL agent is unreachable, the adapter falls back to offline verification for those DID methods (CRYPTOGRAPHIC if the issuer is cached, TRUSTED_ISSUER otherwise).

## Testing issuance → verification

### Self-signed credentials (no external issuer needed)

The `test/issue-and-verify` tool generates an Ed25519 keypair, derives a `did:key`, signs a credential with URDNA2015, and verifies it through all three paths:

```bash
cd test/issue-and-verify && go run .
```

### Inji Certify issuance (VCDM v1.0, v2.0, SD-JWT)

The `test/certify-e2e` tool issues credentials from Inji Certify v0.14.0 via the Pre-Authorized Code flow and verifies each through Inji Verify directly and the adapter. Three credential formats are tested:

| Config | Format | Data Model | Signature |
| --- | --- | --- | --- |
| FarmerCredential | `ldp_vc` | VCDM 1.1 (`issuanceDate`) | Ed25519Signature2020 |
| FarmerCredentialV2 | `ldp_vc` | VCDM 2.0 (`validFrom`) | Ed25519Signature2020 |
| FarmerCredentialSdJwt | `vc+sd-jwt` | SD-JWT (x5c) | EdDSA |

```bash
# Start the full stack (adapter + Inji Verify + Certify)
docker network create mosip_network 2>/dev/null
docker compose -f docker-compose.test.yml -f docker-compose.certify-test.yml up --build -d

# Online verification (routes to Inji Verify)
cd test/certify-e2e && go run . \
  --adapter http://localhost:8085 \
  --certify http://localhost:8090/v1/certify \
  --certify-nginx http://localhost:8091 \
  --inji-verify http://localhost:8082

# Offline verification (syncs issuer DID, verifies locally)
go run . \
  --adapter http://localhost:8085 \
  --certify http://localhost:8090/v1/certify \
  --certify-nginx http://localhost:8091 \
  --inji-verify http://localhost:8082 \
  --offline
```

Output:

```txt
━━━ Test 1: VCDM v1.0 (ldp_vc) ━━━
  Issued: ldp_vc (1882 bytes)
  Verify A: Inji Verify direct... SUCCESS
  Verify B: Adapter (auto)... SUCCESS

━━━ Test 2: VCDM v2.0 (ldp_vc) ━━━
  Issued: ldp_vc (2244 bytes)
  Verify A: Inji Verify direct... SUCCESS
  Verify B: Adapter (auto)... SUCCESS

━━━ Test 3: SD-JWT (vc+sd-jwt) ━━━
  Issued: vc+sd-jwt (6441 chars)
  Verify A: Inji Verify direct... SUCCESS
  Verify B: Adapter (auto)... SUCCESS

═══════════════════════════════
  Results: 6/6 passed
═══════════════════════════════
```

The Certify issuance uses the Pre-Authorized Code flow with `PreAuthDataProviderPlugin`, which accepts credential claims directly without eSignet. Certify acts as its own OAuth authorization server. The issuer DID is `did:web:certify-nginx`, resolved over HTTPS via a self-signed certificate on the nginx proxy.

### Physical QR code testing (scan with Inji Verify UI)

Issue credentials and generate QR codes for physical scanning:

```bash
# 1. Issue all three credential formats (saves to /tmp)
cd test/certify-e2e && go run . \
  --adapter http://localhost:8085 \
  --certify http://localhost:8090/v1/certify \
  --certify-nginx http://localhost:8091 \
  --inji-verify http://localhost:8082

# 2. Generate PixelPass QR codes (Base45 + zlib compression)
python3 -c "
import sys, zlib
CHARSET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ \$%*+-./:' 
def base45_encode(data):
    result = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            n = data[i] * 256 + data[i+1]
            c, n = divmod(n, 45*45)
            b, a = divmod(n, 45)
            result.extend([CHARSET[a], CHARSET[b], CHARSET[c]])
        else:
            b, a = divmod(data[i], 45)
            result.extend([CHARSET[a], CHARSET[b]])
    return ''.join(result)
for name in ['FarmerCredential', 'FarmerCredentialV2']:
    with open(f'/tmp/certify-{name}.json', 'rb') as f:
        data = f.read()
    encoded = base45_encode(zlib.compress(data))
    with open(f'/tmp/qr-{name}.txt', 'w') as f:
        f.write(encoded)
    print(f'{name}: {len(data)} bytes -> {len(encoded)} chars')
"

# 3. Generate QR code images (requires qrencode)
qrencode -o /tmp/qr-v1.png -l L -s 4 < /tmp/qr-FarmerCredential.txt
qrencode -o /tmp/qr-v2.png -l L -s 4 < /tmp/qr-FarmerCredentialV2.txt

# 4. Open QR code image and Inji Verify UI
xdg-open /tmp/qr-v1.png          # display QR on screen
xdg-open http://localhost:3001    # open Inji Verify UI

# 5. Scan the QR code with the Inji Verify UI scanner
```

The Inji Verify UI at `localhost:3001` routes verification requests through the adapter via nginx. The adapter decodes the PixelPass QR (Base45 → zlib → JSON-LD), resolves the Certify issuer's DID, and verifies the Ed25519Signature2020 proof.

**Inji Verify UI rendering patch:** The Inji Verify UI 0.16.0 has hardcoded credential type renderers. It crashes with `Cannot read properties of undefined (reading 'farmerCredentialRenderOrder')` after successful verification because `FarmerCredential` is not in its built-in renderer switch. The verification succeeds (visible in the browser Network tab) but the UI fails to display the result. To fix, patch the JS to remove the `FarmerCredential` case so it falls through to the generic `default` renderer:

```bash
# Copy, patch, and replace the main JS bundle
docker cp inji-verify-ui:/usr/share/nginx/html/static/js/main.b48651be.js /tmp/inji-verify-main.js

python3 -c "
with open('/tmp/inji-verify-main.js') as f: c = f.read()
c = c.replace('case\"FarmerCredential\":return Nv(hv().farmerCredentialRenderOrder,a,t);', '')
with open('/tmp/inji-verify-main.js', 'w') as f: f.write(c)
print('Patched')
"

docker cp /tmp/inji-verify-main.js inji-verify-ui:/usr/share/nginx/html/static/js/main.b48651be.js
# Hard refresh the browser: Ctrl+Shift+R
```

After patching, the UI uses its built-in default renderer which displays all credential subject fields generically.

SD-JWT credentials (6441 chars) exceed the QR code capacity limit (~4296 bytes) due to the embedded x5c certificate chain. They can be verified via API:

```bash
curl -X POST http://localhost:8085/v1/verify/vc-verification \
  -H "Content-Type: application/vc+sd-jwt" \
  -d @/tmp/certify-FarmerCredentialSdJwt.jwt
```

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

| Scenario | LDP_VC | SD-JWT (x5c) |
| --- | --- | --- |
| `/verify-offline` with network | CRYPTOGRAPHIC | CRYPTOGRAPHIC |
| `/verify-offline` after restart, with network | CRYPTOGRAPHIC | CRYPTOGRAPHIC |
| `--network none` (true air-gap) | TRUSTED_ISSUER | **CRYPTOGRAPHIC** |

**LDP_VC air-gap limitation:** json-gold's `DefaultDocumentLoader` does not bundle W3C contexts — it always fetches over HTTP. In a true air-gap, canonicalization fails and the adapter falls back to `TRUSTED_ISSUER`. Pre-cached contexts (via the archived WASM module or a custom document loader) would be needed for CRYPTOGRAPHIC in a true air-gap.

**SD-JWT works in a true air-gap** because the issuer's public key is embedded in the JWT header as an X.509 certificate (`x5c` claim). No context fetching, no DID resolution, no network access needed. The adapter parses the JWT, extracts the cert, and verifies the EdDSA/ES256/RS256 signature locally. Tested with `docker run --network none`.

### CBOR / MOSIP Claim 169

The adapter also decodes MOSIP Claim 169 QR codes — CBOR-encoded credentials wrapped in COSE_Sign1 and compressed via PixelPass (Base45 + zlib). This is a different format from the JSON-based W3C VCs that the adapter's existing PixelPass path handles.

After Base45 → zlib decompression, the adapter inspects the first byte to determine the payload type:

- `{` (0x7b) or `j` → JSON or JSON-XT URI → existing W3C VC path
- `0x80`-`0xff` → CBOR → decode COSE_Sign1 → extract Claim 169 map → convert to JSON

The CBOR decoder maps integer keys to field names per the [Claim 169 specification](https://docs.mosip.io/1.2.0/readme/standards-and-specifications/mosip-standards/169-qr-code-specification) (1=fullName, 2=dateOfBirth, 23=UIN, etc.) and outputs a JSON object. Claim 169 credentials are not W3C VCs — they use COSE_Sign1 signatures (RFC 8152), not JSON-LD Data Integrity proofs. COSE signature verification is a separate concern from the adapter's W3C VC verification pipeline.

### Full test results

**Inji Certify issuance → verification (6 tests × 2 modes = 12 total):**

| Format | Inji Verify direct | Adapter online | Adapter offline |
| --- | --- | --- | --- |
| VCDM v1.0 (`ldp_vc`, Ed25519Signature2020) | SUCCESS | SUCCESS | SUCCESS |
| VCDM v2.0 (`ldp_vc`, Ed25519Signature2020) | SUCCESS | SUCCESS | SUCCESS |
| SD-JWT (`vc+sd-jwt`, EdDSA, x5c) | SUCCESS | SUCCESS | SUCCESS |

**Air-gap verification (`--network none`):**

| Format | Result | Why |
| --- | --- | --- |
| LDP_VC | TRUSTED_ISSUER | Context fetch fails, structural check only |
| SD-JWT (x5c) | **CRYPTOGRAPHIC** | x5c cert is self-contained, no network needed |

**Other formats:**

```txt
CBOR / Claim 169
  PixelPass decode:           Works (CBOR → JSON conversion)
  VC verification:            N/A (Claim 169 is not a W3C VC —
                              COSE_Sign1 verification is separate)
```

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
