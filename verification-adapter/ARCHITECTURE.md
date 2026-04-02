# Architecture

## System context

```txt
┌─────────────────────┐
│   Verification UI   │  Inji Verify UI, mobile app, curl
│   (any client)      │
└─────────┬───────────┘
          │ POST /v1/verify/vc-verification
          │      /verify-offline
          │      /sync
          ▼
┌─────────────────────┐
│      Adapter        │  This service. Single Go binary.
│   :8085             │  Routes by DID method, verifies offline.
└──┬──────┬──────┬────┘
   │      │      │
   ▼      ▼      ▼
┌──────┐┌──────┐┌──────────────┐
│ Inji ││walt. ││   CREDEBL    │  Any backend declared
│Verify││id    ││   Agent      │  in backends.json.
│:8080 ││:7003 ││   :8004      │
└──────┘└──────┘└──────────────┘
```

The adapter sits between the verification UI and one or more verification backends. It decides whether to route online or verify locally, based on connectivity and cached issuer keys.

## Request lifecycle

```txt
Request arrives (POST /v1/verify/vc-verification)
  │
  ├─ Content-Type contains "sd-jwt"?
  │   YES → VerifySDJWT(): raw passthrough to each backend until one returns SUCCESS/INVALID
  │   (no JSON parsing, no canonicalization)
  │
  NO ↓
  │
  ├─ ParseRequestBody()
  │   ├─ PixelPass encoded? → base45 decode → zlib decompress
  │   ├─ JSON-XT URI? → template expansion → full JSON-LD credential
  │   └─ Plain JSON? → parse, check nested fields for JSON-XT URIs
  │
  ├─ ExtractCredential()
  │   Accepts: verifiableCredentials[], credential, verifiableCredential,
  │            credentialDocument, or raw body with @context
  │
  ├─ extractIssuerDID() → extractDidMethod()
  │   "did:key:z6Mk..." → "did:key"
  │
  ├─ connectivity.IsOnline(didMethod)?
  │
  │   ONLINE ↓                              OFFLINE ↓
  │   registry.Select(didMethod)            cache.Get(issuerDID)
  │     │                                     │
  │     ├─ backend found                      ├─ cached → VerifyCredentialSignature()
  │     │   → backend.Verify()                │   ├─ SUCCESS → CRYPTOGRAPHIC
  │     │   (builds request per config:       │   └─ error → validateStructure()
  │     │    wrapField, contentType,          │       ├─ valid → TRUSTED_ISSUER
  │     │    auth, successField)              │       └─ invalid → INVALID
  │     │                                     │
  │     └─ no backend                         ├─ not cached, did:key?
  │         → fall back to OFFLINE ↗          │   → ResolveDidKey() (local, no network)
  │                                           │   → cache + retry verification
  │                                           │
  │                                           └─ not cached → UNKNOWN_ISSUER
  └───────────────────────────────────────────────┘
```

## File map

```txt
adapter-standalone/
├── main.go              Entrypoint. Wires config → cache → registry → connectivity → server.
├── config.go            LoadConfig() from env vars. LoadBackends() from backends.json or env fallback.
├── backend.go           Backend interface, BackendRegistry, ConfigurableBackend (data-driven HTTP client).
│                        Preset factories: CredeblBackendConfig, InjiVerifyBackendConfig, WaltIDBackendConfig.
├── verify.go            Adapter struct. VerifyCredential (online/offline dispatch), VerifySDJWT (raw passthrough),
│                        SyncIssuer (backend resolver → direct DID resolution fallback), ParseRequestBody.
├── server.go            HTTP handlers, CORS middleware, SD-JWT content-type detection.
├── connectivity.go      Per-backend health probes. IsOnline(didMethod), IsAnyOnline(), Status().
├── cache.go             SQLite issuer cache. TTL expiry, legacy JSON migration, stats.
├── canon.go             Canonicalizer interface + NativeCanonicalizer (json-gold, URDNA2015).
├── signature.go         VerifyCredentialSignature: two-hash pattern, Ed25519, secp256k1, RSA PKCS#1v1.5.
├── did.go               DID resolution: did:key (local), did:web (HTTPS), did:polygon (eth_call).
│                        Public key extraction: multibase, hex, base58, JWK (Ed25519, secp256k1, RSA).
├── decode.go            PixelPass (Base45 + zlib per RFC 9285), JSON-XT template expansion.
├── backends.json        Default backend config: inji-verify, waltid-verifier, credebl-agent.
├── Dockerfile                Multi-stage: golang:1.24-alpine → alpine:3.21. CGO_ENABLED=0.
├── docker-compose.test.yml   Test stack: adapter + inji-verify + walt.id verifier/issuer/wallet.
├── docker-compose.certify-test.yml   Overlay: adds Inji Certify v0.14.0 issuance stack.
└── test/
    ├── smoke.sh                    Health + connectivity + basic verification checks.
    ├── issue-and-verify/main.go    Signs credential with json-gold, verifies through all paths.
    ├── certify-e2e/main.go         Issues VCDM v1.0, v2.0, SD-JWT via Certify Pre-Auth Code,
    │                               verifies each through Inji Verify direct + adapter.
    ├── certify-test.sh             Runner: starts Certify stack, waits, runs E2E.
    ├── certify/                    Certify config: SQL init (3 credential configs), nginx (HTTP+HTTPS),
    │                               self-signed TLS cert, farmer CSV data, properties.
    ├── inji-ui/                    Inji Verify UI config + nginx proxy.
    └── waltid-*/config/            Minimal walt.id verifier/issuer/wallet configuration.
```

## Backend interface

```go
type Backend interface {
    Name() string
    CanVerify(didMethod string) bool
    Verify(credential map[string]any) VerificationResult      // JSON-LD credentials
    VerifyRaw(token string, contentType string) VerificationResult  // SD-JWT, raw strings
    HealthEndpoint() string
}
```

`ConfigurableBackend` implements this entirely from `BackendConfig` data — endpoint paths, auth, request wrapping, response parsing. Adding a backend is a JSON entry, not Go code.

`DIDResolverBackend` is an optional extension for backends that can resolve DID documents (used by `/sync`).

## JSON-LD verification flow

```txt
┌──────────────────────────────────────────────────────────────────────┐
│  Input: W3C Verifiable Credential (JSON-LD with proof)               │
│                                                                      │
│  {                                                                   │
│    "@context": ["https://www.w3.org/2018/credentials/v1", ...],      │
│    "type": ["VerifiableCredential"],                                 │
│    "issuer": "did:key:z6Mk...",                                      │
│    "credentialSubject": { ... },                                     │
│    "proof": {                                                        │
│      "type": "Ed25519Signature2020",                                 │
│      "proofValue": "z5Vad...",                                       │
│      "verificationMethod": "did:key:z6Mk...#z6Mk...",                │
│      ...                                                             │
│    }                                                                 │
│  }                                                                   │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  1. Separate document from proof                                     │
│                                                                      │
│     document = credential minus "proof" field                        │
│     proofOptions = proof minus "proofValue"/"jws", plus @context     │
│                    inherited from the document                       │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  2. Canonicalize both (URDNA2015 via json-gold)                      │
│                                                                      │
│     For each of document and proofOptions:                           │
│       a. Fetch @context URLs → expand all terms to full IRIs         │
│       b. Convert expanded JSON-LD to RDF triples                     │
│       c. Canonicalize blank node identifiers (URDNA2015)             │
│       d. Serialize as sorted N-Quads string                          │
│                                                                      │
│     json-gold's CachingDocumentLoader fetches context URLs over      │
│     HTTP on first use. Contexts are cached in memory for the         │
│     process lifetime. No persistent context cache.                   │
│                                                                      │
│     If a context URL is unreachable (true air-gap), canonicalization │
│     fails and the adapter falls back to TRUSTED_ISSUER.              │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  3. Two-hash pattern (W3C Data Integrity)                            │
│                                                                      │
│     proofHash = SHA-256( canonicalized proofOptions )                │
│     docHash   = SHA-256( canonicalized document )                    │
│     hashData  = proofHash ‖ docHash          (64 bytes)              │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  4. Extract signature from proof                                     │
│                                                                      │
│     proofValue "z..." → base58btc decode (Ed25519Signature2020)      │
│     jws "eyJ..."      → split on ".", base64url decode part 3        │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  5. Verify signature against cached public key                       │
│                                                                      │
│     Ed25519:   ed25519.Verify(pubKey, hashData, signature)           │
│     secp256k1: ecdsa.Verify(SHA256(hashData), signature, pubKey)     │
│     RSA:       rsa.VerifyPKCS1v15(pubKey, SHA256, SHA256(hashData),  │
│                                   signature)                         │
│                                                                      │
│     Public key source: SQLite cache, populated by POST /sync         │
│     Key formats: multibase, hex, base58, JWK (Ed25519, secp256k1,    │
│                  RSA)                                                │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  6. Result                                                           │
│                                                                      │
│     Signature valid   → { verificationStatus: SUCCESS,               │
│                           verificationLevel: CRYPTOGRAPHIC }         │
│     Signature invalid → { verificationStatus: INVALID }              │
│     Error (context fetch, unsupported proof type)                    │
│                       → fall back to validateStructure()             │
│                       → TRUSTED_ISSUER or INVALID                    │
└──────────────────────────────────────────────────────────────────────┘
```

## SD-JWT verification flow

```txt
┌──────────────────────────────────────────────────────────────────────┐
│  Input: SD-JWT token string                                          │
│  Content-Type: application/vc+sd-jwt                                 │
│                                                                      │
│  eyJhbGciOiJFZERTQSIsInR5cCI6InZjK3NkLWp3dCIsIng1YyI6Wy4uLl19...~ │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ├─ Online (backend reachable)?
               │
               │   YES ↓
               │   Raw passthrough to backend. No JSON parsing, no
               │   canonicalization. Token string (including trailing ~)
               │   forwarded with original Content-Type preserved.
               │   First backend returning SUCCESS or INVALID wins.
               │
               │   Backend (Inji Verify): SdJwtVerifier
               │     1. Parse JWT header → extract x5c cert chain
               │     2. x5c[0] → X.509 certificate → extract public key
               │     3. Verify EdDSA/ES256 signature over header.payload
               │     4. Validate claims: _sd_alg, typ, alg
               │     5. Validate disclosures against _sd digests
               │
               │     ⚠ Inji's SdJwtVerifier resolves keys from x5c only.
               │       did:key/did:web in kid is not resolved.
               │
               │   NO (offline / forced offline) ↓
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Adapter: local SD-JWT verification (VerifySDJWTSignature)           │
│                                                                      │
│  1. Strip trailing ~ and disclosures → extract JWT (header.payload.  │
│     signature)                                                       │
│  2. base64url decode header → extract alg and x5c certificate        │
│  3. Parse X.509 certificate → extract public key                     │
│  4. Verify signature over base64url(header) + "." + base64url(       │
│     payload) using:                                                  │
│       EdDSA → ed25519.Verify(pubKey, signingInput, sig)              │
│       ES256 → ecdsa.Verify(pubKey, SHA256(signingInput), r, s)       │
│       RS256 → rsa.VerifyPKCS1v15(pubKey, SHA256, hash, sig)          │
│                                                                      │
│  No network needed. No DID resolution. No context fetching.          │
│  The public key is extracted from the x5c certificate embedded       │
│  in the JWT header itself.                                           │
│                                                                      │
│  ✓ Works with --network none (true air-gap).                         │
│    Tested: CRYPTOGRAPHIC SUCCESS with docker run --network none.     │
└──────────────────────────────────────────────────────────────────────┘
```

## CBOR / Claim 169 decode flow

```txt
┌──────────────────────────────────────────────────────────────────────┐
│  Input: PixelPass QR data (Base45 string)                            │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  DecodePixelPass(): Base45 decode → zlib decompress                  │
│  (shared with JSON/JSON-XT path)                                     │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ├─ first byte == '{' or 'j'?
               │   YES → JSON / JSON-XT → existing W3C VC path
               │
               │   NO (0x80-0xff) → CBOR
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  decodeCBORPayload()                                                 │
│                                                                      │
│  1. Try 4-element CBOR array → COSE_Sign1                           │
│     [protected, unprotected, payload, signature]                     │
│     → extract payload bstr → decode inner CBOR map                  │
│                                                                      │
│  2. Try CBOR tag 18 (CWT) → unwrap → COSE_Sign1                    │
│                                                                      │
│  3. Try raw CBOR map (no COSE wrapper)                               │
└──────────────┬───────────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│  decodeCBORMap(): integer keys → human-readable field names          │
│                                                                      │
│  Claim 169 keys: 1=fullName, 2=dateOfBirth, 3=gender,              │
│  5=email, 6=phone, 23=UIN, 24=VID, ...                              │
│  CWT claims: 1=iss, 4=exp, 6=iat                                   │
│  Key 169 = nested Claim 169 payload (expanded inline)               │
│                                                                      │
│  Binary values (biometrics) → "[binary:N bytes]" placeholder        │
│  Output: JSON string                                                 │
└──────────────────────────────────────────────────────────────────────┘
```

Claim 169 credentials are **not W3C VCs** — they have no `@context`, no `type: VerifiableCredential`, no JSON-LD proof. They use COSE_Sign1 (RFC 8152) for signatures, not Data Integrity proofs. The adapter decodes them to JSON but does not route them through the W3C VC verification pipeline. COSE signature verification is a separate concern.

## Verification modes

### Online (LDP_VC)

The adapter selects a backend by DID method (`registry.Select`), builds a request per the backend's config (`wrapField`, `contentType`, `tokenPath`), sends it, and interprets the response (`successField`, `successValue`).

For Inji Verify: raw credential body + `Content-Type: application/vc+ld+json`. For CREDEBL Agent: `{"credential": cred}` + bearer token from `/agent/token`.

### Online (SD-JWT)

Raw token string forwarded to each backend in registration order with the original `Content-Type` preserved. First backend returning SUCCESS or INVALID wins.

### Offline (CRYPTOGRAPHIC)

The JSON-LD verification flow above, using a cached public key from SQLite. Requires network access to fetch `@context` URLs (json-gold has no persistent context cache).

### Offline (TRUSTED_ISSUER)

Fallback when cryptographic verification fails (unsupported proof type, context fetch error, true air-gap). Checks: issuer DID matches cache, proof references issuer, required VC fields present.

## Connectivity

`ConnectivityChecker` probes each registered backend's `healthPath` at a configurable interval. `IsOnline(didMethod)` returns true if at least one backend that handles that DID method is reachable. Per-backend status is exposed at `/health`.

## Cache

SQLite via `modernc.org/sqlite` (pure Go, no CGO). Schema:

```sql
issuers (did TEXT PRIMARY KEY, did_document TEXT, public_key_hex TEXT, key_type TEXT, cached_at INTEGER)
metadata (key TEXT PRIMARY KEY, value TEXT, updated_at INTEGER)
```

`/sync` resolves a DID, extracts the public key, and stores it. Resolution tries the backend's `resolvePath` first, then falls back to direct DID method resolution (did:key local, did:web HTTPS, did:polygon eth_call).

## DID method routing (default backends.json)

| DID method | Backend | Auth | Content-Type |
| --- | --- | --- | --- |
| did:polygon, did:indy, did:sov, did:peer | credebl-agent | Bearer token via `/agent/token` | application/json |
| did:web, did:key, did:jwk | inji-verify | None | application/vc+ld+json |
| did:jwk, did:web, did:key, did:cheqd | waltid-verifier | None | application/json |

First match wins. Inji Verify is registered before walt.id, so `did:web`/`did:key`/`did:jwk` route to Inji by default.

## Credential format support

| Format | Online | Offline | Air-gap (`--network none`) |
| --- | --- | --- | --- |
| LDP_VC (Ed25519Signature2018) | Inji Verify, CREDEBL | CRYPTOGRAPHIC | TRUSTED_ISSUER (context fetch fails) |
| LDP_VC (Ed25519Signature2020) | Inji Verify, CREDEBL | CRYPTOGRAPHIC | TRUSTED_ISSUER (context fetch fails) |
| LDP_VC (EcdsaSecp256k1Signature2019) | CREDEBL | CRYPTOGRAPHIC | TRUSTED_ISSUER (context fetch fails) |
| LDP_VC (RsaSignature2018) | Inji Verify | CRYPTOGRAPHIC (if RSA key cached) | TRUSTED_ISSUER (context fetch fails) |
| SD-JWT (EdDSA, x5c in header) | Inji Verify | CRYPTOGRAPHIC | **CRYPTOGRAPHIC** (x5c is self-contained) |
| SD-JWT (ES256/RS256, x5c) | Inji Verify | CRYPTOGRAPHIC | **CRYPTOGRAPHIC** |
| SD-JWT (kid/DID, no x5c) | Not supported by Inji 0.16.0 | Not supported | Not supported |
| CBOR / Claim 169 (COSE_Sign1) | Decode only (not a W3C VC) | Decode only | Decode only |
| JWT_VC_JSON | walt.id (OID4VP flow) | Not supported | Not supported |

## Differences from the original Node.js adapter

The [original adapter](../nodejs-credebl-inji-adapter/) is a Node.js file hardcoded to CREDEBL Agent and Inji Verify. This standalone adapter preserves the same API surface and routing logic with two intentional changes:

1. **Content-Type fix.** The original sends `application/json` with `{"verifiableCredentials": [cred]}` to Inji Verify. Inji's controller passes `@RequestBody String vc` to the verifier library — when the body is the wrapper object, parsing fails. The standalone sends the raw credential with `Content-Type: application/vc+ld+json`, matching the delegated-access-poc's approach.

2. **Removed Ed25519Signature2020 offline-preference heuristic.** The original forces offline for `did:web`/`did:key` with Ed25519Signature2020 if cached, commenting "Inji Verify can't fetch JSON-LD contexts from w3id.org". With the Content-Type fix, Inji Verify handles these credentials correctly online. The heuristic is no longer needed.

Everything else is preserved: same endpoints, same DID method routing, same offline fallback chain (crypto → trusted-issuer → unknown), same PixelPass + JSON-XT decoding, same sync with DID resolution fallback, same CORS handling.

## Inji Certify integration

`docker-compose.certify-test.yml` adds Inji Certify v0.14.0 for end-to-end issuance → verification testing.

### Stack topology

```txt
┌─────────────────────────────────────────────────────────────────────┐
│  certify-e2e (Go test tool, runs on host)                          │
│                                                                     │
│  Pre-Auth Code flow:                                                │
│    POST /pre-authorized-data → credential_offer_uri                 │
│    GET  /credential-offer-data/{id} → pre-authorized_code           │
│    POST /oauth/token → access_token + c_nonce                       │
│    POST /issuance/credential (+ RS256 proof JWT) → VC               │
└───┬───────────────────────────────────────┬─────────────────────────┘
    │ :8090                                 │ :8085 / :8082
    ▼                                       ▼
┌──────────┐  ┌───────────────┐  ┌─────────┐  ┌──────────────┐
│  Certify  │←│ certify-nginx │  │ Adapter │  │ Inji Verify  │
│  :8090    │  │ :80 (HTTP)    │  │ :8085   │  │ :8080        │
│           │  │ :443 (HTTPS)  │  │         │  │              │
└──────────┘  └───────────────┘  └─────────┘  └──────────────┘
                      │                              │
              ┌───────┴───────┐              ┌───────┴──────┐
              │ Self-signed   │              │ Imports cert │
              │ TLS cert for  │              │ into Java    │
              │ did:web HTTPS │              │ truststore   │
              └───────────────┘              └──────────────┘
```

### Credential configurations (seeded in `certify_init.sql`)

| Config ID | Format | Data Model | Template highlights |
| --- | --- | --- | --- |
| FarmerCredential | `ldp_vc` | VCDM 1.1 | `issuanceDate`, `expirationDate`, credentials/v1 context |
| FarmerCredentialV2 | `ldp_vc` | VCDM 2.0 | `validFrom`, `validUntil`, credentials/v2 context, `@vocab` fallback |
| FarmerCredentialSdJwt | `vc+sd-jwt` | SD-JWT | `vct` identifier, no JSON-LD context, x5c in header |

All three use Ed25519 signing (`CERTIFY_VC_SIGN_ED25519` key alias), `PreAuthDataProviderPlugin` (claims-as-data, no CSV lookup), and `did:web:certify-nginx` as the issuer DID.

### did:web HTTPS resolution

The `did:web` spec mandates HTTPS for non-localhost hosts. Docker-internal hostnames are HTTP-only. The solution:

1. **certify-nginx** serves HTTPS on port 443 with a self-signed certificate (generated in `test/certify/certs/`)
2. **Inji Verify** imports the cert into Java's cacerts truststore via `keytool -importcert` (compose entrypoint override)
3. **The adapter** tries HTTPS first (with `InsecureSkipVerify` for self-signed certs), falls back to HTTP

### Pre-Auth Code flow (no eSignet dependency)

Certify acts as its own OAuth authorization server (`mosip.certify.authorization.url=${mosip.certify.domain.url}`). The `PreAuthDataProviderPlugin` uses claims from the Pre-Auth request directly as credential data — no CSV lookup, no external identity provider.

The `MockCSVDataProviderPlugin` is **incompatible** with Pre-Auth Code flow because it does `claims.get("sub")` → CSV row lookup, but Pre-Auth serializes all claims to JSON in `sub`.

### SD-JWT template constraints

The SD-JWT template must NOT include `iss`, `iat`, `exp` — Certify adds these automatically. Including them causes `SDObjectBuilder` to conflict with reserved JWT claim names, resulting in `Failed to parse SD-Claims`.

### Physical QR code testing

LDP_VC credentials (1882–2244 bytes) compress to 1715–1853 chars via PixelPass (Base45 + zlib) and fit in a QR code. SD-JWT credentials (6441 chars) exceed the QR limit due to the embedded x5c certificate chain (2667 bytes DER → 4954 chars base64 in the JWT header).

The Inji Verify UI at `:3001` scans QR codes and routes verification through the adapter via nginx proxy. The `test/inji-ui/nginx.conf` forwards `/v1/verify/vc-verification` to `adapter:8085`.

### Test results

All 12 tests pass (3 formats × 2 verification paths × 2 modes):

| Format | Inji Verify direct | Adapter online | Adapter offline |
| --- | --- | --- | --- |
| VCDM v1.0 (ldp_vc) | SUCCESS | SUCCESS | SUCCESS |
| VCDM v2.0 (ldp_vc) | SUCCESS | SUCCESS | SUCCESS |
| SD-JWT (vc+sd-jwt) | SUCCESS | SUCCESS | SUCCESS |
