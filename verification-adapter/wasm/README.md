# WASM URDNA2015 Canonicalizer

A WebAssembly module that runs the W3C reference JSON-LD implementation (`jsonld` npm v8, by Digital Bazaar) inside a pure-Go WASM runtime (wazero). It produces bit-identical N-Quads to the reference implementation without requiring Node.js.

## Why it exists

The adapter's default canonicalizer (json-gold, a Go library) requires HTTP access to fetch `@context` URLs at runtime. In a true air-gap environment (`--network none`), context fetching fails and offline verification degrades from `CRYPTOGRAPHIC` to `TRUSTED_ISSUER`.

This WASM module was built to solve that: it embeds W3C standard contexts (`credentials/v1`, `credentials/v2`, `ed25519-2020/v1`) directly in the compiled binary, enabling URDNA2015 canonicalization without any network access. Custom contexts (e.g. `credissuer.com/templates/...`) are not embedded and would still fail in air-gap mode.

During testing, json-gold and the WASM module produced **identical N-Quads** for every credential tested, including W3C VC v1/v2 documents with Ed25519Signature2020 proofs. The canonicalization divergence that was originally suspected between Go and Java implementations turned out to be a Content-Type issue, not an algorithm difference.

The adapter currently defaults to json-gold (which handles custom contexts via HTTP fetching). The WASM module is archived here for air-gap deployments or as a reference implementation for correctness validation.

## How it was implemented

### Build pipeline

```txt
canonicalize.js                  JS entrypoint: reads stdin, calls jsonld.canonize(), writes stdout
       │
       ▼
esbuild --bundle                 Bundles jsonld npm + all dependencies into one file
       │                         Aliases: crypto → crypto-shim.js (pure-JS SHA-256)
       │                                  http/https/net/tls/... → node-stubs.js (no-ops)
       │                                  undici/@digitalbazaar/http-client → no-ops
       ▼
Javy v8.1.0 --build             Compiles bundled JS to WASM via QuickJS
       │                         Flags: -J event-loop=y (jsonld.canonize is async)
       │                                -J javy-stream-io=y (Javy.IO.readSync/writeSync)
       │                                -J text-encoding=y (TextEncoder/TextDecoder)
       ▼
canonicalize.wasm (2.0 MB)       Self-contained WASM binary, no external dependencies
```

The entire build runs inside Docker (`build.Dockerfile`) — no local toolchain required:

```bash
docker build -f wasm/build.Dockerfile -o type=local,dest=wasm .
```

### Go wrapper (`canonwasm.go`)

Uses wazero (pure-Go WASM runtime, no CGO) with WASI for stdin/stdout:

```go
type WASMCanonicalizer struct {
    runtime  wazero.Runtime
    compiled wazero.CompiledModule
    mu       sync.Mutex
}

func (c *WASMCanonicalizer) Canonicalize(doc map[string]any) (string, error) {
    // Marshal doc to JSON → write to WASM stdin
    // Instantiate module with fresh stdin/stdout buffers
    // Read canonical N-Quads from stdout
}
```

The compiled module is embedded via `//go:embed wasm/canonicalize.wasm` and pre-compiled at startup. Each `Canonicalize` call instantiates a fresh module with new stdin/stdout (Javy convention). Thread-safe via mutex.

### Polyfills

| File | Purpose |
| --- | --- |
| `crypto-shim.js` | Pure-JS SHA-256 replacing Node.js `crypto.createHash("sha256")` used by `rdf-canonize` |
| `node-stubs.js` | No-op exports for `http`, `https`, `net`, `tls`, `assert`, etc. — modules that `jsonld`'s document loader imports at init time but never calls in WASM |
| `loader-stub.js` | No-op replacement for `@digitalbazaar/http-client` |

### Embedded contexts

`canonicalize.js` includes a static `CONTEXTS` map with:

- `https://www.w3.org/2018/credentials/v1`
- `https://www.w3.org/ns/credentials/v2`
- `https://w3id.org/security/suites/ed25519-2020/v1`

A custom `documentLoader` serves these from memory. Unrecognised context URLs throw an error.

## Files

| File | Description |
| --- | --- |
| `canonicalize.wasm` | Compiled WASM binary (2.0 MB) |
| `canonicalize.js` | JS entrypoint with embedded W3C contexts |
| `crypto-shim.js` | Pure-JS SHA-256 for QuickJS |
| `node-stubs.js` | No-op stubs for Node.js built-ins |
| `loader-stub.js` | No-op HTTP client stub |
| `package.json` | npm dependency: `jsonld ^8.0.0` |
| `build.Dockerfile` | Full build pipeline (esbuild + Javy) |

## Files in parent directory

| File | Description |
| --- | --- |
| `canonwasm.go` | Go wrapper using wazero + WASI stdin/stdout |
| `canonwasm_test.go` | Tests: simple doc, deterministic, VC doc, empty doc, WASM-vs-native comparison |

## Usage

To wire the WASM canonicalizer into the adapter instead of json-gold, change `main.go`:

```go
// Replace:
canon := NewNativeCanonicalizer()

// With:
canon, err := NewWASMCanonicalizer()
if err != nil {
    log.Fatalf("wasm init: %v", err)
}
defer canon.Close()
```

Note: the file must be named `canonwasm.go` (not `canon_wasm.go`) — Go interprets `_wasm` as a GOOS build constraint and excludes the file on non-WASM platforms.

## Dependencies

- `github.com/tetratelabs/wazero` — pure-Go WASM runtime (add to `go.mod`)
- `jsonld` npm v8 — compiled into the WASM binary, not a runtime dependency
