// canon_wasm.go — WASM-backed URDNA2015 canonicalizer.
//
// Runs the W3C reference implementation (@digitalbazaar/jsonld v8) compiled
// to WebAssembly via Javy, inside the wazero pure-Go WASM runtime. This
// produces bit-identical N-Quads to Inji Verify's Titanium JSON-LD (Java),
// eliminating the cross-processor canonicalization divergence that causes
// json-gold-signed credentials to fail Inji verification.
//
// The WASM module reads a JSON document from stdin and writes canonical
// N-Quads to stdout (Javy convention). The compiled module is pre-loaded
// at startup; each Canonicalize call instantiates a fresh module with new
// stdin/stdout buffers.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed wasm/canonicalize.wasm
var canonicalizeWasm []byte

// WASMCanonicalizer implements Canonicalizer by running the W3C reference
// JSON-LD implementation inside a WASM sandbox. Thread-safe via mutex.
type WASMCanonicalizer struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	mu       sync.Mutex
}

// NewWASMCanonicalizer compiles the embedded WASM module. Call Close() when
// done to release resources.
func NewWASMCanonicalizer() (*WASMCanonicalizer, error) {
	ctx := context.Background()

	rt := wazero.NewRuntime(ctx)

	// Instantiate WASI — Javy modules require it for stdin/stdout.
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("wasm: instantiate WASI: %w", err)
	}

	compiled, err := rt.CompileModule(ctx, canonicalizeWasm)
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("wasm: compile module: %w", err)
	}

	return &WASMCanonicalizer{
		runtime:  rt,
		compiled: compiled,
	}, nil
}

// Canonicalize converts a JSON-LD document to canonical N-Quads using the
// WASM-embedded @digitalbazaar/jsonld reference implementation.
func (c *WASMCanonicalizer) Canonicalize(doc map[string]any) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	input, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("wasm: marshal input: %w", err)
	}

	ctx := context.Background()
	stdin := bytes.NewReader(input)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	config := wazero.NewModuleConfig().
		WithStdin(stdin).
		WithStdout(stdout).
		WithStderr(stderr).
		WithName("") // anonymous — allows repeated instantiation

	mod, err := c.runtime.InstantiateModule(ctx, c.compiled, config)
	if err != nil {
		errMsg := stderr.String()
		if errMsg != "" {
			return "", fmt.Errorf("wasm: execute: %w\nstderr: %s", err, errMsg)
		}
		return "", fmt.Errorf("wasm: execute: %w", err)
	}
	defer mod.Close(ctx)

	return stdout.String(), nil
}

// Close releases the WASM runtime resources.
func (c *WASMCanonicalizer) Close() error {
	return c.runtime.Close(context.Background())
}

// compile-time interface check.
var _ Canonicalizer = (*WASMCanonicalizer)(nil)
