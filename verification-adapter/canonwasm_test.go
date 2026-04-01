package main

import (
	"strings"
	"testing"
)

// TestWASMCanonVCDocument verifies WASM canonicalization of a W3C VC —
// the primary use case for this adapter.
func TestWASMCanonVCDocument(t *testing.T) {
	c, err := NewWASMCanonicalizer()
	if err != nil {
		t.Fatalf("NewWASMCanonicalizer: %v", err)
	}
	defer c.Close()

	doc := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer":   "did:web:example.com",
		"credentialSubject": map[string]any{
			"id":   "did:key:z6MkTest",
			"name": "Test",
		},
	}

	result, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("Canonicalize VC: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty canonical form")
	}
	t.Logf("N-Quads:\n%s", result)
}

// TestWASMCanonDeterministic verifies repeated WASM canonicalization of the
// same VC document produces identical results.
func TestWASMCanonDeterministic(t *testing.T) {
	c, err := NewWASMCanonicalizer()
	if err != nil {
		t.Fatalf("NewWASMCanonicalizer: %v", err)
	}
	defer c.Close()

	doc := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
			map[string]any{"@vocab": "https://example.org/vocab#"},
		},
		"type":   []any{"VerifiableCredential"},
		"issuer": "did:key:z6MkTest",
		"credentialSubject": map[string]any{
			"id":   "did:key:z6MkSubject",
			"name": "Alice",
		},
	}

	r1, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	r2, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if r1 != r2 {
		t.Errorf("not deterministic:\n  run1: %s\n  run2: %s", r1, r2)
	}
}

// TestWASMCanonEmptyDocument verifies empty input produces empty output.
func TestWASMCanonEmptyDocument(t *testing.T) {
	c, err := NewWASMCanonicalizer()
	if err != nil {
		t.Fatalf("NewWASMCanonicalizer: %v", err)
	}
	defer c.Close()

	result, err := c.Canonicalize(map[string]any{})
	if err != nil {
		t.Fatalf("Canonicalize empty: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty for empty doc, got: %s", result)
	}
}

// TestWASMCanonVCWithEd25519Context verifies canonicalization with the
// Ed25519Signature2020 context — the exact context used in credential
// signing and verification.
func TestWASMCanonVCWithEd25519Context(t *testing.T) {
	c, err := NewWASMCanonicalizer()
	if err != nil {
		t.Fatalf("NewWASMCanonicalizer: %v", err)
	}
	defer c.Close()

	doc := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
			map[string]any{"@vocab": "https://example.org/vocab#"},
		},
		"type":         []any{"VerifiableCredential"},
		"issuer":       "did:key:z6MkwZ6btH9UDtYAHg9C8ERD8GXQhces7sve46QEPuxGb6tL",
		"issuanceDate": "2026-04-01T08:39:30Z",
		"credentialSubject": map[string]any{
			"id":   "did:key:z6MkSubjectExample",
			"name": "Alice Wonderland",
		},
	}

	result, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty canonical form")
	}
	if !strings.Contains(result, "Alice Wonderland") {
		t.Errorf("expected N-Quads to contain 'Alice Wonderland', got:\n%s", result)
	}
	t.Logf("N-Quads (%d bytes):\n%s", len(result), result)
}

// TestWASMvsNativeVCCanon compares WASM and Native canonicalization of
// a credential document. Differences here explain why json-gold-signed
// credentials fail Inji Verify (which uses a reference-compatible impl).
func TestWASMvsNativeVCCanon(t *testing.T) {
	wasm, err := NewWASMCanonicalizer()
	if err != nil {
		t.Fatalf("NewWASMCanonicalizer: %v", err)
	}
	defer wasm.Close()
	native := NewNativeCanonicalizer()

	doc := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
			map[string]any{"@vocab": "https://example.org/vocab#"},
		},
		"type":         []any{"VerifiableCredential"},
		"issuer":       "did:key:z6MkTest",
		"issuanceDate": "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{
			"id":   "did:key:z6MkSubject",
			"name": "Test User",
		},
	}

	wasmResult, err := wasm.Canonicalize(doc)
	if err != nil {
		t.Fatalf("WASM: %v", err)
	}
	nativeResult, err := native.Canonicalize(doc)
	if err != nil {
		t.Fatalf("Native: %v", err)
	}

	if wasmResult == nativeResult {
		t.Log("WASM and Native produce IDENTICAL N-Quads — no cross-processor divergence")
	} else {
		t.Log("WASM and Native produce DIFFERENT N-Quads — this divergence is why")
		t.Log("json-gold-signed credentials fail Inji Verify (Titanium JSON-LD).")
		t.Logf("\nWASM (%d bytes):\n%s", len(wasmResult), wasmResult)
		t.Logf("\nNative (%d bytes):\n%s", len(nativeResult), nativeResult)
	}
}
