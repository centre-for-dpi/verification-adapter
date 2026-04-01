package main

import (
	"path/filepath"
	"testing"
	"time"
)

// TestExtractIssuerDID verifies issuer extraction from both string and
// object formats.
func TestExtractIssuerDID(t *testing.T) {
	cases := []struct {
		name string
		cred map[string]any
		want string
	}{
		{
			"string issuer",
			map[string]any{"issuer": "did:key:z6MkTest"},
			"did:key:z6MkTest",
		},
		{
			"object issuer",
			map[string]any{"issuer": map[string]any{"id": "did:web:example.com", "name": "Test"}},
			"did:web:example.com",
		},
		{
			"missing issuer",
			map[string]any{},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractIssuerDID(tc.cred)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestExtractDidMethod verifies DID method extraction.
func TestExtractDidMethod(t *testing.T) {
	cases := []struct {
		did  string
		want string
	}{
		{"did:polygon:0xABC", "did:polygon"},
		{"did:key:z6MkTest", "did:key"},
		{"did:web:example.com", "did:web"},
		{"not-a-did", ""},
	}
	for _, tc := range cases {
		got := extractDidMethod(tc.did)
		if got != tc.want {
			t.Errorf("extractDidMethod(%q) = %q, want %q", tc.did, got, tc.want)
		}
	}
}

// TestExtractCredential verifies credential extraction from various
// request body formats used by verification UIs.
func TestExtractCredential(t *testing.T) {
	cred := map[string]any{"@context": "test", "type": "VC"}

	cases := []struct {
		name    string
		request map[string]any
		found   bool
	}{
		{"verifiableCredentials array", map[string]any{"verifiableCredentials": []any{cred}}, true},
		{"credential field", map[string]any{"credential": cred}, true},
		{"verifiableCredential field", map[string]any{"verifiableCredential": cred}, true},
		{"raw credential with @context", cred, true},
		{"empty request", map[string]any{"foo": "bar"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractCredential(tc.request)
			if tc.found && got == nil {
				t.Error("expected credential, got nil")
			}
			if !tc.found && got != nil {
				t.Errorf("expected nil, got %v", got)
			}
		})
	}
}

// TestValidateStructure verifies the structural validation fallback.
func TestValidateStructure(t *testing.T) {
	a := testAdapter(t)

	cached := &IssuerEntry{DID: "did:key:z6MkTest"}

	validCred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:key:z6MkTest",
		"credentialSubject": map[string]any{"id": "did:key:z6MkSubject"},
		"proof": map[string]any{
			"type":               "Ed25519Signature2020",
			"verificationMethod": "did:key:z6MkTest#key-1",
			"proofValue":         "zSomeSignature",
		},
	}

	if !a.validateStructure(validCred, cached) {
		t.Error("expected valid structure")
	}

	// Issuer mismatch.
	badIssuer := copyMap(validCred)
	badIssuer["issuer"] = "did:key:z6MkOther"
	if a.validateStructure(badIssuer, cached) {
		t.Error("expected invalid for issuer mismatch")
	}

	// No proof.
	noProof := copyMap(validCred)
	delete(noProof, "proof")
	if a.validateStructure(noProof, cached) {
		t.Error("expected invalid for missing proof")
	}
}

// TestVerifyOnlineSelectsBackend verifies that online verification routes
// to the correct backend based on DID method.
func TestVerifyOnlineSelectsBackend(t *testing.T) {
	a := testAdapter(t)

	// Registry has no backends, so online should fall back to offline.
	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:web:unknown.example.com",
		"credentialSubject": map[string]any{"id": "did:key:z6MkSubject"},
	}

	result := a.verifyOnline(cred, "did:web")
	// Should fall back to offline → UNKNOWN_ISSUER (no backend, no cache).
	if result.Status != "UNKNOWN_ISSUER" {
		t.Errorf("status = %q, want UNKNOWN_ISSUER (no backend registered)", result.Status)
	}
}

func testAdapter(t *testing.T) *Adapter {
	t.Helper()
	dir := t.TempDir()
	cache, err := NewIssuerCache(filepath.Join(dir, "test.db"), 24*time.Hour)
	if err != nil {
		t.Fatalf("NewIssuerCache: %v", err)
	}
	t.Cleanup(func() { cache.Close() })

	registry := NewBackendRegistry()
	cfg := LoadConfig()

	return &Adapter{
		config:       cfg,
		cache:        cache,
		canon:        NewNativeCanonicalizer(),
		connectivity: NewConnectivityChecker(registry, cfg.ConnTimeout, cfg.ConnCheckInterval),
		registry:     registry,
	}
}

func copyMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}
