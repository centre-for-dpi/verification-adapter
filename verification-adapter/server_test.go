package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHealthEndpoint verifies the /health endpoint returns adapter status.
func TestHealthEndpoint(t *testing.T) {
	a := testAdapterForServer(t)
	srv := NewRouter(a)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["status"] != "ok" {
		t.Errorf("status = %v, want 'ok'", resp["status"])
	}
	if resp["canonicalization"] != "URDNA2015" {
		t.Errorf("canonicalization = %v, want 'URDNA2015'", resp["canonicalization"])
	}
	if resp["service"] != "verification-adapter-go" {
		t.Errorf("service = %v, want 'verification-adapter-go'", resp["service"])
	}
	// Per-backend status should be present.
	if _, ok := resp["backends"]; !ok {
		t.Error("expected 'backends' field in health response")
	}
}

// TestCacheEndpoint verifies the /cache endpoint returns cache stats.
func TestCacheEndpoint(t *testing.T) {
	a := testAdapterForServer(t)
	a.cache.Set(IssuerEntry{DID: "did:key:z6MkTest", KeyType: "Ed25519"})

	srv := NewRouter(a)
	req := httptest.NewRequest("GET", "/cache", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var stats CacheStats
	json.NewDecoder(w.Body).Decode(&stats)
	if stats.TotalIssuers != 1 {
		t.Errorf("TotalIssuers = %d, want 1", stats.TotalIssuers)
	}
}

// TestTemplatesEndpointNotLoaded verifies 404 when templates are not loaded.
func TestTemplatesEndpointNotLoaded(t *testing.T) {
	a := testAdapterForServer(t)
	a.templates = nil

	srv := NewRouter(a)
	req := httptest.NewRequest("GET", "/templates", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

// TestVerifyEndpointNoCredential verifies error when no credential is provided.
func TestVerifyEndpointNoCredential(t *testing.T) {
	a := testAdapterForServer(t)
	srv := NewRouter(a)

	body := `{"foo": "bar"}`
	req := httptest.NewRequest("POST", "/v1/verify/vc-verification", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// TestVerifyEndpointRawCredential verifies that a raw credential with
// @context is accepted and routed to offline verification.
func TestVerifyEndpointRawCredential(t *testing.T) {
	a := testAdapterForServer(t)
	srv := NewRouter(a)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:web:unknown.example.com",
		"credentialSubject": map[string]any{"id": "did:key:z6MkTest"},
		"proof":             map[string]any{"type": "Ed25519Signature2020", "proofValue": "zTest"},
	}

	body, _ := json.Marshal(cred)
	req := httptest.NewRequest("POST", "/verify-offline", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var result VerificationResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.Status != "UNKNOWN_ISSUER" {
		t.Errorf("status = %q, want UNKNOWN_ISSUER", result.Status)
	}
}

// TestCORSHeaders verifies that CORS headers are set on all responses.
func TestCORSHeaders(t *testing.T) {
	a := testAdapterForServer(t)
	srv := NewRouter(a)

	req := httptest.NewRequest("OPTIONS", "/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS Allow-Origin header")
	}
}

func testAdapterForServer(t *testing.T) *Adapter {
	t.Helper()
	dir := t.TempDir()
	cache, err := NewIssuerCache(filepath.Join(dir, "test.db"), 24*time.Hour)
	if err != nil {
		t.Fatalf("NewIssuerCache: %v", err)
	}
	t.Cleanup(func() { cache.Close() })

	cfg := LoadConfig()
	registry := NewBackendRegistry()
	return &Adapter{
		config:       cfg,
		cache:        cache,
		canon:        NewNativeCanonicalizer(),
		connectivity: NewConnectivityChecker(registry, cfg.ConnTimeout, cfg.ConnCheckInterval),
		registry:     registry,
	}
}
