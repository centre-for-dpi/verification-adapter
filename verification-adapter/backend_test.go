package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRegistrySelect verifies that the registry returns the first backend
// that can handle a DID method.
func TestRegistrySelect(t *testing.T) {
	reg := NewBackendRegistry()
	reg.Register(NewConfigurableBackend(BackendConfig{
		Name:       "backend-a",
		DIDMethods: []string{"did:polygon"},
	}))
	reg.Register(NewConfigurableBackend(BackendConfig{
		Name:       "backend-b",
		DIDMethods: []string{"did:web", "did:key"},
	}))

	b := reg.Select("did:polygon")
	if b == nil || b.Name() != "backend-a" {
		t.Errorf("expected backend-a for did:polygon, got %v", b)
	}

	b = reg.Select("did:web")
	if b == nil || b.Name() != "backend-b" {
		t.Errorf("expected backend-b for did:web, got %v", b)
	}

	b = reg.Select("did:unknown")
	if b != nil {
		t.Errorf("expected nil for did:unknown, got %v", b.Name())
	}
}

// TestRegistrySelectCatchAll verifies that a backend with empty DIDMethods
// matches any DID method.
func TestRegistrySelectCatchAll(t *testing.T) {
	reg := NewBackendRegistry()
	reg.Register(NewConfigurableBackend(BackendConfig{
		Name:       "catch-all",
		DIDMethods: nil, // empty = accept all
	}))

	b := reg.Select("did:anything")
	if b == nil || b.Name() != "catch-all" {
		t.Errorf("expected catch-all for any DID method, got %v", b)
	}
}

// TestRegistryPriorityOrder verifies that backends registered first have
// higher priority when multiple can handle the same DID method.
func TestRegistryPriorityOrder(t *testing.T) {
	reg := NewBackendRegistry()
	reg.Register(NewConfigurableBackend(BackendConfig{
		Name:       "high-priority",
		DIDMethods: []string{"did:web"},
	}))
	reg.Register(NewConfigurableBackend(BackendConfig{
		Name:       "low-priority",
		DIDMethods: []string{"did:web"},
	}))

	b := reg.Select("did:web")
	if b == nil || b.Name() != "high-priority" {
		t.Errorf("expected high-priority, got %v", b.Name())
	}
}

// TestConfigurableBackendVerify verifies the full request/response cycle
// against a mock HTTP server.
func TestConfigurableBackendVerify(t *testing.T) {
	// Mock verification server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/verify" {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)

			// Check that credential was wrapped correctly.
			if _, ok := body["credential"]; !ok {
				t.Error("expected 'credential' field in request body")
			}

			json.NewEncoder(w).Encode(map[string]any{"isValid": true})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	backend := NewConfigurableBackend(BackendConfig{
		Name:         "test-backend",
		URL:          server.URL,
		VerifyPath:   "/verify",
		HealthPath:   "/health",
		DIDMethods:   []string{"did:test"},
		WrapField:    "credential",
		SuccessField: "isValid",
	})

	cred := map[string]any{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "VerifiableCredential",
		"issuer":   "did:test:issuer",
	}

	result := backend.Verify(cred)
	if result.Status != "SUCCESS" {
		t.Errorf("status = %q, want SUCCESS", result.Status)
	}
	if result.Backend != "test-backend" {
		t.Errorf("backend = %q, want test-backend", result.Backend)
	}
}

// TestConfigurableBackendWithAuth verifies the token-based auth flow.
func TestConfigurableBackendWithAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// Check API key.
			if r.Header.Get("Authorization") != "my-api-key" {
				t.Errorf("expected API key 'my-api-key', got %q", r.Header.Get("Authorization"))
			}
			json.NewEncoder(w).Encode(map[string]string{"token": "jwt-token-123"})

		case "/verify":
			// Check bearer token.
			auth := r.Header.Get("Authorization")
			if auth != "Bearer jwt-token-123" {
				t.Errorf("expected Bearer token, got %q", auth)
			}
			json.NewEncoder(w).Encode(map[string]any{"isValid": true})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	backend := NewConfigurableBackend(BackendConfig{
		Name:         "authed-backend",
		URL:          server.URL,
		VerifyPath:   "/verify",
		TokenPath:    "/token",
		APIKey:       "my-api-key",
		HealthPath:   "/health",
		WrapField:    "credential",
		SuccessField: "isValid",
	})

	result := backend.Verify(map[string]any{"@context": "test"})
	if result.Status != "SUCCESS" {
		t.Errorf("status = %q, want SUCCESS (auth flow failed)", result.Status)
	}
}

// TestConfigurableBackendArrayWrap verifies the WrapArray option wraps
// credentials in a single-element array.
func TestConfigurableBackendArrayWrap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)

		arr, ok := body["verifiableCredentials"].([]any)
		if !ok || len(arr) != 1 {
			t.Errorf("expected single-element array in verifiableCredentials, got %v", body["verifiableCredentials"])
		}

		json.NewEncoder(w).Encode(map[string]string{"verificationStatus": "SUCCESS"})
	}))
	defer server.Close()

	backend := NewConfigurableBackend(BackendConfig{
		Name:         "array-backend",
		URL:          server.URL,
		VerifyPath:   "/",
		HealthPath:   "/",
		WrapField:    "verifiableCredentials",
		WrapArray:    true,
		SuccessField: "verificationStatus",
		SuccessValue: "SUCCESS",
	})

	result := backend.Verify(map[string]any{"@context": "test"})
	if result.Status != "SUCCESS" {
		t.Errorf("status = %q, want SUCCESS", result.Status)
	}
}

// TestPresetConfigs verifies that factory presets produce valid configs.
func TestPresetConfigs(t *testing.T) {
	credebl := CredeblBackendConfig("http://localhost:8004", "secret")
	if credebl.Name != "credebl-agent" {
		t.Errorf("CREDEBL name = %q", credebl.Name)
	}
	if credebl.TokenPath == "" {
		t.Error("CREDEBL should have token auth")
	}

	inji := InjiVerifyBackendConfig("http://localhost:8080")
	if inji.Name != "inji-verify" {
		t.Errorf("Inji name = %q", inji.Name)
	}
	if inji.ContentType != "application/vc+ld+json" {
		t.Errorf("Inji ContentType = %q, want application/vc+ld+json", inji.ContentType)
	}

	waltid := WaltIDBackendConfig("http://localhost:7003")
	if waltid.Name != "waltid-verifier" {
		t.Errorf("walt.id name = %q", waltid.Name)
	}
}

// TestIsTruthy verifies truthy evaluation for different response types.
func TestIsTruthy(t *testing.T) {
	cases := []struct {
		val  any
		want bool
	}{
		{true, true},
		{false, false},
		{"SUCCESS", true},
		{"true", true},
		{"INVALID", false},
		{"", false},
		{nil, false},
		{float64(1), true},
		{float64(0), false},
	}
	for _, tc := range cases {
		got := isTruthy(tc.val)
		if got != tc.want {
			t.Errorf("isTruthy(%v) = %v, want %v", tc.val, got, tc.want)
		}
	}
}
