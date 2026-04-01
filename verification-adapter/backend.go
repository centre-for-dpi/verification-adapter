// backend.go — Pluggable verification backend interface.
//
// The adapter is backend-agnostic: adding a new verifier (CREDEBL, walt.id,
// or any W3C-compliant service) requires only a JSON configuration entry —
// no Go code changes. Each backend declares which DID methods it handles,
// how to authenticate, how to wrap the credential in a request body, and
// how to interpret the response.
//
// A BackendRegistry holds backends in priority order and selects the first
// one that can handle a given DID method. Health status is tracked
// per-backend so routing decisions reflect which services are actually
// reachable.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --------------------------------------------------------------------------
// Interface.
// --------------------------------------------------------------------------

// Backend is the abstraction that verification services implement.
// Adding a new verifier means registering a new Backend — the rest of the
// adapter (routing, caching, offline fallback) works unchanged.
type Backend interface {
	// Name returns a human-readable identifier (e.g. "credebl-agent").
	Name() string
	// CanVerify returns true if this backend accepts the given DID method.
	CanVerify(didMethod string) bool
	// Verify sends a credential for online verification and returns the result.
	Verify(credential map[string]any) VerificationResult
	// VerifyRaw sends a raw credential string (e.g. SD-JWT) with the given
	// Content-Type. Used for non-JSON credential formats.
	VerifyRaw(token string, contentType string) VerificationResult
	// HealthEndpoint returns the full URL probed by the connectivity checker.
	HealthEndpoint() string
}

// DIDResolverBackend is an optional interface. Backends that implement it
// can resolve DID documents, which the adapter uses during /sync.
type DIDResolverBackend interface {
	Backend
	ResolveDID(did string) (map[string]any, error)
}

// --------------------------------------------------------------------------
// Registry.
// --------------------------------------------------------------------------

// BackendRegistry maintains an ordered list of verification backends.
// The first backend whose CanVerify returns true for a DID method is selected.
type BackendRegistry struct {
	backends []Backend
	mu       sync.RWMutex
}

// NewBackendRegistry creates an empty registry.
func NewBackendRegistry() *BackendRegistry {
	return &BackendRegistry{}
}

// Register appends a backend. Backends registered first have higher priority.
func (r *BackendRegistry) Register(b Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backends = append(r.backends, b)
	log.Printf("[REGISTRY] registered backend %q", b.Name())
}

// Select returns the first backend that can verify the given DID method,
// or nil if none can.
func (r *BackendRegistry) Select(didMethod string) Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range r.backends {
		if b.CanVerify(didMethod) {
			return b
		}
	}
	return nil
}

// All returns every registered backend (used by connectivity checker and
// health endpoint).
func (r *BackendRegistry) All() []Backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Backend, len(r.backends))
	copy(out, r.backends)
	return out
}

// SelectResolver returns the first backend that implements DIDResolverBackend
// and can resolve the given DID method.
func (r *BackendRegistry) SelectResolver(didMethod string) DIDResolverBackend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range r.backends {
		if resolver, ok := b.(DIDResolverBackend); ok && b.CanVerify(didMethod) {
			return resolver
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// ConfigurableBackend — works with any HTTP-based verifier.
// --------------------------------------------------------------------------

// BackendConfig describes a verification backend entirely in data. Adding a
// new verifier is a config change, not a code change.
type BackendConfig struct {
	// Name is a human-readable identifier shown in logs and responses.
	Name string `json:"name"`
	// URL is the base URL of the verifier service (e.g. "http://credebl:8004").
	URL string `json:"url"`

	// VerifyPath is appended to URL for verification requests.
	VerifyPath string `json:"verifyPath"` // e.g. "/agent/credential/verify"
	// HealthPath is appended to URL for connectivity probes.
	HealthPath string `json:"healthPath"` // e.g. "/agent"

	// DIDMethods lists which DID methods this backend handles.
	// An empty list means "accept all DID methods".
	DIDMethods []string `json:"didMethods"`

	// --- Authentication ---

	// TokenPath, if non-empty, means the backend uses bearer-token auth.
	// The adapter POSTs to URL+TokenPath with APIKey in the Authorization
	// header to obtain a JWT.
	TokenPath string `json:"tokenPath,omitempty"` // e.g. "/agent/token"
	// APIKey is the shared secret sent when requesting a token.
	APIKey string `json:"apiKey,omitempty"`

	// --- Request format ---

	// WrapField is the JSON key that wraps the credential in the request body.
	// Examples: "credential" → {"credential": cred}
	//           "verifiableCredentials" → {"verifiableCredentials": [cred]}
	// Empty means send the credential as the top-level body.
	WrapField string `json:"wrapField,omitempty"`
	// WrapArray wraps the credential in a single-element array inside WrapField.
	WrapArray bool `json:"wrapArray,omitempty"`

	// --- Request options ---

	// ContentType overrides the HTTP Content-Type header. Defaults to
	// "application/json". Inji Verify requires "application/vc+ld+json"
	// for LDP_VC credentials sent as raw body.
	ContentType string `json:"contentType,omitempty"`

	// --- Response parsing ---

	// SuccessField is the JSON key checked in the response to determine success.
	// Examples: "isValid" (CREDEBL), "verificationStatus" (Inji), "verified".
	SuccessField string `json:"successField"`
	// SuccessValue is the string the field must equal for success.
	// If empty, any truthy value (true, "true", "SUCCESS") counts.
	SuccessValue string `json:"successValue,omitempty"`

	// --- DID Resolution (optional) ---

	// ResolvePath, if non-empty, enables DID resolution via this backend.
	// The DID is appended to URL+ResolvePath.
	ResolvePath string `json:"resolvePath,omitempty"` // e.g. "/dids/"
	// ResolveDocField is the JSON key containing the DID document in the response.
	ResolveDocField string `json:"resolveDocField,omitempty"` // e.g. "didDocument"
}

// ConfigurableBackend is a Backend driven entirely by BackendConfig.
type ConfigurableBackend struct {
	cfg    BackendConfig
	client *http.Client
}

// NewConfigurableBackend creates a backend from a config entry.
func NewConfigurableBackend(cfg BackendConfig) *ConfigurableBackend {
	return &ConfigurableBackend{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (b *ConfigurableBackend) Name() string { return b.cfg.Name }

func (b *ConfigurableBackend) CanVerify(didMethod string) bool {
	if len(b.cfg.DIDMethods) == 0 {
		return true // empty list = accepts all
	}
	for _, m := range b.cfg.DIDMethods {
		if m == didMethod {
			return true
		}
	}
	return false
}

func (b *ConfigurableBackend) HealthEndpoint() string {
	return b.cfg.URL + b.cfg.HealthPath
}

// Verify sends the credential to the backend and interprets the response.
func (b *ConfigurableBackend) Verify(credential map[string]any) VerificationResult {
	// Build request body.
	body, err := b.buildRequestBody(credential)
	if err != nil {
		return VerificationResult{Status: "ERROR", Error: "build request: " + err.Error()}
	}

	req, err := http.NewRequest("POST", b.cfg.URL+b.cfg.VerifyPath, bytes.NewReader(body))
	if err != nil {
		return VerificationResult{Status: "ERROR", Error: err.Error()}
	}
	ct := b.cfg.ContentType
	if ct == "" {
		ct = "application/json"
	}
	req.Header.Set("Content-Type", ct)

	// Auth.
	if err := b.authenticate(req); err != nil {
		return VerificationResult{Status: "ERROR", Error: "auth: " + err.Error()}
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return VerificationResult{Status: "ERROR", Error: err.Error()}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerificationResult{Status: "ERROR", Error: "read response: " + err.Error()}
	}

	return b.parseResponse(respBody)
}

// VerifyRaw sends a raw string credential (SD-JWT) to the backend with the
// specified Content-Type. No JSON wrapping — the token is the body.
func (b *ConfigurableBackend) VerifyRaw(token string, contentType string) VerificationResult {
	req, err := http.NewRequest("POST", b.cfg.URL+b.cfg.VerifyPath, strings.NewReader(token))
	if err != nil {
		return VerificationResult{Status: "ERROR", Error: err.Error()}
	}
	req.Header.Set("Content-Type", contentType)

	if err := b.authenticate(req); err != nil {
		return VerificationResult{Status: "ERROR", Error: "auth: " + err.Error()}
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return VerificationResult{Status: "ERROR", Error: err.Error()}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerificationResult{Status: "ERROR", Error: "read response: " + err.Error()}
	}

	return b.parseResponse(respBody)
}

func (b *ConfigurableBackend) buildRequestBody(credential map[string]any) ([]byte, error) {
	if b.cfg.WrapField == "" {
		return json.Marshal(credential)
	}
	var wrapped any = credential
	if b.cfg.WrapArray {
		wrapped = []any{credential}
	}
	return json.Marshal(map[string]any{b.cfg.WrapField: wrapped})
}

func (b *ConfigurableBackend) authenticate(req *http.Request) error {
	if b.cfg.TokenPath == "" {
		return nil // no auth required
	}

	tokenReq, err := http.NewRequest("POST", b.cfg.URL+b.cfg.TokenPath, nil)
	if err != nil {
		return err
	}
	if b.cfg.APIKey != "" {
		tokenReq.Header.Set("Authorization", b.cfg.APIKey)
	}

	resp, err := b.client.Do(tokenReq)
	if err != nil {
		return fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse token: %w", err)
	}

	token, _ := result["token"].(string)
	if token == "" {
		return fmt.Errorf("no token in response")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (b *ConfigurableBackend) parseResponse(body []byte) VerificationResult {
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return VerificationResult{Status: "ERROR", Error: "parse response: " + err.Error()}
	}

	status := "INVALID"
	field := b.cfg.SuccessField
	if field == "" {
		field = "verified" // sensible default
	}

	val := result[field]
	if b.cfg.SuccessValue != "" {
		// Exact string match.
		if fmt.Sprintf("%v", val) == b.cfg.SuccessValue {
			status = "SUCCESS"
		}
	} else {
		// Truthy: true, "true", "SUCCESS", non-empty string, non-zero number.
		if isTruthy(val) {
			status = "SUCCESS"
		}
	}

	return VerificationResult{
		Status:  status,
		Online:  true,
		Backend: b.cfg.Name,
		Details: result,
	}
}

func isTruthy(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		s := strings.ToLower(val)
		return s == "true" || s == "success" || s == "valid"
	case float64:
		return val != 0
	case nil:
		return false
	default:
		return true
	}
}

// --------------------------------------------------------------------------
// DID resolution (optional).
// --------------------------------------------------------------------------

// ResolveDID fetches a DID document via the backend's resolution endpoint.
// Only available if ResolvePath is configured.
func (b *ConfigurableBackend) ResolveDID(did string) (map[string]any, error) {
	if b.cfg.ResolvePath == "" {
		return nil, fmt.Errorf("backend %q does not support DID resolution", b.cfg.Name)
	}

	req, err := http.NewRequest("GET", b.cfg.URL+b.cfg.ResolvePath+did, nil)
	if err != nil {
		return nil, err
	}
	if err := b.authenticate(req); err != nil {
		return nil, err
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read DID response: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse DID response: %w", err)
	}

	// If a specific field is configured, extract it.
	if b.cfg.ResolveDocField != "" {
		if doc, ok := result[b.cfg.ResolveDocField].(map[string]any); ok {
			return doc, nil
		}
		return nil, fmt.Errorf("field %q not found in resolution response", b.cfg.ResolveDocField)
	}
	return result, nil
}

// Compile-time checks.
var _ Backend = (*ConfigurableBackend)(nil)
var _ DIDResolverBackend = (*ConfigurableBackend)(nil)

// --------------------------------------------------------------------------
// Preset factory functions — zero-config defaults for common backends.
// --------------------------------------------------------------------------

// CredeblBackendConfig returns a BackendConfig preset for the CREDEBL Agent.
func CredeblBackendConfig(url, apiKey string) BackendConfig {
	return BackendConfig{
		Name:            "credebl-agent",
		URL:             url,
		VerifyPath:      "/agent/credential/verify",
		HealthPath:      "/agent",
		TokenPath:       "/agent/token",
		APIKey:          apiKey,
		DIDMethods:      []string{"did:polygon", "did:indy", "did:sov", "did:peer"},
		WrapField:       "credential",
		SuccessField:    "isValid",
		ResolvePath:     "/dids/",
		ResolveDocField: "didDocument",
	}
}

// WaltIDBackendConfig returns a BackendConfig preset for the walt.id Verifier API.
func WaltIDBackendConfig(url string) BackendConfig {
	return BackendConfig{
		Name:         "waltid-verifier",
		URL:          url,
		VerifyPath:   "/openid4vc/verify",
		HealthPath:   "/health",
		DIDMethods:   []string{"did:jwk", "did:web", "did:key", "did:cheqd", "did:ebsi"},
		WrapField:    "vp_token",
		SuccessField: "verified",
	}
}

// InjiVerifyBackendConfig returns a BackendConfig preset for the Inji Verify Service.
// Inji's vc-verification endpoint expects the raw credential as the body with
// Content-Type: application/vc+ld+json (not wrapped in a JSON envelope).
func InjiVerifyBackendConfig(url string) BackendConfig {
	return BackendConfig{
		Name:         "inji-verify",
		URL:          url,
		VerifyPath:   "/v1/verify/vc-verification",
		HealthPath:   "/v1/verify/actuator/health",
		DIDMethods:   []string{"did:web", "did:key", "did:jwk"},
		ContentType:  "application/vc+ld+json",
		SuccessField: "verificationStatus",
		SuccessValue: "SUCCESS",
	}
}

