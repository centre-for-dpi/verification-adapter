// verify.go — Verification orchestration: online routing, offline fallback.
//
// The Adapter is the central coordinator. It uses a BackendRegistry to route
// online verification to the appropriate backend by DID method, and performs
// URDNA2015-based offline verification when no backend is reachable.
//
// Adding a new verification backend (CREDEBL, walt.id, or any W3C-compliant
// service) requires only a backends.json entry — no changes to this file.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

// Adapter wires all components into a verification pipeline.
type Adapter struct {
	config       Config
	cache        *IssuerCache
	canon        Canonicalizer
	connectivity *ConnectivityChecker
	registry     *BackendRegistry
	templates    map[string]JsonXTTemplate
}

// VerificationResult is the JSON response returned to the UI.
type VerificationResult struct {
	Status       string         `json:"verificationStatus"`
	Online       bool           `json:"online,omitempty"`
	Offline      bool           `json:"offline,omitempty"`
	Level        string         `json:"verificationLevel,omitempty"`
	Backend      string         `json:"backend,omitempty"`
	Message      string         `json:"message,omitempty"`
	Note         string         `json:"note,omitempty"`
	VC           map[string]any `json:"vc,omitempty"`
	VCField      map[string]any `json:"verifiableCredential,omitempty"`
	CachedIssuer *CachedInfo    `json:"cachedIssuer,omitempty"`
	Details      any            `json:"details,omitempty"`
	Error        string         `json:"error,omitempty"`
}

// CachedInfo is metadata about a cached issuer included in the response.
type CachedInfo struct {
	DID      string `json:"did"`
	CachedAt string `json:"cachedAt,omitempty"`
}

// SyncResult is the response for a single DID sync operation.
type SyncResult struct {
	Success      bool   `json:"success"`
	DID          string `json:"did"`
	KeyType      string `json:"keyType,omitempty"`
	PublicKeyHex string `json:"publicKeyHex,omitempty"` // truncated
	CachedAt     string `json:"cachedAt,omitempty"`
	Error        string `json:"error,omitempty"`
}

// --------------------------------------------------------------------------
// Main entry point.
// --------------------------------------------------------------------------

// VerifyCredential decides between online and offline verification and
// dispatches accordingly.
func (a *Adapter) VerifyCredential(credential map[string]any, forceOffline bool) VerificationResult {
	issuerDID := extractIssuerDID(credential)
	didMethod := extractDidMethod(issuerDID)

	log.Printf("[VERIFY] issuer=%s method=%s", issuerDID, didMethod)

	online := !forceOffline && a.connectivity.IsOnline(didMethod)

	log.Printf("[VERIFY] mode=%s", modeStr(online))

	if online {
		return a.verifyOnline(credential, didMethod)
	}
	return a.verifyOffline(credential, issuerDID, didMethod)
}

// --------------------------------------------------------------------------
// Online verification — route to registered backend.
// --------------------------------------------------------------------------

func (a *Adapter) verifyOnline(credential map[string]any, didMethod string) VerificationResult {
	backend := a.registry.Select(didMethod)
	if backend == nil {
		log.Printf("[VERIFY] no backend registered for %s, falling back to offline", didMethod)
		issuerDID := extractIssuerDID(credential)
		return a.verifyOffline(credential, issuerDID, didMethod)
	}

	log.Printf("[VERIFY] routing to backend %q", backend.Name())
	return backend.Verify(credential)
}

// --------------------------------------------------------------------------
// Offline verification — local crypto with URDNA2015.
// --------------------------------------------------------------------------

func (a *Adapter) verifyOffline(credential map[string]any, issuerDID, didMethod string) VerificationResult {
	log.Printf("[VERIFY] offline verification for %s", issuerDID)

	cached := a.cache.Get(issuerDID)

	// did:key can be resolved locally without cache or network.
	if cached == nil && didMethod == "did:key" {
		key, err := ResolveDidKey(issuerDID)
		if err == nil {
			a.cache.Set(IssuerEntry{
				DID:          issuerDID,
				PublicKeyHex: key.PublicKeyHex,
				KeyType:      key.KeyType,
			})
			cached = a.cache.Get(issuerDID)
		}
	}

	if cached == nil {
		return VerificationResult{
			Status:  "UNKNOWN_ISSUER",
			Offline: true,
			Message: "Issuer not in cache. Sync when online to verify this credential.",
		}
	}

	cachedInfo := &CachedInfo{
		DID:      cached.DID,
		CachedAt: time.UnixMilli(cached.CachedAt).Format(time.RFC3339),
	}

	// Attempt cryptographic verification with URDNA2015.
	valid, err := VerifyCredentialSignature(credential, cached.PublicKeyHex, cached.KeyType, a.canon)
	if err == nil {
		status := "INVALID"
		if valid {
			status = "SUCCESS"
		}
		return VerificationResult{
			Status:       status,
			Offline:      true,
			Level:        "CRYPTOGRAPHIC",
			CachedIssuer: cachedInfo,
		}
	}

	// Cryptographic verification failed — fall back to structural validation.
	log.Printf("[VERIFY] crypto failed: %v, falling back to trusted issuer", err)

	if a.validateStructure(credential, cached) {
		return VerificationResult{
			Status:       "SUCCESS",
			Offline:      true,
			Level:        "TRUSTED_ISSUER",
			Message:      "Credential verified via trusted cached issuer. Structure validated.",
			CachedIssuer: cachedInfo,
			Note:         err.Error(),
		}
	}

	return VerificationResult{
		Status:       "INVALID",
		Offline:      true,
		Error:        "Credential structure validation failed",
		CachedIssuer: cachedInfo,
	}
}

// validateStructure checks that a credential's structure is consistent with
// the cached issuer — a fallback when cryptographic verification fails.
func (a *Adapter) validateStructure(credential map[string]any, cached *IssuerEntry) bool {
	credIssuer := extractIssuerDID(credential)
	if credIssuer != cached.DID {
		log.Printf("[VALIDATE] issuer mismatch: %s != %s", credIssuer, cached.DID)
		return false
	}

	proof, ok := credential["proof"].(map[string]any)
	if !ok {
		log.Println("[VALIDATE] no proof")
		return false
	}

	vm, _ := proof["verificationMethod"].(string)
	if vm != "" && !strings.HasPrefix(vm, cached.DID) {
		log.Printf("[VALIDATE] verification method %s doesn't match issuer %s", vm, cached.DID)
		return false
	}

	if _, hasPV := proof["proofValue"]; !hasPV {
		if _, hasJWS := proof["jws"]; !hasJWS {
			log.Println("[VALIDATE] proof has no signature")
			return false
		}
	}

	if credential["@context"] == nil || credential["type"] == nil || credential["credentialSubject"] == nil {
		log.Println("[VALIDATE] missing required fields")
		return false
	}

	return true
}

// --------------------------------------------------------------------------
// Sync — resolve and cache issuer DIDs while online.
// --------------------------------------------------------------------------

// SyncIssuer resolves a DID and caches the result. It tries registered
// backends first (if they implement DIDResolverBackend), then falls back
// to direct DID method resolution.
func (a *Adapter) SyncIssuer(did string) SyncResult {
	didMethod := extractDidMethod(did)
	log.Printf("[SYNC] syncing %s (%s)", did, didMethod)

	var didDoc map[string]any
	var key *ResolvedKey
	var err error

	// Try backend-provided DID resolution first.
	if resolver := a.registry.SelectResolver(didMethod); resolver != nil {
		log.Printf("[SYNC] trying %s for DID resolution", resolver.Name())
		didDoc, err = resolver.ResolveDID(did)
		if err == nil {
			key, err = ExtractPublicKey(didDoc)
		}
		if err != nil {
			log.Printf("[SYNC] backend resolution failed: %v", err)
		}
	}

	// Fallback to direct resolution.
	if key == nil {
		log.Printf("[SYNC] trying direct resolution for %s", didMethod)
		switch didMethod {
		case "did:polygon":
			didDoc, err = ResolveDidPolygon(did, a.config.PolygonRPCURL, a.config.PolygonDIDRegistry)
			if err == nil {
				key, err = ExtractPublicKey(didDoc)
			}
		case "did:key":
			key, err = ResolveDidKey(did)
		case "did:web":
			didDoc, err = ResolveDidWeb(did)
			if err == nil {
				key, err = ExtractPublicKey(didDoc)
			}
		default:
			err = fmt.Errorf("unsupported DID method for direct sync: %s", didMethod)
		}
	}

	if err != nil {
		return SyncResult{DID: did, Error: err.Error()}
	}

	var docJSON string
	if didDoc != nil {
		raw, _ := json.Marshal(didDoc)
		docJSON = string(raw)
	}

	a.cache.Set(IssuerEntry{
		DID:          did,
		DIDDocument:  docJSON,
		PublicKeyHex: key.PublicKeyHex,
		KeyType:      key.KeyType,
	})

	truncated := key.PublicKeyHex
	if len(truncated) > 16 {
		truncated = truncated[:16] + "..."
	}

	return SyncResult{
		Success:      true,
		DID:          did,
		KeyType:      key.KeyType,
		PublicKeyHex: truncated,
		CachedAt:     time.Now().Format(time.RFC3339),
	}
}

// --------------------------------------------------------------------------
// SD-JWT verification — raw string passthrough to backend.
// --------------------------------------------------------------------------

// VerifySDJWT verifies an SD-JWT credential. Online: forwards the raw token
// to a backend. Offline: parses the JWT, extracts the x5c certificate from
// the header, and verifies the signature locally.
func (a *Adapter) VerifySDJWT(token string, contentType string, forceOffline bool) VerificationResult {
	if !forceOffline {
		// Try each reachable backend.
		for _, b := range a.registry.All() {
			log.Printf("[VERIFY] SD-JWT: trying backend %s", b.Name())
			result := b.VerifyRaw(token, contentType)
			if result.Status == "SUCCESS" || result.Status == "INVALID" {
				result.Backend = b.Name()
				return result
			}
			log.Printf("[VERIFY] SD-JWT: backend %s: %s", b.Name(), result.Error)
		}
	}

	// Offline: verify locally using x5c certificate from JWT header.
	log.Println("[VERIFY] SD-JWT: attempting offline verification")
	valid, err := VerifySDJWTSignature(token)
	if err != nil {
		return VerificationResult{
			Status:  "INVALID",
			Offline: true,
			Error:   err.Error(),
		}
	}
	if !valid {
		return VerificationResult{
			Status:  "INVALID",
			Offline: true,
		}
	}
	return VerificationResult{
		Status:  "SUCCESS",
		Offline: true,
		Level:   "CRYPTOGRAPHIC",
	}
}

// --------------------------------------------------------------------------
// Request body parsing with PixelPass + JSON-XT support.
// --------------------------------------------------------------------------

// ParseRequestBody handles all input formats: PixelPass-encoded, JSON-XT URI,
// or plain JSON. Returns the parsed request and whether JSON-XT was used.
func (a *Adapter) ParseRequestBody(raw string) (map[string]any, bool, error) {
	trimmed := strings.TrimSpace(raw)

	// PixelPass decode first.
	if IsPixelPassEncoded(trimmed) {
		log.Println("[ADAPTER] detected PixelPass-encoded data")
		decoded, err := DecodePixelPass(trimmed)
		if err != nil {
			log.Printf("[ADAPTER] PixelPass decode failed: %v", err)
		} else {
			trimmed = decoded
		}
	}

	// Raw JSON-XT URI.
	if IsJsonXTURI(trimmed) {
		log.Println("[ADAPTER] detected JSON-XT URI")
		cred, err := DecodeJsonXT(trimmed, a.templates)
		if err != nil {
			return nil, false, fmt.Errorf("JSON-XT decode: %w", err)
		}
		return map[string]any{"credential": cred}, true, nil
	}

	// Plain JSON.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, false, fmt.Errorf("parse JSON: %w", err)
	}

	// Check for JSON-XT URIs nested inside JSON fields.
	jsonxt := false
	for _, field := range []string{"credential", "verifiableCredential"} {
		if uri, ok := parsed[field].(string); ok && IsJsonXTURI(uri) {
			cred, err := DecodeJsonXT(uri, a.templates)
			if err != nil {
				return nil, false, err
			}
			parsed[field] = cred
			jsonxt = true
		}
	}

	if arr, ok := parsed["verifiableCredentials"].([]any); ok {
		for i, item := range arr {
			if uri, ok := item.(string); ok && IsJsonXTURI(uri) {
				cred, err := DecodeJsonXT(uri, a.templates)
				if err != nil {
					return nil, false, err
				}
				arr[i] = cred
				jsonxt = true
			}
		}
	}

	return parsed, jsonxt, nil
}

// ExtractCredential pulls a credential from a parsed request body,
// supporting all wrapper formats used by verification UIs.
func ExtractCredential(request map[string]any) map[string]any {
	if arr, ok := request["verifiableCredentials"].([]any); ok && len(arr) > 0 {
		if cred, ok := arr[0].(map[string]any); ok {
			return cred
		}
	}
	for _, field := range []string{"credential", "verifiableCredential", "credentialDocument"} {
		if cred, ok := request[field].(map[string]any); ok {
			return cred
		}
	}
	if request["@context"] != nil {
		return request
	}
	return nil
}

// --------------------------------------------------------------------------
// Helpers.
// --------------------------------------------------------------------------

func extractIssuerDID(credential map[string]any) string {
	switch v := credential["issuer"].(type) {
	case string:
		return v
	case map[string]any:
		if id, ok := v["id"].(string); ok {
			return id
		}
	}
	return ""
}

func extractDidMethod(did string) string {
	parts := strings.SplitN(did, ":", 3)
	if len(parts) >= 2 && parts[0] == "did" {
		return "did:" + parts[1]
	}
	return ""
}

func modeStr(online bool) string {
	if online {
		return "ONLINE"
	}
	return "OFFLINE"
}
