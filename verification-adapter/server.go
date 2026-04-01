// server.go — HTTP handlers and routing.
//
// Exposes the same API surface as the Node.js adapter so the Inji Verify UI
// can switch backends without changes. All endpoints accept and return JSON.
//
// Endpoints:
//   POST /v1/verify/vc-verification  — verify a credential (auto online/offline)
//   POST /verify-offline             — force offline verification
//   POST /sync                       — cache issuer DID(s)
//   GET  /cache                      — cache statistics
//   GET  /templates                  — JSON-XT templates
//   GET  /health                     — health check
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// NewRouter creates an http.Handler with all adapter endpoints.
func NewRouter(a *Adapter) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", a.handleHealth)
	mux.HandleFunc("GET /cache", a.handleCacheStats)
	mux.HandleFunc("GET /templates", a.handleTemplates)
	mux.HandleFunc("POST /v1/verify/vc-verification", a.handleVerify)
	mux.HandleFunc("POST /verify-offline", a.handleVerifyOffline)
	mux.HandleFunc("POST /sync", a.handleSync)

	// CORS middleware.
	return corsMiddleware(mux)
}

// --------------------------------------------------------------------------
// Handlers.
// --------------------------------------------------------------------------

func (a *Adapter) handleHealth(w http.ResponseWriter, r *http.Request) {
	stats := a.cache.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                "ok",
		"service":               "verification-adapter-go",
		"canonicalization":      "URDNA2015",
		"connectivity":         modeStr(a.connectivity.IsAnyOnline()),
		"backends":             a.connectivity.Status(),
		"lastConnectivityCheck": a.connectivity.LastCheck(),
		"cache":                 stats,
	})
}

func (a *Adapter) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.cache.Stats())
}

func (a *Adapter) handleTemplates(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "JSON-XT templates not loaded"})
		return
	}
	writeJSON(w, http.StatusOK, a.templates)
}

func (a *Adapter) handleVerify(w http.ResponseWriter, r *http.Request) {
	a.doVerify(w, r, false)
}

func (a *Adapter) handleVerifyOffline(w http.ResponseWriter, r *http.Request) {
	a.doVerify(w, r, true)
}

func (a *Adapter) doVerify(w http.ResponseWriter, r *http.Request, forceOffline bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, VerificationResult{Status: "ERROR", Error: "read body: " + err.Error()})
		return
	}

	ct := r.Header.Get("Content-Type")

	// SD-JWT: raw string body, not JSON. Pass through to backend with
	// the original content type preserved.
	if isSDJWTContentType(ct) {
		log.Printf("[ADAPTER] SD-JWT credential detected (Content-Type: %s)", ct)
		result := a.VerifySDJWT(string(body), ct, forceOffline)
		writeJSON(w, http.StatusOK, result)
		return
	}

	parsed, jsonxt, err := a.ParseRequestBody(string(body))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, VerificationResult{Status: "ERROR", Error: err.Error()})
		return
	}

	if jsonxt {
		log.Println("[ADAPTER] credential decoded from JSON-XT format")
	}

	credential := ExtractCredential(parsed)
	if credential == nil {
		log.Printf("[ADAPTER] no credential found in request. Keys: %v", mapKeys(parsed))
		writeJSON(w, http.StatusBadRequest, VerificationResult{Status: "INVALID", Error: "no credential provided"})
		return
	}

	log.Printf("[ADAPTER] processing credential from issuer: %s", extractIssuerDID(credential))
	result := a.VerifyCredential(credential, forceOffline)
	result.VC = credential
	result.VCField = credential

	writeJSON(w, http.StatusOK, result)
}

func isSDJWTContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "sd-jwt")
}

func (a *Adapter) handleSync(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	var req struct {
		DID  string   `json:"did"`
		DIDs []string `json:"dids"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	toSync := req.DIDs
	if req.DID != "" && len(toSync) == 0 {
		toSync = []string{req.DID}
	}

	results := make([]SyncResult, 0, len(toSync))
	for _, did := range toSync {
		results = append(results, a.SyncIssuer(did))
	}

	a.cache.SetLastSync()
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// --------------------------------------------------------------------------
// CORS and helpers.
// --------------------------------------------------------------------------

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
