// adapter-standalone is a backend-agnostic verification adapter that bridges
// any verification UI to any W3C-compliant verifier backend.
//
// Backends (CREDEBL Agent, Inji Verify, walt.id, or custom) are configured
// via a backends.json file — no code changes needed to add a new verifier.
// Offline verification uses URDNA2015 JSON-LD canonicalization, producing
// bit-identical digests to any standards-compliant issuer.
//
// Run with: go run . or via Docker.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := LoadConfig()

	// Canonicalizer — URDNA2015 via json-gold. Uses a CachingDocumentLoader
	// that fetches and caches remote @context URLs over HTTP, supporting
	// custom credential schemas (e.g. credissuer.com templates).
	//
	// The WASM backend (@digitalbazaar/jsonld) is available but only bundles
	// W3C standard contexts — it cannot fetch custom contexts at runtime.
	// json-gold produces identical N-Quads (proven in tests) and handles
	// custom contexts via network access.
	canon := NewNativeCanonicalizer()
	log.Println("[CANON] using json-gold canonicalizer (URDNA2015 with HTTP context fetching)")

	// SQLite issuer cache.
	cache, err := NewIssuerCache(cfg.CacheDBPath, cfg.CacheTTL)
	if err != nil {
		log.Fatalf("cache init: %v", err)
	}
	defer cache.Close()

	// JSON-XT templates.
	templates, err := LoadTemplates(cfg.TemplatesPath)
	if err != nil {
		log.Printf("[JSONXT] templates not loaded: %v", err)
	} else {
		log.Printf("[JSONXT] loaded %d template(s) from %s", len(templates), cfg.TemplatesPath)
	}

	// Backend registry — load from config file or env vars.
	registry := NewBackendRegistry()
	for _, bcfg := range LoadBackends(cfg) {
		registry.Register(NewConfigurableBackend(bcfg))
	}

	// Connectivity checker probes each registered backend.
	conn := NewConnectivityChecker(registry, cfg.ConnTimeout, cfg.ConnCheckInterval)
	go conn.Start()
	defer conn.Stop()

	// Adapter wires all components together.
	adapter := &Adapter{
		config:       cfg,
		cache:        cache,
		canon:        canon,
		connectivity: conn,
		registry:     registry,
		templates:    templates,
	}

	// HTTP server.
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      NewRouter(adapter),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		printBanner(cfg, registry)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	// Graceful shutdown on SIGINT/SIGTERM.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[SHUTDOWN] shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[SHUTDOWN] forced: %v", err)
	}
}

func printBanner(cfg Config, registry *BackendRegistry) {
	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println("  VERIFICATION ADAPTER (Go)")
	fmt.Println("  URDNA2015 Canonicalization")
	fmt.Println("===========================================")
	fmt.Println()
	fmt.Printf("  Port:          %d\n", cfg.Port)
	fmt.Printf("  Cache DB:      %s\n", cfg.CacheDBPath)
	fmt.Printf("  Templates:     %s\n", cfg.TemplatesPath)
	fmt.Println()
	fmt.Println("  Backends:")
	for _, b := range registry.All() {
		fmt.Printf("    - %s (%s)\n", b.Name(), b.HealthEndpoint())
	}
	fmt.Println()
	fmt.Println("  Endpoints:")
	fmt.Println("    POST /v1/verify/vc-verification  — verify credential")
	fmt.Println("    POST /verify-offline             — force offline mode")
	fmt.Println("    POST /sync                       — cache issuer(s)")
	fmt.Println("    GET  /cache                      — cache stats")
	fmt.Println("    GET  /templates                  — JSON-XT templates")
	fmt.Println("    GET  /health                     — health check")
	fmt.Println()
	fmt.Println("===========================================")
	fmt.Println()
}
