// config.go — Adapter configuration.
//
// Configuration is loaded in two layers:
//
//  1. A backends.json file (path set by BACKENDS_CONFIG) that declares
//     verification backends — their URLs, auth, request/response formats,
//     and supported DID methods. Adding a new verifier is a config change.
//
//  2. Environment variables for adapter-level settings (port, cache, Polygon
//     RPC) and backward-compatible CREDEBL/Inji defaults when no backends
//     file is present.
package main

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds adapter-level settings that are independent of which
// verification backends are in use.
type Config struct {
	// Port the adapter listens on.
	Port int

	// PolygonRPCURL is a public Polygon RPC endpoint for on-chain DID resolution.
	PolygonRPCURL string
	// PolygonDIDRegistry is the EVM address of the Polygon DID registry contract.
	PolygonDIDRegistry string

	// CacheDBPath is the filesystem path for the SQLite issuer cache.
	CacheDBPath string
	// CacheTTL controls how long a cached issuer entry stays valid.
	CacheTTL time.Duration

	// ConnCheckInterval is how often the adapter pings upstream backends.
	ConnCheckInterval time.Duration
	// ConnTimeout is the HTTP timeout for connectivity probes.
	ConnTimeout time.Duration

	// TemplatesPath points to the JSON-XT templates file.
	TemplatesPath string

	// BackendsConfigPath points to a JSON file defining verification backends.
	// When empty, the adapter falls back to CREDEBL + Inji Verify defaults.
	BackendsConfigPath string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() Config {
	return Config{
		Port:               envInt("ADAPTER_PORT", 8085),
		PolygonRPCURL:      envStr("POLYGON_RPC_URL", "https://polygon-bor-rpc.publicnode.com"),
		PolygonDIDRegistry: envStr("POLYGON_DID_REGISTRY", "0x0C16958c4246271622201101C83B9F0Fc7180d15"),
		CacheDBPath:        envStr("CACHE_DB", "./cache/issuer-cache.db"),
		CacheTTL:           time.Duration(envInt("CACHE_TTL_HOURS", 168)) * time.Hour, // 7 days
		ConnCheckInterval:  time.Duration(envInt("CONN_CHECK_INTERVAL_SEC", 30)) * time.Second,
		ConnTimeout:        time.Duration(envInt("CONN_TIMEOUT_MS", 5000)) * time.Millisecond,
		TemplatesPath:      envStr("TEMPLATES_PATH", "./templates/jsonxt-templates.json"),
		BackendsConfigPath: envStr("BACKENDS_CONFIG", ""),
	}
}

// LoadBackends reads backend configurations. If a backends.json file is
// configured and exists, it is used. Otherwise, the adapter constructs
// default backends from legacy CREDEBL/Inji environment variables.
func LoadBackends(cfg Config) []BackendConfig {
	if cfg.BackendsConfigPath != "" {
		backends, err := loadBackendsFile(cfg.BackendsConfigPath)
		if err != nil {
			log.Printf("[CONFIG] failed to load %s: %v, falling back to env defaults", cfg.BackendsConfigPath, err)
		} else {
			log.Printf("[CONFIG] loaded %d backend(s) from %s", len(backends), cfg.BackendsConfigPath)
			return backends
		}
	}

	// Backward-compatible defaults from environment variables.
	log.Println("[CONFIG] no backends config file, using env var defaults")

	agentURL := envStr("CREDEBL_AGENT_URL", "http://host.docker.internal:8004")
	agentKey := envStr("CREDEBL_API_KEY", "supersecret-that-too-16chars")
	injiURL := envStr("UPSTREAM_VERIFY_SERVICE", "http://inji-verify-service:8080")

	return []BackendConfig{
		CredeblBackendConfig(agentURL, agentKey),
		InjiVerifyBackendConfig(injiURL),
	}
}

func loadBackendsFile(path string) ([]BackendConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var file struct {
		Backends []BackendConfig `json:"backends"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file.Backends, nil
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
