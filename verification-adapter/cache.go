// cache.go — SQLite-backed issuer cache for offline verification.
//
// Stores resolved DID documents and extracted public keys so the adapter can
// verify credential signatures without network access. Uses pure-Go SQLite
// (modernc.org/sqlite) for a single-binary deployment with no CGO.
//
// Cache entries expire after a configurable TTL (default 7 days). The cache
// also supports migration from the Node.js adapter's legacy JSON file format.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// IssuerEntry is a cached DID resolution result.
type IssuerEntry struct {
	DID          string `json:"did"`
	DIDDocument  string `json:"didDocument,omitempty"` // raw JSON
	PublicKeyHex string `json:"publicKeyHex,omitempty"`
	KeyType      string `json:"keyType,omitempty"` // "Ed25519" or "secp256k1"
	CachedAt     int64  `json:"cachedAt"`          // unix millis
}

// CacheStats is returned by the /cache endpoint.
type CacheStats struct {
	TotalIssuers int            `json:"totalIssuers"`
	LastSync     *time.Time     `json:"lastSync,omitempty"`
	Storage      string         `json:"storage"`
	DBPath       string         `json:"dbPath"`
	Issuers      []IssuerBrief  `json:"issuers"`
}

// IssuerBrief is a summary of a cached issuer for the stats endpoint.
type IssuerBrief struct {
	DID       string `json:"did"`
	CachedAt  string `json:"cachedAt"`
	ExpiresAt string `json:"expiresAt"`
}

// IssuerCache provides TTL-aware storage of DID resolution results in SQLite.
type IssuerCache struct {
	db  *sql.DB
	ttl time.Duration
}

// NewIssuerCache opens (or creates) a SQLite database at dbPath and
// initialises the schema. The cache directory is created if it does not
// exist.
func NewIssuerCache(dbPath string, ttl time.Duration) (*IssuerCache, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("cache: mkdir %s: %w", dir, err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("cache: open %s: %w", dbPath, err)
	}

	// WAL mode for better concurrent read performance.
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("cache: WAL: %w", err)
	}

	c := &IssuerCache{db: db, ttl: ttl}
	if err := c.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	count, _ := c.Count()
	log.Printf("[CACHE] SQLite initialised with %d issuer(s)", count)
	return c, nil
}

func (c *IssuerCache) initSchema() error {
	_, err := c.db.Exec(`
		CREATE TABLE IF NOT EXISTS issuers (
			did          TEXT PRIMARY KEY,
			did_document TEXT,
			public_key_hex TEXT,
			key_type     TEXT,
			cached_at    INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_issuers_cached_at ON issuers(cached_at);

		CREATE TABLE IF NOT EXISTS metadata (
			key       TEXT PRIMARY KEY,
			value     TEXT,
			updated_at INTEGER
		);
	`)
	if err != nil {
		return fmt.Errorf("cache: schema: %w", err)
	}
	return nil
}

// Get retrieves a cached issuer entry, returning nil if not found or expired.
func (c *IssuerCache) Get(did string) *IssuerEntry {
	row := c.db.QueryRow(
		"SELECT did, did_document, public_key_hex, key_type, cached_at FROM issuers WHERE did = ?",
		did,
	)
	var e IssuerEntry
	var docNull, keyNull, typeNull sql.NullString
	if err := row.Scan(&e.DID, &docNull, &keyNull, &typeNull, &e.CachedAt); err != nil {
		return nil
	}
	e.DIDDocument = docNull.String
	e.PublicKeyHex = keyNull.String
	e.KeyType = typeNull.String

	// TTL check.
	if time.Since(time.UnixMilli(e.CachedAt)) > c.ttl {
		log.Printf("[CACHE] expired entry for %s", did)
		return nil
	}
	return &e
}

// Set inserts or replaces an issuer cache entry.
func (c *IssuerCache) Set(entry IssuerEntry) error {
	if entry.CachedAt == 0 {
		entry.CachedAt = time.Now().UnixMilli()
	}
	_, err := c.db.Exec(
		"INSERT OR REPLACE INTO issuers (did, did_document, public_key_hex, key_type, cached_at) VALUES (?,?,?,?,?)",
		entry.DID, nullStr(entry.DIDDocument), nullStr(entry.PublicKeyHex), nullStr(entry.KeyType), entry.CachedAt,
	)
	if err != nil {
		return fmt.Errorf("cache: set %s: %w", entry.DID, err)
	}
	log.Printf("[CACHE] cached issuer: %s", entry.DID)
	return nil
}

// Delete removes an issuer from the cache.
func (c *IssuerCache) Delete(did string) {
	c.db.Exec("DELETE FROM issuers WHERE did = ?", did)
}

// Count returns the number of cached issuers.
func (c *IssuerCache) Count() (int, error) {
	var n int
	err := c.db.QueryRow("SELECT COUNT(*) FROM issuers").Scan(&n)
	return n, err
}

// CleanExpired removes entries older than the TTL.
func (c *IssuerCache) CleanExpired() int64 {
	cutoff := time.Now().Add(-c.ttl).UnixMilli()
	res, err := c.db.Exec("DELETE FROM issuers WHERE cached_at < ?", cutoff)
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		log.Printf("[CACHE] cleaned %d expired issuers", n)
	}
	return n
}

// Stats returns cache statistics for the /cache endpoint.
func (c *IssuerCache) Stats() CacheStats {
	stats := CacheStats{
		Storage: "sqlite",
	}

	rows, err := c.db.Query("SELECT did, cached_at FROM issuers")
	if err != nil {
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var did string
		var cachedAt int64
		if err := rows.Scan(&did, &cachedAt); err != nil {
			continue
		}
		t := time.UnixMilli(cachedAt)
		stats.Issuers = append(stats.Issuers, IssuerBrief{
			DID:       did,
			CachedAt:  t.Format(time.RFC3339),
			ExpiresAt: t.Add(c.ttl).Format(time.RFC3339),
		})
	}
	stats.TotalIssuers = len(stats.Issuers)

	// Last sync time from metadata.
	var syncVal sql.NullString
	c.db.QueryRow("SELECT value FROM metadata WHERE key = 'last_sync'").Scan(&syncVal)
	if syncVal.Valid {
		if ts, err := time.Parse(time.RFC3339, syncVal.String); err == nil {
			stats.LastSync = &ts
		}
	}

	return stats
}

// SetLastSync records the current time as the last sync timestamp.
func (c *IssuerCache) SetLastSync() {
	now := time.Now().Format(time.RFC3339)
	c.db.Exec(
		"INSERT OR REPLACE INTO metadata (key, value, updated_at) VALUES ('last_sync', ?, ?)",
		now, time.Now().UnixMilli(),
	)
}

// MigrateFromJSON imports entries from a legacy Node.js adapter JSON cache
// file if it exists. The file is renamed to .migrated after import.
func (c *IssuerCache) MigrateFromJSON(jsonPath string) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil // file not found is not an error
	}

	var legacy struct {
		Issuers  map[string]json.RawMessage `json:"issuers"`
		LastSync int64                      `json:"lastSync"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return fmt.Errorf("cache: parse legacy JSON: %w", err)
	}

	for did, raw := range legacy.Issuers {
		var entry struct {
			PublicKeyHex string `json:"publicKeyHex"`
			KeyType      string `json:"keyType"`
			PublicKey    string `json:"publicKey"`
			CachedAt     int64  `json:"cachedAt"`
		}
		json.Unmarshal(raw, &entry)
		kt := entry.KeyType
		if kt == "" {
			kt = entry.PublicKey
		}
		c.Set(IssuerEntry{
			DID:          did,
			DIDDocument:  string(raw),
			PublicKeyHex: entry.PublicKeyHex,
			KeyType:      kt,
			CachedAt:     entry.CachedAt,
		})
	}

	os.Rename(jsonPath, jsonPath+".migrated")
	log.Printf("[CACHE] migrated %d issuers from JSON", len(legacy.Issuers))
	return nil
}

// Close closes the underlying database connection.
func (c *IssuerCache) Close() error {
	return c.db.Close()
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
