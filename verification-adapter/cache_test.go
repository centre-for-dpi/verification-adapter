package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCacheSetGet verifies basic insert and retrieval.
func TestCacheSetGet(t *testing.T) {
	c := testCache(t)

	entry := IssuerEntry{
		DID:          "did:key:z6MkTest123",
		PublicKeyHex: "abcdef0123456789",
		KeyType:      "Ed25519",
	}
	if err := c.Set(entry); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := c.Get("did:key:z6MkTest123")
	if got == nil {
		t.Fatal("expected cached entry, got nil")
	}
	if got.PublicKeyHex != "abcdef0123456789" {
		t.Errorf("PublicKeyHex = %q, want %q", got.PublicKeyHex, "abcdef0123456789")
	}
	if got.KeyType != "Ed25519" {
		t.Errorf("KeyType = %q, want %q", got.KeyType, "Ed25519")
	}
}

// TestCacheGetMiss verifies that a missing DID returns nil.
func TestCacheGetMiss(t *testing.T) {
	c := testCache(t)
	got := c.Get("did:key:nonexistent")
	if got != nil {
		t.Errorf("expected nil for missing DID, got %+v", got)
	}
}

// TestCacheTTLExpiry verifies that expired entries are not returned.
func TestCacheTTLExpiry(t *testing.T) {
	c := testCacheWithTTL(t, 1*time.Millisecond)

	c.Set(IssuerEntry{
		DID:          "did:key:z6MkExpired",
		PublicKeyHex: "dead",
		KeyType:      "Ed25519",
		CachedAt:     time.Now().Add(-1 * time.Hour).UnixMilli(),
	})

	got := c.Get("did:key:z6MkExpired")
	if got != nil {
		t.Errorf("expected nil for expired entry, got %+v", got)
	}
}

// TestCacheUpsert verifies that Set replaces an existing entry.
func TestCacheUpsert(t *testing.T) {
	c := testCache(t)

	c.Set(IssuerEntry{DID: "did:key:z6MkUp", PublicKeyHex: "old", KeyType: "Ed25519"})
	c.Set(IssuerEntry{DID: "did:key:z6MkUp", PublicKeyHex: "new", KeyType: "Ed25519"})

	got := c.Get("did:key:z6MkUp")
	if got == nil || got.PublicKeyHex != "new" {
		t.Errorf("expected updated key 'new', got %+v", got)
	}
}

// TestCacheCount verifies the count of cached issuers.
func TestCacheCount(t *testing.T) {
	c := testCache(t)

	c.Set(IssuerEntry{DID: "did:key:a", KeyType: "Ed25519"})
	c.Set(IssuerEntry{DID: "did:key:b", KeyType: "Ed25519"})

	n, err := c.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 2 {
		t.Errorf("Count = %d, want 2", n)
	}
}

// TestCacheStats verifies the stats endpoint returns correct data.
func TestCacheStats(t *testing.T) {
	c := testCache(t)

	c.Set(IssuerEntry{DID: "did:key:z6MkStats", KeyType: "Ed25519"})
	c.SetLastSync()

	stats := c.Stats()
	if stats.TotalIssuers != 1 {
		t.Errorf("TotalIssuers = %d, want 1", stats.TotalIssuers)
	}
	if stats.LastSync == nil {
		t.Error("expected LastSync to be set")
	}
}

// testCache creates a temporary in-memory cache for testing.
func testCache(t *testing.T) *IssuerCache {
	t.Helper()
	return testCacheWithTTL(t, 24*time.Hour)
}

func testCacheWithTTL(t *testing.T, ttl time.Duration) *IssuerCache {
	t.Helper()
	dir := t.TempDir()
	c, err := NewIssuerCache(filepath.Join(dir, "test.db"), ttl)
	if err != nil {
		t.Fatalf("NewIssuerCache: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestCacheMigrateFromJSON verifies legacy JSON cache migration.
func TestCacheMigrateFromJSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "legacy.json")
	now := time.Now().UnixMilli()
	os.WriteFile(jsonPath, []byte(fmt.Sprintf(`{
		"issuers": {
			"did:key:z6MkLegacy": {
				"publicKeyHex": "aabbcc",
				"keyType": "Ed25519",
				"cachedAt": %d
			}
		},
		"lastSync": %d
	}`, now, now)), 0o644)

	c, err := NewIssuerCache(filepath.Join(dir, "db.sqlite"), 24*time.Hour)
	if err != nil {
		t.Fatalf("NewIssuerCache: %v", err)
	}
	defer c.Close()

	if err := c.MigrateFromJSON(jsonPath); err != nil {
		t.Fatalf("MigrateFromJSON: %v", err)
	}

	got := c.Get("did:key:z6MkLegacy")
	if got == nil {
		t.Fatal("expected migrated entry, got nil")
	}
	if got.PublicKeyHex != "aabbcc" {
		t.Errorf("PublicKeyHex = %q, want %q", got.PublicKeyHex, "aabbcc")
	}

	// Legacy file should be renamed.
	if _, err := os.Stat(jsonPath + ".migrated"); os.IsNotExist(err) {
		t.Error("expected legacy file to be renamed to .migrated")
	}
}
