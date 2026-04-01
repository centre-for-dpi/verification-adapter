package main

import (
	"strings"
	"testing"
)

// TestCanonSimpleDocument verifies that a basic schema.org document
// produces non-empty N-Quads containing the expected literal value.
func TestCanonSimpleDocument(t *testing.T) {
	c := NewNativeCanonicalizer()
	doc := map[string]any{
		"@context": "https://schema.org/",
		"@type":    "Person",
		"name":     "Alice",
	}
	result, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty canonical form")
	}
	if !strings.Contains(result, "Alice") {
		t.Errorf("canonical form should contain 'Alice', got:\n%s", result)
	}
}

// TestCanonDeterministic verifies that repeated canonicalization of the same
// document produces identical N-Quads — the core guarantee of URDNA2015.
func TestCanonDeterministic(t *testing.T) {
	c := NewNativeCanonicalizer()
	doc := map[string]any{
		"@context": "https://schema.org/",
		"@type":    "Person",
		"name":     "Bob",
		"email":    "bob@example.com",
	}
	r1, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("run 1: %v", err)
	}
	r2, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if r1 != r2 {
		t.Errorf("not deterministic:\n  run1: %s\n  run2: %s", r1, r2)
	}
}

// TestCanonVCDocument verifies canonicalization of a W3C VC Data Model 2.0
// document, which is the primary use case for this adapter.
func TestCanonVCDocument(t *testing.T) {
	c := NewNativeCanonicalizer()
	doc := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/credentials/v2",
		},
		"type":      []any{"VerifiableCredential"},
		"issuer":    "did:web:example.com",
		"validFrom": "2026-03-30T10:00:00Z",
		"credentialSubject": map[string]any{
			"id":   "did:key:z6MkhaXgBZDvotDkL5257",
			"name": "Test Subject",
		},
	}
	result, err := c.Canonicalize(doc)
	if err != nil {
		t.Fatalf("Canonicalize VC: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty canonical form for VC")
	}
}

// TestCanonEmptyDocument verifies that an empty JSON-LD document produces
// an empty N-Quads string (no triples).
func TestCanonEmptyDocument(t *testing.T) {
	c := NewNativeCanonicalizer()
	result, err := c.Canonicalize(map[string]any{})
	if err != nil {
		t.Fatalf("Canonicalize empty: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for empty doc, got: %s", result)
	}
}

// TestCanonKeyOrderIrrelevant verifies that two documents with the same
// content but different Go map iteration order produce identical N-Quads.
// This is the property that JSON.stringify with sorted keys tries (and
// fails) to approximate.
func TestCanonKeyOrderIrrelevant(t *testing.T) {
	c := NewNativeCanonicalizer()

	doc1 := map[string]any{
		"@context": "https://schema.org/",
		"@type":    "Person",
		"name":     "Charlie",
		"email":    "charlie@example.com",
	}
	doc2 := map[string]any{
		"email":    "charlie@example.com",
		"@type":    "Person",
		"@context": "https://schema.org/",
		"name":     "Charlie",
	}

	r1, err := c.Canonicalize(doc1)
	if err != nil {
		t.Fatalf("doc1: %v", err)
	}
	r2, err := c.Canonicalize(doc2)
	if err != nil {
		t.Fatalf("doc2: %v", err)
	}
	if r1 != r2 {
		t.Errorf("different key order should produce same canonical form:\n  doc1: %s\n  doc2: %s", r1, r2)
	}
}
