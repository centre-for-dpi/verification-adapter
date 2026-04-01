package main

import (
	"testing"
)

// TestResolveDidKeyEd25519 verifies local resolution of an Ed25519 did:key.
func TestResolveDidKeyEd25519(t *testing.T) {
	// This is a well-known test vector: ed25519 public key 0xed01 prefix.
	// did:key:z6Mk... encodes 0xed01 + 32-byte key.
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	key, err := ResolveDidKey(did)
	if err != nil {
		t.Fatalf("ResolveDidKey: %v", err)
	}
	if key.KeyType != "Ed25519" {
		t.Errorf("KeyType = %q, want Ed25519", key.KeyType)
	}
	if len(key.PublicKeyHex) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("PublicKeyHex length = %d, want 64", len(key.PublicKeyHex))
	}
}

// TestResolveDidKeyInvalid verifies error handling for malformed did:key DIDs.
func TestResolveDidKeyInvalid(t *testing.T) {
	cases := []struct {
		name string
		did  string
	}{
		{"too few parts", "did:key"},
		{"wrong prefix", "did:web:example.com"},
		{"not multibase z", "did:key:f6MkTest"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveDidKey(tc.did)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc.did)
			}
		})
	}
}

// TestExtractPublicKeyMultibase verifies extraction from a DID document
// with a publicKeyMultibase verification method.
func TestExtractPublicKeyMultibase(t *testing.T) {
	doc := map[string]any{
		"verificationMethod": []any{
			map[string]any{
				"type":               "Ed25519VerificationKey2020",
				"publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			},
		},
	}

	key, err := ExtractPublicKey(doc)
	if err != nil {
		t.Fatalf("ExtractPublicKey: %v", err)
	}
	if key.KeyType != "Ed25519" {
		t.Errorf("KeyType = %q, want Ed25519", key.KeyType)
	}
}

// TestExtractPublicKeyHex verifies extraction from a DID document
// with a publicKeyHex verification method (Polygon-style).
func TestExtractPublicKeyHex(t *testing.T) {
	doc := map[string]any{
		"verificationMethod": []any{
			map[string]any{
				"type":         "EcdsaSecp256k1VerificationKey2019",
				"publicKeyHex": "04abcdef1234567890",
			},
		},
	}

	key, err := ExtractPublicKey(doc)
	if err != nil {
		t.Fatalf("ExtractPublicKey: %v", err)
	}
	if key.KeyType != "secp256k1" {
		t.Errorf("KeyType = %q, want secp256k1", key.KeyType)
	}
	if key.PublicKeyHex != "04abcdef1234567890" {
		t.Errorf("PublicKeyHex = %q, want 04abcdef1234567890", key.PublicKeyHex)
	}
}

// TestExtractPublicKeyNoVM verifies error when no verification method exists.
func TestExtractPublicKeyNoVM(t *testing.T) {
	doc := map[string]any{
		"id": "did:example:123",
	}
	_, err := ExtractPublicKey(doc)
	if err == nil {
		t.Error("expected error for missing verification method")
	}
}
