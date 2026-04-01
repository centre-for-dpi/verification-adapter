package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/mr-tron/base58"
)

// TestVerifyEd25519Valid verifies that a correctly signed message passes
// Ed25519 verification.
func TestVerifyEd25519Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	message := []byte("test message for verification")
	sig := ed25519.Sign(priv, message)

	valid, err := verifyEd25519(message, sig, hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("verifyEd25519: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}
}

// TestVerifyEd25519Invalid verifies that a tampered message fails
// Ed25519 verification.
func TestVerifyEd25519Invalid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	sig := ed25519.Sign(priv, []byte("original"))

	valid, err := verifyEd25519([]byte("tampered"), sig, hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("verifyEd25519: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered data")
	}
}

// TestVerifyEd25519WrongKeySize verifies error handling for wrong key size.
func TestVerifyEd25519WrongKeySize(t *testing.T) {
	_, err := verifyEd25519([]byte("data"), []byte("sig"), "aabb")
	if err == nil {
		t.Error("expected error for wrong key size")
	}
}

// TestExtractSignatureMultibase verifies extraction of a z-prefixed
// base58btc multibase proof value.
func TestExtractSignatureMultibase(t *testing.T) {
	// Create a known signature and encode it.
	original := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	encoded := "z" + base58.Encode(original)

	proof := map[string]any{
		"proofValue": encoded,
	}

	sig, err := extractSignature(proof)
	if err != nil {
		t.Fatalf("extractSignature: %v", err)
	}
	if len(sig) != len(original) {
		t.Errorf("sig length = %d, want %d", len(sig), len(original))
	}
}

// TestExtractSignatureJWS verifies extraction of a JWS compact signature.
func TestExtractSignatureJWS(t *testing.T) {
	proof := map[string]any{
		"jws": "eyJhbGciOiJFZERTQSJ9..dGVzdHNpZw",
	}

	sig, err := extractSignature(proof)
	if err != nil {
		t.Fatalf("extractSignature: %v", err)
	}
	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}
}

// TestExtractSignatureNoSig verifies error when proof has no signature.
func TestExtractSignatureNoSig(t *testing.T) {
	proof := map[string]any{
		"type":    "Ed25519Signature2020",
		"created": "2025-01-01T00:00:00Z",
	}

	_, err := extractSignature(proof)
	if err == nil {
		t.Error("expected error for missing signature")
	}
}

// TestVerifyCredentialSignatureEndToEnd performs an end-to-end test:
// sign a credential with Ed25519 using the two-hash pattern, then verify.
func TestVerifyCredentialSignatureEndToEnd(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	canon := NewNativeCanonicalizer()

	// Build a simple credential.
	credential := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer":   "did:key:z6MkTest",
		"credentialSubject": map[string]any{
			"id":   "did:key:z6MkSubject",
			"name": "Test",
		},
	}

	// Sign: canonicalize doc and proof options, hash, sign.
	proofOpts := map[string]any{
		"@context":           credential["@context"],
		"type":               "Ed25519Signature2020",
		"created":            "2026-01-01T00:00:00Z",
		"verificationMethod": "did:key:z6MkTest#key-1",
		"proofPurpose":       "assertionMethod",
	}

	canonDoc, err := canon.Canonicalize(credential)
	if err != nil {
		t.Fatalf("canonicalize doc: %v", err)
	}
	canonProof, err := canon.Canonicalize(proofOpts)
	if err != nil {
		t.Fatalf("canonicalize proof: %v", err)
	}

	proofHash := sha256.Sum256([]byte(canonProof))
	docHash := sha256.Sum256([]byte(canonDoc))
	hashData := append(proofHash[:], docHash[:]...)

	sig := ed25519.Sign(priv, hashData)

	// Attach proof to credential.
	credential["proof"] = map[string]any{
		"type":               "Ed25519Signature2020",
		"created":            "2026-01-01T00:00:00Z",
		"verificationMethod": "did:key:z6MkTest#key-1",
		"proofPurpose":       "assertionMethod",
		"proofValue":         "z" + base58.Encode(sig),
	}

	// Verify.
	valid, err := VerifyCredentialSignature(credential, hex.EncodeToString(pub), "Ed25519", canon)
	if err != nil {
		t.Fatalf("VerifyCredentialSignature: %v", err)
	}
	if !valid {
		t.Error("expected valid signature in end-to-end test")
	}

	// Tamper with the credential and verify again.
	credential["issuer"] = "did:key:z6MkTampered"
	valid, err = VerifyCredentialSignature(credential, hex.EncodeToString(pub), "Ed25519", canon)
	if err != nil {
		t.Fatalf("VerifyCredentialSignature (tampered): %v", err)
	}
	if valid {
		t.Error("expected invalid signature after tampering")
	}
}
