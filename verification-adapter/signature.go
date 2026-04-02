// signature.go — Cryptographic signature verification using URDNA2015.
//
// This is the key improvement over the Node.js adapter: instead of hashing
// a JSON.stringify'd credential (which produces a different digest than what
// the issuer signed), we canonicalize using URDNA2015 and apply the W3C Data
// Integrity two-hash pattern:
//
//   hashData = SHA256(URDNA2015(proofOptions)) || SHA256(URDNA2015(document))
//
// This produces bit-identical digests to any standards-compliant issuer,
// enabling true offline cryptographic verification.
//
// Supported proof suites:
//   - Ed25519Signature2018        (Ed25519, proofValue or JWS)
//   - Ed25519Signature2020        (Ed25519, multibase proofValue)
//   - EcdsaSecp256k1Signature2019 (secp256k1, proofValue or JWS)
//   - RsaSignature2018            (RSA PKCS#1 v1.5, JWS)
//   - DataIntegrityProof/eddsa-rdfc-2022 (Ed25519, base64url proofValue)
package main

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"

	dcrsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/mr-tron/base58"
)

// VerifyCredentialSignature verifies the Data Integrity proof on a credential
// using proper URDNA2015 canonicalization. Returns true if the signature is
// valid, false otherwise. Returns an error if the proof type is unsupported
// or the inputs are malformed.
func VerifyCredentialSignature(credential map[string]any, pubKeyHex string, keyType string, canon Canonicalizer) (bool, error) {
	proof, ok := credential["proof"].(map[string]any)
	if !ok {
		return false, fmt.Errorf("sig: no proof in credential")
	}

	proofType, _ := proof["type"].(string)
	cryptoSuite, _ := proof["cryptosuite"].(string)

	// Build the two inputs for the two-hash pattern:
	// 1. Document without proof.
	// 2. Proof options (proof without signature fields, with @context).
	doc := make(map[string]any, len(credential)-1)
	for k, v := range credential {
		if k != "proof" {
			doc[k] = v
		}
	}

	proofOpts := make(map[string]any, len(proof))
	for k, v := range proof {
		// Strip signature-bearing fields from proof options.
		if k == "proofValue" || k == "jws" {
			continue
		}
		proofOpts[k] = v
	}
	// Proof options inherit @context from the document for canonicalization.
	proofOpts["@context"] = credential["@context"]

	// Canonicalize both parts.
	canonDoc, err := canon.Canonicalize(doc)
	if err != nil {
		return false, fmt.Errorf("sig: canonicalize document: %w", err)
	}
	canonProof, err := canon.Canonicalize(proofOpts)
	if err != nil {
		return false, fmt.Errorf("sig: canonicalize proof options: %w", err)
	}

	// Two-hash pattern: SHA256(canonProof) || SHA256(canonDoc).
	proofHash := sha256.Sum256([]byte(canonProof))
	docHash := sha256.Sum256([]byte(canonDoc))
	hashData := append(proofHash[:], docHash[:]...)

	log.Printf("[SIG] proof type=%s, cryptosuite=%s, keyType=%s", proofType, cryptoSuite, keyType)

	// Extract the signature bytes from the proof.
	sigBytes, err := extractSignature(proof)
	if err != nil {
		return false, err
	}

	// Dispatch to the appropriate verification function.
	switch {
	case proofType == "DataIntegrityProof" && cryptoSuite == "eddsa-rdfc-2022":
		return verifyEd25519(hashData, sigBytes, pubKeyHex)

	case proofType == "Ed25519Signature2020":
		return verifyEd25519(hashData, sigBytes, pubKeyHex)

	case proofType == "Ed25519Signature2018":
		return verifyEd25519(hashData, sigBytes, pubKeyHex)

	case proofType == "EcdsaSecp256k1Signature2019":
		return verifySecp256k1(hashData, sigBytes, pubKeyHex)

	case proofType == "RsaSignature2018":
		return verifyRSA(hashData, sigBytes, pubKeyHex)

	default:
		return false, fmt.Errorf("sig: unsupported proof type: %s (cryptosuite: %s)", proofType, cryptoSuite)
	}
}

// extractSignature reads the signature bytes from a proof's proofValue or jws.
func extractSignature(proof map[string]any) ([]byte, error) {
	// proofValue — base58btc multibase or raw base58.
	if pv, ok := proof["proofValue"].(string); ok && pv != "" {
		// Multibase 'z' prefix = base58btc.
		if strings.HasPrefix(pv, "z") {
			return base58.Decode(pv[1:])
		}
		// Try base64url (DataIntegrityProof).
		if decoded, err := base64.RawURLEncoding.DecodeString(pv); err == nil && len(decoded) > 0 {
			return decoded, nil
		}
		// Fall back to raw base58.
		return base58.Decode(pv)
	}

	// JWS compact serialization: header.payload.signature
	if jws, ok := proof["jws"].(string); ok && jws != "" {
		parts := strings.Split(jws, ".")
		if len(parts) < 3 {
			return nil, fmt.Errorf("sig: invalid JWS format")
		}
		return base64.RawURLEncoding.DecodeString(parts[2])
	}

	return nil, fmt.Errorf("sig: no proofValue or jws in proof")
}

// verifyEd25519 verifies an Ed25519 signature over the given data.
func verifyEd25519(data, sig []byte, pubKeyHex string) (bool, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("sig: decode Ed25519 public key: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("sig: Ed25519 key wrong size: %d bytes (want %d)", len(pubKeyBytes), ed25519.PublicKeySize)
	}

	return ed25519.Verify(ed25519.PublicKey(pubKeyBytes), data, sig), nil
}

// verifySecp256k1 verifies an ECDSA-secp256k1 signature over the SHA256
// hash of the given data. Supports both DER and compact (R||S) formats.
func verifySecp256k1(data, sig []byte, pubKeyHex string) (bool, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("sig: decode secp256k1 public key: %w", err)
	}

	pubKey, err := dcrsecp.ParsePubKey(pubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("sig: parse secp256k1 public key: %w", err)
	}

	// Hash the data with SHA256 (secp256k1 ECDSA signs over a hash).
	hash := sha256.Sum256(data)

	// Try DER format first (most common in JWS).
	if derSig, err := dcrecdsa.ParseDERSignature(sig); err == nil {
		return derSig.Verify(hash[:], pubKey), nil
	}

	// Try compact format (R || S, 64 bytes).
	if len(sig) == 64 {
		var r, s dcrsecp.ModNScalar
		r.SetByteSlice(sig[:32])
		s.SetByteSlice(sig[32:])
		compactSig := dcrecdsa.NewSignature(&r, &s)
		return compactSig.Verify(hash[:], pubKey), nil
	}

	return false, fmt.Errorf("sig: unrecognised secp256k1 signature format (%d bytes)", len(sig))
}

// verifyRSA verifies an RSA PKCS#1 v1.5 signature (SHA-256) over the given
// data. This is the proof type used by Inji Certify (RsaSignature2018).
//
// The public key can be provided as:
//   - Hex-encoded DER (PKCS#1 or SPKI)
//   - Hex-encoded raw modulus (with assumed exponent 65537)
//   - PEM-encoded (hex of the PEM bytes)
func verifyRSA(data, sig []byte, pubKeyHex string) (bool, error) {
	rsaPub, err := parseRSAPublicKey(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("sig: parse RSA public key: %w", err)
	}

	// RsaSignature2018 uses SHA-256 with PKCS#1 v1.5 padding.
	hash := sha256.Sum256(data)

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig)
	if err != nil {
		return false, nil // signature mismatch, not an error
	}
	return true, nil
}

// parseRSAPublicKey tries multiple formats to extract an RSA public key
// from a hex-encoded string.
func parseRSAPublicKey(pubKeyHex string) (*rsa.PublicKey, error) {
	keyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}

	// Try PKIX/SPKI DER format (most common from DID documents).
	if pub, err := x509.ParsePKIXPublicKey(keyBytes); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("PKIX key is not RSA")
	}

	// Try PKCS#1 DER format.
	if rsaPub, err := x509.ParsePKCS1PublicKey(keyBytes); err == nil {
		return rsaPub, nil
	}

	// Try PEM-encoded (the hex might encode PEM text).
	if block, _ := pem.Decode(keyBytes); block != nil {
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if rsaPub, ok := pub.(*rsa.PublicKey); ok {
				return rsaPub, nil
			}
		}
		if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			return rsaPub, nil
		}
	}

	// Last resort: treat as raw modulus bytes with standard exponent.
	if len(keyBytes) >= 128 { // RSA-1024 minimum
		n := new(big.Int).SetBytes(keyBytes)
		return &rsa.PublicKey{N: n, E: 65537}, nil
	}

	return nil, fmt.Errorf("could not parse RSA key from %d bytes", len(keyBytes))
}

// ============================================================================
// SD-JWT signature verification.
// ============================================================================

// VerifySDJWTSignature verifies an SD-JWT token offline by extracting the
// issuer's public key from the x5c certificate in the JWT header and
// verifying the JWS signature. No network access, no DID resolution,
// no canonicalization — the certificate is self-contained in the token.
//
// Supports EdDSA (Ed25519) and ES256 (P-256) algorithms.
func VerifySDJWTSignature(token string) (bool, error) {
	// Strip trailing ~ and any disclosures for signature verification.
	// SD-JWT format: <JWT>~<disclosure1>~<disclosure2>~
	jwt := token
	if idx := strings.Index(token, "~"); idx >= 0 {
		jwt = token[:idx]
	}

	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		return false, fmt.Errorf("sdjwt: invalid JWT format (expected 3 parts, got %d)", len(parts))
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, fmt.Errorf("sdjwt: decode header: %w", err)
	}
	var header struct {
		Alg string   `json:"alg"`
		Typ string   `json:"typ"`
		X5C []string `json:"x5c"`
		Kid string   `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return false, fmt.Errorf("sdjwt: parse header: %w", err)
	}

	log.Printf("[SIG] SD-JWT: alg=%s typ=%s x5c=%d certs", header.Alg, header.Typ, len(header.X5C))

	// Extract public key from x5c certificate.
	if len(header.X5C) == 0 {
		return false, fmt.Errorf("sdjwt: no x5c certificate in JWT header (kid=%s)", header.Kid)
	}

	certDER, err := base64.StdEncoding.DecodeString(header.X5C[0])
	if err != nil {
		return false, fmt.Errorf("sdjwt: decode x5c certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return false, fmt.Errorf("sdjwt: parse x5c certificate: %w", err)
	}

	// Decode signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("sdjwt: decode signature: %w", err)
	}

	// The JWS signing input is: base64url(header) + "." + base64url(payload)
	signingInput := []byte(parts[0] + "." + parts[1])

	// Verify based on algorithm.
	switch header.Alg {
	case "EdDSA":
		pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return false, fmt.Errorf("sdjwt: x5c certificate key is not Ed25519")
		}
		return ed25519.Verify(pubKey, signingInput, sigBytes), nil

	case "ES256":
		pubKey, ok := cert.PublicKey.(*stdecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("sdjwt: x5c certificate key is not ECDSA")
		}
		if pubKey.Curve != elliptic.P256() {
			return false, fmt.Errorf("sdjwt: expected P-256 curve, got %s", pubKey.Curve.Params().Name)
		}
		h := sha256.Sum256(signingInput)
		// ES256 signature is R || S (32 bytes each).
		if len(sigBytes) != 64 {
			return false, fmt.Errorf("sdjwt: ES256 signature wrong size: %d (want 64)", len(sigBytes))
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		return stdecdsa.Verify(pubKey, h[:], r, s), nil

	case "RS256":
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("sdjwt: x5c certificate key is not RSA")
		}
		h := sha256.Sum256(signingInput)
		err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h[:], sigBytes)
		return err == nil, nil

	default:
		return false, fmt.Errorf("sdjwt: unsupported algorithm: %s", header.Alg)
	}
}
