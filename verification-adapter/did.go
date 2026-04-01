// did.go — DID resolution for did:polygon, did:key, and did:web.
//
// did:polygon  Calls the on-chain DID registry via JSON-RPC eth_call.
// did:key      Extracts the public key directly from the DID (no network).
// did:web      Fetches /.well-known/did.json over HTTPS.
//
// Each resolver returns enough information to cache the issuer's public key
// for offline signature verification.
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/mr-tron/base58"
)

// ResolvedKey is the output of DID resolution: a key type and hex-encoded
// public key suitable for signature verification.
type ResolvedKey struct {
	KeyType      string // "Ed25519" or "secp256k1"
	PublicKeyHex string
}

// --------------------------------------------------------------------------
// did:key — local resolution, no network required.
// --------------------------------------------------------------------------

// ResolveDidKey extracts the public key from a did:key DID. The key type is
// determined by the multicodec prefix: 0xed01 = Ed25519, 0xe701 = secp256k1.
func ResolveDidKey(did string) (*ResolvedKey, error) {
	parts := strings.Split(did, ":")
	if len(parts) < 3 || parts[0] != "did" || parts[1] != "key" {
		return nil, fmt.Errorf("did: invalid did:key format: %s", did)
	}

	multibaseVal := parts[2]
	if !strings.HasPrefix(multibaseVal, "z") {
		return nil, fmt.Errorf("did: unsupported multibase encoding (expected 'z')")
	}

	decoded, err := base58.Decode(multibaseVal[1:])
	if err != nil {
		return nil, fmt.Errorf("did: base58 decode: %w", err)
	}

	if len(decoded) < 3 {
		return nil, fmt.Errorf("did: decoded key too short (%d bytes)", len(decoded))
	}

	// Multicodec prefix determines key type.
	switch {
	case decoded[0] == 0xed && decoded[1] == 0x01:
		return &ResolvedKey{
			KeyType:      "Ed25519",
			PublicKeyHex: hex.EncodeToString(decoded[2:]),
		}, nil
	case decoded[0] == 0xe7 && decoded[1] == 0x01:
		return &ResolvedKey{
			KeyType:      "secp256k1",
			PublicKeyHex: hex.EncodeToString(decoded[2:]),
		}, nil
	default:
		return nil, fmt.Errorf("did: unsupported multicodec prefix 0x%02x%02x", decoded[0], decoded[1])
	}
}

// --------------------------------------------------------------------------
// did:web — HTTPS resolution.
// --------------------------------------------------------------------------

// ResolveDidWeb fetches the DID document for a did:web DID.
//   - did:web:example.com            → https://example.com/.well-known/did.json
//   - did:web:example.com:path:to    → https://example.com/path/to/did.json
func ResolveDidWeb(did string) (map[string]any, error) {
	parts := strings.Split(did, ":")
	if len(parts) < 3 || parts[0] != "did" || parts[1] != "web" {
		return nil, fmt.Errorf("did: invalid did:web format: %s", did)
	}

	domain := strings.ReplaceAll(parts[2], "%3A", ":")
	pathParts := parts[3:]

	var u string
	if len(pathParts) > 0 {
		u = fmt.Sprintf("https://%s/%s/did.json", domain, strings.Join(pathParts, "/"))
	} else {
		u = fmt.Sprintf("https://%s/.well-known/did.json", domain)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, fmt.Errorf("did: fetch %s: %w", u, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("did: read %s: %w", u, err)
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("did: parse DID document from %s: %w", u, err)
	}
	return doc, nil
}

// --------------------------------------------------------------------------
// did:polygon — on-chain resolution via Ethereum JSON-RPC.
// --------------------------------------------------------------------------

// ResolveDidPolygon reads the DID document from the Polygon DID registry
// contract by calling getDID(address) via eth_call.
func ResolveDidPolygon(did, rpcURL, registryAddr string) (map[string]any, error) {
	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("did: invalid did:polygon format: %s", did)
	}

	// Address is the last part (handles did:polygon:0x... and did:polygon:testnet:0x...).
	address := parts[len(parts)-1]
	address = strings.ToLower(strings.TrimPrefix(address, "0x"))

	// getDID(address) selector = keccak256("getDID(address)")[:4] = 0x5c86b7c3
	callData := "0x5c86b7c3" + fmt.Sprintf("%064s", address)

	result, err := ethCall(rpcURL, registryAddr, callData)
	if err != nil {
		return nil, fmt.Errorf("did: polygon eth_call: %w", err)
	}
	if result == "" || result == "0x" {
		return nil, fmt.Errorf("did: DID not found on chain: %s", did)
	}

	docJSON, err := decodeABIString(result)
	if err != nil {
		return nil, fmt.Errorf("did: decode ABI string: %w", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		return nil, fmt.Errorf("did: parse polygon DID document: %w", err)
	}
	return doc, nil
}

func ethCall(rpcURL, to, data string) (string, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_call",
		"params": []any{
			map[string]string{"to": to, "data": data},
			"latest",
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(rpcURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return "", err
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("rpc error: %s", rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

// decodeABIString decodes an ABI-encoded string from an eth_call result.
// Layout: 32-byte offset | 32-byte length | data bytes.
func decodeABIString(hexStr string) (string, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if len(hexStr) < 128 {
		return "", fmt.Errorf("ABI response too short")
	}

	lengthHex := hexStr[64:128]
	length := new(big.Int)
	length.SetString(lengthHex, 16)
	n := int(length.Int64())

	dataHex := hexStr[128:]
	if len(dataHex) < n*2 {
		return "", fmt.Errorf("ABI data truncated")
	}

	data, err := hex.DecodeString(dataHex[:n*2])
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// --------------------------------------------------------------------------
// Public key extraction from DID documents.
// --------------------------------------------------------------------------

// ExtractPublicKey extracts the first usable public key from a DID document.
// It checks verificationMethod, assertionMethod, and authentication arrays.
func ExtractPublicKey(didDoc map[string]any) (*ResolvedKey, error) {
	vm := firstVerificationMethod(didDoc)
	if vm == nil {
		return nil, fmt.Errorf("did: no verification method found in DID document")
	}

	// publicKeyMultibase (Ed25519Signature2020, DataIntegrityProof).
	if mb, ok := vm["publicKeyMultibase"].(string); ok && strings.HasPrefix(mb, "z") {
		decoded, err := base58.Decode(mb[1:])
		if err != nil {
			return nil, fmt.Errorf("did: decode publicKeyMultibase: %w", err)
		}
		if len(decoded) > 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
			return &ResolvedKey{KeyType: "Ed25519", PublicKeyHex: hex.EncodeToString(decoded[2:])}, nil
		}
		if len(decoded) > 2 && decoded[0] == 0xe7 && decoded[1] == 0x01 {
			return &ResolvedKey{KeyType: "secp256k1", PublicKeyHex: hex.EncodeToString(decoded[2:])}, nil
		}
		return &ResolvedKey{KeyType: detectKeyType(vm), PublicKeyHex: hex.EncodeToString(decoded)}, nil
	}

	// publicKeyHex (EcdsaSecp256k1VerificationKey2019, legacy).
	if pkh, ok := vm["publicKeyHex"].(string); ok {
		return &ResolvedKey{KeyType: detectKeyType(vm), PublicKeyHex: pkh}, nil
	}

	// publicKeyBase58 (Ed25519VerificationKey2018).
	if pkb, ok := vm["publicKeyBase58"].(string); ok {
		decoded, err := base58.Decode(pkb)
		if err != nil {
			return nil, fmt.Errorf("did: decode publicKeyBase58: %w", err)
		}
		return &ResolvedKey{KeyType: detectKeyType(vm), PublicKeyHex: hex.EncodeToString(decoded)}, nil
	}

	// publicKeyJwk (JsonWebKey2020).
	if jwk, ok := vm["publicKeyJwk"].(map[string]any); ok {
		return extractFromJWK(jwk)
	}

	return nil, fmt.Errorf("did: no supported public key format in verification method")
}

func firstVerificationMethod(doc map[string]any) map[string]any {
	for _, field := range []string{"verificationMethod", "assertionMethod", "authentication"} {
		arr, ok := doc[field].([]any)
		if !ok || len(arr) == 0 {
			continue
		}
		if vm, ok := arr[0].(map[string]any); ok {
			return vm
		}
	}
	return nil
}

func detectKeyType(vm map[string]any) string {
	t, _ := vm["type"].(string)
	if strings.Contains(t, "Secp256k1") || strings.Contains(t, "secp256k1") {
		return "secp256k1"
	}
	if strings.Contains(t, "Rsa") || strings.Contains(t, "RSA") || strings.Contains(t, "rsa") {
		return "RSA"
	}
	return "Ed25519"
}

func extractFromJWK(jwk map[string]any) (*ResolvedKey, error) {
	kty, _ := jwk["kty"].(string)

	// RSA keys use kty:"RSA" with n (modulus) and e (exponent).
	if kty == "RSA" {
		return extractRSAFromJWK(jwk)
	}

	crv, _ := jwk["crv"].(string)
	switch crv {
	case "Ed25519":
		x, _ := jwk["x"].(string)
		if x == "" {
			return nil, fmt.Errorf("did: JWK missing x coordinate")
		}
		keyBytes, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil {
			return nil, fmt.Errorf("did: decode JWK x: %w", err)
		}
		return &ResolvedKey{KeyType: "Ed25519", PublicKeyHex: hex.EncodeToString(keyBytes)}, nil

	case "secp256k1":
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if x == "" || y == "" {
			return nil, fmt.Errorf("did: JWK missing x or y coordinate")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(y)
		if err != nil {
			return nil, err
		}
		pubHex := "04" + hex.EncodeToString(xBytes) + hex.EncodeToString(yBytes)
		return &ResolvedKey{KeyType: "secp256k1", PublicKeyHex: pubHex}, nil

	default:
		return nil, fmt.Errorf("did: unsupported JWK type: kty=%s crv=%s", kty, crv)
	}
}

// extractRSAFromJWK parses an RSA public key from JWK format (n + e fields)
// and returns it as hex-encoded PKIX DER for storage in the issuer cache.
func extractRSAFromJWK(jwk map[string]any) (*ResolvedKey, error) {
	nB64, _ := jwk["n"].(string)
	eB64, _ := jwk["e"].(string)
	if nB64 == "" || eB64 == "" {
		return nil, fmt.Errorf("did: RSA JWK missing n or e")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("did: decode RSA n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("did: decode RSA e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	pub := &rsa.PublicKey{N: n, E: e}

	// Encode as PKIX DER for hex storage (parseRSAPublicKey can decode this).
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("did: marshal RSA PKIX: %w", err)
	}

	return &ResolvedKey{KeyType: "RSA", PublicKeyHex: hex.EncodeToString(der)}, nil
}
