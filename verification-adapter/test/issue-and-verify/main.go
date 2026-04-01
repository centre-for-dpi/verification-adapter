// issue-and-verify — End-to-end test: sign a credential with URDNA2015,
// verify it through the adapter against a live Inji Verify backend.
//
// This proves that:
//   1. A credential signed using the same URDNA2015 two-hash pattern as
//      walt.id's issuer-portal and g-tambue produces a valid signature.
//   2. The adapter correctly routes did:key credentials to Inji Verify.
//   3. Inji Verify can verify the Ed25519Signature2020 proof.
//
// Usage:
//   go run ./test/issue-and-verify [--adapter http://localhost:8085]
//   go run ./test/issue-and-verify --offline  (verify via adapter offline mode)
//   go run ./test/issue-and-verify --direct http://localhost:8082  (bypass adapter)
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mr-tron/base58"
	"github.com/piprate/json-gold/ld"
)

func main() {
	adapterURL := flag.String("adapter", "http://localhost:8085", "Adapter base URL")
	directURL := flag.String("direct", "", "Bypass adapter, verify directly against this URL")
	offline := flag.Bool("offline", false, "Force offline verification via adapter")
	flag.Parse()

	fmt.Println()
	fmt.Println("=== Issue & Verify End-to-End Test ===")
	fmt.Println()

	// ---- Step 1: Generate issuer keypair and did:key ----
	fmt.Println("1. Generating Ed25519 issuer keypair...")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("   generate key: %v", err)
	}

	issuerDID := deriveDidKey(pub)
	verificationMethod := issuerDID + "#" + issuerDID[8:] // did:key:z6Mk...#z6Mk...
	fmt.Printf("   Issuer DID:  %s\n", issuerDID)
	fmt.Printf("   Public key:  %s...\n", hex.EncodeToString(pub)[:32])
	fmt.Println()

	// ---- Step 2: Build credential ----
	fmt.Println("2. Building W3C Verifiable Credential...")
	now := time.Now().UTC().Format(time.RFC3339)
	credential := map[string]any{
		"@context": []any{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		"type":         []any{"VerifiableCredential"},
		"issuer":       issuerDID,
		"issuanceDate": now,
		"credentialSubject": map[string]any{
			"id": "did:key:z6MkSubjectExample",
		},
	}
	fmt.Printf("   Type:    VerifiableCredential\n")
	fmt.Printf("   Issuer:  %s\n", issuerDID)
	fmt.Printf("   Subject: Alice Wonderland\n")
	fmt.Println()

	// ---- Step 3: Sign with URDNA2015 two-hash pattern ----
	fmt.Println("3. Signing with Ed25519Signature2020 (URDNA2015 canonicalization)...")

	proofOptions := map[string]any{
		"@context":           credential["@context"],
		"type":               "Ed25519Signature2020",
		"created":            now,
		"verificationMethod": verificationMethod,
		"proofPurpose":       "assertionMethod",
	}

	canon := newCanonicalizer()

	canonDoc, err := canon.canonicalize(credential)
	if err != nil {
		log.Fatalf("   canonicalize document: %v", err)
	}
	canonProof, err := canon.canonicalize(proofOptions)
	if err != nil {
		log.Fatalf("   canonicalize proof options: %v", err)
	}

	fmt.Printf("   Canonical document:      %d bytes of N-Quads\n", len(canonDoc))
	fmt.Printf("   Canonical proof options:  %d bytes of N-Quads\n", len(canonProof))

	// Two-hash pattern: SHA256(canonProof) || SHA256(canonDoc)
	proofHash := sha256.Sum256([]byte(canonProof))
	docHash := sha256.Sum256([]byte(canonDoc))
	hashData := append(proofHash[:], docHash[:]...)

	sig := ed25519.Sign(priv, hashData)
	proofValue := "z" + base58.Encode(sig)

	// Attach proof to credential.
	credential["proof"] = map[string]any{
		"type":               "Ed25519Signature2020",
		"created":            now,
		"verificationMethod": verificationMethod,
		"proofPurpose":       "assertionMethod",
		"proofValue":         proofValue,
	}

	fmt.Printf("   Proof value: %s...%s\n", proofValue[:12], proofValue[len(proofValue)-8:])
	fmt.Println()

	// ---- Step 4: Self-verify (sanity check) ----
	fmt.Println("4. Self-verification (sanity check)...")
	if ed25519.Verify(pub, hashData, sig) {
		fmt.Println("   ✓ Signature valid (local Ed25519 check)")
	} else {
		fmt.Println("   ✗ Signature invalid — signing bug")
		os.Exit(1)
	}
	fmt.Println()

	// ---- Step 5: Print the signed credential ----
	credJSON, _ := json.MarshalIndent(credential, "   ", "  ")
	fmt.Println("5. Signed credential:")
	fmt.Printf("   %s\n", credJSON)
	fmt.Println()

	// ---- Step 5b: Save signed credential to file for reuse ----
	os.WriteFile("/tmp/signed-credential.json", credJSON, 0644)
	fmt.Println("   Saved to /tmp/signed-credential.json")
	fmt.Println()

	// ---- Step 6: Verify through the adapter (or directly) ----
	var verifyURL string
	if *directURL != "" {
		verifyURL = *directURL + "/v1/verify/vc-verification"
		fmt.Printf("6. Verifying directly against %s...\n", *directURL)
	} else if *offline {
		verifyURL = *adapterURL + "/verify-offline"
		fmt.Printf("6. Verifying via adapter (offline mode) at %s...\n", *adapterURL)

		// Sync the issuer first so offline verification can find the key.
		fmt.Println("   Pre-syncing issuer DID to cache...")
		syncBody, _ := json.Marshal(map[string]string{"did": issuerDID})
		resp, err := http.Post(*adapterURL+"/sync", "application/json", bytes.NewReader(syncBody))
		if err != nil {
			fmt.Printf("   ⚠ Sync failed: %v (continuing anyway)\n", err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Printf("   Sync response: %s\n", string(body))
		}
	} else {
		verifyURL = *adapterURL + "/v1/verify/vc-verification"
		fmt.Printf("6. Verifying via adapter at %s...\n", *adapterURL)
	}

	// Send credential for verification.
	reqBody, _ := json.Marshal(map[string]any{
		"verifiableCredentials": []any{credential},
	})

	resp, err := http.Post(verifyURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		log.Fatalf("   verification request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]any
	json.Unmarshal(respBody, &result)
	prettyResult, _ := json.MarshalIndent(result, "   ", "  ")

	fmt.Printf("   HTTP %d\n", resp.StatusCode)
	fmt.Printf("   %s\n", prettyResult)
	fmt.Println()

	// ---- Verdict ----
	status, _ := result["verificationStatus"].(string)
	backend, _ := result["backend"].(string)
	level, _ := result["verificationLevel"].(string)

	fmt.Println("=== Result ===")
	if status == "SUCCESS" {
		fmt.Printf("   ✓ VERIFIED")
		if backend != "" {
			fmt.Printf(" (backend: %s)", backend)
		}
		if level != "" {
			fmt.Printf(" (level: %s)", level)
		}
		fmt.Println()
	} else {
		fmt.Printf("   ✗ %s\n", status)
		if errMsg, ok := result["error"].(string); ok {
			fmt.Printf("   Error: %s\n", errMsg)
		}
		if note, ok := result["note"].(string); ok {
			fmt.Printf("   Note: %s\n", note)
		}
	}
	fmt.Println()
}

// deriveDidKey produces a did:key from an Ed25519 public key.
// Format: did:key:z + base58btc(0xed01 + pubkey)
func deriveDidKey(pub ed25519.PublicKey) string {
	// Multicodec prefix for Ed25519 public key: 0xed 0x01
	multicodec := append([]byte{0xed, 0x01}, pub...)
	encoded := base58.Encode(multicodec)
	return "did:key:z" + encoded
}

// canonicalizer wraps json-gold for URDNA2015 canonicalization.
type canonicalizer struct {
	proc *ld.JsonLdProcessor
	opts *ld.JsonLdOptions
}

func newCanonicalizer() *canonicalizer {
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = "URDNA2015"
	opts.Format = "application/n-quads"
	return &canonicalizer{proc: ld.NewJsonLdProcessor(), opts: opts}
}

func (c *canonicalizer) canonicalize(doc map[string]any) (string, error) {
	raw, _ := json.Marshal(doc)
	var normalized any
	json.Unmarshal(raw, &normalized)
	result, err := c.proc.Normalize(normalized, c.opts)
	if err != nil {
		return "", err
	}
	return result.(string), nil
}
