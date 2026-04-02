// certify-e2e — End-to-end test: issue credentials via Inji Certify's
// Pre-Authorized Code flow and verify through Inji Verify and the adapter.
//
// Tests three credential formats:
//  1. FarmerCredential       — W3C VCDM v1.0 (ldp_vc, Ed25519Signature2020)
//  2. FarmerCredentialV2     — W3C VCDM v2.0 (ldp_vc, Ed25519Signature2020)
//  3. FarmerCredentialSdJwt  — SD-JWT (vc+sd-jwt, EdDSA, selective disclosure)
//
// Uses the Pre-Auth Code flow (Certify as its own auth server, no eSignet).
// The PreAuthDataProviderPlugin uses claims directly from the pre-auth request
// as credential data — no CSV lookup needed.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type testCase struct {
	Name              string
	ConfigKeyID       string
	Format            string
	CredDef           any    // credential_definition (ldp_vc) or nil (sd-jwt)
	VCT               string // vct for sd-jwt
	VerifyContentType string
}

var tests = []testCase{
	{
		Name: "VCDM v1.0 (ldp_vc)", ConfigKeyID: "FarmerCredential", Format: "ldp_vc",
		CredDef: map[string]any{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiableCredential", "FarmerCredential"},
		},
		VerifyContentType: "application/vc+ld+json",
	},
	{
		Name: "VCDM v2.0 (ldp_vc)", ConfigKeyID: "FarmerCredentialV2", Format: "ldp_vc",
		CredDef: map[string]any{
			"@context": []string{"https://www.w3.org/ns/credentials/v2"},
			"type":     []string{"VerifiableCredential", "FarmerCredential"},
		},
		VerifyContentType: "application/vc+ld+json",
	},
	{
		Name: "SD-JWT (vc+sd-jwt)", ConfigKeyID: "FarmerCredentialSdJwt", Format: "vc+sd-jwt",
		VCT: "https://example.com/credentials/FarmerCredential",
		VerifyContentType: "application/vc+sd-jwt",
	},
}

func main() {
	adapterURL := flag.String("adapter", "http://localhost:8085", "Adapter base URL")
	certifyURL := flag.String("certify", "http://localhost:8090/v1/certify", "Certify API base URL")
	certifyNginxURL := flag.String("certify-nginx", "http://localhost:8091", "Certify nginx URL")
	injiVerifyURL := flag.String("inji-verify", "http://localhost:8082", "Inji Verify direct URL")
	offline := flag.Bool("offline", false, "Verify via adapter offline mode")
	txCode := flag.String("tx-code", "12345", "Pre-authorized transaction code")
	flag.Parse()

	fmt.Println()
	fmt.Println("=== Inji Certify E2E: VCDM v1.0, v2.0, SD-JWT ===")
	fmt.Println()

	// Wait for services.
	fmt.Print("Waiting for Certify... ")
	waitForHealth(*certifyURL+"/.well-known/openid-credential-issuer", 180*time.Second)
	fmt.Println("ready.")
	fmt.Print("Waiting for Inji Verify... ")
	waitForHealth(*injiVerifyURL+"/v1/verify/actuator/health", 60*time.Second)
	fmt.Println("ready.")
	fmt.Print("Waiting for adapter... ")
	waitForHealth(*adapterURL+"/health", 30*time.Second)
	fmt.Println("ready.")

	// Fetch issuer DID.
	didDoc := httpGet(*certifyNginxURL + "/.well-known/did.json")
	var did map[string]any
	json.Unmarshal(didDoc, &did)
	issuerDID, _ := did["id"].(string)
	fmt.Printf("Issuer DID: %s\n", issuerDID)

	if *offline {
		fmt.Println("Syncing issuer DID to adapter cache...")
		syncBody, _ := json.Marshal(map[string]string{"did": issuerDID})
		resp, err := http.Post(*adapterURL+"/sync", "application/json", bytes.NewReader(syncBody))
		if err != nil {
			log.Fatalf("Sync failed: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("Sync: %s\n", body)
	}
	fmt.Println()

	holderKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	passed, failed := 0, 0
	total := len(tests) * 2

	for i, tc := range tests {
		fmt.Printf("━━━ Test %d: %s ━━━\n", i+1, tc.Name)

		credential, rawToken := issuePreAuth(*certifyURL, tc, *txCode, holderKey)
		if credential == nil && rawToken == "" {
			fmt.Printf("  SKIP: issuance failed\n\n")
			failed += 2
			continue
		}

		// Verify A: Inji Verify direct.
		fmt.Printf("  Verify A: Inji Verify direct... ")
		var body string
		if tc.Format == "vc+sd-jwt" {
			body = rawToken
		} else {
			b, _ := json.Marshal(credential)
			body = string(b)
		}
		resultA := verify(*injiVerifyURL+"/v1/verify/vc-verification", body, tc.VerifyContentType)
		printResult(resultA, &passed, &failed)

		// Verify B: Adapter.
		var verifyURL string
		if *offline {
			verifyURL = *adapterURL + "/verify-offline"
			fmt.Printf("  Verify B: Adapter (offline)... ")
		} else {
			verifyURL = *adapterURL + "/v1/verify/vc-verification"
			fmt.Printf("  Verify B: Adapter (auto)... ")
		}

		if tc.Format == "vc+sd-jwt" || *offline {
			resultB := verify(verifyURL, body, tc.VerifyContentType)
			printResult(resultB, &passed, &failed)
		} else {
			wrapped, _ := json.Marshal(map[string]any{"verifiableCredentials": []any{credential}})
			resultB := verify(verifyURL, string(wrapped), "application/json")
			printResult(resultB, &passed, &failed)
		}
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════")
	fmt.Printf("  Results: %d/%d passed", passed, total)
	if failed > 0 {
		fmt.Printf(", %d failed", failed)
	}
	fmt.Println()
	fmt.Println("═══════════════════════════════")
	fmt.Println()
	if failed > 0 {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Pre-Auth Code flow (Certify as its own auth server).
// ---------------------------------------------------------------------------

func issuePreAuth(certifyURL string, tc testCase, txCode string, holderKey *rsa.PrivateKey) (map[string]any, string) {
	// Claims must match credential_subject/sd_jwt_claims definition in the DB config.
	claims := map[string]any{
		"fullName": "Jane Thompson", "mobileNumber": "7550166914",
		"dateOfBirth": "24-01-1998", "gender": "Female",
		"state": "Karnataka", "district": "Bangalore",
		"villageOrTown": "Koramangala", "postalCode": "560068",
		"landArea": "5 acres", "landOwnershipType": "Self-owned",
		"primaryCropType": "Cotton", "secondaryCropType": "Barley",
		"farmerID": "4567538771",
	}

	// 1. Generate pre-authorized code.
	preAuthResp, err := httpPostJSONSafe(certifyURL+"/pre-authorized-data", map[string]any{
		"credential_configuration_id": tc.ConfigKeyID,
		"claims":                      claims,
		"expires_in":                  600,
		"tx_code":                     txCode,
	})
	if err != nil {
		fmt.Printf("  pre-auth error: %v\n", err)
		return nil, ""
	}

	var preAuth struct {
		CredentialOfferURI string `json:"credential_offer_uri"`
	}
	json.Unmarshal(preAuthResp, &preAuth)
	if preAuth.CredentialOfferURI == "" {
		fmt.Printf("  pre-auth: no offer URI: %s\n", string(preAuthResp))
		return nil, ""
	}

	// Extract offer ID from URI.
	outerURI, _ := url.Parse(preAuth.CredentialOfferURI)
	innerURI := outerURI.Query().Get("credential_offer_uri")
	if innerURI == "" {
		innerURI, _ = url.QueryUnescape(preAuth.CredentialOfferURI)
	}
	innerParsed, _ := url.Parse(innerURI)
	pathParts := strings.Split(innerParsed.Path, "/")
	offerID := pathParts[len(pathParts)-1]

	// 2. Get credential offer.
	offerResp := httpGet(certifyURL + "/credential-offer-data/" + offerID)
	var offer struct {
		CredentialIssuer string         `json:"credential_issuer"`
		Grants           map[string]any `json:"grants"`
	}
	json.Unmarshal(offerResp, &offer)

	preAuthGrant, _ := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)
	preAuthCode, _ := preAuthGrant["pre-authorized_code"].(string)

	// 3. Exchange for token.
	tokenResp := httpPostForm(certifyURL+"/oauth/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
		"tx_code":             {txCode},
	})
	var tokenResult struct {
		AccessToken string `json:"access_token"`
		CNonce      string `json:"c_nonce"`
	}
	json.Unmarshal(tokenResp, &tokenResult)
	if tokenResult.AccessToken == "" {
		fmt.Printf("  token exchange failed: %s\n", string(tokenResp))
		return nil, ""
	}

	// 4. Build proof JWT.
	audURL := offer.CredentialIssuer
	if audURL == "" {
		audURL = certifyURL
	}
	proofJWT := buildProofJWT(holderKey, tokenResult.CNonce, audURL)

	// 5. Request credential.
	credReq := map[string]any{
		"format": tc.Format,
		"proof":  map[string]any{"proof_type": "jwt", "jwt": proofJWT},
	}
	if tc.Format == "vc+sd-jwt" {
		credReq["vct"] = tc.VCT
	} else {
		credReq["credential_definition"] = tc.CredDef
	}

	credResp := httpPostJSONWithAuth(certifyURL+"/issuance/credential", credReq, tokenResult.AccessToken)
	var credResult struct {
		Credential any `json:"credential"`
	}
	json.Unmarshal(credResp, &credResult)
	if credResult.Credential == nil {
		fmt.Printf("  issuance failed: %s\n", string(credResp))
		return nil, ""
	}

	switch v := credResult.Credential.(type) {
	case string:
		fmt.Printf("  Issued: %s (%d chars)\n", tc.Format, len(v))
		os.WriteFile(fmt.Sprintf("/tmp/certify-%s.jwt", tc.ConfigKeyID), []byte(v), 0644)
		return nil, v
	case map[string]any:
		j, _ := json.MarshalIndent(v, "  ", "  ")
		fmt.Printf("  Issued: %s (%d bytes)\n", tc.Format, len(j))
		os.WriteFile(fmt.Sprintf("/tmp/certify-%s.json", tc.ConfigKeyID), j, 0644)
		return v, ""
	default:
		fmt.Printf("  unexpected credential type %T\n", credResult.Credential)
		return nil, ""
	}
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

func verify(u, body, contentType string) string {
	resp, err := http.Post(u, contentType, strings.NewReader(body))
	if err != nil {
		return "ERROR: " + err.Error()
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]any
	json.Unmarshal(respBody, &result)

	if s, ok := result["verificationStatus"].(string); ok {
		if s == "SUCCESS" {
			return "SUCCESS"
		}
		detail := s
		if e, ok := result["error"].(string); ok && e != "" {
			detail += ": " + e
		}
		return detail
	}
	return "UNKNOWN: " + string(respBody)
}

func printResult(result string, passed, failed *int) {
	if result == "SUCCESS" {
		fmt.Println("SUCCESS")
		*passed++
	} else {
		fmt.Printf("FAIL (%s)\n", result)
		*failed++
	}
}

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

func buildProofJWT(key *rsa.PrivateKey, nonce, audience string) string {
	header := map[string]any{
		"alg": "RS256", "typ": "openid4vci-proof+jwt",
		"jwk": rsaPublicKeyJWK(&key.PublicKey),
	}
	now := time.Now().Unix()
	payload := map[string]any{
		"aud": audience, "nonce": nonce, "iss": "",
		"iat": now, "exp": now + 600,
	}
	return signJWT(key, header, payload)
}

func signJWT(key *rsa.PrivateKey, header, payload map[string]any) string {
	h := base64URLEncode(mustMarshal(header))
	p := base64URLEncode(mustMarshal(payload))
	input := h + "." + p
	hash := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	return input + "." + base64URLEncode(sig)
}

func rsaPublicKeyJWK(pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "n": base64URLEncode(pub.N.Bytes()),
		"e": base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
		"alg": "RS256", "use": "sig",
	}
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

func waitForHealth(u string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	c := &http.Client{Timeout: 5 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := c.Get(u)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(5 * time.Second)
	}
	log.Fatalf("timed out waiting for %s", u)
}

func httpGet(u string) []byte {
	resp, err := http.Get(u)
	if err != nil {
		log.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		log.Fatalf("GET %s: HTTP %d: %s", u, resp.StatusCode, string(body))
	}
	return body
}

func httpPostJSONSafe(u string, data any) ([]byte, error) {
	body, _ := json.Marshal(data)
	resp, err := http.Post(u, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func httpPostJSONWithAuth(u string, data any, token string) []byte {
	body, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		log.Fatalf("POST %s: HTTP %d: %s", u, resp.StatusCode, string(respBody))
	}
	return respBody
}

func httpPostForm(u string, data url.Values) []byte {
	resp, err := http.PostForm(u, data)
	if err != nil {
		log.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		log.Fatalf("POST %s: HTTP %d: %s", u, resp.StatusCode, string(body))
	}
	return body
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
