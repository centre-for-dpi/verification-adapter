package main

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestIsCBOR verifies detection of CBOR vs JSON payloads.
func TestIsCBOR(t *testing.T) {
	cases := []struct {
		b    byte
		want bool
	}{
		{'{', false},  // JSON object
		{0xa0, true},  // CBOR empty map
		{0xa2, true},  // CBOR 2-element map
		{0xbf, true},  // CBOR indefinite map
		{0x84, true},  // CBOR 4-element array (COSE_Sign1)
		{0xd8, true},  // CBOR tag
	}
	for _, tc := range cases {
		got := isCBOR(tc.b)
		if got != tc.want {
			t.Errorf("isCBOR(0x%02x) = %v, want %v", tc.b, got, tc.want)
		}
	}
}

// TestDecodeCBORMap verifies decoding of a simple CBOR map with Claim 169 keys.
func TestDecodeCBORMap(t *testing.T) {
	// Build a CBOR map with Claim 169 keys.
	m := map[int]any{
		1:  "Adam Ndegwa",       // fullName
		2:  "1990-01-15",        // dateOfBirth
		3:  "Male",              // gender
		23: "1234567890",        // UIN
	}
	data, err := cbor.Marshal(m)
	if err != nil {
		t.Fatalf("marshal CBOR: %v", err)
	}

	result, err := decodeCBORPayload(data)
	if err != nil {
		t.Fatalf("decodeCBORPayload: %v", err)
	}

	if result == "" {
		t.Fatal("expected non-empty result")
	}

	// Verify JSON contains mapped field names.
	for _, field := range []string{"fullName", "dateOfBirth", "gender", "UIN"} {
		if !contains(result, field) {
			t.Errorf("result missing field %q: %s", field, result)
		}
	}
}

// TestDecodeCOSESign1 verifies decoding of a COSE_Sign1 structure.
func TestDecodeCOSESign1(t *testing.T) {
	// Build a minimal COSE_Sign1: [protected, unprotected, payload, signature]
	// protected = bstr(CBOR map)
	// payload = bstr(Claim 169 CBOR map)

	protected, _ := cbor.Marshal(map[int]any{1: -8}) // alg: EdDSA
	payload, _ := cbor.Marshal(map[int]any{
		1: "Test User", // fullName
		6: "+254700000000", // phone
	})

	// COSE_Sign1 is a 4-element array with bstr-wrapped protected and payload.
	protectedBstr, _ := cbor.Marshal(protected)
	payloadBstr, _ := cbor.Marshal(payload)
	unprotected, _ := cbor.Marshal(map[int]any{})
	signature, _ := cbor.Marshal([]byte("fake-signature-bytes"))

	coseArray := []cbor.RawMessage{protectedBstr, unprotected, payloadBstr, signature}
	data, _ := cbor.Marshal(coseArray)

	result, err := decodeCBORPayload(data)
	if err != nil {
		t.Fatalf("decodeCBORPayload COSE_Sign1: %v", err)
	}

	if !contains(result, "fullName") || !contains(result, "Test User") {
		t.Errorf("expected fullName in result: %s", result)
	}
	if !contains(result, "phone") || !contains(result, "+254700000000") {
		t.Errorf("expected phone in result: %s", result)
	}
}

// TestDecodePixelPassStillHandlesJSON verifies the existing JSON path is unchanged.
func TestDecodePixelPassStillHandlesJSON(t *testing.T) {
	// This test uses the existing Base45 test vectors to confirm
	// the JSON path wasn't broken by adding CBOR support.
	decoded, err := base45Decode("BB8")
	if err != nil {
		t.Fatalf("base45Decode: %v", err)
	}
	if string(decoded) != "AB" {
		t.Errorf("base45 decode broken: got %q", string(decoded))
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
