package main

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestIsPixelPassEncoded verifies detection of Base45-encoded data.
func TestIsPixelPassEncoded(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"NCFF-J91S7MJ.20T9KC-RIKQ:K88OUD04M8EP1234567890", true},
		{`{"@context": "..."}`, false},            // JSON
		{"jxt:local:educ:1:data", false},           // JSON-XT
		{"short", false},                           // too short
	}
	for _, tc := range cases {
		got := IsPixelPassEncoded(tc.input)
		if got != tc.want {
			t.Errorf("IsPixelPassEncoded(%q) = %v, want %v", tc.input[:20], got, tc.want)
		}
	}
}

// TestIsJsonXTURI verifies JSON-XT URI detection.
func TestIsJsonXTURI(t *testing.T) {
	if !IsJsonXTURI("jxt:local:educ:1:data") {
		t.Error("expected true for jxt: prefix")
	}
	if IsJsonXTURI(`{"@context": "..."}`) {
		t.Error("expected false for JSON")
	}
}

// TestBase45RoundTrip verifies that base45 decoding works on a known value.
func TestBase45Decode(t *testing.T) {
	// RFC 9285 test vector: "BB8" decodes to "AB".
	decoded, err := base45Decode("BB8")
	if err != nil {
		t.Fatalf("base45Decode: %v", err)
	}
	if string(decoded) != "AB" {
		t.Errorf("got %q, want %q", string(decoded), "AB")
	}
}

// TestBase45DecodeHelloWorld verifies the "Hello!!" test vector from RFC 9285.
func TestBase45DecodeHelloWorld(t *testing.T) {
	// RFC 9285: "%69 VD92EX0" decodes to "Hello!!"
	decoded, err := base45Decode("%69 VD92EX0")
	if err != nil {
		t.Fatalf("base45Decode: %v", err)
	}
	if string(decoded) != "Hello!!" {
		t.Errorf("got %q, want %q", string(decoded), "Hello!!")
	}
}

// TestDecodeJsonXT verifies JSON-XT URI expansion with a test template.
func TestDecodeJsonXT(t *testing.T) {
	templates := map[string]JsonXTTemplate{
		"test:1": {
			Columns: []JsonXTColumn{
				{Path: "issuer", Encoder: "string"},
				{Path: "credentialSubject.name", Encoder: "string"},
			},
			Template: map[string]any{
				"@context": "https://www.w3.org/2018/credentials/v1",
				"type":     "VerifiableCredential",
				"credentialSubject": map[string]any{
					"type": "TestCredential",
				},
			},
		},
	}

	uri := "jxt:local:test:1:" + url.QueryEscape("did:example:issuer") + "/" + url.QueryEscape("Alice Smith")

	doc, err := DecodeJsonXT(uri, templates)
	if err != nil {
		t.Fatalf("DecodeJsonXT: %v", err)
	}

	issuer, _ := doc["issuer"].(string)
	if issuer != "did:example:issuer" {
		t.Errorf("issuer = %q, want 'did:example:issuer'", issuer)
	}

	cs, _ := doc["credentialSubject"].(map[string]any)
	name, _ := cs["name"].(string)
	if name != "Alice Smith" {
		t.Errorf("credentialSubject.name = %q, want 'Alice Smith'", name)
	}

	// Template fields should be preserved.
	csType, _ := cs["type"].(string)
	if csType != "TestCredential" {
		t.Errorf("credentialSubject.type = %q, want 'TestCredential'", csType)
	}
}

// TestDecodeJsonXTMissingTemplate verifies error for unknown template key.
func TestDecodeJsonXTMissingTemplate(t *testing.T) {
	templates := map[string]JsonXTTemplate{}
	_, err := DecodeJsonXT("jxt:local:nope:1:data", templates)
	if err == nil {
		t.Error("expected error for unknown template")
	}
}

// TestDecodeValue verifies the different encoder types.
func TestDecodeValue(t *testing.T) {
	// String encoder.
	v, _ := decodeValue("hello", "string")
	if v != "hello" {
		t.Errorf("string encoder: got %v", v)
	}

	// isodatetime-epoch-base32: use strconv to compute the correct encoding.
	// 1700000000 epoch = 2023-11-14T22:13:20Z
	b32 := strconv.FormatInt(1700000000, 32)
	v, _ = decodeValue(b32, "isodatetime-epoch-base32")
	s, ok := v.(string)
	if !ok {
		t.Fatalf("expected string, got %T", v)
	}
	if !strings.HasPrefix(s, "2023-11-14") {
		t.Errorf("isodatetime: got %q, expected date starting with 2023-11-14", s)
	}
}

// TestSetNestedValue verifies dot-path value setting.
func TestSetNestedValue(t *testing.T) {
	doc := map[string]any{}
	setNestedValue(doc, "a.b.c", "deep")

	a, _ := doc["a"].(map[string]any)
	b, _ := a["b"].(map[string]any)
	c, _ := b["c"].(string)
	if c != "deep" {
		t.Errorf("nested value = %q, want 'deep'", c)
	}
}
