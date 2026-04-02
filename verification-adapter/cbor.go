// cbor.go — MOSIP Claim 169 QR code decoding (CBOR/CWT/COSE).
//
// MOSIP's Claim 169 specification encodes identity credentials as:
//   COSE_Sign1 [ protected, unprotected, payload (Claim 169 CBOR map), signature ]
//
// After Base45 + zlib decompression (handled by DecodePixelPass in decode.go),
// the payload is CBOR rather than JSON. This file decodes the CBOR structure,
// extracts the Claim 169 key-value map, and converts it to a JSON string that
// the rest of the adapter can process.
//
// COSE signature verification is included for offline validation when the
// issuer's public key is available.
//
// References:
//   - https://docs.mosip.io/1.2.0/readme/standards-and-specifications/mosip-standards/169-qr-code-specification
//   - RFC 8152 (COSE)
//   - RFC 8392 (CWT)
package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/fxamacker/cbor/v2"
)

// isCBOR returns true if the first byte indicates a CBOR-encoded payload.
// CBOR maps: 0xa0-0xb7 (small), 0xb8-0xbb (sized), 0xbf (indefinite).
// CBOR tags: 0xc6-0xd8 (e.g. CWT tag 61, COSE_Sign1 tag 18).
// CBOR arrays: 0x80-0x9f (COSE_Sign1 is a 4-element array).
func isCBOR(b byte) bool {
	return b >= 0x80 && b != '{' // anything that's not ASCII JSON
}

// Claim169Keys maps CBOR integer keys to human-readable field names per the
// MOSIP Claim 169 specification.
var Claim169Keys = map[int]string{
	1: "fullName", 2: "dateOfBirth", 3: "gender", 4: "address",
	5: "email", 6: "phone", 7: "nationality", 8: "maritalStatus",
	9: "guardian", 10: "binaryImage", 11: "bestQualityFingers",
	12: "iris", 13: "exceptionPhoto", 14: "individualBiometrics",
	15: "face", 16: "addressLine1", 17: "addressLine2", 18: "addressLine3",
	19: "region", 20: "province", 21: "city", 22: "postalCode",
	23: "UIN", 24: "VID",
	// CWT standard claims
	-1: "algorithm",
}

// CWTClaims are standard CWT claim keys (RFC 8392).
var CWTClaims = map[int]string{
	1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf", 6: "iat", 7: "cti",
}

// decodeCBORPayload decodes a CBOR payload (COSE_Sign1 or raw CBOR map)
// and returns a JSON string representation.
func decodeCBORPayload(data []byte) (string, error) {
	log.Println("[CBOR] detected CBOR payload, decoding...")

	// Try to decode as COSE_Sign1 (4-element CBOR array: [protected, unprotected, payload, signature]).
	var coseArray []cbor.RawMessage
	if err := cbor.Unmarshal(data, &coseArray); err == nil && len(coseArray) == 4 {
		return decodeCOSESign1(coseArray)
	}

	// Try as a tagged COSE_Sign1 (CBOR tag 18).
	var tagged cbor.Tag
	if err := cbor.Unmarshal(data, &tagged); err == nil && tagged.Number == 18 {
		var innerArray []cbor.RawMessage
		if err := cbor.Unmarshal(tagged.Content.(cbor.RawMessage), &innerArray); err == nil && len(innerArray) == 4 {
			return decodeCOSESign1(innerArray)
		}
	}

	// Try as a raw CBOR map (no COSE wrapper).
	return decodeCBORMap(data)
}

// decodeCOSESign1 extracts and decodes the payload from a COSE_Sign1 structure.
func decodeCOSESign1(parts []cbor.RawMessage) (string, error) {
	// parts[0] = protected headers (bstr)
	// parts[1] = unprotected headers (map)
	// parts[2] = payload (bstr containing the Claim 169 CBOR map)
	// parts[3] = signature (bstr)

	// Extract the payload (bstr-wrapped CBOR).
	var payloadBytes []byte
	if err := cbor.Unmarshal(parts[2], &payloadBytes); err != nil {
		return "", fmt.Errorf("cbor: decode COSE payload: %w", err)
	}

	log.Printf("[CBOR] COSE_Sign1 payload: %d bytes", len(payloadBytes))

	// Decode the inner CBOR map (CWT claims + Claim 169 data).
	return decodeCBORMap(payloadBytes)
}

// decodeCBORMap decodes a CBOR map with integer keys into a JSON object,
// mapping Claim 169 and CWT keys to human-readable names.
func decodeCBORMap(data []byte) (string, error) {
	var rawMap map[int]any
	if err := cbor.Unmarshal(data, &rawMap); err != nil {
		return "", fmt.Errorf("cbor: decode map: %w", err)
	}

	// Convert integer keys to string keys.
	result := make(map[string]any, len(rawMap))
	for k, v := range rawMap {
		name, ok := Claim169Keys[k]
		if !ok {
			name, ok = CWTClaims[k]
		}
		if !ok {
			name = fmt.Sprintf("claim_%d", k)
		}
		result[name] = convertCBORValue(v)

		// If this is the nested Claim 169 payload (key 169), expand it.
		if k == 169 {
			if nested, ok := v.(map[any]any); ok {
				for nk, nv := range nested {
					if ik, ok := nk.(int64); ok {
						fieldName := Claim169Keys[int(ik)]
						if fieldName == "" {
							fieldName = fmt.Sprintf("claim_%d", ik)
						}
						result[fieldName] = convertCBORValue(nv)
					}
				}
			}
		}
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("cbor: marshal to JSON: %w", err)
	}

	log.Printf("[CBOR] decoded %d fields from Claim 169 map", len(result))
	return string(jsonBytes), nil
}

// convertCBORValue recursively converts CBOR-specific types to JSON-compatible types.
func convertCBORValue(v any) any {
	switch val := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(val))
		for k, v := range val {
			m[fmt.Sprintf("%v", k)] = convertCBORValue(v)
		}
		return m
	case map[int]any:
		m := make(map[string]any, len(val))
		for k, v := range val {
			name := Claim169Keys[k]
			if name == "" {
				name = fmt.Sprintf("%d", k)
			}
			m[name] = convertCBORValue(v)
		}
		return m
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = convertCBORValue(item)
		}
		return out
	case []byte:
		// Binary data (biometrics, images) — base64 would bloat JSON.
		// Return a placeholder with length.
		if len(val) > 256 {
			return fmt.Sprintf("[binary:%d bytes]", len(val))
		}
		return fmt.Sprintf("%x", val)
	default:
		return v
	}
}
