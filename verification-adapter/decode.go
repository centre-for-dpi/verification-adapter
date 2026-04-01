// decode.go — PixelPass (Base45 + zlib) and JSON-XT decoding.
//
// QR codes issued by MOSIP/CREDEBL encode credentials in a compact binary
// format: Base45 → zlib → JSON-XT URI → full JSON-LD credential.
//
// PixelPass decoding is the first stage — it reverses the Base45 + zlib
// compression applied by @mosip/pixelpass to produce either a JSON string
// or a JSON-XT URI.
//
// JSON-XT decoding is the second stage — it expands a compact URI like
// "jxt:local:educ:1:field1/field2/..." into a full W3C Verifiable Credential
// using pre-defined templates.
package main

import (
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// JSON-XT template types and loader.
// ============================================================================

// JsonXTTemplate defines how a compact URI maps to a full credential.
type JsonXTTemplate struct {
	Columns  []JsonXTColumn `json:"columns"`
	Template map[string]any `json:"template"`
}

// JsonXTColumn maps a positional value to a path in the template.
type JsonXTColumn struct {
	Path    string `json:"path"`    // dot-separated path, e.g. "credentialSubject.name"
	Encoder string `json:"encoder"` // "string", "isodatetime-epoch-base32", "isodate-1900-base32"
}

// LoadTemplates reads JSON-XT templates from a JSON file. Returns nil map
// (not an error) if the file does not exist, allowing graceful degradation.
func LoadTemplates(path string) (map[string]JsonXTTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("templates file not found: %s", path)
		}
		return nil, err
	}

	var templates map[string]JsonXTTemplate
	if err := json.Unmarshal(data, &templates); err != nil {
		return nil, fmt.Errorf("decode: parse templates: %w", err)
	}
	return templates, nil
}

// ============================================================================
// PixelPass decoding (Base45 + zlib).
// ============================================================================

// IsPixelPassEncoded returns true if the input looks like Base45-encoded
// PixelPass data (not JSON, not a JSON-XT URI).
func IsPixelPassEncoded(input string) bool {
	if len(input) < 10 {
		return false
	}
	if strings.HasPrefix(input, "{") || strings.HasPrefix(input, "jxt:") {
		return false
	}
	// Base45 character set: 0-9 A-Z space $ % * + - . / :
	check := input
	if len(check) > 50 {
		check = check[:50]
	}
	for _, c := range check {
		if !isBase45Char(c) {
			return false
		}
	}
	return true
}

func isBase45Char(c rune) bool {
	return (c >= '0' && c <= '9') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		c == ' ' || c == '$' || c == '%' || c == '*' ||
		c == '+' || c == '-' || c == '.' || c == '/' ||
		c == ':' || c == '_'
}

// DecodePixelPass decodes Base45+zlib compressed data from a QR code.
func DecodePixelPass(encoded string) (string, error) {
	// Step 1: Base45 decode.
	compressed, err := base45Decode(encoded)
	if err != nil {
		return "", fmt.Errorf("decode: base45: %w", err)
	}

	// Step 2: zlib decompress.
	r, err := zlib.NewReader(strings.NewReader(string(compressed)))
	if err != nil {
		// Not zlib compressed — return raw decoded data.
		return string(compressed), nil
	}
	defer r.Close()

	decompressed, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("decode: zlib: %w", err)
	}
	return string(decompressed), nil
}

// base45Decode implements RFC 9285 Base45 decoding.
func base45Decode(s string) ([]byte, error) {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
	charMap := make(map[byte]int, len(charset))
	for i := 0; i < len(charset); i++ {
		charMap[charset[i]] = i
	}

	// Handle uppercase conversion for case-insensitive matching.
	input := strings.ToUpper(s)

	var result []byte
	for i := 0; i < len(input); i += 3 {
		remaining := len(input) - i
		if remaining < 2 {
			return nil, fmt.Errorf("base45: incomplete group at position %d", i)
		}

		c0, ok0 := charMap[input[i]]
		c1, ok1 := charMap[input[i+1]]
		if !ok0 || !ok1 {
			return nil, fmt.Errorf("base45: invalid character at position %d", i)
		}

		if remaining >= 3 {
			c2, ok2 := charMap[input[i+2]]
			if !ok2 {
				return nil, fmt.Errorf("base45: invalid character at position %d", i+2)
			}
			n := c0 + c1*45 + c2*45*45
			if n > 0xFFFF {
				return nil, fmt.Errorf("base45: value overflow at position %d", i)
			}
			result = append(result, byte(n>>8), byte(n&0xFF))
		} else {
			n := c0 + c1*45
			if n > 0xFF {
				return nil, fmt.Errorf("base45: value overflow at position %d", i)
			}
			result = append(result, byte(n))
		}
	}
	return result, nil
}

// ============================================================================
// JSON-XT URI decoding.
// ============================================================================

// IsJsonXTURI returns true if the input is a JSON-XT URI (starts with "jxt:").
func IsJsonXTURI(input string) bool {
	return strings.HasPrefix(input, "jxt:")
}

// DecodeJsonXT expands a JSON-XT URI into a full JSON-LD credential using
// the provided templates. URI format: jxt:resolver:type:version:val1/val2/...
func DecodeJsonXT(uri string, templates map[string]JsonXTTemplate) (map[string]any, error) {
	if templates == nil {
		return nil, fmt.Errorf("decode: JSON-XT templates not loaded")
	}

	// Parse URI: jxt:resolver:type:version:data
	parts := strings.SplitN(uri, ":", 5)
	if len(parts) < 5 {
		return nil, fmt.Errorf("decode: invalid JSON-XT URI (expected 5+ colon-separated parts)")
	}

	templateKey := parts[2] + ":" + parts[3] // e.g. "educ:1"
	tmpl, ok := templates[templateKey]
	if !ok {
		return nil, fmt.Errorf("decode: unknown JSON-XT template: %s", templateKey)
	}

	// Split encoded data by "/" separator and URL-decode each value.
	encodedValues := strings.Split(parts[4], "/")
	if len(encodedValues) < len(tmpl.Columns) {
		return nil, fmt.Errorf("decode: JSON-XT data has %d values, template expects %d",
			len(encodedValues), len(tmpl.Columns))
	}

	// Deep-copy the template to avoid mutation.
	doc, err := deepCopy(tmpl.Template)
	if err != nil {
		return nil, fmt.Errorf("decode: copy template: %w", err)
	}

	// Map each decoded value to its path in the document.
	for i, col := range tmpl.Columns {
		raw, err := url.QueryUnescape(encodedValues[i])
		if err != nil {
			raw = encodedValues[i]
		}

		decoded, err := decodeValue(raw, col.Encoder)
		if err != nil {
			return nil, fmt.Errorf("decode: column %q: %w", col.Path, err)
		}

		setNestedValue(doc, col.Path, decoded)
	}

	return doc, nil
}

// decodeValue applies the column encoder to a raw string value.
func decodeValue(raw, encoder string) (any, error) {
	switch encoder {
	case "string":
		return raw, nil

	case "isodatetime-epoch-base32":
		// Base32-encoded epoch seconds → ISO 8601 datetime.
		epoch, err := strconv.ParseInt(raw, 32, 64)
		if err != nil {
			return raw, nil // fall back to raw string
		}
		return time.Unix(epoch, 0).UTC().Format(time.RFC3339), nil

	case "isodate-1900-base32":
		// Base32-encoded days since 1900-01-01 → ISO 8601 date.
		days, err := strconv.ParseInt(raw, 32, 64)
		if err != nil {
			return raw, nil
		}
		base := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
		return base.AddDate(0, 0, int(days)).Format("2006-01-02"), nil

	default:
		return raw, nil
	}
}

// setNestedValue sets a value at a dot-separated path in a nested map,
// creating intermediate maps as needed.
func setNestedValue(doc map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	current := doc
	for i, part := range parts {
		if i == len(parts)-1 {
			current[part] = value
			return
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			next = make(map[string]any)
			current[part] = next
		}
		current = next
	}
}

// deepCopy creates an independent copy of a map by JSON round-tripping.
func deepCopy(src map[string]any) (map[string]any, error) {
	data, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	var dst map[string]any
	err = json.Unmarshal(data, &dst)
	return dst, err
}
