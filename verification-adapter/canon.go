// canon.go — URDNA2015 JSON-LD canonicalization.
//
// Provides a Canonicalizer interface (matching g-tambue's lib/jsonld) with a
// NativeCanonicalizer backed by json-gold. The interface allows swapping in a
// WASM backend (e.g. @digitalbazaar/jsonld via wazero) without changing any
// call-sites.
//
// URDNA2015 converts a JSON-LD document to a deterministic N-Quads string by:
//   1. Expanding all terms against their @context definitions into full IRIs.
//   2. Converting the expanded form to an RDF dataset (set of quads).
//   3. Canonicalizing blank node identifiers using the URDNA2015 algorithm.
//   4. Serializing the dataset as sorted N-Quads.
//
// This is the W3C-standard canonicalization used by Data Integrity proof
// suites (Ed25519Signature2018/2020, EcdsaSecp256k1Signature2019,
// eddsa-rdfc-2022). The Node.js adapter's JSON.stringify-with-sorted-keys
// approach cannot reproduce these digests.
package main

import (
	"encoding/json"
	"fmt"

	"github.com/piprate/json-gold/ld"
)

// Canonicalizer produces a canonical N-Quads string from a JSON-LD document
// using the URDNA2015 algorithm. The output is suitable for hashing and
// signature verification.
type Canonicalizer interface {
	Canonicalize(doc map[string]any) (string, error)
}

// NativeCanonicalizer implements Canonicalizer using the Go json-gold library.
// It is a lighter-weight alternative to a WASM backend but may diverge from
// the reference npm implementation on complex RDF graph structures.
type NativeCanonicalizer struct {
	proc *ld.JsonLdProcessor
	opts *ld.JsonLdOptions
}

// NewNativeCanonicalizer creates a Canonicalizer backed by json-gold with
// URDNA2015 and N-Quads output.
func NewNativeCanonicalizer() *NativeCanonicalizer {
	opts := ld.NewJsonLdOptions("")
	opts.Algorithm = "URDNA2015"
	opts.Format = "application/n-quads"
	return &NativeCanonicalizer{
		proc: ld.NewJsonLdProcessor(),
		opts: opts,
	}
}

// Canonicalize converts doc to its canonical N-Quads form. The input map is
// not modified. Returns an empty string for an empty document.
func (c *NativeCanonicalizer) Canonicalize(doc map[string]any) (string, error) {
	// json-gold expects interface{} values, so round-trip through JSON to
	// normalise Go-specific map types (map[string]any → map[string]interface{}).
	raw, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("canon: marshal: %w", err)
	}
	var normalised any
	if err := json.Unmarshal(raw, &normalised); err != nil {
		return "", fmt.Errorf("canon: unmarshal: %w", err)
	}

	result, err := c.proc.Normalize(normalised, c.opts)
	if err != nil {
		return "", fmt.Errorf("canon: canonicalize: %w", err)
	}

	str, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("canon: expected string, got %T", result)
	}
	return str, nil
}

// compile-time interface check.
var _ Canonicalizer = (*NativeCanonicalizer)(nil)
