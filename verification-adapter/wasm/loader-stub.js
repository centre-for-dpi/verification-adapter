// loader-stub.js — Replaces jsonld's Node.js document loader with a no-op.
// The WASM module doesn't fetch remote contexts — all contexts used by
// URDNA2015 canonicalization must be embedded or pre-expanded.
export default function() {
  return async function nodeDocumentLoader(url) {
    throw new Error("Document loading disabled in WASM: " + url);
  };
}
