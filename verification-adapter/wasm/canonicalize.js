// canonicalize.js — Javy entrypoint for URDNA2015 canonicalization.
//
// Reads a JSON-LD document from stdin, canonicalizes it using the jsonld
// npm package (W3C reference implementation), and writes the resulting
// N-Quads to stdout.
//
// Uses a custom document loader with embedded W3C contexts so no network
// access is needed.

import jsonld from "jsonld";

// Embedded W3C contexts — the minimum set needed for VC verification.
// These are the actual context definitions, not URLs.
const CONTEXTS = {
  // W3C VC Data Model v1
  "https://www.w3.org/2018/credentials/v1": {
    "@context": {
      "@version": 1.1, "@protected": true,
      "id": "@id", "type": "@type",
      "VerifiableCredential": { "@id": "https://www.w3.org/2018/credentials#VerifiableCredential", "@context": { "@version": 1.1, "@protected": true, "id": "@id", "type": "@type", "credentialSchema": { "@id": "https://www.w3.org/2018/credentials#credentialSchema", "@type": "@id", "@context": { "@version": 1.1, "@protected": true, "id": "@id", "type": "@type" } }, "credentialStatus": { "@id": "https://www.w3.org/2018/credentials#credentialStatus", "@type": "@id" }, "credentialSubject": { "@id": "https://www.w3.org/2018/credentials#credentialSubject", "@type": "@id" }, "evidence": { "@id": "https://www.w3.org/2018/credentials#evidence", "@type": "@id" }, "expirationDate": { "@id": "https://www.w3.org/2018/credentials#expirationDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }, "holder": { "@id": "https://www.w3.org/2018/credentials#holder", "@type": "@id" }, "issued": { "@id": "https://www.w3.org/2018/credentials#issued", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }, "issuer": { "@id": "https://www.w3.org/2018/credentials#issuer", "@type": "@id" }, "issuanceDate": { "@id": "https://www.w3.org/2018/credentials#issuanceDate", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }, "proof": { "@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph" }, "refreshService": { "@id": "https://www.w3.org/2018/credentials#refreshService", "@type": "@id" }, "termsOfUse": { "@id": "https://www.w3.org/2018/credentials#termsOfUse", "@type": "@id" }, "validFrom": { "@id": "https://www.w3.org/2018/credentials#validFrom", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }, "validUntil": { "@id": "https://www.w3.org/2018/credentials#validUntil", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" } } },
      "VerifiablePresentation": { "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation", "@context": { "@version": 1.1, "@protected": true, "id": "@id", "type": "@type", "holder": { "@id": "https://www.w3.org/2018/credentials#holder", "@type": "@id" }, "proof": { "@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph" }, "verifiableCredential": { "@id": "https://www.w3.org/2018/credentials#verifiableCredential", "@type": "@id", "@container": "@graph" } } }
    }
  },
  // W3C VC Data Model v2
  "https://www.w3.org/ns/credentials/v2": {
    "@context": {
      "@version": 1.1, "@protected": true,
      "id": "@id", "type": "@type",
      "description": "https://schema.org/description",
      "name": "https://schema.org/name",
      "VerifiableCredential": { "@id": "https://www.w3.org/2018/credentials#VerifiableCredential", "@context": { "@version": 1.1, "@protected": true, "id": "@id", "type": "@type", "credentialSchema": { "@id": "https://www.w3.org/2018/credentials#credentialSchema", "@type": "@id" }, "credentialStatus": { "@id": "https://www.w3.org/2018/credentials#credentialStatus", "@type": "@id" }, "credentialSubject": { "@id": "https://www.w3.org/2018/credentials#credentialSubject", "@type": "@id" }, "evidence": { "@id": "https://www.w3.org/2018/credentials#evidence", "@type": "@id" }, "issuer": { "@id": "https://www.w3.org/2018/credentials#issuer", "@type": "@id" }, "proof": { "@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph" }, "validFrom": { "@id": "https://www.w3.org/2018/credentials#validFrom", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }, "validUntil": { "@id": "https://www.w3.org/2018/credentials#validUntil", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" } } },
      "VerifiablePresentation": { "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation", "@context": { "@version": 1.1, "@protected": true, "id": "@id", "type": "@type", "holder": { "@id": "https://www.w3.org/2018/credentials#holder", "@type": "@id" }, "proof": { "@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph" }, "verifiableCredential": { "@id": "https://www.w3.org/2018/credentials#verifiableCredential", "@type": "@id", "@container": "@graph" } } }
    }
  },
  // Ed25519Signature2020 suite
  "https://w3id.org/security/suites/ed25519-2020/v1": {
    "@context": {
      "id": "@id", "type": "@type",
      "@protected": true,
      "proof": { "@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph" },
      "Ed25519VerificationKey2020": { "@id": "https://w3id.org/security#Ed25519VerificationKey2020", "@context": { "@protected": true, "id": "@id", "type": "@type", "controller": { "@id": "https://w3id.org/security#controller", "@type": "@id" }, "revoked": { "@id": "https://w3id.org/security#revoked", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }, "publicKeyMultibase": { "@id": "https://w3id.org/security#publicKeyMultibase", "@type": "https://w3id.org/security#multibase" } } },
      "Ed25519Signature2020": { "@id": "https://w3id.org/security#Ed25519Signature2020", "@context": { "@protected": true, "id": "@id", "type": "@type", "challenge": "https://w3id.org/security#challenge", "created": { "@id": "http://purl.org/dc/terms/created", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }, "domain": "https://w3id.org/security#domain", "expires": { "@id": "https://w3id.org/security#expiration", "@type": "http://www.w3.org/2001/XMLSchema#dateTime" }, "nonce": "https://w3id.org/security#nonce", "proofPurpose": { "@id": "https://w3id.org/security#proofPurpose", "@type": "@vocab", "@context": { "@protected": true, "id": "@id", "type": "@type", "assertionMethod": { "@id": "https://w3id.org/security#assertionMethod", "@type": "@id", "@container": "@set" }, "authentication": { "@id": "https://w3id.org/security#authenticationMethod", "@type": "@id", "@container": "@set" } } }, "proofValue": { "@id": "https://w3id.org/security#proofValue", "@type": "https://w3id.org/security#multibase" }, "verificationMethod": { "@id": "https://w3id.org/security#verificationMethod", "@type": "@id" } } }
    }
  }
};

// Custom document loader that serves embedded contexts.
const customLoader = jsonld.documentLoaders
  ? (function() {
      return async function(url) {
        if (CONTEXTS[url]) {
          return {
            contextUrl: null,
            document: CONTEXTS[url],
            documentUrl: url,
          };
        }
        throw new Error("Unknown context: " + url + " (not embedded in WASM module)");
      };
    })()
  : async function(url) {
      if (CONTEXTS[url]) {
        return {
          contextUrl: null,
          document: CONTEXTS[url],
          documentUrl: url,
        };
      }
      throw new Error("Unknown context: " + url + " (not embedded in WASM module)");
    };

// Register custom document loader.
jsonld.documentLoader = customLoader;

// Read all of stdin into a buffer.
function readStdin() {
  const chunks = [];
  const buf = new Uint8Array(4096);
  while (true) {
    const n = Javy.IO.readSync(0, buf);
    if (n === 0) break;
    chunks.push(buf.slice(0, n));
  }
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

const input = readStdin();
const docStr = new TextDecoder().decode(input);

// Handle empty input.
if (!docStr || docStr.trim() === "" || docStr.trim() === "{}") {
  Javy.IO.writeSync(1, new TextEncoder().encode(""));
} else {
  const doc = JSON.parse(docStr);
  const canonicalized = await jsonld.canonize(doc, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
  });
  Javy.IO.writeSync(1, new TextEncoder().encode(canonicalized));
}
