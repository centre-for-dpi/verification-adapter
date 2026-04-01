// node-stubs.js — No-op stubs for Node.js built-in modules that jsonld
// tries to require() at init time but never uses in our WASM context
// (no network, no filesystem).

// HTTP/HTTPS stubs — document loader init references these but we never
// actually fetch remote contexts.
export function request() { throw new Error("no network in WASM"); }
export function get() { throw new Error("no network in WASM"); }
export default { request, get };
