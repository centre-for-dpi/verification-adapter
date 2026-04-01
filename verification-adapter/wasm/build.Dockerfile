# Build canonicalize.wasm using esbuild (bundle) + Javy (compile).
#
# Usage from adapter-standalone/:
#   docker build -f wasm/build.Dockerfile -o type=local,dest=wasm .
#
# Produces: wasm/canonicalize.wasm

FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y curl

WORKDIR /build

# Install JS dependencies.
COPY wasm/package.json .
RUN npm install
RUN npx esbuild --version

# Bundle canonicalize.js + all deps into one file.
COPY wasm/canonicalize.js wasm/crypto-shim.js wasm/node-stubs.js wasm/loader-stub.js ./
# - Alias Node.js "crypto" to our pure-JS SHA-256 shim (QuickJS has no crypto).
# - Exclude HTTP-related modules (no network in WASM).
RUN npx esbuild canonicalize.js \
      --bundle \
      --format=esm \
      --platform=node \
      --target=esnext \
      --main-fields=module,main \
      --alias:crypto=./crypto-shim.js \
      --alias:crypto=./crypto-shim.js \
      --alias:http=./node-stubs.js \
      --alias:https=./node-stubs.js \
      --alias:url=./node-stubs.js \
      --alias:assert=./node-stubs.js \
      --alias:net=./node-stubs.js \
      --alias:tls=./node-stubs.js \
      --alias:zlib=./node-stubs.js \
      --alias:stream=./node-stubs.js \
      --alias:events=./node-stubs.js \
      --alias:buffer=./node-stubs.js \
      --alias:util=./node-stubs.js \
      --alias:string_decoder=./node-stubs.js \
      --alias:diagnostics_channel=./node-stubs.js \
      --alias:worker_threads=./node-stubs.js \
      --alias:perf_hooks=./node-stubs.js \
      --alias:async_hooks=./node-stubs.js \
      --alias:console=./node-stubs.js \
      --alias:querystring=./node-stubs.js \
      --alias:path=./node-stubs.js \
      --alias:child_process=./node-stubs.js \
      --alias:cluster=./node-stubs.js \
      --alias:undici=./node-stubs.js \
      --alias:@digitalbazaar/http-client=./loader-stub.js \
      --alias:ky-universal=./node-stubs.js \
      --alias:ky=./node-stubs.js \
      --alias:node-fetch=./node-stubs.js \
      --alias:xmlhttprequest=./node-stubs.js \
      --outfile=bundle.js && \
    wc -c bundle.js

# Install Javy (bytecodealliance/javy v8.1.0).
RUN curl -fSL "https://github.com/bytecodealliance/javy/releases/download/v8.1.0/javy-x86_64-linux-v8.1.0.gz" \
      -o /tmp/javy.gz && \
    gzip -d /tmp/javy.gz && \
    chmod +x /tmp/javy && \
    /tmp/javy --version

# Download the Javy plugin (required for v8+).
RUN curl -fSL "https://github.com/bytecodealliance/javy/releases/download/v8.1.0/plugin.wasm.gz" \
      -o /tmp/plugin.wasm.gz && \
    gzip -d /tmp/plugin.wasm.gz

# Compile JS bundle to WASM.
#   -J event-loop=y     — jsonld.canonize() is async, needs event loop
#   -J javy-stream-io=y — Javy.IO.readSync/writeSync for stdin/stdout
#   -J text-encoding=y  — TextEncoder/TextDecoder for string conversion
RUN mkdir -p /out && \
    /tmp/javy build \
      -J event-loop=y \
      -J javy-stream-io=y \
      -J text-encoding=y \
      -o /out/canonicalize.wasm \
      bundle.js && \
    ls -lh /out/canonicalize.wasm

FROM scratch
COPY --from=0 /out/canonicalize.wasm /canonicalize.wasm
