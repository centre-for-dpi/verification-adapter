#!/usr/bin/env node
/**
 * JSON-LD Context Proxy Server
 *
 * Serves cached JSON-LD contexts for offline verification.
 * Maps w3id.org and other context URLs to local cached files.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = process.env.CONTEXT_PROXY_PORT || 8086;
const CONTEXTS_DIR = process.env.CONTEXTS_DIR || path.join(__dirname, 'contexts');

// Context URL mappings
const CONTEXT_MAPPINGS = {
    // Ed25519 2020 suite
    '/security/suites/ed25519-2020/v1': 'ed25519-2020.jsonld',

    // W3C Credentials
    '/2018/credentials/v1': 'credentials-v1.json',

    // DID context
    '/ns/did/v1': 'did-v1.json',

    // Security vocab
    '/security/v1': 'security-v1.json',
    '/security/v2': 'security-v2.json',
};

// Try to fetch and cache a context from the network
async function fetchAndCacheContext(url, localPath) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;

        const request = client.get(url, { timeout: 10000 }, (res) => {
            // Follow redirects
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                console.log(`[CONTEXT] Following redirect: ${res.headers.location}`);
                fetchAndCacheContext(res.headers.location, localPath)
                    .then(resolve)
                    .catch(reject);
                return;
            }

            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode}`));
                return;
            }

            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    // Validate it's JSON
                    JSON.parse(data);
                    fs.writeFileSync(localPath, data);
                    console.log(`[CONTEXT] Cached: ${localPath}`);
                    resolve(data);
                } catch (e) {
                    reject(new Error('Invalid JSON'));
                }
            });
        });

        request.on('error', reject);
        request.on('timeout', () => {
            request.destroy();
            reject(new Error('Timeout'));
        });
    });
}

// Serve a context
function serveContext(contextPath, res) {
    const filename = CONTEXT_MAPPINGS[contextPath];

    if (!filename) {
        console.log(`[CONTEXT] Unknown context: ${contextPath}`);
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Context not found' }));
        return;
    }

    const filePath = path.join(CONTEXTS_DIR, filename);

    if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        console.log(`[CONTEXT] Serving cached: ${contextPath}`);
        res.writeHead(200, {
            'Content-Type': 'application/ld+json',
            'Access-Control-Allow-Origin': '*'
        });
        res.end(content);
    } else {
        console.log(`[CONTEXT] Cache miss: ${contextPath}`);
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Context not cached' }));
    }
}

const server = http.createServer((req, res) => {
    // CORS preflight
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        });
        res.end();
        return;
    }

    // Health check
    if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: 'ok',
            service: 'context-proxy',
            cachedContexts: Object.keys(CONTEXT_MAPPINGS)
        }));
        return;
    }

    // List cached contexts
    if (req.url === '/contexts') {
        const contexts = {};
        for (const [contextPath, file] of Object.entries(CONTEXT_MAPPINGS)) {
            const filePath = path.join(CONTEXTS_DIR, file);
            contexts[contextPath] = {
                file,
                cached: fs.existsSync(filePath),
                size: fs.existsSync(filePath) ? fs.statSync(filePath).size : 0
            };
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(contexts, null, 2));
        return;
    }

    // Serve context
    serveContext(req.url, res);
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('===========================================');
    console.log('  JSON-LD Context Proxy Server');
    console.log('===========================================');
    console.log('');
    console.log(`  Port: ${PORT}`);
    console.log(`  Contexts dir: ${CONTEXTS_DIR}`);
    console.log('');
    console.log('  Mapped contexts:');
    for (const [contextPath, file] of Object.entries(CONTEXT_MAPPINGS)) {
        const filePath = `${CONTEXTS_DIR}/${file}`;
        const cached = fs.existsSync(filePath) ? 'CACHED' : 'MISSING';
        console.log(`    ${contextPath} -> ${file} [${cached}]`);
    }
    console.log('');
    console.log('  Endpoints:');
    console.log('    GET /health    - Health check');
    console.log('    GET /contexts  - List cached contexts');
    console.log('    GET /<path>    - Serve context');
    console.log('');
    console.log('===========================================');
});
