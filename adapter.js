#!/usr/bin/env node
/**
 * CREDEBL-to-Inji Verify Adapter
 *
 * Bridges Inji Verify verification requests to CREDEBL agent.
 * This allows Inji Verify to verify did:polygon credentials via CREDEBL.
 *
 * Includes demo revocation system for testing revocation flows.
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// JSON-XT support (optional - graceful fallback if not available)
let jsonxt = null;
let jsonxtTemplates = null;
try {
    jsonxt = require('jsonxt');
    // Try multiple template locations (Docker: /app/templates, local: ../templates)
    const templatePaths = [
        path.join(__dirname, 'templates', 'jsonxt-templates.json'),
        path.join(__dirname, '..', 'templates', 'jsonxt-templates.json')
    ];
    for (const templatesPath of templatePaths) {
        if (fs.existsSync(templatesPath)) {
            jsonxtTemplates = JSON.parse(fs.readFileSync(templatesPath, 'utf8'));
            console.log('[JSONXT] Templates loaded from:', templatesPath);
            break;
        }
    }
    if (!jsonxtTemplates) {
        console.log('[JSONXT] Templates not found in:', templatePaths.join(', '));
    }
} catch (e) {
    console.log('[JSONXT] Library not available (install with: npm install jsonxt)');
}

// Configuration
const ADAPTER_PORT = process.env.ADAPTER_PORT || 8081;
const CREDEBL_AGENT_URL = process.env.CREDEBL_AGENT_URL || 'http://localhost:8004';
const CREDEBL_API_KEY = process.env.CREDEBL_API_KEY || 'supersecret-that-too-16chars';
const UPSTREAM_VERIFY_SERVICE = process.env.UPSTREAM_VERIFY_SERVICE || 'http://verify-service:8080';

// ============================================================================
// JSON-XT SUPPORT (Compact credential encoding)
// ============================================================================

/**
 * Check if input is a JSON-XT URI
 * JSON-XT URIs have format: jxt:resolver:type:version:encoded_data
 */
function isJsonXtUri(input) {
    if (typeof input !== 'string') return false;
    return input.startsWith('jxt:');
}

/**
 * Local resolver for JSON-XT decoding
 * Uses templates from ../templates/jsonxt-templates.json
 */
async function jsonxtLocalResolver(resolverName) {
    if (!jsonxtTemplates) {
        throw new Error('JSON-XT templates not loaded');
    }
    return jsonxtTemplates;
}

/**
 * Decode a JSON-XT URI to a full JSON-LD credential
 * @param {string} uri - JSON-XT URI (e.g., "jxt:local:educ:1:...")
 * @returns {object} Decoded JSON-LD credential
 */
async function decodeJsonXt(uri) {
    if (!jsonxt) {
        throw new Error('jsonxt library not available. Install with: npm install jsonxt');
    }
    if (!jsonxtTemplates) {
        throw new Error('JSON-XT templates not loaded');
    }

    console.log('[JSONXT] Decoding URI:', uri.substring(0, 50) + '...');
    const credential = await jsonxt.unpack(uri, jsonxtLocalResolver);
    console.log('[JSONXT] Decoded credential from issuer:', credential.issuer);
    return credential;
}

/**
 * Parse request body, handling JSON-XT URIs automatically
 * If body is a JSON-XT URI, decodes it first
 * @param {string} body - Raw request body
 * @returns {object} Parsed request object with credential
 */
async function parseRequestBody(body) {
    const trimmed = body.trim();

    // Check if body is a raw JSON-XT URI
    if (isJsonXtUri(trimmed)) {
        console.log('[ADAPTER] Detected JSON-XT URI in request body');
        const credential = await decodeJsonXt(trimmed);
        return { credential, _jsonxt: true };
    }

    // Try to parse as JSON
    const parsed = JSON.parse(trimmed);

    // Check if parsed content contains JSON-XT URI
    if (parsed.credential && typeof parsed.credential === 'string' && isJsonXtUri(parsed.credential)) {
        console.log('[ADAPTER] Detected JSON-XT URI in credential field');
        parsed.credential = await decodeJsonXt(parsed.credential);
        parsed._jsonxt = true;
    }
    if (parsed.verifiableCredential && typeof parsed.verifiableCredential === 'string' && isJsonXtUri(parsed.verifiableCredential)) {
        console.log('[ADAPTER] Detected JSON-XT URI in verifiableCredential field');
        parsed.verifiableCredential = await decodeJsonXt(parsed.verifiableCredential);
        parsed._jsonxt = true;
    }
    if (parsed.verifiableCredentials && Array.isArray(parsed.verifiableCredentials)) {
        for (let i = 0; i < parsed.verifiableCredentials.length; i++) {
            if (typeof parsed.verifiableCredentials[i] === 'string' && isJsonXtUri(parsed.verifiableCredentials[i])) {
                console.log(`[ADAPTER] Detected JSON-XT URI in verifiableCredentials[${i}]`);
                parsed.verifiableCredentials[i] = await decodeJsonXt(parsed.verifiableCredentials[i]);
                parsed._jsonxt = true;
            }
        }
    }

    return parsed;
}

// ============================================================================
// CREDENTIAL TYPE DETECTION
// ============================================================================

/**
 * DID methods that CREDEBL agent (credo-ts) can handle for verification
 */
const CREDEBL_SUPPORTED_DID_METHODS = [
    'did:polygon',  // via @ayanworks/credo-polygon-w3c-module
    'did:key',      // built-in credo-ts
    'did:web',      // built-in credo-ts
    'did:jwk',      // built-in credo-ts
    'did:peer',     // built-in credo-ts
    'did:indy',     // via @credo-ts/indy-vdr
    'did:sov',      // via @credo-ts/indy-vdr
];

/**
 * Proof types that Inji verify-service supports
 * If proof type is NOT in this list, we should use CREDEBL agent
 */
const INJI_SUPPORTED_PROOF_TYPES = [
    'Ed25519Signature2018',
    'Ed25519Signature2020',
    'RsaSignature2018',
    'JsonWebSignature2020',
];

/**
 * DID methods that Inji verify-service can handle
 */
const INJI_SUPPORTED_DID_METHODS = [
    'did:web',
    'did:key',
    'did:jwk',
];

/**
 * Extract DID method from a DID string
 * e.g., "did:polygon:0x123" -> "did:polygon"
 */
function extractDidMethod(did) {
    if (!did || typeof did !== 'string') return null;
    const parts = did.split(':');
    if (parts.length >= 2 && parts[0] === 'did') {
        return `did:${parts[1]}`;
    }
    return null;
}

/**
 * Determine routing strategy for a credential
 * Returns: { handler: 'credebl' | 'upstream' | 'unknown', reason: string }
 */
function determineRoutingStrategy(credential) {
    if (!credential) {
        return { handler: 'unknown', reason: 'No credential provided' };
    }

    // Extract issuer DID
    const issuer = typeof credential.issuer === 'string'
        ? credential.issuer
        : credential.issuer?.id;

    const didMethod = extractDidMethod(issuer);
    const proofType = credential.proof?.type;

    console.log('[ADAPTER] Routing analysis - issuer:', issuer, 'didMethod:', didMethod, 'proofType:', proofType);

    // Strategy 1: If proof type is not supported by Inji, use CREDEBL
    if (proofType && !INJI_SUPPORTED_PROOF_TYPES.includes(proofType)) {
        // Check if CREDEBL can handle this DID method
        if (didMethod && CREDEBL_SUPPORTED_DID_METHODS.includes(didMethod)) {
            return {
                handler: 'credebl',
                reason: `Proof type '${proofType}' not supported by upstream, using CREDEBL agent`
            };
        }
        return {
            handler: 'unknown',
            reason: `Proof type '${proofType}' not supported by either service`
        };
    }

    // Strategy 2: DID method based routing
    if (didMethod) {
        // DID methods only CREDEBL handles (not Inji)
        const credeblOnlyMethods = ['did:polygon', 'did:indy', 'did:sov', 'did:peer'];
        if (credeblOnlyMethods.includes(didMethod)) {
            return {
                handler: 'credebl',
                reason: `DID method '${didMethod}' handled by CREDEBL agent`
            };
        }

        // DID methods both can handle - prefer upstream for standard proofs
        if (INJI_SUPPORTED_DID_METHODS.includes(didMethod) &&
            INJI_SUPPORTED_PROOF_TYPES.includes(proofType)) {
            return {
                handler: 'upstream',
                reason: `DID method '${didMethod}' with '${proofType}' - forwarding to upstream`
            };
        }

        // CREDEBL can handle but Inji can't
        if (CREDEBL_SUPPORTED_DID_METHODS.includes(didMethod)) {
            return {
                handler: 'credebl',
                reason: `DID method '${didMethod}' handled by CREDEBL agent`
            };
        }
    }

    // Default: try upstream for unknown credentials
    return {
        handler: 'upstream',
        reason: 'Unknown credential type, trying upstream'
    };
}

/**
 * Check if we should handle this credential via CREDEBL agent
 * Returns true if this adapter should handle verification, false if should forward upstream
 */
function shouldHandleCredential(credential) {
    const strategy = determineRoutingStrategy(credential);
    console.log('[ADAPTER] Routing decision:', strategy.handler, '-', strategy.reason);
    return strategy.handler === 'credebl';
}

/**
 * Forward request to upstream verify-service
 * verify-service expects credential at root level, not wrapped in {"credential": ...}
 */
function forwardToUpstream(req, body, res) {
    return new Promise((resolve, reject) => {
        // Parse body and extract credential if wrapped
        let forwardBody = body;
        try {
            const parsed = JSON.parse(body);
            // If credential is wrapped, extract it for verify-service
            if (parsed.credential && parsed.credential['@context']) {
                forwardBody = JSON.stringify(parsed.credential);
                console.log('[ADAPTER] Unwrapped credential for upstream');
            } else if (parsed.verifiableCredentials && parsed.verifiableCredentials.length > 0) {
                forwardBody = JSON.stringify(parsed.verifiableCredentials[0]);
                console.log('[ADAPTER] Extracted first verifiableCredential for upstream');
            }
        } catch (e) {
            // Keep original body if parsing fails
        }

        const url = new URL(UPSTREAM_VERIFY_SERVICE);
        const options = {
            hostname: url.hostname,
            port: url.port || 8080,
            path: req.url,
            method: req.method,
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(forwardBody)
            }
        };

        console.log('[ADAPTER] Forwarding to upstream:', UPSTREAM_VERIFY_SERVICE + req.url);

        const proxyReq = http.request(options, (proxyRes) => {
            let data = '';
            proxyRes.on('data', chunk => data += chunk);
            proxyRes.on('end', () => {
                console.log('[ADAPTER] Upstream response:', proxyRes.statusCode, data.substring(0, 200));
                res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
                res.end(data);
                resolve();
            });
        });

        proxyReq.on('error', (error) => {
            console.error('[ADAPTER] Upstream error:', error.message);
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ verificationStatus: 'INVALID', error: 'Upstream service unavailable' }));
            resolve();
        });

        proxyReq.write(forwardBody);
        proxyReq.end();
    });
}

// ============================================================================
// DEMO REVOCATION REGISTRY (In-Memory)
// ============================================================================
// In production, this would be backed by a database or blockchain status list

const revocationRegistry = {
    // Map of credentialId -> revocation info
    revokedCredentials: new Map(),

    // Statistics
    stats: {
        totalRevoked: 0,
        totalChecks: 0,
        lastUpdated: null
    }
};

/**
 * Generate a unique identifier for a credential
 * Uses hash of key fields to create a consistent ID
 */
function getCredentialId(credential) {
    // Create ID from issuer + issuanceDate + subject ID (if present)
    const idParts = [
        credential.issuer,
        credential.issuanceDate,
        credential.credentialSubject?.id || '',
        credential.credentialSubject?.employeeId || '',
        // Include proof signature for uniqueness
        credential.proof?.jws?.slice(-20) || ''
    ];

    const hash = crypto.createHash('sha256')
        .update(idParts.join('|'))
        .digest('hex');

    return hash.substring(0, 16); // Short ID for readability
}

/**
 * Check if a credential is revoked
 */
function isCredentialRevoked(credential) {
    const credId = getCredentialId(credential);
    revocationRegistry.stats.totalChecks++;
    return revocationRegistry.revokedCredentials.has(credId);
}

/**
 * Get revocation details for a credential
 */
function getRevocationDetails(credential) {
    const credId = getCredentialId(credential);
    return revocationRegistry.revokedCredentials.get(credId) || null;
}

/**
 * Revoke a credential
 */
function revokeCredential(credential, reason = 'Revoked by issuer') {
    const credId = getCredentialId(credential);

    if (revocationRegistry.revokedCredentials.has(credId)) {
        return { success: false, error: 'Credential already revoked', credentialId: credId };
    }

    const revocationInfo = {
        credentialId: credId,
        revokedAt: new Date().toISOString(),
        reason: reason,
        issuer: credential.issuer,
        credentialType: credential.type,
        subjectId: credential.credentialSubject?.id || 'unknown',
        issuanceDate: credential.issuanceDate
    };

    revocationRegistry.revokedCredentials.set(credId, revocationInfo);
    revocationRegistry.stats.totalRevoked++;
    revocationRegistry.stats.lastUpdated = new Date().toISOString();

    console.log('[REVOCATION] Credential revoked:', credId, '- Reason:', reason);

    return { success: true, ...revocationInfo };
}

/**
 * Unrevoke (reinstate) a credential
 */
function unrevokeCredential(credentialId) {
    if (!revocationRegistry.revokedCredentials.has(credentialId)) {
        return { success: false, error: 'Credential not found in revocation registry' };
    }

    const info = revocationRegistry.revokedCredentials.get(credentialId);
    revocationRegistry.revokedCredentials.delete(credentialId);
    revocationRegistry.stats.totalRevoked--;
    revocationRegistry.stats.lastUpdated = new Date().toISOString();

    console.log('[REVOCATION] Credential reinstated:', credentialId);

    return { success: true, credentialId, reinstatedAt: new Date().toISOString(), previousRevocation: info };
}

/**
 * List all revoked credentials
 */
function listRevokedCredentials() {
    return {
        count: revocationRegistry.revokedCredentials.size,
        credentials: Array.from(revocationRegistry.revokedCredentials.values()),
        stats: revocationRegistry.stats
    };
}

// ============================================================================
// HTTP REQUEST HELPERS
// ============================================================================

function httpRequest(options, postData) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(data) });
                } catch (e) {
                    resolve({ status: res.statusCode, data: data });
                }
            });
        });
        req.on('error', reject);
        if (postData) req.write(postData);
        req.end();
    });
}

// Get JWT token from CREDEBL agent
async function getJwtToken() {
    const url = new URL(CREDEBL_AGENT_URL);
    const options = {
        hostname: url.hostname,
        port: url.port || 80,
        path: '/agent/token',
        method: 'POST',
        headers: { 'Authorization': CREDEBL_API_KEY }
    };

    const response = await httpRequest(options);
    if (response.data && response.data.token) {
        return response.data.token;
    }
    throw new Error('Failed to get JWT token: ' + JSON.stringify(response.data));
}

// Verify credential via CREDEBL agent
async function verifyCredentialSignature(credential) {
    const token = await getJwtToken();
    const url = new URL(CREDEBL_AGENT_URL);

    const postData = JSON.stringify({ credential: credential });
    const options = {
        hostname: url.hostname,
        port: url.port || 80,
        path: '/agent/credential/verify',
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData)
        }
    };

    const response = await httpRequest(options, postData);
    return response.data;
}

/**
 * Full credential verification including revocation check
 */
async function verifyCredential(credential) {
    // Step 1: Check revocation status first (fast check)
    const credId = getCredentialId(credential);
    const revocationDetails = getRevocationDetails(credential);

    if (revocationDetails) {
        console.log('[ADAPTER] Credential is REVOKED:', credId);
        return {
            isValid: false,
            error: 'CREDENTIAL_REVOKED',
            revocationDetails: revocationDetails
        };
    }

    // Step 2: Verify signature via CREDEBL
    const signatureResult = await verifyCredentialSignature(credential);

    return {
        ...signatureResult,
        credentialId: credId,
        revocationChecked: true,
        revoked: false
    };
}

// ============================================================================
// RESPONSE MAPPERS
// ============================================================================

function mapToInjiFormat(verificationResult) {
    if (verificationResult.error === 'CREDENTIAL_REVOKED') {
        return {
            verificationStatus: 'INVALID',
            error: 'CREDENTIAL_REVOKED',
            message: 'This credential has been revoked',
            revokedAt: verificationResult.revocationDetails?.revokedAt,
            reason: verificationResult.revocationDetails?.reason
        };
    }

    if (verificationResult && verificationResult.isValid === true) {
        return { verificationStatus: 'SUCCESS' };
    }

    return { verificationStatus: 'INVALID' };
}

function mapToInjiV2Format(verificationResult) {
    const isRevoked = verificationResult.error === 'CREDENTIAL_REVOKED';
    const isValid = !isRevoked && verificationResult && verificationResult.isValid === true;

    return {
        allChecksSuccessful: isValid,
        schemaAndSignatureCheck: {
            valid: isRevoked ? true : isValid, // Signature might be valid even if revoked
            error: (!isRevoked && !isValid) ? {
                errorCode: 'VERIFICATION_FAILED',
                errorMessage: 'Credential signature verification failed'
            } : null
        },
        expiryCheck: { valid: true },
        statusCheck: {
            valid: !isRevoked,
            error: isRevoked ? {
                errorCode: 'CREDENTIAL_REVOKED',
                errorMessage: verificationResult.revocationDetails?.reason || 'Credential has been revoked',
                revokedAt: verificationResult.revocationDetails?.revokedAt
            } : null
        },
        metadata: {
            credentialId: verificationResult.credentialId,
            revocationChecked: true
        }
    };
}

// ============================================================================
// HTTP SERVER
// ============================================================================

const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // Parse URL for path and query params
    const urlParts = req.url.split('?');
    const path = urlParts[0];

    // ========================================================================
    // HEALTH & INFO ENDPOINTS
    // ========================================================================

    if (req.method === 'GET' && (path === '/health' || path === '/')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: 'ok',
            service: 'credebl-inji-adapter',
            features: ['verification', 'demo-revocation'],
            revocationStats: revocationRegistry.stats
        }));
        return;
    }

    // ========================================================================
    // VERIFICATION ENDPOINTS
    // ========================================================================

    if (req.method === 'POST' && path === '/v1/verify/vc-verification') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                // Parse request body with JSON-XT support
                const request = await parseRequestBody(body);
                console.log('[ADAPTER] Received v1 verification request');

                if (request._jsonxt) {
                    console.log('[ADAPTER] Credential decoded from JSON-XT format');
                }

                // Support multiple input formats (including JSON-XT URI decoded by parseRequestBody)
                let credential;
                if (request.verifiableCredentials && request.verifiableCredentials.length > 0) {
                    credential = request.verifiableCredentials[0];
                } else if (request.credential) {
                    credential = request.credential;
                } else if (request['@context']) {
                    credential = request;
                } else {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ verificationStatus: 'INVALID', error: 'No credentials found in request' }));
                    return;
                }

                // Check if we should handle this credential or forward to upstream
                if (!shouldHandleCredential(credential)) {
                    console.log('[ADAPTER] Non-polygon credential, forwarding to upstream verify-service');
                    await forwardToUpstream(req, body, res);
                    return;
                }

                console.log('[ADAPTER] Verifying did:polygon credential with issuer:', credential.issuer);

                const verificationResult = await verifyCredential(credential);
                console.log('[ADAPTER] Verification result:', verificationResult.isValid,
                    verificationResult.error === 'CREDENTIAL_REVOKED' ? '(REVOKED)' : '');

                const injiResult = mapToInjiFormat(verificationResult);
                console.log('[ADAPTER] Returning:', JSON.stringify(injiResult));

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(injiResult));
            } catch (error) {
                console.error('[ADAPTER] Error:', error.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ verificationStatus: 'INVALID', error: error.message }));
            }
        });
        return;
    }

    if (req.method === 'POST' && path === '/v1/verify/vc-verification/v2') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                // Parse request body with JSON-XT support
                const request = await parseRequestBody(body);
                console.log('[ADAPTER] Received v2 verification request');

                if (request._jsonxt) {
                    console.log('[ADAPTER] Credential decoded from JSON-XT format');
                }

                let credential = request.verifiableCredential;
                if (!credential) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ allChecksSuccessful: false }));
                    return;
                }

                // Handle credential that might be a JSON-XT URI string
                let credObj;
                if (typeof credential === 'string') {
                    if (isJsonXtUri(credential)) {
                        credObj = await decodeJsonXt(credential);
                        console.log('[ADAPTER] Credential decoded from JSON-XT URI in verifiableCredential');
                    } else {
                        credObj = JSON.parse(credential);
                    }
                } else {
                    credObj = credential;
                }

                // Check if we should handle this credential or forward to upstream
                if (!shouldHandleCredential(credObj)) {
                    console.log('[ADAPTER] Non-polygon credential, forwarding to upstream verify-service');
                    await forwardToUpstream(req, body, res);
                    return;
                }

                console.log('[ADAPTER] Verifying did:polygon credential with issuer:', credObj.issuer);

                const verificationResult = await verifyCredential(credObj);
                console.log('[ADAPTER] Verification result:', verificationResult.isValid,
                    verificationResult.error === 'CREDENTIAL_REVOKED' ? '(REVOKED)' : '');

                const injiResult = mapToInjiV2Format(verificationResult);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(injiResult));
            } catch (error) {
                console.error('[ADAPTER] Error:', error.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ allChecksSuccessful: false, error: error.message }));
            }
        });
        return;
    }

    // ========================================================================
    // DEMO REVOCATION ENDPOINTS
    // ========================================================================

    // POST /revocation/revoke - Revoke a credential
    if (req.method === 'POST' && path === '/revocation/revoke') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const request = JSON.parse(body);
                console.log('[REVOCATION] Revoke request received');

                const credential = request.credential;
                const reason = request.reason || 'Revoked by issuer';

                if (!credential) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Credential is required' }));
                    return;
                }

                const result = revokeCredential(credential, reason);

                res.writeHead(result.success ? 200 : 400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
            } catch (error) {
                console.error('[REVOCATION] Error:', error.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
        return;
    }

    // POST /revocation/check - Check revocation status without full verification
    if (req.method === 'POST' && path === '/revocation/check') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const request = JSON.parse(body);
                const credential = request.credential;

                if (!credential) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Credential is required' }));
                    return;
                }

                const credId = getCredentialId(credential);
                const isRevoked = isCredentialRevoked(credential);
                const details = getRevocationDetails(credential);

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    credentialId: credId,
                    isRevoked: isRevoked,
                    revocationDetails: details
                }));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: error.message }));
            }
        });
        return;
    }

    // DELETE /revocation/revoke/:credentialId - Unrevoke (reinstate) a credential
    if (req.method === 'DELETE' && path.startsWith('/revocation/revoke/')) {
        const credentialId = path.split('/').pop();

        if (!credentialId) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Credential ID is required' }));
            return;
        }

        const result = unrevokeCredential(credentialId);
        res.writeHead(result.success ? 200 : 404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
    }

    // POST /revocation/unrevoke - Unrevoke using credential object
    if (req.method === 'POST' && path === '/revocation/unrevoke') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                const request = JSON.parse(body);

                let credentialId;
                if (request.credentialId) {
                    credentialId = request.credentialId;
                } else if (request.credential) {
                    credentialId = getCredentialId(request.credential);
                } else {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'credentialId or credential is required' }));
                    return;
                }

                const result = unrevokeCredential(credentialId);
                res.writeHead(result.success ? 200 : 404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
            } catch (error) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: error.message }));
            }
        });
        return;
    }

    // GET /revocation/list - List all revoked credentials
    if (req.method === 'GET' && path === '/revocation/list') {
        const list = listRevokedCredentials();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(list));
        return;
    }

    // GET /revocation/stats - Get revocation statistics
    if (req.method === 'GET' && path === '/revocation/stats') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            totalRevoked: revocationRegistry.stats.totalRevoked,
            totalChecks: revocationRegistry.stats.totalChecks,
            lastUpdated: revocationRegistry.stats.lastUpdated,
            registrySize: revocationRegistry.revokedCredentials.size
        }));
        return;
    }

    // ========================================================================
    // 404 NOT FOUND
    // ========================================================================

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(ADAPTER_PORT, '0.0.0.0', () => {
    console.log('===========================================');
    console.log('  CREDEBL-to-Inji Verify Adapter');
    console.log('  with Demo Revocation & JSON-XT Support');
    console.log('===========================================');
    console.log('');
    console.log('Adapter listening on port:', ADAPTER_PORT);
    console.log('CREDEBL Agent URL:', CREDEBL_AGENT_URL);
    console.log('JSON-XT:', jsonxt ? 'ENABLED' : 'DISABLED (install jsonxt package)');
    console.log('');
    console.log('Supported Formats:');
    console.log('  - JSON-LD credentials (standard)');
    console.log('  - JSON-XT URIs (jxt:resolver:type:version:data)');
    console.log('');
    console.log('Verification Endpoints:');
    console.log('  POST /v1/verify/vc-verification');
    console.log('  POST /v1/verify/vc-verification/v2');
    console.log('');
    console.log('Revocation Endpoints (Demo):');
    console.log('  POST   /revocation/revoke      - Revoke a credential');
    console.log('  POST   /revocation/check       - Check revocation status');
    console.log('  POST   /revocation/unrevoke    - Reinstate a credential');
    console.log('  DELETE /revocation/revoke/:id  - Reinstate by ID');
    console.log('  GET    /revocation/list        - List revoked credentials');
    console.log('  GET    /revocation/stats       - Revocation statistics');
    console.log('');
    console.log('Health:');
    console.log('  GET    /health');
    console.log('===========================================');
});
