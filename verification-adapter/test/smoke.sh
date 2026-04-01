#!/usr/bin/env bash
# smoke.sh — Verify the adapter can reach all configured backends.
#
# Usage:
#   docker compose -f docker-compose.test.yml up --build -d
#   ./test/smoke.sh
set -euo pipefail

ADAPTER="http://localhost:8085"
INJI="http://localhost:8082"
WALTID_VERIFIER="http://localhost:7003"
# WALTID_ISSUER not included — needs config files for OIDCIssuerServiceConfig.

pass=0
fail=0
total=0

check() {
  total=$((total + 1))
  local name="$1"
  local result="$2"
  if [ "$result" = "ok" ]; then
    echo "  ✓ $name"
    pass=$((pass + 1))
  else
    echo "  ✗ $name — $result"
    fail=$((fail + 1))
  fi
}

echo ""
echo "=== Adapter Smoke Tests ==="
echo ""

# ---------- 1. Health endpoints ----------
echo "1. Health endpoints"

status=$(curl -sf "$ADAPTER/health" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "unreachable")
check "Adapter /health" "$([ "$status" = "ok" ] && echo ok || echo "$status")"

status=$(curl -sf "$INJI/v1/verify/actuator/health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "unreachable")
check "Inji Verify health" "$([ "$status" = "UP" ] && echo ok || echo "$status")"

status=$(curl -sf "$WALTID_VERIFIER/" > /dev/null 2>&1 && echo ok || echo "unreachable")
check "walt.id Verifier health" "$status"

echo ""

# ---------- 2. Backend connectivity (via adapter) ----------
echo "2. Backend connectivity (via adapter /health)"

backends=$(curl -sf "$ADAPTER/health" 2>/dev/null)
inji_ok=$(echo "$backends" | python3 -c "import sys,json; print(json.load(sys.stdin).get('backends',{}).get('inji-verify', False))" 2>/dev/null || echo "false")
check "Adapter sees inji-verify" "$([ "$inji_ok" = "True" ] && echo ok || echo "not connected")"

waltid_ok=$(echo "$backends" | python3 -c "import sys,json; print(json.load(sys.stdin).get('backends',{}).get('waltid-verifier', False))" 2>/dev/null || echo "false")
check "Adapter sees waltid-verifier" "$([ "$waltid_ok" = "True" ] && echo ok || echo "not connected")"

credebl_ok=$(echo "$backends" | python3 -c "import sys,json; print(json.load(sys.stdin).get('backends',{}).get('credebl-agent', False))" 2>/dev/null || echo "false")
check "Adapter sees credebl-agent" "$([ "$credebl_ok" = "True" ] && echo ok || echo "not connected (expected if full stack not running)")"
echo ""

# ---------- 3. Cache endpoints ----------
echo "3. Cache endpoint"

cache=$(curl -sf "$ADAPTER/cache" 2>/dev/null)
check "GET /cache" "$([ -n "$cache" ] && echo ok || echo "empty response")"
echo ""

# ---------- 4. Offline verification (did:key — no backend needed) ----------
echo "4. Offline verification (did:key, no backend needed)"

result=$(curl -sf -X POST "$ADAPTER/verify-offline" \
  -H "Content-Type: application/json" \
  -d '{
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "credentialSubject": {"id": "did:key:z6MkTest", "name": "Test"},
    "proof": {"type": "Ed25519Signature2020", "proofValue": "zInvalidSig"}
  }' 2>/dev/null)

offline=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('offline', False))" 2>/dev/null || echo "false")
check "Offline mode activated" "$([ "$offline" = "True" ] && echo ok || echo "not offline")"

level=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verificationLevel', ''))" 2>/dev/null || echo "")
check "Verification attempted" "$([ -n "$level" ] && echo ok || echo "no level returned")"
echo ""

# ---------- 5. Sync endpoint ----------
echo "5. Sync endpoint (did:key — local resolution)"

sync_result=$(curl -sf -X POST "$ADAPTER/sync" \
  -H "Content-Type: application/json" \
  -d '{"did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"}' 2>/dev/null)

success=$(echo "$sync_result" | python3 -c "import sys,json; r=json.load(sys.stdin)['results'][0]; print(r['success'])" 2>/dev/null || echo "false")
check "Sync did:key" "$([ "$success" = "True" ] && echo ok || echo "sync failed")"
echo ""

# ---------- 6. Online verification via Inji Verify ----------
echo "6. Online verification via Inji Verify (did:web credential)"

result=$(curl -sf -X POST "$ADAPTER/v1/verify/vc-verification" \
  -H "Content-Type: application/json" \
  -d '{
    "verifiableCredentials": [{
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      "type": ["VerifiableCredential"],
      "issuer": "did:web:example.com",
      "issuanceDate": "2025-01-01T00:00:00Z",
      "credentialSubject": {"id": "did:key:z6MkTest", "name": "Test"},
      "proof": {
        "type": "Ed25519Signature2018",
        "created": "2025-01-01T00:00:00Z",
        "verificationMethod": "did:web:example.com#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": "zInvalidSigForTesting"
      }
    }]
  }' 2>/dev/null)

backend=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('backend', 'none'))" 2>/dev/null || echo "none")
check "Routed to backend" "$([ "$backend" != "none" ] && echo ok || echo "no backend")"
echo ""

# ---------- Summary ----------
echo "==========================="
echo "  Results: $pass passed, $fail failed (of $total)"
echo "==========================="
echo ""

exit $fail
