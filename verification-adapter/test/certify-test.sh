#!/usr/bin/env bash
# certify-test.sh — End-to-end test: Inji Certify issuance → adapter verification.
#
# Starts the adapter + Inji Verify + Certify stack, issues a FarmerCredential
# via the Pre-Authorized Code flow, and verifies it through the adapter.
#
# Usage:
#   ./test/certify-test.sh           # full stack test
#   ./test/certify-test.sh --offline  # verify via adapter offline mode
set -euo pipefail

cd "$(dirname "$0")/.."

ADAPTER="http://localhost:8085"
CERTIFY="http://localhost:8090/v1/certify"
CERTIFY_NGINX="http://localhost:8091"
INJI_VERIFY="http://localhost:8082"
OFFLINE_FLAG=""

if [[ "${1:-}" == "--offline" ]]; then
  OFFLINE_FLAG="--offline"
fi

echo ""
echo "=== Certify Integration Test ==="
echo ""

# 1. Create external network if needed.
echo "1. Ensuring mosip_network exists..."
docker network inspect mosip_network >/dev/null 2>&1 || \
    docker network create --driver bridge mosip_network
echo "   Done."
echo ""

# 2. Start the combined stack.
echo "2. Starting adapter + Inji Verify + Certify stack..."
docker compose -f docker-compose.test.yml -f docker-compose.certify-test.yml up --build -d
echo "   Stack started."
echo ""

# 3. Wait for Certify health (Spring Boot, ~2 min).
echo "3. Waiting for Certify to be healthy (this takes ~2 minutes)..."
timeout=180
elapsed=0
while ! curl -sf "$CERTIFY/actuator/health" >/dev/null 2>&1; do
  if [ $elapsed -ge $timeout ]; then
    echo "   ERROR: Certify did not become healthy within ${timeout}s"
    docker compose -f docker-compose.test.yml -f docker-compose.certify-test.yml logs certify | tail -30
    exit 1
  fi
  sleep 5
  elapsed=$((elapsed + 5))
  printf "   %ds...\r" "$elapsed"
done
echo "   Certify healthy after ${elapsed}s."
echo ""

# 4. Run smoke tests (existing).
echo "4. Running smoke tests..."
./test/smoke.sh || true
echo ""

# 5. Run Certify E2E test.
echo "5. Running Certify E2E test..."
echo ""
cd test/certify-e2e
go run . \
  --adapter "$ADAPTER" \
  --certify "$CERTIFY" \
  --certify-nginx "$CERTIFY_NGINX" \
  --inji-verify "$INJI_VERIFY" \
  $OFFLINE_FLAG
cd ../..

echo ""
echo "=== Certify Integration Test Complete ==="
echo ""
