#!/bin/bash
# smoke_test.sh
# Runs a suite of fraud detection scenarios against the live API endpoint.
# Usage: bash smoke_test.sh [api_endpoint]
# If no endpoint provided, reads from terraform output.

set -e

API="${1:-$(terraform output -raw api_endpoint 2>/dev/null)}"

if [ -z "$API" ]; then
  echo "ERROR: No API endpoint. Pass as argument or run from terraform directory."
  echo "Usage: bash smoke_test.sh https://xxxx.execute-api.us-east-1.amazonaws.com"
  exit 1
fi

ENDPOINT="${API%/}/evaluate"
PASS=0
FAIL=0

run_test() {
  local description="$1"
  local payload="$2"
  local expected_level="$3"
  local expected_action="$4"

  echo ""
  echo "──────────────────────────────────────────"
  echo "TEST: $description"
  echo "──────────────────────────────────────────"

  RESPONSE=$(curl -s -X POST "$ENDPOINT" \
    -H 'Content-Type: application/json' \
    -d "$payload")

  echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

  ACTUAL_LEVEL=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('risk_level','UNKNOWN'))" 2>/dev/null)
  ACTUAL_ACTION=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('recommended_action','UNKNOWN'))" 2>/dev/null)

  if [ "$ACTUAL_LEVEL" = "$expected_level" ] && [ "$ACTUAL_ACTION" = "$expected_action" ]; then
    echo "✅ PASS — risk_level=$ACTUAL_LEVEL, action=$ACTUAL_ACTION"
    PASS=$((PASS + 1))
  else
    echo "❌ FAIL — expected $expected_level/$expected_action, got $ACTUAL_LEVEL/$ACTUAL_ACTION"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "🛡️  Fraud Sentinel — Scenario Test Suite"
echo "   Endpoint: $ENDPOINT"
echo ""
echo "Signal weights: HIGH_VALUE_TXN=0.35, FAILED_LOGIN_BURST=0.30,"
echo "SUSPICIOUS_COUNTRY=0.25, RAPID_API_CALLS=0.20,"
echo "ACCOUNT_CHANGE_POST_TXN=0.15, UNEXPECTED_IP_CLASS=0.10"
echo "Thresholds: LOW<0.25, MEDIUM<0.55, HIGH<0.80, CRITICAL>=0.80"
echo ""

# ── LOW RISK (score < 0.25) ───────────────────────────────────────────────────

run_test \
  "LOW: small domestic transaction (score=0.0)" \
  '{"user_id":"user-001","ip_address":"1.2.3.4","event_type":"transaction","payload":{},"amount_cents":1000,"country_code":"US"}' \
  "LOW" "ALLOW"

run_test \
  "LOW: normal login (score=0.0)" \
  '{"user_id":"user-002","ip_address":"5.6.7.8","event_type":"login_attempt","payload":{"attempt_count":1}}' \
  "LOW" "ALLOW"

run_test \
  "LOW: single signal - unexpected IP (score=0.10)" \
  '{"user_id":"user-003","ip_address":"10.0.0.1","event_type":"login_attempt","payload":{"attempt_count":1}}' \
  "LOW" "ALLOW"

run_test \
  "LOW: single signal - rapid API calls (score=0.20)" \
  '{"user_id":"user-004","ip_address":"1.2.3.4","event_type":"api_call","payload":{"calls_per_minute":130}}' \
  "LOW" "ALLOW"

# ── MEDIUM RISK (score 0.25–0.55) ────────────────────────────────────────────

run_test \
  "MEDIUM: login burst alone (score=0.30)" \
  '{"user_id":"user-005","ip_address":"1.2.3.4","event_type":"login_attempt","payload":{"attempt_count":7}}' \
  "MEDIUM" "STEP_UP_AUTH"

run_test \
  "MEDIUM: large transaction alone (score=0.35)" \
  '{"user_id":"user-006","ip_address":"1.2.3.4","event_type":"transaction","payload":{},"amount_cents":600000,"country_code":"US"}' \
  "MEDIUM" "STEP_UP_AUTH"

run_test \
  "MEDIUM: suspicious country alone (score=0.25)" \
  '{"user_id":"user-007","ip_address":"1.2.3.4","event_type":"login_attempt","payload":{"attempt_count":1},"country_code":"XX"}' \
  "MEDIUM" "STEP_UP_AUTH"

# ── HIGH RISK (score 0.55–0.80) ───────────────────────────────────────────────

run_test \
  "HIGH: large txn + suspicious country (score=0.60)" \
  '{"user_id":"user-008","ip_address":"1.2.3.4","event_type":"transaction","payload":{},"amount_cents":750000,"country_code":"XX"}' \
  "HIGH" "HOLD_FOR_REVIEW"

run_test \
  "HIGH: login burst + suspicious country (score=0.55)" \
  '{"user_id":"user-009","ip_address":"1.2.3.4","event_type":"login_attempt","payload":{"attempt_count":6},"country_code":"XX"}' \
  "HIGH" "REQUIRE_MFA"

run_test \
  "HIGH: large txn + rapid API + unexpected IP (score=0.65)" \
  '{"user_id":"user-010","ip_address":"10.0.0.1","event_type":"transaction","payload":{"calls_per_minute":150},"amount_cents":750000,"country_code":"US"}' \
  "HIGH" "HOLD_FOR_REVIEW"

# ── CRITICAL RISK (score >= 0.80) ─────────────────────────────────────────────

run_test \
  "CRITICAL: large txn + suspicious country + login burst (score=0.90)" \
  '{"user_id":"user-011","ip_address":"1.2.3.4","event_type":"transaction","payload":{"attempt_count":6},"amount_cents":750000,"country_code":"XX"}' \
  "CRITICAL" "BLOCK_AND_ALERT"

run_test \
  "CRITICAL: all signals firing (score=1.0 clamped)" \
  '{"user_id":"user-012","ip_address":"10.0.0.1","event_type":"transaction","payload":{"attempt_count":10,"calls_per_minute":200,"seconds_since_last_txn":10},"amount_cents":999999,"country_code":"YY"}' \
  "CRITICAL" "BLOCK_AND_ALERT"

# ── HIGH VOLUME BURST ─────────────────────────────────────────────────────────

echo ""
echo "──────────────────────────────────────────"
echo "TEST: High volume burst (20 concurrent requests)"
echo "──────────────────────────────────────────"

for i in $(seq 1 20); do
  curl -s -X POST "$ENDPOINT" \
    -H 'Content-Type: application/json' \
    -d "{\"user_id\":\"bulk-user-$i\",\"ip_address\":\"1.2.3.4\",\"event_type\":\"transaction\",\"payload\":{},\"amount_cents\":$((RANDOM % 1000000)),\"country_code\":\"US\"}" &
done
wait
echo ""
echo "✅ High volume burst complete"

# ── SUMMARY ───────────────────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "══════════════════════════════════════════"
echo ""
if [ $FAIL -eq 0 ]; then
  echo "🎉 All tests passed!"
else
  echo "⚠️  $FAIL tests failed — check output above"
fi