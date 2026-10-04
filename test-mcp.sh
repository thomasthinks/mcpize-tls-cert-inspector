#!/bin/bash
# MCP Protocol Smoke Test for tls-cert-inspector
# Usage: Start the server first (npm run dev / node dist/index.js), then: bash test-mcp.sh

BASE_URL="${MCP_URL:-http://localhost:8080}"
MCP_ENDPOINT="$BASE_URL/mcp"
HEALTH_ENDPOINT="$BASE_URL/health"
PASSED=0
FAILED=0

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}FAIL${NC} $1: $2"; FAILED=$((FAILED + 1)); }

echo "Testing tls-cert-inspector at $BASE_URL"
echo "================================"

# 1. Health check
echo ""
echo "--- Health Check ---"
HEALTH=$(curl -sf "$HEALTH_ENDPOINT" 2>/dev/null) || true
if echo "$HEALTH" | grep -q "healthy"; then
  pass "GET /health returns healthy"
else
  fail "GET /health" "Expected 'healthy' in response, got: $HEALTH"
fi

ACCEPT_HDR=(-H "Accept: application/json, text/event-stream" -H "Content-Type: application/json")

# 2. Initialize handshake
echo ""
echo "--- MCP Initialize ---"
INIT_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" "${ACCEPT_HDR[@]}" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": { "name": "smoke-test", "version": "1.0" }
    }
  }' 2>/dev/null) || true

if echo "$INIT_RESPONSE" | grep -q '"result"'; then
  pass "initialize returns result"
else
  fail "initialize" "No 'result' in response: $INIT_RESPONSE"
fi

# 3. List tools
echo ""
echo "--- List Tools ---"
TOOLS_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" "${ACCEPT_HDR[@]}" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }' 2>/dev/null) || true

if echo "$TOOLS_RESPONSE" | grep -q '"tools"'; then
  pass "tools/list returns tools array"
  TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null || echo "?")
  echo "     Found $TOOL_COUNT tool(s)"
else
  fail "tools/list" "No 'tools' in response: $TOOLS_RESPONSE"
fi

# 4. Check expected tools exist (and the hello/echo template tools are gone)
EXPECTED_TOOLS=("inspect_cert" "check_expiry_bulk")
for TOOL in "${EXPECTED_TOOLS[@]}"; do
  if echo "$TOOLS_RESPONSE" | grep -q "\"$TOOL\""; then
    pass "Tool '$TOOL' is registered"
  else
    fail "Tool '$TOOL'" "Not found in tools/list response"
  fi
done
for DEAD in "hello" "echo"; do
  if echo "$TOOLS_RESPONSE" | grep -q "\"name\":\"$DEAD\""; then
    fail "Template tool '$DEAD'" "Template example tool was not removed"
  else
    pass "Template tool '$DEAD' is gone"
  fi
done

# 5. Call inspect_cert on a real host
echo ""
echo "--- Call inspect_cert ---"
CALL_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" "${ACCEPT_HDR[@]}" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "inspect_cert",
      "arguments": { "hostname": "example.com" }
    }
  }' 2>/dev/null) || true

if echo "$CALL_RESPONSE" | grep -q '"subject_cn"'; then
  pass "inspect_cert returns cert data"
else
  fail "inspect_cert" "No 'subject_cn' in response: $(echo "$CALL_RESPONSE" | head -c 300)"
fi
if echo "$CALL_RESPONSE" | grep -q '"isError":true'; then
  fail "inspect_cert isError" "Unexpected error: $(echo "$CALL_RESPONSE" | head -c 300)"
else
  pass "inspect_cert did not return isError"
fi

# 6. Call check_expiry_bulk (mixed: one good host, one unresolvable host)
echo ""
echo "--- Call check_expiry_bulk ---"
BULK_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" "${ACCEPT_HDR[@]}" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "check_expiry_bulk",
      "arguments": { "hostnames": ["example.com", "this-host-definitely-does-not-exist-xyz.invalid"] }
    }
  }' 2>/dev/null) || true

if echo "$BULK_RESPONSE" | grep -q '"warnings"'; then
  pass "check_expiry_bulk returns warnings"
else
  fail "check_expiry_bulk" "No 'warnings' in response: $(echo "$BULK_RESPONSE" | head -c 300)"
fi
if echo "$BULK_RESPONSE" | grep -q '"hostname":"this-host-definitely-does-not-exist-xyz.invalid"[^}]*"error"'; then
  pass "check_expiry_bulk reports per-host error without failing the batch"
else
  fail "check_expiry_bulk per-host error" "Expected an error entry for the bad host: $(echo "$BULK_RESPONSE" | head -c 400)"
fi

# 6b. Garbage hostname is rejected at the schema boundary with a helpful error
echo ""
echo "--- Garbage hostname validation ---"
GARBAGE_RESPONSE=$(curl -s -X POST "$MCP_ENDPOINT" "${ACCEPT_HDR[@]}" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "inspect_cert",
      "arguments": { "hostname": "not a host!!!" }
    }
  }' 2>/dev/null) || true

if echo "$GARBAGE_RESPONSE" | grep -q "Invalid hostname"; then
  pass "garbage hostname rejected with helpful validation error"
else
  fail "garbage hostname" "Expected 'Invalid hostname' in response: $(echo "$GARBAGE_RESPONSE" | head -c 300)"
fi

# 7. Ping
echo ""
echo "--- Ping ---"
PING_RESPONSE=$(curl -sf -X POST "$MCP_ENDPOINT" "${ACCEPT_HDR[@]}" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "ping",
    "params": {}
  }' 2>/dev/null) || true

if echo "$PING_RESPONSE" | grep -q '"result"'; then
  pass "ping returns result"
else
  fail "ping" "No 'result' in response: $PING_RESPONSE"
fi

# Summary
echo ""
echo "================================"
echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"

if [ $FAILED -gt 0 ]; then
  exit 1
fi
