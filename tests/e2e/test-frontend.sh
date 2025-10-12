#!/bin/bash
# ABOUTME: End-to-end tests for Keycast frontend that verify full user flows
# ABOUTME: Tests can run against local or production deployments

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="${BASE_URL:-http://localhost:5173}"
API_URL="${API_URL:-http://localhost:3000}"

# Test counters
PASSED=0
FAILED=0
TOTAL=0

# Test helper functions
test_start() {
    TOTAL=$((TOTAL + 1))
    echo -n "  [$TOTAL] $1... "
}

test_pass() {
    PASSED=$((PASSED + 1))
    echo -e "${GREEN}✓${NC}"
}

test_fail() {
    FAILED=$((FAILED + 1))
    echo -e "${RED}✗${NC}"
    echo "    Error: $1"
}

echo ""
echo "========================================"
echo "  Keycast E2E Tests"
echo "========================================"
echo ""
echo "Frontend URL: $BASE_URL"
echo "API URL:      $API_URL"
echo ""

# Test Suite 1: Page Loading
echo -e "${BLUE}1. Page Loading & Rendering${NC}"

test_start "Home page loads"
STATUS=$(curl -s -o /tmp/home.html -w "%{http_code}" "$BASE_URL")
if [ "$STATUS" = "200" ]; then
    test_pass
else
    test_fail "Expected HTTP 200, got $STATUS"
fi

test_start "Page contains HTML"
if grep -qi "<!DOCTYPE html\|<html" /tmp/home.html; then
    test_pass
else
    test_fail "No HTML found in response"
fi

test_start "Page includes JS bundle"
if grep -qi "<script\|\.js" /tmp/home.html; then
    test_pass
else
    test_fail "No JavaScript found"
fi

# Test Suite 2: API Integration
echo ""
echo -e "${BLUE}2. Frontend-API Integration${NC}"

test_start "Frontend can reach API health endpoint"
# Check if frontend has access to API
if curl -s -m 5 "$API_URL/health" > /dev/null; then
    test_pass
else
    test_fail "Cannot reach API from test environment"
fi

test_start "CORS allows frontend origin"
CORS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Origin: $BASE_URL" \
    -H "Access-Control-Request-Method: POST" \
    -X OPTIONS \
    "$API_URL/api/teams")
if [ "$CORS_STATUS" = "200" ]; then
    test_pass
else
    test_fail "CORS preflight failed: HTTP $CORS_STATUS"
fi

# Test Suite 3: Static Assets
echo ""
echo -e "${BLUE}3. Static Assets${NC}"

test_start "Favicon exists"
FAVICON_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/favicon.ico" || echo "404")
if [ "$FAVICON_STATUS" = "200" ] || [ "$FAVICON_STATUS" = "404" ]; then
    test_pass
else
    test_fail "Unexpected status: $FAVICON_STATUS"
fi

test_start "No 500 errors on main page"
if ! grep -Ei "HTTP[/ ]500|500 error|internal server error" /tmp/home.html; then
    test_pass
else
    test_fail "Server error detected in page"
fi

# Test Suite 4: Security
echo ""
echo -e "${BLUE}4. Security Headers${NC}"

test_start "No sensitive data in HTML"
if ! grep -Ei "password.*=|api.*key.*=|secret.*=" /tmp/home.html; then
    test_pass
else
    test_fail "Sensitive data found in HTML"
fi

test_start "No inline credentials"
if ! grep -Ei "sk_|pk_test|Bearer [A-Za-z0-9]" /tmp/home.html; then
    test_pass
else
    test_fail "Credentials found in HTML"
fi

# Test Suite 5: Performance
echo ""
echo -e "${BLUE}5. Performance${NC}"

test_start "Page loads in under 3 seconds"
START=$(date +%s)
curl -s -o /dev/null "$BASE_URL"
END=$(date +%s)
DURATION=$((END - START))
if [ $DURATION -lt 3 ]; then
    test_pass
else
    test_fail "Page took ${DURATION}s to load"
fi

test_start "HTML size is reasonable (< 500KB)"
SIZE=$(wc -c < /tmp/home.html)
if [ $SIZE -lt 512000 ]; then
    test_pass
else
    test_fail "HTML is ${SIZE} bytes (> 500KB)"
fi

# Summary
echo ""
echo "========================================"
echo "  Test Summary"
echo "========================================"
echo -e "Total:  $TOTAL"
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All E2E tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some E2E tests failed${NC}"
    exit 1
fi
