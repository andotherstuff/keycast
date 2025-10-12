#!/bin/bash
# ABOUTME: End-to-end test script for OAuth flow using real HTTP requests
# ABOUTME: Simulates an external OAuth client application interacting with the API

set -e

API_BASE_URL="${API_BASE_URL:-http://localhost:3000}"
CLIENT_ID="e2e_test_app"
REDIRECT_URI="http://localhost:8888/callback"
SCOPE="sign_event encrypt decrypt"

echo "=== Starting OAuth E2E Test ==="
echo "API Base URL: $API_BASE_URL"
echo ""

# Step 1: Register a new user
echo "Step 1: Registering a new user..."
REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"oauth-test-$(date +%s)@example.com\",\"password\":\"testpass123\"}")

echo "Register response: $REGISTER_RESPONSE"

# Extract JWT token (if provided)
JWT_TOKEN=$(echo "$REGISTER_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 || echo "")

if [ -z "$JWT_TOKEN" ]; then
  echo "ERROR: Failed to get JWT token from registration"
  exit 1
fi

echo "✓ User registered successfully"
echo ""

# Step 2: Simulate OAuth authorization (POST directly to approve)
echo "Step 2: User approving OAuth authorization..."
APPROVE_RESPONSE=$(curl -s -i -X POST "$API_BASE_URL/oauth/authorize" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=$JWT_TOKEN" \
  -d "{\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\",\"scope\":\"$SCOPE\",\"approved\":true}")

echo "$APPROVE_RESPONSE" | head -20

# Extract authorization code from Location header
AUTH_CODE=$(echo "$APPROVE_RESPONSE" | grep -i "location:" | grep -o "code=[^&[:space:]]*" | cut -d'=' -f2 | tr -d '\r\n')

if [ -z "$AUTH_CODE" ]; then
  echo "ERROR: Failed to get authorization code from redirect"
  echo "Full response:"
  echo "$APPROVE_RESPONSE"
  exit 1
fi

echo "✓ Authorization code obtained: $AUTH_CODE"
echo ""

# Step 3: Exchange authorization code for bunker URL
echo "Step 3: Exchanging authorization code for bunker URL..."
TOKEN_RESPONSE=$(curl -s -X POST "$API_BASE_URL/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"$AUTH_CODE\",\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\"}")

echo "Token response: $TOKEN_RESPONSE"

# Extract bunker URL
BUNKER_URL=$(echo "$TOKEN_RESPONSE" | grep -o '"bunker_url":"[^"]*"' | cut -d'"' -f4)

if [ -z "$BUNKER_URL" ]; then
  echo "ERROR: Failed to get bunker URL from token response"
  exit 1
fi

echo "✓ Bunker URL obtained: $BUNKER_URL"
echo ""

# Validate bunker URL format
if [[ ! "$BUNKER_URL" =~ ^bunker:// ]]; then
  echo "ERROR: Invalid bunker URL format (should start with bunker://)"
  exit 1
fi

if [[ ! "$BUNKER_URL" =~ relay= ]]; then
  echo "ERROR: Bunker URL missing relay parameter"
  exit 1
fi

if [[ ! "$BUNKER_URL" =~ secret= ]]; then
  echo "ERROR: Bunker URL missing secret parameter"
  exit 1
fi

echo "✓ Bunker URL format validated"
echo ""

# Step 4: Verify code cannot be reused
echo "Step 4: Verifying authorization code cannot be reused..."
REUSE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE_URL/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"$AUTH_CODE\",\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\"}")

HTTP_CODE=$(echo "$REUSE_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$REUSE_RESPONSE" | head -n-1)

if [ "$HTTP_CODE" != "401" ]; then
  echo "ERROR: Expected 401 Unauthorized when reusing code, got $HTTP_CODE"
  echo "Response: $RESPONSE_BODY"
  exit 1
fi

echo "✓ Authorization code correctly rejected on reuse"
echo ""

# Step 5: Test denial flow
echo "Step 5: Testing OAuth denial flow..."
DENY_RESPONSE=$(curl -s -i -X POST "$API_BASE_URL/oauth/authorize" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=$JWT_TOKEN" \
  -d "{\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\",\"scope\":\"$SCOPE\",\"approved\":false}")

DENY_LOCATION=$(echo "$DENY_RESPONSE" | grep -i "location:" | grep -o "error=[^&[:space:]]*" | cut -d'=' -f2 | tr -d '\r\n')

if [ "$DENY_LOCATION" != "access_denied" ]; then
  echo "ERROR: Expected 'access_denied' error in redirect, got: $DENY_LOCATION"
  exit 1
fi

echo "✓ Denial flow working correctly"
echo ""

# Step 6: Test invalid redirect_uri
echo "Step 6: Testing redirect URI validation..."

# First, get a valid code
APPROVE2_RESPONSE=$(curl -s -i -X POST "$API_BASE_URL/oauth/authorize" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=$JWT_TOKEN" \
  -d "{\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\",\"scope\":\"$SCOPE\",\"approved\":true}")

AUTH_CODE2=$(echo "$APPROVE2_RESPONSE" | grep -i "location:" | grep -o "code=[^&[:space:]]*" | cut -d'=' -f2 | tr -d '\r\n')

# Try to use it with wrong redirect_uri
WRONG_URI_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE_URL/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"$AUTH_CODE2\",\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"http://evil.com/callback\"}")

HTTP_CODE2=$(echo "$WRONG_URI_RESPONSE" | tail -n1)

if [ "$HTTP_CODE2" != "400" ]; then
  echo "ERROR: Expected 400 Bad Request for mismatched redirect_uri, got $HTTP_CODE2"
  exit 1
fi

echo "✓ Redirect URI validation working correctly"
echo ""

echo "=== All OAuth E2E Tests Passed Successfully! ==="
