#!/bin/bash
# ABOUTME: End-to-end test for OAuth + Nostr client flow
# ABOUTME: Tests registration, OAuth authorization, and bunker URL retrieval for Nostr signing

set -e

API_BASE_URL="${API_BASE_URL:-http://localhost:3000}"
CLIENT_ID="nostr-web-client"
REDIRECT_URI="http://localhost:8000/callback"
SCOPE="sign_event"

echo "=========================================="
echo "Nostr OAuth Flow Test"
echo "=========================================="
echo "API Base URL: $API_BASE_URL"
echo "Client ID: $CLIENT_ID"
echo ""

# Step 1: Register a new user
echo "Step 1: Registering new user..."
EMAIL="nostr-test-$(date +%s)@example.com"
PASSWORD="testpass123"

REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")

echo "Register response: $REGISTER_RESPONSE"

# Extract JWT token
JWT_TOKEN=$(echo "$REGISTER_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 || echo "")

if [ -z "$JWT_TOKEN" ]; then
  echo "ERROR: Failed to get JWT token from registration"
  exit 1
fi

echo "✓ User registered successfully"
echo "  Email: $EMAIL"
echo "  JWT Token: ${JWT_TOKEN:0:20}..."
echo ""

# Step 2: Initiate OAuth authorization
echo "Step 2: User approving OAuth authorization..."
APPROVE_RESPONSE=$(curl -s -i -X POST "$API_BASE_URL/api/oauth/authorize" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=$JWT_TOKEN" \
  -d "{\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\",\"scope\":\"$SCOPE\",\"approved\":true}")

# Extract authorization code from Location header
AUTH_CODE=$(echo "$APPROVE_RESPONSE" | grep -i "location:" | grep -o "code=[^&[:space:]]*" | cut -d'=' -f2 | tr -d '\r\n')

if [ -z "$AUTH_CODE" ]; then
  echo "ERROR: Failed to get authorization code from redirect"
  echo "Full response:"
  echo "$APPROVE_RESPONSE"
  exit 1
fi

echo "✓ OAuth authorization approved"
echo "  Authorization Code: $AUTH_CODE"
echo ""

# Step 3: Exchange authorization code for bunker URL
echo "Step 3: Exchanging authorization code for bunker URL..."
TOKEN_RESPONSE=$(curl -s -X POST "$API_BASE_URL/api/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"$AUTH_CODE\",\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\"}")

echo "Token response: $TOKEN_RESPONSE"

# Extract bunker URL
BUNKER_URL=$(echo "$TOKEN_RESPONSE" | grep -o '"bunker_url":"[^"]*"' | cut -d'"' -f4)

if [ -z "$BUNKER_URL" ]; then
  echo "ERROR: Failed to get bunker URL from token response"
  exit 1
fi

echo "✓ Bunker URL obtained successfully"
echo "  Bunker URL: $BUNKER_URL"
echo ""

# Step 4: Validate bunker URL format for Nostr client use
echo "Step 4: Validating bunker URL for Nostr client..."

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

# Extract and validate pubkey from bunker URL
PUBKEY=$(echo "$BUNKER_URL" | grep -o "bunker://[0-9a-f]*" | cut -d'/' -f3)

if [ ${#PUBKEY} -ne 64 ]; then
  echo "ERROR: Invalid pubkey length (should be 64 hex characters)"
  exit 1
fi

echo "✓ Bunker URL format validated for Nostr client"
echo "  Public Key: $PUBKEY"
echo "  Format: bunker://{pubkey}?relay={relay}&secret={secret} ✓"
echo ""

# Step 5: Verify Nostr client can extract required information
echo "Step 5: Verifying Nostr client compatibility..."

# Extract relay URL
RELAY_URL=$(echo "$BUNKER_URL" | grep -o "relay=[^&]*" | cut -d'=' -f2)
echo "  Relay URL: $RELAY_URL"

# Extract secret
SECRET=$(echo "$BUNKER_URL" | grep -o "secret=.*" | cut -d'=' -f2)
echo "  Secret: ${SECRET:0:10}... (length: ${#SECRET})"

if [ -z "$RELAY_URL" ] || [ -z "$SECRET" ]; then
  echo "ERROR: Failed to extract relay URL or secret"
  exit 1
fi

echo "✓ All Nostr client requirements satisfied"
echo ""

echo "=========================================="
echo "✓ Nostr OAuth Flow Test PASSED!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  ✓ User registration successful"
echo "  ✓ OAuth authorization successful"
echo "  ✓ Bunker URL obtained"
echo "  ✓ Bunker URL format valid"
echo "  ✓ Nostr client can extract:"
echo "      - Public key: $PUBKEY"
echo "      - Relay URL: $RELAY_URL"
echo "      - Secret: ${SECRET:0:10}..."
echo ""
echo "Next steps:"
echo "  1. Open examples/nostr-client-oauth.html in a browser"
echo "  2. Configure API URL to $API_BASE_URL"
echo "  3. Register/Login and authorize"
echo "  4. Post a note to Nostr using remote signing!"
echo ""
