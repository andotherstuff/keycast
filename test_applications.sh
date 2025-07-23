#!/bin/bash

# Test script for application management endpoints

API_BASE="http://localhost:8080/api"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Testing Application Management Endpoints${NC}"
echo "========================================"

# First, we need to be logged in
echo -e "\n${YELLOW}1. Logging in...${NC}"
SESSION_COOKIE=$(curl -s -c - -X POST "$API_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "test@example.com", "password": "password123"}' | grep session | awk '{print $7}')

if [ -z "$SESSION_COOKIE" ]; then
    echo -e "${RED}Failed to login. Make sure you have a test user.${NC}"
    exit 1
fi

echo -e "${GREEN}Login successful${NC}"

# Test 1: List all applications (public endpoint)
echo -e "\n${YELLOW}2. List all applications (public)${NC}"
echo "Request: GET /api/applications"
RESPONSE=$(curl -s -X GET "$API_BASE/applications")
echo "Response: $RESPONSE"

# Test 2: List applications with pagination
echo -e "\n${YELLOW}3. List applications with pagination${NC}"
echo "Request: GET /api/applications?page=1&per_page=10"
RESPONSE=$(curl -s -X GET "$API_BASE/applications?page=1&per_page=10")
echo "Response: $RESPONSE"

# Test 3: List only verified applications
echo -e "\n${YELLOW}4. List only verified applications${NC}"
echo "Request: GET /api/applications?verified_only=true"
RESPONSE=$(curl -s -X GET "$API_BASE/applications?verified_only=true")
echo "Response: $RESPONSE"

# Test 4: Get specific application (if any exist)
echo -e "\n${YELLOW}5. Get specific application${NC}"
# First get an app ID if available
APP_ID=$(curl -s -X GET "$API_BASE/applications" | jq -r '.applications[0].id // empty')
if [ -n "$APP_ID" ]; then
    echo "Request: GET /api/applications/$APP_ID"
    RESPONSE=$(curl -s -X GET "$API_BASE/applications/$APP_ID")
    echo "Response: $RESPONSE"
else
    echo "No applications found to test with"
fi

# Test 5: List user's connected applications
echo -e "\n${YELLOW}6. List user's connected applications${NC}"
echo "Request: GET /api/users/applications"
RESPONSE=$(curl -s -X GET "$API_BASE/users/applications" \
    -H "Cookie: session=$SESSION_COOKIE")
echo "Response: $RESPONSE"

# Test 6: Get specific user application (if any exist)
echo -e "\n${YELLOW}7. Get specific user application${NC}"
USER_APP_ID=$(curl -s -X GET "$API_BASE/users/applications" \
    -H "Cookie: session=$SESSION_COOKIE" | jq -r '.[0].app.id // empty')
if [ -n "$USER_APP_ID" ]; then
    echo "Request: GET /api/users/applications/$USER_APP_ID"
    RESPONSE=$(curl -s -X GET "$API_BASE/users/applications/$USER_APP_ID" \
        -H "Cookie: session=$SESSION_COOKIE")
    echo "Response: $RESPONSE"
else
    echo "No user applications found to test with"
fi

# Test 7: Try to verify an application (should fail - admin only)
echo -e "\n${YELLOW}8. Try to verify application (admin only - should fail)${NC}"
if [ -n "$APP_ID" ]; then
    echo "Request: PUT /api/applications/$APP_ID/verify"
    RESPONSE=$(curl -s -X PUT "$API_BASE/applications/$APP_ID/verify" \
        -H "Content-Type: application/json" \
        -H "Cookie: session=$SESSION_COOKIE" \
        -d '{"verified": true}' \
        -w "\nHTTP Status: %{http_code}")
    echo "Response: $RESPONSE"
else
    echo "No applications found to test with"
fi

# Test 8: Revoke app authorizations (if user has any)
echo -e "\n${YELLOW}9. Revoke app authorizations${NC}"
if [ -n "$USER_APP_ID" ]; then
    echo "Request: DELETE /api/users/applications/$USER_APP_ID/revoke"
    RESPONSE=$(curl -s -X DELETE "$API_BASE/users/applications/$USER_APP_ID/revoke" \
        -H "Cookie: session=$SESSION_COOKIE" \
        -w "\nHTTP Status: %{http_code}")
    echo "Response: $RESPONSE"
    
    # Verify it was revoked
    echo -e "\n${YELLOW}10. Verify app was revoked${NC}"
    RESPONSE=$(curl -s -X GET "$API_BASE/users/applications" \
        -H "Cookie: session=$SESSION_COOKIE")
    echo "Response: $RESPONSE"
else
    echo "No user applications found to test with"
fi

echo -e "\n${GREEN}Application endpoint tests completed!${NC}"

# Note about creating test data
echo -e "\n${YELLOW}Note:${NC} To fully test these endpoints, you need:"
echo "1. Some applications registered in the database"
echo "2. Some authorizations for the test user"
echo "3. You can create these using the authorization flow"