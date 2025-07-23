#!/bin/bash
# Test script for user key management endpoints

# Set base URL
BASE_URL="http://localhost:3000/api"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "Testing User Key Management Endpoints"
echo "===================================="

# First, register a test user
echo -e "\n${GREEN}1. Registering test user...${NC}"
REGISTER_RESPONSE=$(curl -s -X POST $BASE_URL/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "keytest@example.com",
    "password": "testpass123",
    "display_name": "Key Test User"
  }')

echo "Response: $REGISTER_RESPONSE"

# Login to get session token
echo -e "\n${GREEN}2. Logging in...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "keytest@example.com",
    "password": "testpass123"
  }')

SESSION_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.session_token')
echo "Session token: $SESSION_TOKEN"

# List keys (should be empty initially)
echo -e "\n${GREEN}3. Listing keys (should be empty)...${NC}"
curl -s -X GET $BASE_URL/users/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Create a new key
echo -e "\n${GREEN}4. Creating a new key...${NC}"
CREATE_KEY_RESPONSE=$(curl -s -X POST $BASE_URL/users/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My First Key",
    "is_primary": true
  }')

KEY_ID=$(echo $CREATE_KEY_RESPONSE | jq -r '.id')
echo "Created key ID: $KEY_ID"
echo "Full response: $CREATE_KEY_RESPONSE" | jq .

# List keys again
echo -e "\n${GREEN}5. Listing keys (should have one key)...${NC}"
curl -s -X GET $BASE_URL/users/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Get specific key
echo -e "\n${GREEN}6. Getting specific key...${NC}"
curl -s -X GET $BASE_URL/users/keys/$KEY_ID \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Update key name
echo -e "\n${GREEN}7. Updating key name...${NC}"
curl -s -X PUT $BASE_URL/users/keys/$KEY_ID \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Updated Key"
  }' | jq .

# Create a second key
echo -e "\n${GREEN}8. Creating a second key...${NC}"
CREATE_KEY2_RESPONSE=$(curl -s -X POST $BASE_URL/users/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Second Key",
    "is_primary": false
  }')

KEY2_ID=$(echo $CREATE_KEY2_RESPONSE | jq -r '.id')
echo "Created second key ID: $KEY2_ID"

# List all keys
echo -e "\n${GREEN}9. Listing all keys...${NC}"
curl -s -X GET $BASE_URL/users/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Set second key as primary
echo -e "\n${GREEN}10. Setting second key as primary...${NC}"
curl -s -X POST $BASE_URL/users/keys/$KEY2_ID/set-primary \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# List keys to verify primary change
echo -e "\n${GREEN}11. Listing keys to verify primary change...${NC}"
curl -s -X GET $BASE_URL/users/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Rotate the first key
echo -e "\n${GREEN}12. Rotating the first key...${NC}"
ROTATE_RESPONSE=$(curl -s -X POST $BASE_URL/users/keys/$KEY_ID/rotate \
  -H "Authorization: Bearer $SESSION_TOKEN")

NEW_KEY_ID=$(echo $ROTATE_RESPONSE | jq -r '.new_key_id')
echo "New key ID after rotation: $NEW_KEY_ID"
echo "Full response: $ROTATE_RESPONSE" | jq .

# List keys after rotation
echo -e "\n${GREEN}13. Listing keys after rotation...${NC}"
curl -s -X GET $BASE_URL/users/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Delete the rotated key
echo -e "\n${GREEN}14. Deleting the rotated key...${NC}"
curl -s -X DELETE $BASE_URL/users/keys/$KEY_ID \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -w "\nHTTP Status: %{http_code}\n"

# Final key list
echo -e "\n${GREEN}15. Final key list...${NC}"
curl -s -X GET $BASE_URL/users/keys \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

echo -e "\n${GREEN}Test completed!${NC}"