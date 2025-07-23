#!/bin/bash
# Test script for user policy management endpoints

# Set base URL
BASE_URL="http://localhost:3000/api"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "Testing User Policy Management Endpoints"
echo "======================================="

# First, register a test user
echo -e "\n${GREEN}1. Registering test user...${NC}"
REGISTER_RESPONSE=$(curl -s -X POST $BASE_URL/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "policytest@example.com",
    "password": "testpass123",
    "display_name": "Policy Test User"
  }')

echo "Response: $REGISTER_RESPONSE"

# Login to get session token
echo -e "\n${GREEN}2. Logging in...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "policytest@example.com",
    "password": "testpass123"
  }')

SESSION_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.session_token')
echo "Session token: $SESSION_TOKEN"

# Get policy templates
echo -e "\n${GREEN}3. Getting policy templates...${NC}"
curl -s -X GET $BASE_URL/users/policies/templates \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# List policies (should be empty)
echo -e "\n${GREEN}4. Listing policies (should be empty)...${NC}"
curl -s -X GET $BASE_URL/users/policies \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Create a social media policy
echo -e "\n${GREEN}5. Creating a social media policy...${NC}"
CREATE_POLICY_RESPONSE=$(curl -s -X POST $BASE_URL/users/policies \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Social Media Policy",
    "permissions": [
      {
        "identifier": "sign_event:1",
        "permission_data": {"kind": 1, "description": "Short text notes"}
      },
      {
        "identifier": "sign_event:0",
        "permission_data": {"kind": 0, "description": "Profile metadata"}
      },
      {
        "identifier": "encrypt",
        "permission_data": {"description": "Encrypt messages"}
      },
      {
        "identifier": "decrypt",
        "permission_data": {"description": "Decrypt messages"}
      }
    ]
  }')

POLICY_ID=$(echo $CREATE_POLICY_RESPONSE | jq -r '.id')
echo "Created policy ID: $POLICY_ID"
echo "Full response: $CREATE_POLICY_RESPONSE" | jq .

# Get specific policy
echo -e "\n${GREEN}6. Getting specific policy...${NC}"
curl -s -X GET $BASE_URL/users/policies/$POLICY_ID \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Update policy name
echo -e "\n${GREEN}7. Updating policy name...${NC}"
curl -s -X PUT $BASE_URL/users/policies/$POLICY_ID \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Social Media Policy"
  }' | jq .

# List permissions for the policy
echo -e "\n${GREEN}8. Listing permissions for the policy...${NC}"
curl -s -X GET $BASE_URL/users/policies/$POLICY_ID/permissions \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Add a new permission
echo -e "\n${GREEN}9. Adding a new permission...${NC}"
curl -s -X POST $BASE_URL/users/policies/$POLICY_ID/permissions \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "sign_event:7",
    "permission_data": {"kind": 7, "description": "Reactions"}
  }' \
  -w "\nHTTP Status: %{http_code}\n"

# List permissions again
echo -e "\n${GREEN}10. Listing permissions after addition...${NC}"
curl -s -X GET $BASE_URL/users/policies/$POLICY_ID/permissions \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Create a read-only policy
echo -e "\n${GREEN}11. Creating a read-only policy...${NC}"
CREATE_READONLY_RESPONSE=$(curl -s -X POST $BASE_URL/users/policies \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Read-Only Policy",
    "permissions": [
      {
        "identifier": "get_public_key",
        "permission_data": {"description": "Get public key"}
      },
      {
        "identifier": "nip04_decrypt",
        "permission_data": {"description": "Decrypt DMs"}
      }
    ]
  }')

READONLY_POLICY_ID=$(echo $CREATE_READONLY_RESPONSE | jq -r '.id')
echo "Created read-only policy ID: $READONLY_POLICY_ID"

# List all policies
echo -e "\n${GREEN}12. Listing all policies...${NC}"
curl -s -X GET $BASE_URL/users/policies \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# Try to delete a policy (should succeed as no authorizations use it)
echo -e "\n${GREEN}13. Deleting read-only policy...${NC}"
curl -s -X DELETE $BASE_URL/users/policies/$READONLY_POLICY_ID \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -w "\nHTTP Status: %{http_code}\n"

# Final policy list
echo -e "\n${GREEN}14. Final policy list...${NC}"
curl -s -X GET $BASE_URL/users/policies \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

echo -e "\n${GREEN}Test completed!${NC}"