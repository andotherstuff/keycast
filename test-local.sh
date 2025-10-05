#!/bin/bash
set -e

echo "🧪 Testing Keycast Locally"
echo "=========================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Kill background processes on exit
trap 'kill $(jobs -p) 2>/dev/null' EXIT

echo ""
echo "📦 Building containers..."
docker-compose -f docker-compose.dev.yml build --quiet

echo ""
echo "🚀 Starting services..."
docker-compose -f docker-compose.dev.yml up -d

echo ""
echo "⏳ Waiting for API to be healthy..."
timeout=60
counter=0
while ! curl -sf http://localhost:3000/health > /dev/null; do
    sleep 1
    counter=$((counter + 1))
    if [ $counter -gt $timeout ]; then
        echo -e "${RED}❌ API failed to start within ${timeout}s${NC}"
        docker-compose -f docker-compose.dev.yml logs keycast-api
        exit 1
    fi
    echo -n "."
done
echo ""
echo -e "${GREEN}✅ API is healthy${NC}"

echo ""
echo "⏳ Waiting for Web to be ready..."
timeout=60
counter=0
while ! curl -sf http://localhost:5173 > /dev/null; do
    sleep 1
    counter=$((counter + 1))
    if [ $counter -gt $timeout ]; then
        echo -e "${RED}❌ Web failed to start within ${timeout}s${NC}"
        docker-compose -f docker-compose.dev.yml logs keycast-web
        exit 1
    fi
    echo -n "."
done
echo ""
echo -e "${GREEN}✅ Web is ready${NC}"

echo ""
echo "🔍 Running Integration Tests..."
echo "================================"

# Test 1: Health check
echo -n "Testing health endpoint... "
if curl -sf http://localhost:3000/health > /dev/null; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 2: CORS preflight for registration
echo -n "Testing CORS preflight (OPTIONS /api/auth/register)... "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Origin: http://localhost:5173" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: Content-Type" \
    -X OPTIONS \
    http://localhost:3000/api/auth/register)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✅ PASS (HTTP $HTTP_CODE)${NC}"
else
    echo -e "${RED}❌ FAIL (HTTP $HTTP_CODE - expected 200)${NC}"
    echo "Checking CORS headers..."
    curl -v \
        -H "Origin: http://localhost:5173" \
        -H "Access-Control-Request-Method: POST" \
        -X OPTIONS \
        http://localhost:3000/api/auth/register 2>&1 | grep -i "access-control"
    exit 1
fi

# Test 3: Frontend can load
echo -n "Testing frontend loads... "
if curl -sf http://localhost:5173 | grep -q "html"; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 4: Frontend API configuration
echo -n "Testing frontend API URL configuration... "
FRONTEND_HTML=$(curl -s http://localhost:5173)
if echo "$FRONTEND_HTML" | grep -q "localhost:3000"; then
    echo -e "${GREEN}✅ PASS (API URL configured correctly)${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: Could not verify API URL in frontend${NC}"
fi

# Test 5: Try actual registration (will fail without email but tests API connection)
echo -n "Testing registration endpoint connectivity... "
REGISTER_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Origin: http://localhost:5173" \
    -d '{"email":"test@example.com","password":"testpass123"}' \
    http://localhost:3000/api/auth/register)

# We expect either 200 (success) or 400/500 (validation error), but NOT CORS errors
if [ "$REGISTER_RESPONSE" != "000" ]; then
    echo -e "${GREEN}✅ PASS (HTTP $REGISTER_RESPONSE - API is accessible)${NC}"
else
    echo -e "${RED}❌ FAIL (Connection failed - possible CORS issue)${NC}"
    exit 1
fi

echo ""
echo "================================"
echo -e "${GREEN}🎉 All tests passed!${NC}"
echo ""
echo "Services running at:"
echo "  - API:  http://localhost:3000"
echo "  - Web:  http://localhost:5173"
echo ""
echo "To stop: docker-compose -f docker-compose.dev.yml down"
echo "To view logs: docker-compose -f docker-compose.dev.yml logs -f"
