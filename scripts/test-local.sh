#!/bin/bash
# ABOUTME: Local testing script for Keycast application
# ABOUTME: Runs health checks and basic functionality tests locally

set -e

echo "🧪 Starting Keycast Local Tests..."

# Check if master key exists
if [ ! -f "./master.key" ]; then
    echo "❌ Error: master.key not found. Run 'bun run key:generate' first"
    exit 1
fi

# Check if database exists
if [ ! -f "./database/keycast.db" ]; then
    echo "📁 Database not found. Creating new database..."
    bun run db:reset
fi

# Function to wait for service
wait_for_service() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=0
    
    echo "⏳ Waiting for $service on port $port..."
    while ! curl -s localhost:$port/health > /dev/null 2>&1; do
        if [ $attempt -eq $max_attempts ]; then
            echo "❌ $service failed to start after $max_attempts attempts"
            return 1
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    echo "✅ $service is ready"
}

# Start services in background
echo "🚀 Starting services..."

# Kill any existing processes
pkill -f "cargo.*keycast" || true
pkill -f "bun.*dev" || true

# Start API
cd api && RUST_LOG=debug cargo run &
API_PID=$!
cd ..

# Start web
cd web && bun run dev &
WEB_PID=$!
cd ..

# Start signer
RUST_LOG=warn,keycast_signer=debug MASTER_KEY_PATH=./master.key cargo run --bin keycast_signer &
SIGNER_PID=$!

# Trap to cleanup on exit
trap "kill $API_PID $WEB_PID $SIGNER_PID 2>/dev/null || true" EXIT

# Wait for services
wait_for_service "API" 3000
wait_for_service "Web" 5173

echo ""
echo "🧪 Running health checks..."

# API health check
echo -n "API Health: "
curl -s localhost:3000/health || echo "❌ Failed"

# Web health check  
echo -n "Web Health: "
curl -s localhost:5173/health || echo "❌ Failed"

echo ""
echo "🧪 Running basic API tests..."

# Test API endpoints
echo -n "Teams endpoint: "
response=$(curl -s -o /dev/null -w "%{http_code}" localhost:3000/api/teams)
if [ "$response" = "200" ] || [ "$response" = "401" ]; then
    echo "✅ OK ($response)"
else
    echo "❌ Failed ($response)"
fi

echo ""
echo "📊 Test Summary:"
echo "- API: http://localhost:3000"
echo "- Web: http://localhost:5173"
echo "- Signer: Running in background"
echo ""
echo "Press Ctrl+C to stop all services"

# Keep script running
wait