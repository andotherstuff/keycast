#!/bin/bash
# ABOUTME: Script to cleanly restart Keycast API and signer daemon services
# ABOUTME: Kills existing processes, rebuilds if needed, and starts fresh instances

set -e

echo "🛑 Stopping all Keycast services..."

# Kill all cargo run processes related to keycast
pkill -f "cargo run.*keycast" || true
sleep 2

# Kill any remaining processes on ports 3000 and 8000
lsof -ti:3000 | xargs kill -9 2>/dev/null || true
sleep 1

echo "✅ Services stopped"
echo ""

# Navigate to project root
cd "$(dirname "$0")"

echo "🔨 Building API..."
cd api
cargo build --quiet --release 2>&1 | grep -v "^warning:" || true
cd ..

echo "🔨 Building signer..."
cd signer
cargo build --quiet --release 2>&1 | grep -v "^warning:" || true
cd ..

echo "✅ Build complete"
echo ""

echo "🚀 Starting API server..."
cd api
cargo run --quiet --release 2>&1 &
API_PID=$!
cd ..

sleep 3

echo "🚀 Starting signer daemon..."
cd signer
cargo run --quiet --release 2>&1 &
SIGNER_PID=$!
cd ..

sleep 5

echo "🚀 Starting HTTP server for examples..."
cd examples
python3 -m http.server 8000 2>&1 &
HTTP_PID=$!
cd ..

echo ""
echo "================================================"
echo "✅ All services started!"
echo "  API:     http://localhost:3000 (PID: $API_PID)"
echo "  Signer:  Running (PID: $SIGNER_PID)"
echo "  Examples: http://localhost:8000 (PID: $HTTP_PID)"
echo "================================================"
echo ""
echo "Test page: http://localhost:8000/keycast-test-bundled.html"
echo ""
echo "To stop services: pkill -f 'cargo run.*keycast' && lsof -ti:8000 | xargs kill"
