#!/bin/bash
# ABOUTME: Quick local test without Docker or complex setup
# ABOUTME: Useful for rapid iteration during development

set -e

echo "🚀 Quick Local Test"
echo ""

# Check prerequisites
if [ ! -f "./master.key" ]; then
    echo "Generating master key..."
    bun run key:generate
fi

# Check if SQLx is installed
if ! command -v sqlx &> /dev/null; then
    echo "⚠️  SQLx CLI not found"
    echo "To install: cargo install sqlx-cli --no-default-features --features rustls,sqlite"
    echo ""
    echo "Skipping database setup..."
else
    # Initialize database if needed
    if [ ! -f "./database/keycast.db" ]; then
        echo "Creating database..."
        mkdir -p database
        touch database/keycast.db
        sqlx database create --database-url sqlite:./database/keycast.db || true
        sqlx migrate run --database-url sqlite:./database/keycast.db --source ./database/migrations || true
    fi
fi

echo ""
echo "📊 Current Setup:"
echo "- Master key: $(if [ -f "./master.key" ]; then echo "✅ Found"; else echo "❌ Missing"; fi)"
echo "- Database: $(if [ -f "./database/keycast.db" ]; then echo "✅ Found"; else echo "❌ Missing"; fi)"
echo "- Node modules: $(if [ -d "./web/node_modules" ]; then echo "✅ Installed"; else echo "❌ Not installed"; fi)"
echo ""

# Install web dependencies if needed
if [ ! -d "./web/node_modules" ]; then
    echo "Installing web dependencies..."
    cd web && bun install --ignore-scripts && cd ..
fi

echo "✅ Local environment ready!"
echo ""
echo "To run services:"
echo "  API:    cd api && cargo run"
echo "  Web:    cd web && bun run dev"
echo "  Signer: MASTER_KEY_PATH=./master.key cargo run --bin keycast_signer"