#!/bin/bash

# ABOUTME: Setup script for test environment with database and master key
# ABOUTME: Run this before running tests to ensure proper test infrastructure

set -e

echo "🧪 Setting up test environment for Keycast..."

# Navigate to project root
cd "$(dirname "$0")/.."

# Generate master key if it doesn't exist
if [ ! -f "master.key" ]; then
    echo "🔑 Generating master key..."
    ./scripts/generate_key.sh
else
    echo "✅ Master key already exists"
fi

# Create test database
TEST_DB_PATH="database/keycast_test.db"
MIGRATIONS_PATH="database/migrations"

echo "📊 Setting up test database..."

# Remove existing test database
if [ -f "$TEST_DB_PATH" ]; then
    echo "🗑️  Removing existing test database..."
    rm -f "$TEST_DB_PATH"
    rm -f "${TEST_DB_PATH}-shm"
    rm -f "${TEST_DB_PATH}-wal"
fi

# Create test database and run migrations
echo "🏗️  Creating test database and running migrations..."
sqlite3 "$TEST_DB_PATH" < "$MIGRATIONS_PATH/0001_initial.sql"

# Set permissions
chmod 644 "$TEST_DB_PATH"

echo "✅ Test database created at $TEST_DB_PATH"

# Create test environment variables
echo "📝 Creating test environment configuration..."
cat > .env.test << EOF
# Test environment configuration
DATABASE_URL=sqlite:../database/keycast_test.db
USE_GCP_KMS=false
AUTH_ID=1

# For tests that need GCP KMS (will be skipped if not available)
GCP_PROJECT_ID=openvine-co
GCP_KMS_LOCATION=global
GCP_KMS_KEY_RING=keycast-keys
GCP_KMS_KEY_NAME=master-key
EOF

echo "✅ Test environment configuration created at .env.test"

echo ""
echo "🎉 Test environment setup complete!"
echo ""
echo "📋 To run tests:"
echo "   cargo test --workspace"
echo ""
echo "📋 To run specific test:"
echo "   cargo test test_name"
echo ""
echo "📋 To run tests with output:"
echo "   cargo test --workspace -- --nocapture"
echo ""
echo "🔧 Files created:"
echo "   - master.key (if not existed)"
echo "   - database/keycast_test.db"
echo "   - .env.test"