#!/bin/bash

# ABOUTME: Test runner script for Keycast with proper environment setup
# ABOUTME: Runs all tests with proper formatting and output

set -e

echo "🧪 Running Keycast Test Suite..."
echo "================================="

# Navigate to project root
cd "$(dirname "$0")/.."

# Setup test environment
echo "🏗️  Setting up test environment..."
./scripts/setup-test-env.sh

echo ""
echo "🧪 Running unit tests..."
echo "========================"
cargo test --workspace --verbose

echo ""
echo "📋 Running code quality checks..."
echo "=================================="

# Check formatting
echo "🎨 Checking code formatting..."
cargo fmt --all -- --check

# Run clippy
echo "🔍 Running clippy lints..."
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Build release
echo "🏗️  Building release..."
cargo build --release --workspace

echo ""
echo "🎉 All tests passed!"
echo "===================="
echo ""
echo "📊 Test Summary:"
echo "  ✅ Unit tests: PASSED"
echo "  ✅ Code formatting: PASSED"
echo "  ✅ Clippy lints: PASSED"
echo "  ✅ Release build: PASSED"
echo ""
echo "🚀 Keycast is ready for production!"