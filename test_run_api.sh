#!/bin/bash

# Script to run API tests with proper setup

echo "Running API Tests"
echo "================="

# Set environment variables
export DATABASE_URL="sqlite::memory:"
export RUST_LOG="warn"

# Navigate to API directory
cd /root/repo/api

# Run specific test module
echo "Running application management tests..."
cargo test --lib applications::tests -- --nocapture 2>&1 | tail -20

echo ""
echo "Running authorization request tests..."
cargo test --lib authorization_requests::tests -- --nocapture 2>&1 | tail -20

echo ""
echo "Test run complete!"