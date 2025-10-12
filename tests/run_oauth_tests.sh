#!/bin/bash
# ABOUTME: Test runner script that runs OAuth tests serially to avoid global state conflicts
# ABOUTME: Runs unit tests, integration tests individually, and provides a summary

echo "=========================================="
echo "Running OAuth Test Suite"
echo "=========================================="
echo ""

FAILED_TESTS=()
PASSED_TESTS=()
TOTAL=0
FAILED=0

# Run unit tests (these can run in parallel)
echo "1. Running OAuth Unit Tests..."
TOTAL=$((TOTAL + 1))
if cargo test --test oauth_unit_test 2>&1 | grep -q "test result: ok"; then
    echo "   ✓ OAuth unit tests passed"
    PASSED_TESTS+=("oauth_unit_test")
else
    echo "   ✗ OAuth unit tests failed"
    FAILED_TESTS+=("oauth_unit_test")
    FAILED=$((FAILED + 1))
fi
echo ""

# Run existing integration tests
echo "2. Running OAuth Integration Tests (existing)..."
TOTAL=$((TOTAL + 1))
if cargo test --test oauth_test 2>&1 | grep -q "test result: ok"; then
    echo "   ✓ OAuth integration tests passed"
    PASSED_TESTS+=("oauth_test")
else
    echo "   ✗ OAuth integration tests failed"
    FAILED_TESTS+=("oauth_test")
    FAILED=$((FAILED + 1))
fi
echo ""

# Run new integration tests serially (to avoid KEYCAST_STATE conflicts)
echo "3. Running OAuth Integration Tests (new) - serial execution..."

# Get list of test names
TESTS=$(cargo test --test oauth_integration_test -- --list 2>/dev/null | grep '^test ' | awk '{print $2}' | sed 's/:$//')

for TEST_NAME in $TESTS; do
    echo -n "   Testing $TEST_NAME... "
    TOTAL=$((TOTAL + 1))
    if cargo test --test oauth_integration_test "$TEST_NAME" 2>&1 | grep -q "test result: ok"; then
        echo "✓"
        PASSED_TESTS+=("$TEST_NAME")
    else
        echo "✗"
        FAILED_TESTS+=("$TEST_NAME")
        FAILED=$((FAILED + 1))
    fi
done
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
PASSED=$((TOTAL - FAILED))
echo "Total test suites: $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -gt 0 ]; then
    echo "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
    echo ""
    exit 1
else
    echo "✓ All OAuth test suites passed!"
    echo ""
    exit 0
fi
