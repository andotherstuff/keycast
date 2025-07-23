# Keycast Testing Guide

**Last Updated**: July 23, 2025  
**Test Coverage**: ~30% (Unit tests for core components)

## Overview

This guide documents the testing strategy, tools, and practices for the Keycast personal authentication system. Following Test-Driven Development (TDD) principles, we aim for comprehensive test coverage across all components.

## Test Structure

### Unit Tests
Unit tests are embedded within source files using `#[cfg(test)]` modules.

**Location**: Within each source file  
**Pattern**:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_something() {
        // test implementation
    }
}
```

### Integration Tests
Integration tests live in the `tests/` directory of each crate.

**Location**: `api/tests/`, `core/tests/`, etc.  
**Pattern**: Separate files for each module being tested

### Manual Test Scripts
Shell scripts for testing API endpoints manually.

**Location**: Repository root  
**Files**:
- `test_user_keys.sh` - User key management endpoints
- `test_user_policies.sh` - Policy management endpoints  
- `test_applications.sh` - Application management endpoints
- `test_run_api.sh` - Run automated API tests

## Testing Tools

### Required Dependencies
Add to `[dev-dependencies]` in Cargo.toml:
```toml
[dev-dependencies]
hyper = { version = "1.0", features = ["full"] }
tower = { version = "0.4", features = ["util"] }
```

### Database Setup
Tests use in-memory SQLite databases for isolation:
```rust
async fn setup_test_db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");
    
    // Run migrations or create tables
    // ...
    
    pool
}
```

### Environment Variables
- `DATABASE_URL` - Not required for tests (use in-memory)
- `RUST_LOG` - Set to "warn" for cleaner test output

## Test Categories

### 1. Database Tests
Test database operations and schema integrity.

**Example**: `core/src/types/authorization.rs`
```rust
#[tokio::test]
async fn test_authorization_create() {
    let pool = setup_test_db().await;
    // Test authorization creation
}
```

### 2. API Endpoint Tests
Test HTTP endpoints with various scenarios.

**Example**: `api/src/api/http/applications.rs`
```rust
#[tokio::test]
async fn test_list_applications_empty() {
    let pool = setup_test_db().await;
    // Test empty application list
}
```

### 3. Business Logic Tests
Test core business logic and services.

**Example**: Authorization flow service tests
```rust
#[tokio::test]
async fn test_approve_request_success() {
    let pool = setup_test_db().await;
    let service = AuthorizationFlowService::new(pool);
    // Test approval logic
}
```

### 4. Error Handling Tests
Test error scenarios and edge cases.

**Example**: Invalid input handling
```rust
#[tokio::test]
async fn test_invalid_uuid_format() {
    // Test handling of malformed UUIDs
}
```

## Writing Tests

### TDD Workflow
1. **Write a failing test** that describes desired behavior
2. **Run the test** to confirm it fails
3. **Write minimal code** to make the test pass
4. **Run the test** to confirm it passes
5. **Refactor** while keeping tests green
6. **Repeat** for each new feature

### Test Naming Convention
Use descriptive names that explain what is being tested:
- `test_<function>_<scenario>_<expected_result>`
- Examples:
  - `test_list_applications_empty`
  - `test_approve_request_not_found`
  - `test_revoke_authorization_success`

### Test Data Helpers
Create helper functions for common test data:
```rust
async fn create_test_user(pool: &SqlitePool) -> Uuid {
    // Create and return test user
}

async fn create_test_app(pool: &SqlitePool, domain: &str) -> Application {
    // Create and return test application
}
```

### Assertions
Use clear, specific assertions:
```rust
assert_eq!(result.len(), 3, "Expected 3 items");
assert!(result.is_err(), "Should fail with invalid input");
assert_eq!(response.status(), StatusCode::NOT_FOUND);
```

## Running Tests

### All Tests
```bash
cargo test
```

### Specific Crate
```bash
cargo test --package keycast_api
```

### Specific Module
```bash
cargo test --lib applications::tests
```

### Single Test
```bash
cargo test test_list_applications_empty
```

### With Output
```bash
cargo test -- --nocapture
```

### Parallel Execution
```bash
cargo test -- --test-threads=4
```

## Test Coverage

### Current Coverage (~30%)
- ✅ Application management endpoints
- ✅ Authorization request validation
- ✅ Basic database operations
- ✅ Error handling for invalid inputs

### Missing Coverage (70%)
- ❌ User key management full coverage
- ❌ Policy evaluation logic
- ❌ Session management
- ❌ Frontend components
- ❌ Integration tests
- ❌ End-to-end tests

## Best Practices

### 1. Test Isolation
Each test should be independent:
- Use fresh database for each test
- Don't rely on test execution order
- Clean up resources after tests

### 2. Realistic Test Data
Use realistic data that matches production:
- Valid UUIDs for IDs
- Proper email formats
- Realistic domain names

### 3. Edge Cases
Always test edge cases:
- Empty lists/results
- Maximum values
- Invalid inputs
- Concurrent operations

### 4. Performance
Keep tests fast:
- Use in-memory databases
- Minimize I/O operations
- Parallelize when possible

### 5. Documentation
Document complex test scenarios:
```rust
// Test that a user cannot approve another user's authorization request
// This ensures proper access control
#[tokio::test]
async fn test_cannot_approve_other_users_request() {
    // ...
}
```

## Troubleshooting

### SQLx Compilation Errors
If you see "set DATABASE_URL to use query macros":
1. Use `query_as` instead of `query!` macro
2. Or set: `export DATABASE_URL=sqlite:keycast.db`

### Async Test Issues
Ensure proper tokio runtime:
```rust
#[tokio::test]
async fn test_async_operation() {
    // test code
}
```

### Database Lock Errors
Use separate in-memory databases for each test to avoid locks.

## CI/CD Integration

### GitHub Actions (Future)
```yaml
- name: Run tests
  run: |
    cargo test --all-features
    cargo test --doc
```

### Pre-commit Hooks (Future)
```bash
#!/bin/bash
cargo test --quiet
```

## Next Steps

1. **Increase Coverage**: Target 80% test coverage
2. **Integration Tests**: Create full API integration tests
3. **E2E Tests**: Add end-to-end user flow tests
4. **Performance Tests**: Add benchmarks for critical paths
5. **CI Pipeline**: Automate test execution

## Resources

- [Rust Testing Book](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Tokio Testing](https://tokio.rs/tokio/topics/testing)
- [SQLx Testing](https://github.com/launchbadge/sqlx#testing)
- [Axum Testing](https://docs.rs/axum-test/latest/axum_test/)