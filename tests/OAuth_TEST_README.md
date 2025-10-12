# OAuth Testing Suite

Complete testing framework for the Keycast OAuth 2.0 authorization flow.

## Test Structure

### 1. Unit Tests (`api/tests/oauth_unit_test.rs`)
Tests individual components and logic:
- ✓ Authorization code format validation (32 alphanumeric characters)
- ✓ Bunker secret format validation
- ✓ Bunker URL format validation
- ✓ Authorization code expiration logic
- ✓ One-time use enforcement for authorization codes
- ✓ Redirect URI validation
- ✓ Multiple authorizations per user support

**Run with:**
```bash
cargo test --test oauth_unit_test
```

### 2. Integration Tests - Original (`api/tests/oauth_test.rs`)
Tests the complete OAuth flow:
- ✓ Full authorization flow (register → authorize → approve → exchange for bunker URL)
- ✓ Authorization without login handling
- ✓ Invalid authorization code rejection

**Run with:**
```bash
cargo test --test oauth_test
```

### 3. Integration Tests - Extended (`api/tests/oauth_integration_test.rs`)
Tests edge cases and error handling:
- ✓ User denial flow
- ✓ Redirect URI mismatch detection
- ✓ Authorization code single-use enforcement
- ✓ Multiple OAuth applications per user
- ✓ Different OAuth scopes

**Run with (serial execution recommended):**
```bash
cargo test --test oauth_integration_test -- --test-threads=1
```

### 4. End-to-End Test Script (`tests/e2e_oauth_test.sh`)
Shell script that simulates a real external OAuth client:
- Registers a user via HTTP API
- Initiates OAuth authorization
- Exchanges code for bunker URL
- Validates bunker URL format
- Tests code reuse prevention
- Tests denial flow
- Tests redirect URI validation

**Run with:**
```bash
export API_BASE_URL=http://localhost:3000  # or your API URL
./tests/e2e_oauth_test.sh
```

### 5. Interactive HTML Test Client (`examples/oauth-test-client.html`)
Beautiful web interface for manual OAuth testing:
- User registration
- OAuth flow visualization
- Manual approve/deny buttons
- Automatic full flow simulation
- Bunker URL display

**Run with:**
```bash
# Start your API server first
cd examples
python3 -m http.server 8000
# Then open http://localhost:8000/oauth-test-client.html
```

## Running All Tests

### Quick Test (Recommended)
```bash
cargo test oauth
```

Or run specific test suites:
```bash
cargo test --test oauth_unit_test
cargo test --test oauth_test
cargo test --test oauth_integration_test
```

All tests can now run in parallel without conflicts!

## Test Coverage

The OAuth test suite covers:

### Security & Validation
- ✓ Authorization code expiration (10-minute lifetime)
- ✓ One-time use enforcement for codes
- ✓ Redirect URI validation
- ✓ Invalid code rejection
- ✓ Expired code rejection

### Flow Variations
- ✓ User approval flow
- ✓ User denial flow
- ✓ Multiple applications per user
- ✓ Different OAuth scopes (sign_event, encrypt, decrypt)

### Output Validation
- ✓ Bunker URL format (`bunker://` protocol)
- ✓ Bunker URL includes relay parameter
- ✓ Bunker URL includes secret parameter
- ✓ Database authorization records created correctly

### Error Handling
- ✓ Missing/invalid authorization codes
- ✓ Redirect URI mismatches
- ✓ Attempting to reuse authorization codes
- ✓ Unauthorized access attempts

## OAuth Flow Diagram

```
┌─────────────┐                                    ┌──────────────┐
│   Client    │                                    │   Keycast    │
│  (Web App)  │                                    │     API      │
└──────┬──────┘                                    └──────┬───────┘
       │                                                  │
       │  1. GET /oauth/authorize?client_id=...          │
       │ ─────────────────────────────────────────────>  │
       │                                                  │
       │  2. Returns authorization page                  │
       │ <─────────────────────────────────────────────  │
       │                                                  │
       │  3. POST /oauth/authorize (approved=true)       │
       │ ─────────────────────────────────────────────>  │
       │                                                  │
       │  4. Redirect with authorization code            │
       │ <─────────────────────────────────────────────  │
       │     (redirect_uri?code=XXXXXXX)                 │
       │                                                  │
       │  5. POST /oauth/token (code=XXXXXXX)            │
       │ ─────────────────────────────────────────────>  │
       │                                                  │
       │  6. Returns bunker URL                          │
       │ <─────────────────────────────────────────────  │
       │     { "bunker_url": "bunker://..." }            │
       │                                                  │
```

## Development

### Adding New Tests

**Unit Tests:**
Add to `api/tests/oauth_unit_test.rs` for testing individual functions or logic.

**Integration Tests:**
Add to `api/tests/oauth_integration_test.rs` for testing HTTP endpoints and full flows.

**E2E Tests:**
Extend `tests/e2e_oauth_test.sh` for testing against a running server.

### Common Issues

**Database Initialization:**
All tests use in-memory SQLite databases that are created fresh for each test. Make sure migrations are run in test setup.

**KeycastState Initialization:**
Tests create their own state instances and pass them to the routes function:
```rust
let key_manager = Box::new(TestKeyManager::new());
let state = Arc::new(KeycastState { db: pool.clone(), key_manager });
let app = keycast_api::api::http::routes::routes(pool, state);
```

This ensures each test has isolated state with no global conflicts.

## Test Results Summary

**Total Test Count:** 15 tests across 3 test suites

- **Unit Tests:** 7 tests ✓
- **Integration Tests (Original):** 3 tests ✓
- **Integration Tests (Extended):** 5 tests ✓
- **E2E Script:** 6 validation checks ✓
- **Interactive HTML Client:** Manual testing ✓

All tests passing! ✨
