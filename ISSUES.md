# Keycast Production Readiness Issues

## Summary
- 7 CRITICAL issues
- 8 HIGH issues
- 9 MEDIUM issues
- 2 LOW issues

---

## CRITICAL Issues

### ✅ 1. Frontend API URL Configuration (FIXED)
**Status:** Fixed in cloudbuild.yaml
- Added `--build-arg VITE_DOMAIN=https://oauth.divine.video`

### ✅ 2. CORS Hardcoded (FIXED)
**Status:** Fixed in api/src/main.rs
- Now reads from `CORS_ALLOWED_ORIGIN` environment variable

### ✅ 3. No Deployment Smoke Tests (FIXED)
**Status:** Added to cloudbuild.yaml
- Tests health endpoint
- Tests CORS preflight

### ⏳ 4. Build Compilation Errors
**Status:** In progress
- Need to diagnose Cloud Build step 0 failure

### ✅ 5. No Integration Tests (FIXED)
**Status:** Fixed
**Location:** `tests/integration/test-api.sh`
- ✅ Created comprehensive integration test suite (10 tests)
- ✅ Tests health, CORS, authentication, API structure, security
- ✅ Works against local and production environments
- ✅ All tests passing

### ✅ 6. No End-to-End Tests (FIXED)
**Status:** Fixed
**Location:** `tests/e2e/test-frontend.sh`
- ✅ Created E2E test suite (11 tests)
- ✅ Tests page loading, API integration, assets, security, performance
- ✅ Works against local environments
- ✅ All tests passing locally

### ❌ 7. Build Args Not Passed Correctly
**Status:** Partially fixed
**Notes:** Still debugging Cloud Build failures

---

## HIGH Priority Issues

### ✅ 8. No Structured Logging for Production (FIXED)
**Status:** Fixed in api/src/main.rs:31-58
**Changes:**
- ✅ Added JSON logging for production (NODE_ENV=production)
- ✅ Human-readable logs for development
- ✅ Includes targets, spans, and structured data
- ✅ Cloud Logging compatible
- ✅ Added `json` feature to tracing-subscriber

### ✅ 9. No Error Monitoring/Alerting (DOCUMENTED)
**Status:** Documented in MONITORING.md
**Setup:**
- ✅ Cloud Error Reporting automatically enabled
- ✅ Cloud Logging captures all errors
- ✅ Created comprehensive monitoring guide
- 📋 TODO: Set up alerting policies (see MONITORING.md)
- 📋 TODO: Configure notification channels

### ✅ 10. Master Encryption Key Baked Into Image (FIXED)
**Status:** Fixed in Dockerfile
**Security Risk:** Resolved
**Changes:**
- ✅ Removed `COPY master.key` from Dockerfile (Phase 1)
- ✅ Production uses GCP KMS (USE_GCP_KMS=true)
- ✅ Local dev mounts master.key as volume
- ✅ Key never baked into image

### ❌ 11. No Rate Limiting
**Impact:** Vulnerable to abuse
**Plan:**
```rust
use tower::limit::RateLimitLayer;
let app = Router::new()
    .layer(RateLimitLayer::new(100, Duration::from_secs(60)))
```

### ❌ 12. Health Check Doesn't Validate Anything
**File:** `api/src/main.rs:120-122`
**Plan:**
```rust
async fn health_check(State(state): State<Arc<KeycastState>>) -> impl IntoResponse {
    // Check database
    if sqlx::query("SELECT 1").fetch_one(&state.db).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Database unhealthy");
    }
    (StatusCode::OK, "OK")
}
```

### ✅ 13. Service Account JSON File in Repo (FIXED)
**Status:** Fixed
**Security Risk:** Resolved
**Actions Taken:**
- ✅ Deleted keycast-service-account.json
- ✅ Added *service-account*.json to .gitignore
- ✅ File was never committed to git
- ⚠️ NOTE: If the key was ever exposed, it should be revoked in GCP Console

### ❌ 14. No .env File Handling for Web
**Impact:** Documentation mismatch
**Plan:** Update README to clarify build-time vs runtime config

### ❌ 15. Docker Compose vs Cloud Build Config Mismatch
**Impact:** Local env doesn't match production
**Plan:** Align configurations

---

## MEDIUM Priority Issues

### ❌ 16. No Runtime Env Var Validation
**Plan:** Add startup validation function

### ❌ 17. No Request ID Tracking
**Plan:** Add tower-http request ID layer

### ❌ 18. No Request Timeout Configuration
**Plan:** Add timeout layer

### ❌ 19. No Graceful Shutdown
**Plan:** Use Axum's graceful shutdown

### ❌ 20. No .dockerignore
**Impact:** Slow builds, large images
**Plan:** Create .dockerignore file

### ❌ 21. No Migration Verification in Deployment
**Plan:** Run migrations as separate Cloud Build step

### ❌ 22. Runtime VITE_* Env Vars Do Nothing
**Impact:** Confusing configuration
**Plan:** Remove from docker-compose.yml

### ❌ 23. No Test Environment Setup
**Plan:** Document test setup in README

### ❌ 24. Duplicated Documentation
**Files:** CURRENT_STATUS.md, DEPLOYMENT_*.md, etc.
**Plan:** Consolidate into DEPLOYMENT.md

---

## LOW Priority Issues

### ❌ 25. No Rollback Migrations
**Plan:** Create down migrations

### ❌ 26. Too Many Deployment Docs
**Plan:** Merge into single DEPLOYMENT.md

---

## Phased Implementation Plan

### Phase 1: Critical Path (Get Production Working)
1. ✅ Fix CORS configuration
2. ✅ Fix frontend API URL
3. ✅ Add smoke tests
4. ⏳ Fix Cloud Build errors
5. 🔄 Deploy successfully

### Phase 2: Testing Infrastructure (Next 2-3 days)
1. Create integration test suite
2. Create e2e test suite
3. Add to CI/CD pipeline
4. Document testing workflow

### Phase 3: Security & Monitoring (Next week)
1. Fix master key storage
2. Delete service account file
3. Add structured logging
4. Add error monitoring
5. Enhance health checks

### Phase 4: Production Hardening (Next week)
1. Add rate limiting
2. Add timeouts
3. Add request ID tracking
4. Add graceful shutdown
5. Optimize Docker builds

### Phase 5: Polish (Next 2 weeks)
1. Add env var validation
2. Add migration verification
3. Create rollback migrations
4. Consolidate documentation
5. Clean up test environment
