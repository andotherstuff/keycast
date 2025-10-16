# Tenant-Scoped Database Query Audit Report

**Generated:** 2025-10-17
**Status:** Migration created, queries need updating

## Executive Summary

**Total Queries Requiring tenant_id Filtering:** 88 queries across 8 files

**Critical Security Issues Found:**
1. `Authorization::all_ids()` returns ALL authorizations (no filtering)
2. `OAuthAuthorization::all_ids()` returns ALL oauth authorizations (no filtering)
3. Email-based lookups can cause cross-tenant account access
4. Username lookups without tenant scoping

## Tables Requiring tenant_id Filtering

From migration `0010_multi_tenancy.sql`:
- users
- teams
- stored_keys
- policies
- authorizations
- personal_keys
- oauth_applications
- oauth_codes
- oauth_authorizations
- signing_activity

## Query Breakdown by File

### 1. core/src/types/user.rs - 7 queries
- All SELECT queries on users, teams, team_users, stored_keys
- Missing tenant_id in WHERE clauses

### 2. core/src/types/team.rs - 5 queries
- Team lookup, team_users, stored_keys, policies queries
- Missing tenant_id filtering

### 3. core/src/types/authorization.rs - 9 queries
- **CRITICAL**: `all_ids()` returns all authorizations (no WHERE clause!)
- All authorization-related queries need tenant_id

### 4. api/src/api/http/teams.rs - 32 queries
- All team CRUD operations
- Stored keys, policies, permissions operations
- Complex DELETE operations with JOINs

### 5. api/src/api/http/auth.rs - 18 queries
- **CRITICAL**: Email lookups without tenant_id (lines 269, 451, 583)
- User registration, login, verification, password reset
- Username queries, profile operations

### 6. api/src/api/http/oauth.rs - 10 queries
- OAuth app registration and lookup
- Authorization code flow queries
- Token exchange queries

### 7. signer/src/signer_daemon.rs - 6 queries
- **CRITICAL**: Loads all authorizations via `all_ids()` (line 51, 86)
- Signing activity logging
- Authorization lookups

### 8. api/src/api/http/routes.rs - 1 query
- NIP-05 username discovery

## Critical Vulnerabilities

### 1. Signer Daemon Loads All Tenants' Data
**File:** `signer/src/signer_daemon.rs:51,86`

```rust
// CURRENT CODE - BROKEN
let ids = Authorization::all_ids(&self.pool).await?;
let oauth_ids = OAuthAuthorization::all_ids(&self.pool).await?;
```

**Problem:** Loads ALL authorizations from ALL tenants into memory.

**Fix Required:**
```rust
// NEED TO ADD
let ids = Authorization::all_ids_for_tenant(&self.pool, tenant_id).await?;
let oauth_ids = OAuthAuthorization::all_ids_for_tenant(&self.pool, tenant_id).await?;
```

**But**: Signer daemon doesn't have tenant context! It's a background process.

**Solution Options:**
1. Run separate signer daemon per tenant (deployment complexity)
2. Signer daemon handles ALL tenants but maintains tenant context during signing
3. Add tenant_id to signing requests and filter in-memory

### 2. Email-Based Authentication
**Files:** `api/src/api/http/auth.rs` (multiple locations)

```rust
// CURRENT CODE - BROKEN
SELECT public_key FROM users WHERE email = ?1

// MUST BECOME
SELECT public_key FROM users WHERE email = ?1 AND tenant_id = ?2
```

**Problem:** Same email can exist in multiple tenants. Login would be ambiguous.

### 3. Username Lookups (NIP-05)
**File:** `api/src/api/http/auth.rs:745`

```rust
// CURRENT CODE - BROKEN
SELECT public_key FROM users WHERE username = ?1

// MUST BECOME
SELECT public_key FROM users WHERE username = ?1 AND tenant_id = ?2
```

**Problem:** `alice@holis.social` and `alice@divine.video` would collide.

## Implementation Strategy

### Phase 1: Database Migration ✅ DONE
- Added tenants table
- Added tenant_id to all tables with DEFAULT 1
- Updated unique constraints to be tenant-scoped
- Inserted oauth.divine.video as tenant_id=1

### Phase 2: Create Tenant Extractor ✅ DONE
- Created `api/src/api/tenant.rs`
- TenantExtractor extracts tenant from Host header
- Helper functions for tenant CRUD

### Phase 3: Query Helper Functions (RECOMMENDED)
Create wrapper functions that automatically inject tenant_id:

```rust
// In api/src/api/db_helpers.rs (new file)

pub async fn get_user_by_email(
    pool: &SqlitePool,
    tenant_id: i64,
    email: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE tenant_id = ?1 AND email = ?2"
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_one(pool)
    .await
}

pub async fn create_user(
    pool: &SqlitePool,
    tenant_id: i64,
    user: CreateUserRequest,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (tenant_id, public_key, email, ...) VALUES (?1, ?2, ?3, ...)"
    )
    .bind(tenant_id)
    .bind(user.public_key)
    // ...
    .fetch_one(pool)
    .await
}
```

### Phase 4: Update All Handlers to Use TenantExtractor
Every handler function must extract tenant:

```rust
// BEFORE
pub async fn login(
    State(pool): State<SqlitePool>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // ...
}

// AFTER
pub async fn login(
    tenant: TenantExtractor,  // Add this
    State(pool): State<SqlitePool>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let tenant_id = tenant.0.id;
    // Use tenant_id in all queries
}
```

### Phase 5: Update All 88 Queries
Systematically update each file:
1. core/src/types/authorization.rs
2. core/src/types/team.rs
3. core/src/types/user.rs
4. api/src/api/http/teams.rs
5. api/src/api/http/auth.rs
6. api/src/api/http/oauth.rs
7. signer/src/signer_daemon.rs
8. api/src/api/http/routes.rs

### Phase 6: Signer Daemon Multi-Tenancy
**Challenge:** Signer daemon is a background process with no HTTP context.

**Solution:** Signer daemon handles all tenants but maintains tenant isolation:

```rust
// Load all authorizations grouped by tenant
struct SignerState {
    authorizations: HashMap<i64, Vec<Authorization>>,  // tenant_id -> auths
    oauth_auths: HashMap<i64, Vec<OAuthAuthorization>>,
}

// When processing signing request, determine tenant from:
// - bunker_secret lookup (bunker_secrets are unique per tenant)
// - Then only access that tenant's authorizations
```

### Phase 7: Testing
- Write tenant isolation tests
- Verify cross-tenant access fails
- Test NIP-05 discovery per tenant
- Test OAuth flows per tenant

### Phase 8: Per-Tenant Static Files
- Serve different HTML/CSS/JS per domain
- Fallback to default if tenant-specific file not found

## Estimated Effort

| Phase | Effort | Status |
|-------|--------|--------|
| 1. Database Migration | 1 hour | ✅ DONE |
| 2. Tenant Extractor | 1 hour | ✅ DONE |
| 3. Query Helpers | 2 hours | ⏳ TODO |
| 4. Update Handlers | 4 hours | ⏳ TODO |
| 5. Update 88 Queries | 8 hours | ⏳ TODO |
| 6. Signer Daemon | 4 hours | ⏳ TODO |
| 7. Testing | 4 hours | ⏳ TODO |
| 8. Static Files | 2 hours | ⏳ TODO |
| **Total** | **26 hours** | **8% complete** |

## Risks

1. **Breaking Existing Deployments:** Migration changes schema, queries will fail until code updated
2. **Signer Daemon Complexity:** Background process needs careful tenant handling
3. **Testing Coverage:** 88 queries = high risk of missing tenant_id somewhere
4. **Performance:** Adding tenant_id to every query adds overhead (minimal, but measurable)

## Recommendations

1. **Create feature branch:** `git checkout -b feature/multi-tenancy`
2. **Run migration in dev first:** Test with local database
3. **Use query helpers:** Avoid duplicating tenant_id logic
4. **Add compile-time checks:** Consider using sqlx compile-time verification
5. **Integration tests first:** Write failing tests, then fix code
6. **Deploy cautiously:** This changes every database query

## Next Steps

1. ✅ Create database migration
2. ✅ Create tenant extractor
3. ✅ Create tenant management CLI
4. ⏳ Create query helper functions
5. ⏳ Update handler signatures to accept TenantExtractor
6. ⏳ Update all 88 queries systematically
7. ⏳ Fix signer daemon tenant handling
8. ⏳ Write tenant isolation tests
9. ⏳ Implement per-tenant static files
10. ⏳ Test in staging environment
11. ⏳ Document tenant provisioning process
12. ⏳ Deploy to production

---

*This is a major refactor. Proceed with caution and thorough testing.*
