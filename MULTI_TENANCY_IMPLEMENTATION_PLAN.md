# Multi-Tenancy Implementation Plan for Keycast

**Created:** 2025-10-17
**Status:** Planning Phase
**Existing Deployment:** oauth.divine.video (must continue working)

---

## Executive Summary

This plan implements domain-based multi-tenancy for keycast, enabling multiple independent instances (e.g., `holis.social`, `divine.video`) to share infrastructure while maintaining complete data isolation.

**Scope:** 88 database queries across 8 files requiring tenant_id filtering
**Critical Risk:** Breaking oauth.divine.video production deployment
**Estimated Duration:** 4-6 weeks with careful testing

---

## Current State Assessment

### ✅ Completed
1. Database migration `0010_multi_tenancy.sql` created
   - Added `tenants` table
   - Added `tenant_id` to all 10 tables with DEFAULT 1
   - Updated unique constraints to be tenant-scoped
   - Created default tenant (oauth.divine.video, id=1)

2. Tenant extractor infrastructure (`api/src/api/tenant.rs`)
   - `TenantExtractor` for Host header-based tenant detection
   - Helper functions for tenant CRUD operations
   - Tenant settings JSON support

### ⚠️ Outstanding Issues
1. **88 queries** lack tenant_id filtering
2. **Auth handlers** perform email/username lookups without tenant scoping
3. **Signer daemon** loads ALL tenants' authorizations (architectural issue)
4. **No rollback mechanism** if deployment fails
5. **No feature flag** for gradual rollout

---

## Phase 1: Foundation & Safety (Week 1) - HIGH PRIORITY

**Goal:** Establish safety mechanisms before touching any queries

### Tasks

#### 1.1 Create Feature Flag System
**File:** `api/src/api/feature_flags.rs` (new)
```rust
pub struct FeatureFlags {
    pub multi_tenancy_enabled: bool,
}

impl FeatureFlags {
    pub fn from_env() -> Self {
        Self {
            multi_tenancy_enabled: std::env::var("ENABLE_MULTI_TENANCY")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false)
        }
    }
}
```

**Rationale:** Allow toggling multi-tenancy without code changes

#### 1.2 Create Database Query Helper Module
**File:** `api/src/api/db_helpers.rs` (new)

Implement tenant-aware wrapper functions:
- `get_user_by_email(pool, tenant_id, email)`
- `get_user_by_username(pool, tenant_id, username)`
- `create_user(pool, tenant_id, user_data)`
- `get_team(pool, tenant_id, team_id)`
- etc.

**Rationale:** Centralize tenant_id logic, reduce duplication, easier testing

#### 1.3 Add Tenant Context to Error Types
**File:** `api/src/api/error.rs`

Add tenant information to error messages for debugging:
```rust
pub struct ApiError {
    pub kind: ErrorKind,
    pub tenant_id: Option<i64>,
    pub message: String,
}
```

#### 1.4 Create Tenant Migration Integration Tests
**File:** `api/tests/tenant_isolation_test.rs` (new)

Write tests that:
- Create two tenants
- Add users with same email to different tenants
- Verify isolation (queries return only tenant's data)
- Test cross-tenant access fails properly

**Success Criteria:**
- Feature flag system works
- Helper functions compile and pass unit tests
- Integration tests exist (may fail - we'll fix in later phases)

**Rollback:** Delete new files, revert env vars

**Estimated Time:** 3-4 days

---

## Phase 2: Core Type Layer (Week 1-2) - CRITICAL SECURITY

**Goal:** Fix the foundational type layer that everything else depends on

**Priority:** These files are used by ALL handlers - fix them first

### Tasks

#### 2.1 Update `core/src/types/user.rs` (7 queries)

**Critical Queries:**
- Line 55: `find_by_pubkey` - Add tenant_id parameter
- Line 70-71: Team membership queries - Add tenant_id filter
- Line 94: Stored keys query - Already has team_id, verify tenant cascade
- Line 124, 140, 154: Admin/member checks - Add tenant_id parameter

**Example:**
```rust
// BEFORE
pub async fn find_by_pubkey(pool: &SqlitePool, pubkey: &PublicKey)
    -> Result<Self, UserError>

// AFTER
pub async fn find_by_pubkey(
    pool: &SqlitePool,
    tenant_id: i64,
    pubkey: &PublicKey
) -> Result<Self, UserError> {
    sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE tenant_id = ?1 AND public_key = ?2"
    )
    .bind(tenant_id)
    .bind(pubkey.to_hex())
    .fetch_one(pool)
    .await
    // ...
}
```

**Breaking Change:** All callers must pass tenant_id

#### 2.2 Update `core/src/types/team.rs` (5 queries)

**Queries:**
- All SELECT queries on teams, policies, team_users
- Add tenant_id to WHERE clauses

**Example:**
```rust
pub async fn find_with_relations(
    pool: &SqlitePool,
    tenant_id: i64,
    team_id: u32
) -> Result<TeamWithRelations, TeamError>
```

#### 2.3 Update `core/src/types/authorization.rs` (9 queries) - CRITICAL

**Most Important:**
- Line 213-222: `all_ids()` - **ADD tenant_id parameter**
  ```rust
  // BEFORE - SECURITY VULNERABILITY
  pub async fn all_ids(pool: &SqlitePool) -> Result<Vec<u32>, AuthorizationError>

  // AFTER
  pub async fn all_ids_for_tenant(
      pool: &SqlitePool,
      tenant_id: i64
  ) -> Result<Vec<u32>, AuthorizationError> {
      sqlx::query_scalar(
          "SELECT id FROM authorizations WHERE tenant_id = ?1"
      )
      .bind(tenant_id)
      .fetch_all(pool)
      .await
  }
  ```

- All other queries: Add tenant_id filtering

**Why Critical:** Signer daemon uses this - loads ALL authorizations!

#### 2.4 Update `core/src/types/oauth_authorization.rs`

Similar changes to authorization.rs:
- Add `all_ids_for_tenant()`
- Add tenant_id to all queries

**Testing Strategy:**
- Update existing unit tests to pass tenant_id
- Add new tests for tenant isolation
- Verify compilation (will break API handlers - expected)

**Success Criteria:**
- All core types accept tenant_id parameter
- Unit tests pass with tenant_id=1 (default)
- Compilation errors in dependent files documented

**Rollback:** Git revert core type changes

**Estimated Time:** 4-5 days

---

## Phase 3: Authentication Handlers (Week 2) - CRITICAL SECURITY

**Goal:** Fix auth.rs queries to prevent cross-tenant account access

**File:** `api/src/api/http/auth.rs` (18 queries)

### Critical Vulnerabilities to Fix

#### 3.1 Registration (lines 260-343)
**Current Issue:** Line 269 checks email without tenant_id
```rust
// BROKEN - Cross-tenant email collision
SELECT public_key FROM users WHERE email = ?1

// FIX
SELECT public_key FROM users WHERE tenant_id = ?1 AND email = ?2
```

**Handler Update:**
```rust
pub async fn register(
    tenant: TenantExtractor,  // ADD THIS
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AuthError> {
    let tenant_id = tenant.0.id;

    // Use tenant_id in all queries
    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT public_key FROM users WHERE tenant_id = ?1 AND email = ?2"
    )
    .bind(tenant_id)
    .bind(&req.email)
    .fetch_optional(pool)
    .await?;

    // Insert with tenant_id
    sqlx::query(
        "INSERT INTO users (tenant_id, public_key, email, ...)
         VALUES (?1, ?2, ?3, ...)"
    )
    .bind(tenant_id)
    // ...
}
```

#### 3.2 Login (lines 443-488)
**Current Issue:** Line 451 email lookup without tenant
```rust
// BROKEN
SELECT public_key, password_hash FROM users
WHERE email = ?1 AND password_hash IS NOT NULL

// FIX
SELECT public_key, password_hash FROM users
WHERE tenant_id = ?1 AND email = ?2 AND password_hash IS NOT NULL
```

#### 3.3 Username Operations (lines 727-775)
**Current Issue:** Username checks without tenant (NIP-05 collision)
```rust
// Line 745 - BROKEN
SELECT public_key FROM users WHERE username = ?1 AND public_key != ?2

// FIX
SELECT public_key FROM users
WHERE tenant_id = ?1 AND username = ?2 AND public_key != ?3
```

#### 3.4 All Other Auth Queries
- Email verification (line 532-573)
- Password reset (line 576-692)
- Bunker URL retrieval (line 491-522)
- Session management (line 795-942)

**Pattern:**
1. Add `tenant: TenantExtractor` parameter
2. Extract `tenant_id`
3. Add tenant_id to ALL WHERE clauses
4. Add tenant_id to ALL INSERT statements

**Testing Strategy:**
- Integration tests with 2 tenants, same email different tenants
- Verify login to tenant A cannot access tenant B's accounts
- Test NIP-05 username@domain resolution

**Success Criteria:**
- All 18 queries have tenant_id filtering
- Integration tests pass
- Can login to oauth.divine.video (tenant_id=1) without breakage

**Rollback:** Git revert auth.rs changes

**Estimated Time:** 5-6 days

---

## Phase 4: Team Management (Week 3) - MEDIUM PRIORITY

**Goal:** Update teams.rs with tenant filtering

**File:** `api/src/api/http/teams.rs` (32 queries)

### Tasks

#### 4.1 List/Create/Get/Update/Delete Teams (lines 25-273)
Add tenant_id to:
- Team creation (line 60-68)
- Team listing (line 29-38)
- Team retrieval (line 138-148)
- Team updates (line 150-173)
- Team deletion cascade (line 175-273)

**Example:**
```rust
pub async fn list_teams(
    tenant: TenantExtractor,  // ADD
    State(pool): State<SqlitePool>,
    AuthEvent(event): AuthEvent,
) -> ApiResult<Json<Vec<TeamWithRelations>>> {
    let tenant_id = tenant.0.id;

    let user = User::find_by_pubkey(&pool, tenant_id, &event.pubkey).await?;
    let teams = user.teams(&pool, tenant_id).await?;

    Ok(Json(teams))
}
```

#### 4.2 User Management (lines 275-373)
- Add user to team (line 275)
- Remove user from team (line 335)

Add tenant verification:
```rust
// Verify team belongs to tenant
let team: Option<(i64,)> = sqlx::query_as(
    "SELECT tenant_id FROM teams WHERE id = ?1"
)
.bind(team_id)
.fetch_optional(&mut *tx)
.await?;

if team.map(|(tid,)| tid) != Some(tenant_id) {
    return Err(ApiError::not_found("Team not found"));
}
```

#### 4.3 Key Management (lines 375-548)
- Add key to team (line 375)
- Remove key from team (line 416)
- Get key details (line 463)

#### 4.4 Authorization/Policy Management (lines 550-682)
- Add authorization (line 550)
- Add policy (line 624)

**Testing Strategy:**
- Create teams in different tenants
- Verify team operations isolated per tenant
- Test admin permissions don't cross tenants

**Success Criteria:**
- All 32 queries tenant-scoped
- Cross-tenant team access fails
- Existing oauth.divine.video teams still work

**Rollback:** Git revert teams.rs

**Estimated Time:** 6-7 days

---

## Phase 5: OAuth Flow (Week 3) - MEDIUM PRIORITY

**Goal:** Update OAuth authorization flow with tenant context

**File:** `api/src/api/http/oauth.rs` (10 queries)

### Tasks

#### 5.1 Authorization Flow (lines 88-175)
```rust
pub async fn authorize_post(
    tenant: TenantExtractor,  // ADD
    State(auth_state): State<super::routes::AuthState>,
    headers: HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> Result<Response, OAuthError> {
    let tenant_id = tenant.0.id;

    // Get/create application with tenant_id
    let app_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM oauth_applications
         WHERE tenant_id = ?1 AND client_id = ?2"
    )
    .bind(tenant_id)
    .bind(&req.client_id)
    .fetch_optional(&auth_state.state.db)
    .await?;

    // Store code with tenant_id
    sqlx::query(
        "INSERT INTO oauth_codes
         (tenant_id, code, user_public_key, ...)
         VALUES (?1, ?2, ?3, ...)"
    )
    .bind(tenant_id)
    // ...
}
```

#### 5.2 Token Exchange (lines 177-269)
Add tenant_id to:
- Code validation (line 186)
- Authorization creation (line 237)

#### 5.3 Nostr-Login Integration (lines 365-659)
- Connection approval (line 514)
- Application lookup/creation (line 571-591)

**Testing Strategy:**
- OAuth flow end-to-end per tenant
- Verify authorization codes can't be used cross-tenant
- Test nostr-login popup flow with multiple tenants

**Success Criteria:**
- All 10 queries tenant-scoped
- OAuth flow works per tenant
- Bunker URLs generated correctly per tenant

**Rollback:** Git revert oauth.rs

**Estimated Time:** 4-5 days

---

## Phase 6: Signer Daemon Architecture (Week 4) - MOST COMPLEX

**Goal:** Make signer daemon handle multiple tenants correctly

**File:** `signer/src/signer_daemon.rs` (6 queries)

### Current Architecture Problem

The signer daemon is a **single background process** that:
1. Loads ALL authorizations from database (line 51, 86)
2. Subscribes to NIP-46 events on relays
3. Processes signing requests

**Issue:** With multi-tenancy, it will load ALL tenants' data into memory.

### Solution: Tenant-Aware In-Memory State

**Don't run separate processes per tenant** - instead:

```rust
pub struct UnifiedSigner {
    // Group authorizations by tenant
    tenant_handlers: Arc<RwLock<HashMap<i64, TenantState>>>,
    client: Client,
    pool: SqlitePool,
    key_manager: Arc<Box<dyn KeyManager>>,
}

struct TenantState {
    tenant_id: i64,
    handlers: HashMap<String, AuthorizationHandler>,  // bunker_pubkey -> handler
}
```

### Implementation Steps

#### 6.1 Update `load_authorizations()` (line 46-122)
```rust
pub async fn load_authorizations(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    let mut tenant_handlers = self.tenant_handlers.write().await;
    tenant_handlers.clear();

    // Get all tenant IDs
    let tenant_ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM tenants"
    )
    .fetch_all(&self.pool)
    .await?;

    for tenant_id in tenant_ids {
        // Load regular authorizations for this tenant
        let regular_auths = Authorization::all_ids_for_tenant(&self.pool, tenant_id).await?;

        let mut handlers = HashMap::new();

        for auth_id in regular_auths {
            let auth = Authorization::find(&self.pool, auth_id).await?;
            // Decrypt and setup handler...
            handlers.insert(bunker_pubkey, handler);
        }

        // Load OAuth authorizations for this tenant
        let oauth_auths = OAuthAuthorization::all_ids_for_tenant(&self.pool, tenant_id).await?;
        // Similar process...

        tenant_handlers.insert(tenant_id, TenantState {
            tenant_id,
            handlers,
        });
    }

    tracing::info!(
        "Loaded authorizations for {} tenants",
        tenant_handlers.len()
    );

    Ok(())
}
```

#### 6.2 Update `reload_authorizations_if_needed()` (line 209-332)
- Keep optimization of checking last 5 authorizations
- But check within each tenant's scope

#### 6.3 Update `handle_nip46_request()` (line 334-567)
**Current:** Looks up bunker_pubkey in flat HashMap
**New:** Check ALL tenants for bunker_pubkey

```rust
async fn handle_nip46_request(
    tenant_handlers: Arc<RwLock<HashMap<i64, TenantState>>>,
    client: Client,
    event: Box<Event>,
) -> Result<(), Box<dyn std::error::Error>> {
    let bunker_pubkey = event.tags
        .iter()
        .find(|tag| tag.kind() == TagKind::p())
        .and_then(|tag| tag.content())
        .ok_or("No p-tag found")?;

    // Search across all tenants for this bunker pubkey
    let handler = {
        let handlers = tenant_handlers.read().await;

        handlers
            .values()
            .find_map(|tenant_state| {
                tenant_state.handlers.get(bunker_pubkey).cloned()
            })
    };

    // Rest of handling...
}
```

**Why This Works:**
- Bunker pubkeys are globally unique (generated UUID + encryption)
- Tenant isolation maintained in database queries
- Single relay subscription handles all tenants
- Scales to millions of users

#### 6.4 Update `log_signing_activity()` (line 634-701)
Add tenant_id to signing_activity inserts:
```rust
sqlx::query(
    "INSERT INTO signing_activity
     (tenant_id, user_public_key, application_id, bunker_secret, ...)
     VALUES (?1, ?2, ?3, ?4, ...)"
)
.bind(tenant_id)  // NEW
// ...
```

**How to get tenant_id?**
- Look up from authorization (regular or OAuth)
- Store in `AuthorizationHandler` struct

### Testing Strategy
- Start signer daemon with 2 tenants
- Create authorizations in each tenant
- Send NIP-46 signing requests to each
- Verify:
  - Requests routed to correct tenant
  - Activity logged with correct tenant_id
  - No cross-tenant data leakage

**Success Criteria:**
- Signer daemon loads all tenants' authorizations
- Signing requests work per tenant
- Activity logs have tenant_id
- Memory usage acceptable (<500MB for 1000s of users)

**Rollback:** Git revert signer changes, restart daemon

**Estimated Time:** 6-7 days (most complex phase)

---

## Phase 7: Routes & NIP-05 (Week 4) - LOW PRIORITY

**Goal:** Update HTTP routes and NIP-05 discovery

**File:** `api/src/api/http/routes.rs` (1 query)

### Tasks

#### 7.1 NIP-05 Username Discovery
```rust
// Current endpoint: GET /.well-known/nostr.json?name=alice
// Returns: {"names": {"alice": "pubkey..."}}

pub async fn nostr_nip05(
    tenant: TenantExtractor,  // ADD - extract from Host header
    Query(params): Query<Nip05Params>,
) -> Result<Json<Nip05Response>, ApiError> {
    let tenant_id = tenant.0.id;

    let user_pubkey: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM users
         WHERE tenant_id = ?1 AND username = ?2"
    )
    .bind(tenant_id)
    .bind(&params.name)
    .fetch_optional(&pool)
    .await?;

    // alice@holis.social different from alice@divine.video
}
```

**Testing:**
- Query `https://holis.social/.well-known/nostr.json?name=alice`
- Query `https://divine.video/.well-known/nostr.json?name=alice`
- Verify different pubkeys returned

**Success Criteria:**
- NIP-05 discovery tenant-scoped
- Same username different domains works

**Estimated Time:** 1 day

---

## Phase 8: Testing & Validation (Week 5) - CRITICAL

**Goal:** Comprehensive tenant isolation testing

### Test Coverage Required

#### 8.1 Tenant Isolation Tests
**File:** `api/tests/tenant_isolation_test.rs`

```rust
#[tokio::test]
async fn test_email_isolation() {
    // Create 2 tenants
    let tenant1 = create_tenant("holis.social").await;
    let tenant2 = create_tenant("divine.video").await;

    // Register alice@test.com on both tenants
    register_user(tenant1, "alice@test.com", "pass1").await;
    register_user(tenant2, "alice@test.com", "pass2").await;

    // Login to tenant1 with pass1 - should succeed
    assert!(login(tenant1, "alice@test.com", "pass1").await.is_ok());

    // Login to tenant1 with pass2 - should FAIL (wrong password)
    assert!(login(tenant1, "alice@test.com", "pass2").await.is_err());

    // Login to tenant2 with pass2 - should succeed
    assert!(login(tenant2, "alice@test.com", "pass2").await.is_ok());
}

#[tokio::test]
async fn test_username_isolation() {
    // Same username on different domains
    // alice@holis.social vs alice@divine.video
}

#[tokio::test]
async fn test_team_isolation() {
    // Create teams in different tenants
    // Verify team admin in tenant1 cannot access tenant2's teams
}

#[tokio::test]
async fn test_oauth_isolation() {
    // OAuth apps and codes can't be used cross-tenant
}

#[tokio::test]
async fn test_signer_isolation() {
    // Signing requests routed to correct tenant
}
```

#### 8.2 Backward Compatibility Tests
Ensure oauth.divine.video (tenant_id=1) still works:
- Existing user logins
- Existing OAuth apps
- Existing bunker URLs
- Existing teams

#### 8.3 Performance Tests
- Load 100 tenants with 100 users each
- Measure query performance with tenant_id indexes
- Measure signer daemon memory usage

**Success Criteria:**
- All isolation tests pass
- oauth.divine.video still works
- Query performance degradation <10%
- Signer daemon memory usage <500MB

**Estimated Time:** 5-6 days

---

## Phase 9: Deployment & Migration (Week 6) - HIGHEST RISK

**Goal:** Deploy multi-tenancy to production without breaking oauth.divine.video

### Pre-Deployment Checklist

- [ ] All 88 queries updated with tenant_id
- [ ] All tests passing (unit + integration)
- [ ] Feature flag `ENABLE_MULTI_TENANCY=false` tested
- [ ] Database migration tested on staging
- [ ] Rollback plan documented
- [ ] Monitoring alerts configured

### Deployment Strategy: Blue-Green with Feature Flag

#### Step 1: Deploy Code with Feature Flag OFF
```bash
# Deploy new code but multi-tenancy disabled
export ENABLE_MULTI_TENANCY=false

# Start API server
./keycast-api

# Verify oauth.divine.video still works
curl https://oauth.divine.video/api/health
```

**Verification:**
- All existing functionality works
- No tenant_id filtering applied (uses DEFAULT 1)
- Feature flag check added to all handlers

#### Step 2: Run Database Migration
```bash
# Backup database first
cp database/keycast.db database/keycast.db.backup.$(date +%s)

# Run migration
sqlx migrate run --source database/migrations

# Verify migration
sqlite3 database/keycast.db "SELECT * FROM tenants;"
# Should show: id=1, domain=oauth.divine.video
```

**Verification:**
- All tables have tenant_id column with DEFAULT 1
- Unique indexes updated to tenant-scoped
- Existing data has tenant_id=1

#### Step 3: Enable Feature Flag Gradually
```bash
# Enable multi-tenancy
export ENABLE_MULTI_TENANCY=true

# Restart API
systemctl restart keycast-api

# Restart signer daemon
systemctl restart keycast-signer
```

**Verification:**
- oauth.divine.video still works (tenant_id=1)
- TenantExtractor returns tenant_id=1 for oauth.divine.video
- All queries include tenant_id=1

#### Step 4: Create Second Tenant (Holis.social)
```bash
# Using management CLI
./scripts/manage-tenants.sh create \
    --domain holis.social \
    --name "Holis Social" \
    --relay wss://relay.holis.social \
    --email noreply@holis.social
```

**Verification:**
- Can register users on holis.social
- Users isolated from oauth.divine.video
- NIP-05 works: alice@holis.social

### Rollback Plan

**If Feature Flag Fails:**
```bash
export ENABLE_MULTI_TENANCY=false
systemctl restart keycast-api
systemctl restart keycast-signer
```

**If Migration Fails:**
```bash
# Restore database backup
cp database/keycast.db.backup.TIMESTAMP database/keycast.db

# Redeploy previous code version
git checkout v0.9.0  # pre-multi-tenancy
cargo build --release
systemctl restart keycast-api
systemctl restart keycast-signer
```

**If Queries Fail:**
- Feature flag OFF immediately
- Investigate via logs
- Fix query, deploy patch
- Re-enable feature flag

### Monitoring & Alerts

Set up alerts for:
- Query errors mentioning "tenant_id"
- Login failures spike
- Signer daemon crashes
- Memory usage >80%
- API response time >500ms

**Success Criteria:**
- oauth.divine.video unchanged (0% downtime)
- holis.social fully functional
- All tenant isolation tests pass in production

**Estimated Time:** 3-4 days (including monitoring)

---

## Risk Mitigation

### Risk Matrix

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Break oauth.divine.video | **CRITICAL** | Medium | Feature flag, rollback plan, staging tests |
| Cross-tenant data leak | **CRITICAL** | Low | Comprehensive isolation tests, code review |
| Signer daemon memory leak | High | Medium | Performance tests, monitoring, graceful restart |
| Query performance degradation | Medium | Low | Indexes on tenant_id, query profiling |
| Migration fails | High | Low | Database backup, test on staging first |

### Mitigation Strategies

1. **Feature Flag:** All changes behind `ENABLE_MULTI_TENANCY` flag
2. **Database Backup:** Automated backups before migration
3. **Staging Environment:** Full test on staging before production
4. **Gradual Rollout:** oauth.divine.video first, then add holis.social
5. **Monitoring:** Real-time alerts on errors/performance
6. **Rollback Plan:** Documented at each phase
7. **Code Review:** Security-focused review before merge

---

## Dependencies Between Phases

```
Phase 1 (Foundation)
    ↓
Phase 2 (Core Types) ←─────┐
    ↓                       │
Phase 3 (Auth) ─────────────┤
    ↓                       │ All depend on
Phase 4 (Teams) ────────────┤ Phase 2
    ↓                       │
Phase 5 (OAuth) ────────────┤
    ↓                       │
Phase 6 (Signer) ───────────┘
    ↓
Phase 7 (Routes)
    ↓
Phase 8 (Testing) ←── ALL phases must complete first
    ↓
Phase 9 (Deployment)
```

**Critical Path:** Phases 1→2→3→6→8→9 (authentication + signer + testing)

---

## Testing Strategy by Phase

| Phase | Unit Tests | Integration Tests | Manual Testing |
|-------|-----------|-------------------|----------------|
| 1. Foundation | Feature flag, helpers | N/A | CLI commands |
| 2. Core Types | All type methods | Type interactions | N/A |
| 3. Auth | Each handler | Full auth flow | Register/login |
| 4. Teams | Each handler | Team CRUD flow | Team operations |
| 5. OAuth | Each handler | OAuth flow | External app auth |
| 6. Signer | Handler loading | Signing requests | NIP-46 client |
| 7. Routes | NIP-05 lookup | Discovery flow | Browser check |
| 8. Testing | N/A | **ALL isolation tests** | Manual verification |
| 9. Deployment | N/A | Production smoke tests | User acceptance |

---

## Estimated Timeline

| Phase | Duration | Start Week | Dependencies |
|-------|----------|------------|--------------|
| 1. Foundation | 3-4 days | Week 1 | None |
| 2. Core Types | 4-5 days | Week 1-2 | Phase 1 |
| 3. Auth | 5-6 days | Week 2 | Phase 2 |
| 4. Teams | 6-7 days | Week 3 | Phase 2 |
| 5. OAuth | 4-5 days | Week 3 | Phase 2 |
| 6. Signer | 6-7 days | Week 4 | Phase 2 |
| 7. Routes | 1 day | Week 4 | Phase 2 |
| 8. Testing | 5-6 days | Week 5 | Phases 2-7 |
| 9. Deployment | 3-4 days | Week 6 | Phase 8 |
| **Total** | **37-45 days** | **6 weeks** | |

**Aggressive:** 5 weeks with parallel work on Phases 3-5
**Conservative:** 8 weeks with sequential work and extended testing

---

## Success Metrics

### Technical Metrics
- [ ] 100% of 88 queries have tenant_id filtering
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] All tenant isolation tests pass
- [ ] Query performance <10% slower
- [ ] Signer daemon memory <500MB

### Business Metrics
- [ ] oauth.divine.video: 0 downtime, 100% functionality
- [ ] holis.social: Fully operational
- [ ] NIP-05 discovery works per domain
- [ ] OAuth apps work per tenant
- [ ] Bunker URLs isolated per tenant

---

## Post-Implementation

### Documentation Needed
1. **Tenant Provisioning Guide** - How to add new domains
2. **Migration Guide** - For existing deployments
3. **Architecture Doc** - How multi-tenancy works
4. **Troubleshooting Guide** - Common issues and fixes

### Future Enhancements
1. Per-tenant static files (HTML/CSS/JS)
2. Tenant admin UI
3. Tenant usage metrics
4. Tenant-specific relay configurations
5. Tenant billing/limits

---

## Decision Log

### Why Single Signer Daemon?
**Considered:** Separate daemon per tenant
**Chosen:** Single daemon with tenant-aware state
**Rationale:**
- Simpler deployment
- Lower resource usage
- Single relay subscription scales better
- Bunker pubkeys globally unique

### Why Feature Flag?
**Rationale:**
- Enable/disable without redeployment
- Gradual rollout
- Quick rollback
- Testing in production

### Why Database DEFAULT 1?
**Rationale:**
- Backward compatibility
- Existing oauth.divine.video becomes tenant 1
- No data migration needed
- Queries work with/without multi-tenancy code

---

## Appendix A: Query Inventory

### By File
- **auth.rs:** 18 queries (email, username, login, registration)
- **teams.rs:** 32 queries (CRUD, keys, policies, users)
- **oauth.rs:** 10 queries (authorization, token exchange)
- **user.rs:** 7 queries (user lookup, team membership)
- **team.rs:** 5 queries (team operations)
- **authorization.rs:** 9 queries (bunker auth management)
- **signer_daemon.rs:** 6 queries (loading auths, activity log)
- **routes.rs:** 1 query (NIP-05 discovery)

**Total:** 88 queries

### By Table
- **users:** 25 queries
- **teams:** 15 queries
- **stored_keys:** 10 queries
- **authorizations:** 12 queries
- **oauth_applications:** 8 queries
- **oauth_codes:** 4 queries
- **oauth_authorizations:** 8 queries
- **personal_keys:** 3 queries
- **policies:** 5 queries
- **signing_activity:** 3 queries

---

## Appendix B: Feature Flag Implementation

```rust
// api/src/api/feature_flags.rs
use std::sync::OnceLock;

static FEATURES: OnceLock<FeatureFlags> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct FeatureFlags {
    pub multi_tenancy_enabled: bool,
}

impl FeatureFlags {
    pub fn global() -> &'static FeatureFlags {
        FEATURES.get_or_init(|| Self::from_env())
    }

    fn from_env() -> Self {
        Self {
            multi_tenancy_enabled: std::env::var("ENABLE_MULTI_TENANCY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false)
        }
    }
}

// Usage in handlers:
pub async fn login(...) -> Result<...> {
    let tenant_id = if FeatureFlags::global().multi_tenancy_enabled {
        tenant.0.id
    } else {
        1  // Default tenant
    };

    // Use tenant_id in queries...
}
```

---

**Document Version:** 1.0
**Last Updated:** 2025-10-17
**Author:** Claude (Anthropic)
**Review Status:** Awaiting Rabble Approval
