# Multi-Domain Hosting Research for Keycast

## Executive Summary

This document outlines strategies for hosting keycast at multiple domains, where each domain has its own content/design but shares the same backend infrastructure. Based on research of multi-tenant architecture patterns and OAuth best practices for 2025.

## Current Architecture Constraints

From exploration of the keycast codebase:
- **Single-domain only**: Currently hardcoded to `oauth.divine.video`
- **SQLite database**: No native Row Level Security (RLS) like PostgreSQL
- **Global unique constraints**: email, username, bunker_public_key, client_id
- **Shared static files**: `/public` directory serves all content
- **Permissive CORS**: Allows all origins for embeddable flows
- **No tenant isolation**: Database has no multi-tenant support

## Multi-Tenant Architecture Patterns

### Pattern 1: Shared Database, Shared Schema (Recommended for Keycast)

**How it works:**
- Single SQLite database with `tenant_id` column on all tables
- Application-level filtering enforces tenant isolation
- Different frontend content served based on request domain
- Shared backend logic with tenant context

**Implementation:**
```
┌─────────────────────────────────────────┐
│         Cloud Run Load Balancer         │
│    Routes based on Host header          │
└─────────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
   alice.com   bob.com    carol.com
        │           │           │
        └───────────┼───────────┘
                    │
        ┌───────────▼───────────┐
        │   Axum Web Server     │
        │                       │
        │  Tenant Middleware    │
        │  - Extract from domain│
        │  - Set tenant_context │
        └───────────────────────┘
                    │
        ┌───────────▼───────────┐
        │   Static File Serving │
        │                       │
        │  /tenants/{id}/public/│
        └───────────────────────┘
                    │
        ┌───────────▼───────────┐
        │   API Layer           │
        │                       │
        │  All queries filtered │
        │  by tenant_id         │
        └───────────────────────┘
                    │
        ┌───────────▼───────────┐
        │   SQLite Database     │
        │                       │
        │  users (tenant_id)    │
        │  oauth_apps (...)     │
        └───────────────────────┘
```

**Database Changes:**
```sql
-- Add tenant_id to all tables
ALTER TABLE users ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1;
ALTER TABLE oauth_applications ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1;
ALTER TABLE oauth_authorizations ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1;
-- etc for all tables

-- Change unique constraints to be tenant-scoped
CREATE UNIQUE INDEX users_email_tenant ON users(tenant_id, email);
CREATE UNIQUE INDEX users_username_tenant ON users(tenant_id, username);
CREATE UNIQUE INDEX oauth_apps_client_id_tenant ON oauth_applications(tenant_id, client_id);

-- Tenants table
CREATE TABLE tenants (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    settings TEXT -- JSON config for customization
);
```

**Pros:**
- Most cost-effective (single instance, single database)
- Easy to scale horizontally
- Shared infrastructure maintenance
- Centralized backups and monitoring
- Can easily query across tenants if needed

**Cons:**
- Requires careful application-level filtering (risk of data leakage)
- No cryptographic tenant isolation
- All tenants affected by same outages
- SQLite has no native RLS (must enforce in code)
- Schema changes affect all tenants

**Estimated Effort:** 3-5 days
- Database migrations
- Tenant middleware
- Query modifications
- Frontend routing
- Testing

---

### Pattern 2: Database Per Tenant

**How it works:**
- Each tenant gets their own SQLite database file
- Application connects to correct DB based on domain
- Separate frontend directories per tenant
- Same backend code, different data stores

**Implementation:**
```
┌─────────────────────────────────────────┐
│         Cloud Run Load Balancer         │
└─────────────────────────────────────────┘
                    │
        ┌───────────▼───────────┐
        │   Axum Web Server     │
        │                       │
        │  Tenant Middleware    │
        │  - Extract from domain│
        │  - Select DB file     │
        └───────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
   alice.db            bob.db   carol.db
   alice/public/       bob/public/  carol/public/
```

**Directory Structure:**
```
/data/
  tenants/
    alice.com/
      keycast.db
      public/
        index.html
        login.html
        dashboard.html
    bob.com/
      keycast.db
      public/
        index.html
        login.html
```

**Pros:**
- Strong tenant isolation (separate files)
- Independent backups per tenant
- Schema changes can be per-tenant
- Easier regulatory compliance
- No risk of cross-tenant data leakage

**Cons:**
- More complex database management
- SQLite file per tenant = more files to backup
- Harder to query across tenants
- Connection pool per tenant (more memory)
- Litestream replication multiplied by tenant count

**Estimated Effort:** 4-6 days
- Dynamic database connection management
- Tenant routing
- Backup strategy changes
- Migration tooling per tenant

---

### Pattern 3: Separate Instances Per Tenant (Simplest)

**How it works:**
- Deploy completely separate keycast instances
- Each has own Cloud Run service, database, domain
- No code changes needed
- Use Terraform/deployment automation

**Implementation:**
```
alice.com → Cloud Run instance 1 → SQLite DB 1
bob.com   → Cloud Run instance 2 → SQLite DB 2
carol.com → Cloud Run instance 3 → SQLite DB 3
```

**Pros:**
- Zero code changes required
- Maximum isolation (separate VMs, networks, databases)
- Independent scaling per tenant
- Complete customization possible (different code versions)
- Simplest security model

**Cons:**
- Highest cost (multiple Cloud Run services)
- Most operational overhead
- Harder to push updates (must deploy to all)
- No shared infrastructure benefits
- Wasted resources for small tenants

**Estimated Effort:** 1-2 days
- Terraform/deployment automation
- Documentation for new tenant provisioning

---

### Pattern 4: Hybrid - Shared Backend + Separate Frontend Proxy

**How it works:**
- Single keycast backend with tenant_id
- CDN/reverse proxy serves different frontend per domain
- Backend API shared, UI customized per tenant

**Implementation:**
```
┌─────────────────────────────────────────┐
│         Cloud CDN / Cloudflare          │
│                                         │
│  alice.com → /tenants/alice/public/*    │
│  bob.com   → /tenants/bob/public/*      │
│  *.com/api → backend Cloud Run          │
└─────────────────────────────────────────┘
                    │
        ┌───────────▼───────────┐
        │   Axum Web Server     │
        │   (API only)          │
        │   Tenant from header  │
        └───────────────────────┘
                    │
        ┌───────────▼───────────┐
        │   SQLite + tenant_id  │
        └───────────────────────┘
```

**Pros:**
- Separates concerns (frontend vs backend multi-tenancy)
- Can use CDN for frontend performance
- Backend complexity reduced
- Easy to customize per-tenant UI

**Cons:**
- Requires CDN or reverse proxy setup
- More moving parts
- Still need tenant_id in database
- Cross-origin considerations

**Estimated Effort:** 3-4 days
- Database changes
- CDN/proxy configuration
- Frontend structure changes

---

## OAuth Multi-Tenancy Considerations

### Redirect URI Management

Each tenant will have different redirect URIs for OAuth:
```
alice.com/oauth/callback
bob.com/oauth/callback
carol.com/oauth/callback
```

**Solution:** Store tenant_id with oauth_applications and validate redirect_uri contains tenant's domain.

### NIP-05 Discovery

Each tenant needs separate NIP-05 endpoints:
```
alice.com/.well-known/nostr.json?name=user
bob.com/.well-known/nostr.json?name=user
```

**Solution:** Filter nostr.json response by tenant based on request domain.

### Bunker URLs

Current format: `bunker://<pubkey>?relay=wss://relay.damus.io`

**Multi-tenant format options:**
1. Keep same relay, tenant implicit in pubkey
2. Separate relay per tenant: `bunker://<pubkey>?relay=wss://alice.com/relay`
3. Include tenant in URL: `bunker://<pubkey>?relay=...&tenant=alice`

**Recommendation:** Option 1 (simplest, no changes needed)

---

## Frontend Content Customization

### Static File Organization

**Option A: Subdirectory per tenant**
```
/public/
  tenants/
    alice/
      index.html
      style.css
      logo.png
    bob/
      index.html
      style.css
      logo.png
    _default/  # fallback
```

**Option B: Template system**
```
/public/
  templates/
    index.html.tmpl  # with {{logo_url}}, {{brand_name}}
  tenants/
    alice/
      config.json  # { "logo_url": "...", "brand_name": "Alice" }
```

**Option C: Dynamic loading**
```
/public/
  index.html  # always same, loads /api/tenant/config
/api/
  tenant/config  # returns JSON with branding per domain
```

**Recommendation:** Option A for simplicity, Option C for flexibility

---

## Implementation Recommendation

### For Keycast: Pattern 1 (Shared Database, Shared Schema)

**Rationale:**
- You're already using SQLite (no RLS available anyway)
- Cost-effective for starting out
- Can migrate to Pattern 2 later if needed
- Simplest operational overhead
- Matches your current Cloud Run deployment model

### Phased Implementation Plan

**Phase 1: Database Multi-Tenancy (Backend)**
1. Add `tenants` table
2. Add `tenant_id` to all existing tables
3. Update unique constraints to be tenant-scoped
4. Create tenant resolution middleware (extract from Host header)
5. Add tenant context to all queries
6. Migration script for existing data (all becomes tenant_id=1)

**Phase 2: Frontend Multi-Tenancy**
1. Create `/public/tenants/{domain}/` directory structure
2. Update static file serving to check domain first
3. Fallback to `/public/_default/` if tenant-specific file not found
4. Add tenant configuration API endpoint

**Phase 3: OAuth Multi-Tenancy**
1. Scope OAuth apps to tenant
2. Update redirect_uri validation to include tenant domain check
3. Scope NIP-05 discovery to tenant
4. Update authorization flow to include tenant context

**Phase 4: Email & Configuration**
1. Per-tenant email sender configuration
2. Per-tenant relay URLs (optional)
3. Per-tenant CORS settings (optional)
4. Tenant admin dashboard

---

## Security Considerations

### Application-Level Filtering is Critical

Since SQLite has no RLS, **every query must include tenant_id filter**:

```rust
// BAD - vulnerable to tenant leakage
let user = sqlx::query_as!(User, "SELECT * FROM users WHERE id = ?", user_id)
    .fetch_one(&pool)
    .await?;

// GOOD - tenant-scoped
let user = sqlx::query_as!(
    User,
    "SELECT * FROM users WHERE id = ? AND tenant_id = ?",
    user_id,
    tenant_id
)
.fetch_one(&pool)
.await?;
```

### Recommendations:
1. **Create query helpers** that automatically inject tenant_id
2. **Code review** all queries for tenant filtering
3. **Integration tests** that verify tenant isolation
4. **Audit logging** for all cross-tenant access attempts
5. **Consider query wrapper** that enforces tenant_id at compile time

---

## Testing Strategy

### Tenant Isolation Tests
```rust
#[tokio::test]
async fn test_user_cannot_access_other_tenant_data() {
    // Create user in tenant A
    let tenant_a_user = create_user("alice.com", "user@alice.com").await;

    // Try to access from tenant B context
    let result = get_user_with_tenant("bob.com", tenant_a_user.id).await;

    assert!(result.is_err());
}
```

### Multi-Domain OAuth Tests
```rust
#[tokio::test]
async fn test_oauth_redirect_uri_must_match_tenant_domain() {
    let app = create_oauth_app("alice.com", "https://alice.com/callback").await;

    // Should reject redirect to different tenant
    let result = authorize_with_redirect(
        "bob.com",
        app.client_id,
        "https://bob.com/callback"
    ).await;

    assert!(result.is_err());
}
```

---

## Migration Strategy

### For Existing `oauth.divine.video` Deployment

1. **Add tenants table** with `divine.video` as tenant_id=1
2. **Add tenant_id columns** with DEFAULT 1 (all existing data becomes tenant 1)
3. **Deploy tenant middleware** that maps `oauth.divine.video` → tenant_id=1
4. **Verify existing functionality** still works
5. **Add new tenant** for testing
6. **Update unique constraints** to be tenant-scoped
7. **Gradually add new domains**

### Zero-Downtime Migration

```sql
-- Step 1: Add columns with defaults (non-breaking)
ALTER TABLE users ADD COLUMN tenant_id INTEGER NOT NULL DEFAULT 1;

-- Step 2: Deploy code that populates tenant_id but doesn't filter yet

-- Step 3: Verify all rows have tenant_id set

-- Step 4: Deploy code that filters by tenant_id

-- Step 5: Update constraints
DROP INDEX IF EXISTS users_email;
CREATE UNIQUE INDEX users_email_tenant ON users(tenant_id, email);
```

---

## Cost Analysis

### Pattern 1 (Shared DB): $0/month additional
- Single Cloud Run instance
- Single SQLite database
- Minimal complexity

### Pattern 2 (DB per tenant): ~$5/month per tenant
- Litestream replication per DB
- More Cloud Storage for backups
- Same Cloud Run cost (scales with total load)

### Pattern 3 (Separate instances): ~$30-50/month per tenant
- Separate Cloud Run service (min $7/month each)
- Separate Cloud SQL or storage
- Highest isolation, highest cost

---

## Alternative: Domain Mapping Without Multi-Tenancy

If you want **same data across all domains** (users can login at any domain), but **different UI**:

1. Keep single-tenant database (no changes)
2. Add domain → theme mapping
3. Serve different static files based on domain
4. All domains access same user pool

**Use case:** White-label OAuth provider where UI is different but user accounts are shared.

---

## Recommended Next Steps

1. **Clarify requirements** with Rabble:
   - Are users isolated per domain? (true multi-tenant)
   - Or can users login at any domain? (white-label)
   - What level of customization per domain? (full custom vs theme)
   - Expected number of domains? (5 vs 500)

2. **Prototype** Pattern 1 on a branch:
   - Add tenant_id to one table
   - Create tenant middleware
   - Serve static files from tenant subdirectory
   - Verify approach works

3. **Document** tenant isolation requirements

4. **Implement** phased rollout per above plan

---

## References

- [Azure Multi-Tenant Architecture Guide](https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/considerations/tenancy-models)
- [Multi-Tenant Database Patterns](https://www.bytebase.com/blog/multi-tenant-database-architecture-patterns-explained/)
- [OAuth Multi-Tenancy with Spring Security](https://docs.spring.io/spring-security/reference/reactive/oauth2/resource-server/multitenancy.html)
- [PostgreSQL Row Level Security](https://aws.amazon.com/blogs/database/multi-tenant-data-isolation-with-postgresql-row-level-security/)

---

*Generated: 2025-10-17 for keycast multi-domain research*
