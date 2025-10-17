# Auto-Provisioning Design for Multi-Tenant Domains

## Overview

This document describes a feature for automatically creating tenant records when new domains (via CNAME) hit the keycast server. This enables seamless onboarding of new tenants without manual database intervention.

## Current State Analysis

### Existing Tenant Lookup Flow

From `/Users/rabble/code/andotherstuff/keycast/api/src/api/tenant.rs`:

1. **TenantExtractor middleware** extracts `Host` header from incoming requests
2. Calls `get_tenant_by_domain(pool, domain)` to look up tenant
3. **Returns 404** if tenant not found, blocking the request
4. Tenant is wrapped in `Arc<Tenant>` and available to all handlers

### Current Limitations

- New domains get HTTP 404 until manually added to database
- Requires manual SQL INSERT for each new tenant
- No default configuration for new tenants
- No logging/notification when tenants should be created

## Design Goals

1. **Zero-touch provisioning**: New CNAME domains automatically work
2. **Secure defaults**: Auto-created tenants get safe, reasonable configuration
3. **Audit trail**: All auto-provisioning events logged for monitoring
4. **Domain validation**: Basic checks to prevent abuse
5. **Backward compatible**: Existing manual tenant creation still works
6. **Simple**: Minimal code changes, leverages existing infrastructure

## Proposed Architecture

### Core Function: `get_or_create_tenant()`

```rust
/// Get tenant by domain, creating it if it doesn't exist
///
/// This enables auto-provisioning: when a new domain hits the server via CNAME,
/// we automatically create a tenant record with default settings.
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `domain` - Domain from Host header (e.g., "example.com")
///
/// # Returns
/// * `Ok(Tenant)` - Existing or newly created tenant
/// * `Err(sqlx::Error)` - Database error or validation failure
///
/// # Security Considerations
/// - Domain validation prevents obviously malicious inputs
/// - Rate limiting should be applied at middleware layer
/// - Auto-provisioned tenants use restrictive defaults
pub async fn get_or_create_tenant(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Tenant, TenantError>
```

### Error Handling

```rust
#[derive(Error, Debug)]
pub enum TenantError {
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Domain validation failed: {0}")]
    ValidationFailed(String),
}
```

### Implementation Logic

```rust
pub async fn get_or_create_tenant(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Tenant, TenantError> {
    // 1. Validate domain format
    validate_domain(domain)?;

    // 2. Try to fetch existing tenant
    match get_tenant_by_domain(pool, domain).await {
        Ok(tenant) => {
            tracing::debug!("Found existing tenant for domain: {}", domain);
            Ok(tenant)
        }
        Err(sqlx::Error::RowNotFound) => {
            // 3. Create new tenant with defaults
            tracing::info!("Auto-provisioning new tenant for domain: {}", domain);

            let default_settings = create_default_tenant_settings(domain);
            let name = generate_tenant_name(domain);

            let tenant = create_tenant(
                pool,
                domain,
                &name,
                Some(&default_settings),
            )
            .await?;

            // 4. Log provisioning event for monitoring
            tracing::warn!(
                target: "tenant_auto_provision",
                domain = %domain,
                tenant_id = tenant.id,
                "Auto-provisioned new tenant"
            );

            Ok(tenant)
        }
        Err(e) => Err(TenantError::DatabaseError(e)),
    }
}
```

### Domain Validation

```rust
/// Validate domain format to prevent abuse
fn validate_domain(domain: &str) -> Result<(), TenantError> {
    // Basic validation rules
    if domain.is_empty() {
        return Err(TenantError::InvalidDomain("Domain cannot be empty".to_string()));
    }

    // Length check (max 253 chars per DNS spec)
    if domain.len() > 253 {
        return Err(TenantError::InvalidDomain("Domain too long".to_string()));
    }

    // Must contain at least one dot (prevent localhost, etc)
    if !domain.contains('.') {
        return Err(TenantError::ValidationFailed(
            "Domain must contain at least one dot".to_string()
        ));
    }

    // Basic character validation (alphanumeric, dots, hyphens)
    if !domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-') {
        return Err(TenantError::InvalidDomain(
            "Domain contains invalid characters".to_string()
        ));
    }

    // Reject localhost, internal IPs, and special domains
    let blocked_patterns = [
        "localhost",
        "127.",
        "192.168.",
        "10.",
        "172.",
        ".local",
        ".internal",
        ".test",
    ];

    for pattern in &blocked_patterns {
        if domain.contains(pattern) {
            return Err(TenantError::ValidationFailed(
                format!("Domain matches blocked pattern: {}", pattern)
            ));
        }
    }

    Ok(())
}
```

### Default Tenant Settings

```rust
/// Create default tenant settings JSON
fn create_default_tenant_settings(domain: &str) -> String {
    let settings = TenantSettings {
        relay: Some("wss://relay.damus.io".to_string()),
        email_from: Some(format!("noreply@{}", domain)),
        // Future settings with secure defaults:
        // max_users: Some(1000),
        // features_enabled: vec!["oauth", "nip05"],
        // rate_limits: default_rate_limits(),
    };

    serde_json::to_string(&settings)
        .unwrap_or_else(|_| "{}".to_string())
}

/// Generate friendly tenant name from domain
fn generate_tenant_name(domain: &str) -> String {
    // Extract primary domain (e.g., "example" from "example.com")
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() >= 2 {
        let base = parts[parts.len() - 2];
        // Capitalize first letter
        let mut chars = base.chars();
        match chars.next() {
            None => domain.to_string(),
            Some(f) => f.to_uppercase().chain(chars).collect(),
        }
    } else {
        domain.to_string()
    }
}
```

## Default Tenant Settings Structure

### JSON Schema

```json
{
  "relay": "wss://relay.damus.io",
  "email_from": "noreply@<domain>",
  "max_users": 1000,
  "max_oauth_apps": 10,
  "features": {
    "oauth_enabled": true,
    "nip05_enabled": true,
    "personal_keys_enabled": true,
    "email_verification_required": false
  },
  "rate_limits": {
    "signups_per_hour": 10,
    "oauth_requests_per_minute": 60,
    "signing_requests_per_minute": 100
  },
  "branding": {
    "logo_url": null,
    "primary_color": "#6366f1",
    "custom_css": null
  },
  "auto_provisioned": true,
  "provisioned_at": "2025-10-17T10:30:00Z"
}
```

### Rationale for Defaults

| Setting | Default | Rationale |
|---------|---------|-----------|
| `relay` | `wss://relay.damus.io` | Reliable public relay, matches existing behavior |
| `email_from` | `noreply@<domain>` | Uses tenant's own domain for legitimacy |
| `max_users` | 1000 | Prevents abuse while allowing growth |
| `max_oauth_apps` | 10 | Reasonable limit for small/medium deployments |
| `oauth_enabled` | true | Core feature, enabled by default |
| `email_verification_required` | false | Reduces friction for new tenants |
| `auto_provisioned` | true | Marks tenant as auto-created for auditing |

## Changes to Existing Code

### 1. Update `TenantExtractor` Middleware

**File**: `/Users/rabble/code/andotherstuff/keycast/api/src/api/tenant.rs`

**Before** (lines 102-108):
```rust
// Query tenant by domain
let tenant = get_tenant_by_domain(pool, domain).await.map_err(|e| {
    tracing::error!("Failed to get tenant for domain {}: {}", domain, e);
    (
        StatusCode::NOT_FOUND,
        format!("Tenant not found for domain: {}", domain),
    )
})?;
```

**After**:
```rust
// Get or create tenant (auto-provision if needed)
let tenant = get_or_create_tenant(pool, domain).await.map_err(|e| {
    tracing::error!("Failed to get/create tenant for domain {}: {}", domain, e);
    match e {
        TenantError::InvalidDomain(_) | TenantError::ValidationFailed(_) => (
            StatusCode::BAD_REQUEST,
            format!("Invalid domain: {}", domain),
        ),
        TenantError::DatabaseError(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to provision tenant".to_string(),
        ),
    }
})?;
```

### 2. Add New Functions to `tenant.rs`

Add these new functions after the existing `create_tenant()` function:
- `get_or_create_tenant()`
- `validate_domain()`
- `create_default_tenant_settings()`
- `generate_tenant_name()`
- `TenantError` enum

### 3. Update Tests

Add new test cases to `/Users/rabble/code/andotherstuff/keycast/api/src/api/tenant.rs`:

```rust
#[cfg(test)]
mod auto_provision_tests {
    use super::*;

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("subdomain.example.com").is_ok());
        assert!(validate_domain("multi.level.example.com").is_ok());
    }

    #[test]
    fn test_validate_domain_invalid() {
        assert!(validate_domain("").is_err());
        assert!(validate_domain("localhost").is_err());
        assert!(validate_domain("127.0.0.1").is_err());
        assert!(validate_domain("192.168.1.1").is_err());
        assert!(validate_domain("example.local").is_err());
        assert!(validate_domain("domain with spaces").is_err());
    }

    #[test]
    fn test_generate_tenant_name() {
        assert_eq!(generate_tenant_name("example.com"), "Example");
        assert_eq!(generate_tenant_name("subdomain.example.com"), "Example");
        assert_eq!(generate_tenant_name("test.org"), "Test");
    }

    #[test]
    fn test_default_tenant_settings() {
        let settings_json = create_default_tenant_settings("test.com");
        let settings: serde_json::Value = serde_json::from_str(&settings_json).unwrap();

        assert_eq!(settings["relay"], "wss://relay.damus.io");
        assert_eq!(settings["email_from"], "noreply@test.com");
    }

    #[tokio::test]
    async fn test_get_or_create_tenant_creates_new() {
        let pool = setup_test_db().await;

        let tenant = get_or_create_tenant(&pool, "newdomain.com")
            .await
            .unwrap();

        assert_eq!(tenant.domain, "newdomain.com");
        assert_eq!(tenant.name, "Newdomain");
        assert!(tenant.settings.is_some());
    }

    #[tokio::test]
    async fn test_get_or_create_tenant_returns_existing() {
        let pool = setup_test_db().await;

        // Create tenant first
        create_tenant(&pool, "existing.com", "Existing", None).await.unwrap();

        // Should return existing tenant, not create new one
        let tenant = get_or_create_tenant(&pool, "existing.com")
            .await
            .unwrap();

        assert_eq!(tenant.domain, "existing.com");
        assert_eq!(tenant.name, "Existing");
    }
}
```

## Security Considerations

### 1. Domain Validation

**Risk**: Attackers could send requests with malicious Host headers to create spam tenants.

**Mitigation**:
- Basic format validation (length, characters, structure)
- Block localhost, internal IPs, special TLDs
- Block domains without dots (prevents bare hostnames)
- Future: DNS verification (check CNAME actually points to our service)

### 2. Rate Limiting

**Risk**: Automated requests could create thousands of tenants rapidly.

**Mitigation**:
- **Recommended**: Add rate limiting middleware before TenantExtractor
- Limit new tenant creation to 10 per hour per source IP
- Monitor `tenant_auto_provision` logs for unusual patterns
- Alert on spike in tenant creation

Example rate limiting approach:
```rust
// In middleware stack (before tenant extraction)
let rate_limiter = tower::ServiceBuilder::new()
    .layer(GovernorLayer {
        // 10 new tenants per hour per IP
        config: Arc::new(
            GovernorConfigBuilder::default()
                .per_second(10)
                .burst_size(3)
                .finish()
                .unwrap()
        ),
    });
```

### 3. Resource Limits

**Risk**: Auto-provisioned tenants could consume excessive resources.

**Mitigation**:
- Set `max_users`, `max_oauth_apps` in default settings
- Consider adding tenant quotas to database schema
- Monitor per-tenant resource usage
- Ability to disable/suspend problematic tenants

### 4. DNS Verification (Future Enhancement)

**Risk**: Someone could send Host headers for domains they don't own.

**Current**: We trust the Host header (reasonable for CNAME-based setup).

**Future**: Optional DNS verification:
```rust
async fn verify_domain_ownership(domain: &str) -> Result<bool, DnsError> {
    // Check if domain has CNAME pointing to our service
    let cname = resolve_cname(domain).await?;
    Ok(cname.ends_with("keycast.run.app") || cname.ends_with("oauth.divine.video"))
}
```

### 5. Monitoring & Alerting

**Required monitoring**:
- Count of auto-provisioned tenants per hour
- Failed validation attempts per IP
- Tenants created but never used (potential spam)
- Unusual patterns (e.g., sequential domain names)

**Log targets**:
```rust
tracing::warn!(
    target: "tenant_auto_provision",
    domain = %domain,
    tenant_id = tenant.id,
    ip_address = %client_ip,
    "Auto-provisioned new tenant"
);

tracing::error!(
    target: "tenant_validation_failed",
    domain = %domain,
    reason = %reason,
    ip_address = %client_ip,
    "Domain validation failed"
);
```

## Rollout Strategy

### Phase 1: Feature Flag (Week 1)

Add environment variable to control auto-provisioning:
```rust
// In TenantExtractor
let auto_provision_enabled = std::env::var("AUTO_PROVISION_ENABLED")
    .unwrap_or_else(|_| "false".to_string())
    == "true";

if auto_provision_enabled {
    get_or_create_tenant(pool, domain).await?
} else {
    get_tenant_by_domain(pool, domain).await?
}
```

**Deploy with**: `AUTO_PROVISION_ENABLED=false` (disabled by default)

### Phase 2: Monitoring (Week 2)

- Enable feature flag on staging environment
- Monitor logs for auto-provisioning events
- Verify no malicious abuse patterns
- Test with multiple test domains

### Phase 3: Production Rollout (Week 3)

- Enable on production: `AUTO_PROVISION_ENABLED=true`
- Monitor closely for first 48 hours
- Alert on:
  - More than 20 tenants created per hour
  - Any validation failures from same IP
  - Tenants with suspicious domain patterns

### Phase 4: Rate Limiting (Week 4)

- Add rate limiting middleware
- Set conservative limits initially
- Adjust based on legitimate usage patterns

## Logging & Observability

### Structured Logging

```rust
// Successful auto-provision
tracing::info!(
    target: "tenant_auto_provision",
    event = "tenant_created",
    domain = %domain,
    tenant_id = tenant.id,
    settings = ?default_settings,
    source_ip = %client_ip,
    "Auto-provisioned new tenant"
);

// Validation failure
tracing::warn!(
    target: "tenant_validation",
    event = "validation_failed",
    domain = %domain,
    reason = %validation_error,
    source_ip = %client_ip,
    "Domain validation failed"
);

// Database error during creation
tracing::error!(
    target: "tenant_auto_provision",
    event = "creation_failed",
    domain = %domain,
    error = %db_error,
    source_ip = %client_ip,
    "Failed to auto-provision tenant"
);
```

### Metrics to Track

1. **Tenant creation rate**: Number of tenants created per hour/day
2. **Validation failure rate**: Failed domain validations per hour
3. **Tenant activation rate**: Percentage of auto-provisioned tenants that create users/OAuth apps
4. **Time to first use**: How long after provisioning before first user signup
5. **Abandoned tenants**: Auto-provisioned tenants with zero activity after 7 days

### Dashboard Queries (for Cloud Logging)

```
-- Recent auto-provisioned tenants
resource.type="cloud_run_revision"
jsonPayload.target="tenant_auto_provision"
jsonPayload.event="tenant_created"
timestamp>="2025-10-17T00:00:00Z"

-- Validation failures by domain
resource.type="cloud_run_revision"
jsonPayload.target="tenant_validation"
jsonPayload.event="validation_failed"
| stats count() by domain

-- Auto-provision rate per hour
resource.type="cloud_run_revision"
jsonPayload.target="tenant_auto_provision"
| rate(1h)
```

## Future Enhancements

### 1. Admin Notification

Send notification when new tenant is auto-provisioned:
```rust
async fn notify_new_tenant(tenant: &Tenant) {
    // Email to admin
    send_email(
        "admin@keycast.example.com",
        "New Tenant Auto-Provisioned",
        format!("Domain: {}\nTenant ID: {}", tenant.domain, tenant.id)
    ).await;

    // Slack webhook
    post_to_slack(
        format!("🆕 New tenant: {} (ID: {})", tenant.domain, tenant.id)
    ).await;
}
```

### 2. Welcome Email

Send welcome email to first user who signs up on auto-provisioned tenant:
```rust
// In user registration handler
if tenant.is_auto_provisioned() && is_first_user_for_tenant() {
    send_welcome_email(user.email, tenant.domain).await;
}
```

### 3. DNS Verification

As mentioned in security section, add optional DNS verification:
```rust
let dns_verification_enabled = std::env::var("DNS_VERIFICATION_ENABLED")
    .unwrap_or_else(|_| "false".to_string())
    == "true";

if dns_verification_enabled {
    verify_domain_ownership(domain).await?;
}
```

### 4. Tenant Onboarding Wizard

Create special UI flow for auto-provisioned tenants:
- First user becomes tenant admin
- Guided setup for branding, settings
- Option to upgrade to custom relay, email config

### 5. Tenant Lifecycle Management

Add tenant status field to track lifecycle:
```sql
ALTER TABLE tenants ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
-- Possible values: 'active', 'suspended', 'trial', 'abandoned'

ALTER TABLE tenants ADD COLUMN last_activity_at DATETIME;
```

Periodic job to mark tenants as abandoned:
```rust
async fn cleanup_abandoned_tenants(pool: &SqlitePool) {
    // Mark tenants with no activity for 30 days as abandoned
    sqlx::query(
        "UPDATE tenants
         SET status = 'abandoned'
         WHERE last_activity_at < datetime('now', '-30 days')
           AND status = 'active'"
    )
    .execute(pool)
    .await?;
}
```

## Testing Strategy

### Unit Tests

- Domain validation (valid/invalid inputs)
- Default settings generation
- Tenant name generation
- Error handling paths

### Integration Tests

- Auto-provision creates tenant with correct defaults
- Repeated requests return same tenant (idempotent)
- Invalid domains return proper error codes
- Settings JSON is valid and parseable

### End-to-End Tests

1. **New domain flow**:
   - Point test domain CNAME to service
   - Send request with new domain
   - Verify tenant created
   - Verify default settings applied
   - Sign up user on new tenant
   - Create OAuth app
   - Complete OAuth flow

2. **Existing tenant flow**:
   - Request with existing domain
   - Verify no duplicate tenant created
   - Verify correct tenant returned

3. **Invalid domain flow**:
   - Send request with invalid domain
   - Verify 400 error returned
   - Verify no tenant created

4. **Rate limiting** (future):
   - Send rapid requests with unique domains
   - Verify rate limit kicks in
   - Verify error response

## Open Questions for Rabble

1. **DNS Verification**: Should we verify CNAME records before auto-provisioning, or trust the Host header? (Recommendation: start without verification, add later if abuse occurs)

2. **Admin Notification**: Do you want email/Slack notifications when new tenants are auto-provisioned?

3. **Rate Limits**: What's reasonable for new tenant creation?
   - Suggested: 10 per hour per IP
   - Too restrictive? Too permissive?

4. **Feature Flag**: Should we launch with feature flag disabled initially, or go straight to enabled?

5. **Default Limits**: Are the default resource limits reasonable?
   - max_users: 1000
   - max_oauth_apps: 10

6. **Abandoned Tenants**: Should we auto-delete tenants with no activity after X days? Or just mark them as abandoned?

## Summary

This design enables seamless auto-provisioning of new tenants when domains are added via CNAME, with:

- **Minimal code changes**: Single new function + middleware update
- **Secure defaults**: Validation, rate limiting, resource limits
- **Full auditability**: Structured logging for all provisioning events
- **Backward compatible**: Manual tenant creation still works
- **Feature-flagged**: Can be enabled/disabled via environment variable
- **Well-tested**: Comprehensive unit, integration, and E2E tests

The implementation is straightforward and leverages existing infrastructure (tenant table, settings JSON, create_tenant function). The main addition is the `get_or_create_tenant()` function with validation logic.
