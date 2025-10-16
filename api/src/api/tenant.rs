// ABOUTME: Multi-tenancy support for domain-based tenant isolation
// ABOUTME: Extracts tenant from Host header and provides tenant context to all handlers

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;

/// Represents a tenant in the system
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: i64,
    pub domain: String,
    pub name: String,
    pub settings: Option<String>, // JSON
    pub created_at: String,
    pub updated_at: String,
}

/// Tenant settings parsed from JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSettings {
    pub relay: Option<String>,
    pub email_from: Option<String>,
    // Add more settings as needed
}

impl Tenant {
    /// Get parsed settings
    pub fn get_settings(&self) -> Result<TenantSettings, serde_json::Error> {
        match &self.settings {
            Some(json) => serde_json::from_str(json),
            None => Ok(TenantSettings {
                relay: None,
                email_from: None,
            }),
        }
    }

    /// Get relay URL with fallback to default
    pub fn relay_url(&self) -> String {
        self.get_settings()
            .ok()
            .and_then(|s| s.relay)
            .unwrap_or_else(|| "wss://relay.damus.io".to_string())
    }

    /// Get email from address with fallback
    pub fn email_from(&self) -> String {
        self.get_settings()
            .ok()
            .and_then(|s| s.email_from)
            .unwrap_or_else(|| format!("noreply@{}", self.domain))
    }
}

/// Extractor for tenant context
/// Usage in handlers: `async fn handler(tenant: TenantExtractor, ...)`
pub struct TenantExtractor(pub Arc<Tenant>);

#[async_trait]
impl<S> FromRequestParts<S> for TenantExtractor
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract Host header
        let host = parts
            .headers
            .get("host")
            .ok_or((
                StatusCode::BAD_REQUEST,
                "Missing Host header".to_string(),
            ))?
            .to_str()
            .map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "Invalid Host header".to_string(),
                )
            })?;

        // Remove port if present (e.g., "localhost:3000" -> "localhost")
        let domain = host.split(':').next().unwrap_or(host);

        // Get database pool from global state
        let pool = crate::state::get_db_pool()
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database not initialized".to_string(),
                )
            })?;

        // Query tenant by domain
        let tenant = get_tenant_by_domain(pool, domain).await.map_err(|e| {
            tracing::error!("Failed to get tenant for domain {}: {}", domain, e);
            (
                StatusCode::NOT_FOUND,
                format!("Tenant not found for domain: {}", domain),
            )
        })?;

        Ok(TenantExtractor(Arc::new(tenant)))
    }
}

/// Get tenant by domain from database
pub async fn get_tenant_by_domain(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Tenant, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, domain, name, settings, created_at, updated_at
         FROM tenants
         WHERE domain = ?",
    )
    .bind(domain)
    .fetch_one(pool)
    .await
}

/// Get tenant by ID from database
pub async fn get_tenant_by_id(
    pool: &SqlitePool,
    tenant_id: i64,
) -> Result<Tenant, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, domain, name, settings, created_at, updated_at
         FROM tenants
         WHERE id = ?",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
}

/// Create a new tenant
pub async fn create_tenant(
    pool: &SqlitePool,
    domain: &str,
    name: &str,
    settings: Option<&str>,
) -> Result<Tenant, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "INSERT INTO tenants (domain, name, settings, created_at, updated_at)
         VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
         RETURNING id, domain, name, settings, created_at, updated_at",
    )
    .bind(domain)
    .bind(name)
    .bind(settings)
    .fetch_one(pool)
    .await
}

/// List all tenants
pub async fn list_tenants(pool: &SqlitePool) -> Result<Vec<Tenant>, sqlx::Error> {
    sqlx::query_as::<_, Tenant>(
        "SELECT id, domain, name, settings, created_at, updated_at
         FROM tenants
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_settings_parsing() {
        let tenant = Tenant {
            id: 1,
            domain: "test.com".to_string(),
            name: "Test".to_string(),
            settings: Some(r#"{"relay":"wss://test.relay","email_from":"noreply@test.com"}"#.to_string()),
            created_at: "2025-01-01".to_string(),
            updated_at: "2025-01-01".to_string(),
        };

        let settings = tenant.get_settings().unwrap();
        assert_eq!(settings.relay, Some("wss://test.relay".to_string()));
        assert_eq!(settings.email_from, Some("noreply@test.com".to_string()));
    }

    #[test]
    fn test_tenant_relay_url_fallback() {
        let tenant = Tenant {
            id: 1,
            domain: "test.com".to_string(),
            name: "Test".to_string(),
            settings: None,
            created_at: "2025-01-01".to_string(),
            updated_at: "2025-01-01".to_string(),
        };

        assert_eq!(tenant.relay_url(), "wss://relay.damus.io");
    }

    #[test]
    fn test_tenant_email_from_fallback() {
        let tenant = Tenant {
            id: 1,
            domain: "test.com".to_string(),
            name: "Test".to_string(),
            settings: None,
            created_at: "2025-01-01".to_string(),
            updated_at: "2025-01-01".to_string(),
        };

        assert_eq!(tenant.email_from(), "noreply@test.com");
    }
}
