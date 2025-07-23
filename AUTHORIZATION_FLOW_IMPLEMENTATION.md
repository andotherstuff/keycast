# Authorization Flow Module - Implementation Guide

## Overview

The authorization_flow module is the critical missing piece that enables dynamic app discovery and user-controlled authorization. This module orchestrates the entire flow from app connection attempt to active authorization.

## Module Structure

```
core/src/authorization_flow/
├── mod.rs                    # Module exports and traits
├── connection_attempt.rs     # App connection tracking
├── authorization_request.rs  # User approval flow
├── flow_service.rs          # Main orchestration service
└── policy_templates.rs      # Pre-defined policy templates
```

## Detailed Implementation

### 1. connection_attempt.rs

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Represents an app's attempt to connect to a user
#[derive(Debug, Serialize, Deserialize)]
pub struct AppConnectionAttempt {
    pub id: String,
    pub app_domain: String,
    pub app_pubkey: Option<String>,
    pub user_nip05: String,
    pub connection_metadata: ConnectionMetadata,
    pub attempted_at: DateTime<Utc>,
    pub processed: bool,
}

/// Metadata provided by the connecting app
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectionMetadata {
    pub app_name: String,
    pub app_description: Option<String>,
    pub app_icon: Option<String>,
    pub requested_permissions: Vec<String>,
    pub user_agent: Option<String>,
    pub relay_urls: Vec<String>,
}

impl AppConnectionAttempt {
    /// Create a new connection attempt
    pub async fn create(
        pool: &SqlitePool,
        app_domain: &str,
        app_pubkey: Option<&str>,
        user_nip05: &str,
        metadata: ConnectionMetadata,
    ) -> Result<Self, sqlx::Error> {
        let id = Uuid::new_v4().to_string();
        let metadata_json = serde_json::to_string(&metadata)?;
        
        sqlx::query!(
            r#"
            INSERT INTO app_connection_attempts (
                id, app_domain, app_pubkey, user_nip05, 
                connection_metadata, attempted_at, processed
            )
            VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, FALSE)
            "#,
            id,
            app_domain,
            app_pubkey,
            user_nip05,
            metadata_json,
        )
        .execute(pool)
        .await?;
        
        Ok(Self {
            id,
            app_domain: app_domain.to_string(),
            app_pubkey: app_pubkey.map(String::from),
            user_nip05: user_nip05.to_string(),
            connection_metadata: metadata,
            attempted_at: Utc::now(),
            processed: false,
        })
    }
    
    /// Get unprocessed attempts for a user
    pub async fn get_unprocessed_for_user(
        pool: &SqlitePool,
        user_nip05: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT * FROM app_connection_attempts
            WHERE user_nip05 = ?1 AND processed = FALSE
            ORDER BY attempted_at DESC
            "#,
            user_nip05
        )
        .fetch_all(pool)
        .await?;
        
        // Convert rows to AppConnectionAttempt
        rows.into_iter()
            .map(|row| {
                let metadata: ConnectionMetadata = 
                    serde_json::from_str(&row.connection_metadata)?;
                Ok(AppConnectionAttempt {
                    id: row.id,
                    app_domain: row.app_domain,
                    app_pubkey: row.app_pubkey,
                    user_nip05: row.user_nip05,
                    connection_metadata: metadata,
                    attempted_at: row.attempted_at,
                    processed: row.processed,
                })
            })
            .collect()
    }
    
    /// Mark attempt as processed
    pub async fn mark_processed(
        pool: &SqlitePool,
        id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE app_connection_attempts SET processed = TRUE WHERE id = ?1",
            id
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
```

### 2. authorization_request.rs

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationRequestStatus {
    Pending,
    Approved,
    Rejected,
}

/// A request awaiting user approval
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub id: String,
    pub user_id: String,
    pub app_domain: String,
    pub app_name: String,
    pub app_description: Option<String>,
    pub app_icon_url: Option<String>,
    pub requested_permissions: Vec<String>,
    pub status: AuthorizationRequestStatus,
    pub created_at: DateTime<Utc>,
    pub responded_at: Option<DateTime<Utc>>,
}

impl AuthorizationRequest {
    /// Create from connection attempt
    pub async fn create_from_attempt(
        pool: &SqlitePool,
        user_id: &str,
        attempt: &AppConnectionAttempt,
    ) -> Result<Self, sqlx::Error> {
        let id = Uuid::new_v4().to_string();
        let permissions_json = serde_json::to_string(
            &attempt.connection_metadata.requested_permissions
        )?;
        
        sqlx::query!(
            r#"
            INSERT INTO authorization_requests (
                id, user_id, app_domain, app_name, 
                app_description, app_icon_url, requested_permissions,
                status, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', CURRENT_TIMESTAMP)
            "#,
            id,
            user_id,
            attempt.app_domain,
            attempt.connection_metadata.app_name,
            attempt.connection_metadata.app_description,
            attempt.connection_metadata.app_icon,
            permissions_json,
        )
        .execute(pool)
        .await?;
        
        Ok(Self {
            id,
            user_id: user_id.to_string(),
            app_domain: attempt.app_domain.clone(),
            app_name: attempt.connection_metadata.app_name.clone(),
            app_description: attempt.connection_metadata.app_description.clone(),
            app_icon_url: attempt.connection_metadata.app_icon.clone(),
            requested_permissions: attempt.connection_metadata.requested_permissions.clone(),
            status: AuthorizationRequestStatus::Pending,
            created_at: Utc::now(),
            responded_at: None,
        })
    }
    
    /// Get pending requests for user
    pub async fn get_pending_for_user(
        pool: &SqlitePool,
        user_id: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT * FROM authorization_requests
            WHERE user_id = ?1 AND status = 'pending'
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(pool)
        .await?;
        
        // Convert rows
        rows.into_iter()
            .map(|row| {
                let permissions: Vec<String> = 
                    serde_json::from_str(&row.requested_permissions)?;
                Ok(AuthorizationRequest {
                    id: row.id,
                    user_id: row.user_id,
                    app_domain: row.app_domain,
                    app_name: row.app_name,
                    app_description: row.app_description,
                    app_icon_url: row.app_icon_url,
                    requested_permissions: permissions,
                    status: AuthorizationRequestStatus::Pending,
                    created_at: row.created_at,
                    responded_at: row.responded_at,
                })
            })
            .collect()
    }
    
    /// Update status
    pub async fn update_status(
        pool: &SqlitePool,
        id: &str,
        status: AuthorizationRequestStatus,
    ) -> Result<(), sqlx::Error> {
        let status_str = match status {
            AuthorizationRequestStatus::Pending => "pending",
            AuthorizationRequestStatus::Approved => "approved",
            AuthorizationRequestStatus::Rejected => "rejected",
        };
        
        sqlx::query!(
            r#"
            UPDATE authorization_requests 
            SET status = ?1, responded_at = CURRENT_TIMESTAMP
            WHERE id = ?2
            "#,
            status_str,
            id
        )
        .execute(pool)
        .await?;
        
        Ok(())
    }
}
```

### 3. flow_service.rs

```rust
use crate::encryption::KeyManager;
use crate::types::{
    application::Application,
    user_enhanced::UserEnhanced,
    user_key::UserKey,
};
use nostr_sdk::prelude::*;
use sqlx::SqlitePool;
use uuid::Uuid;

use super::{AppConnectionAttempt, AuthorizationRequest, ConnectionMetadata};

/// Main service orchestrating the authorization flow
pub struct AuthorizationFlowService {
    pool: SqlitePool,
    key_manager: Box<dyn KeyManager>,
}

impl AuthorizationFlowService {
    pub fn new(pool: SqlitePool, key_manager: Box<dyn KeyManager>) -> Self {
        Self { pool, key_manager }
    }
    
    /// Handle incoming NIP-46 connection request
    pub async fn handle_connection_request(
        &self,
        app_domain: &str,
        app_pubkey: Option<&str>,
        user_nip05: &str,
        metadata: ConnectionMetadata,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // 1. Record connection attempt
        let attempt = AppConnectionAttempt::create(
            &self.pool,
            app_domain,
            app_pubkey,
            user_nip05,
            metadata,
        ).await?;
        
        // 2. Find user by NIP-05
        let user = UserEnhanced::find_by_nip05(&self.pool, user_nip05)
            .await?
            .ok_or("User not found")?;
        
        // 3. Register/update app
        let app = Application::register_or_update(
            &self.pool,
            app_domain,
            &attempt.connection_metadata.app_name,
            // Convert metadata to AppMetadata
        ).await?;
        
        // 4. Create authorization request
        let request = AuthorizationRequest::create_from_attempt(
            &self.pool,
            &user.id,
            &attempt,
        ).await?;
        
        // 5. Mark attempt as processed
        AppConnectionAttempt::mark_processed(&self.pool, &attempt.id).await?;
        
        // 6. Notify user (webhook, websocket, etc.)
        self.notify_user_of_request(&user, &request).await?;
        
        Ok(request.id)
    }
    
    /// Approve authorization request
    pub async fn approve_request(
        &self,
        request_id: &str,
        user_id: &str,
        user_key_id: &str,
        policy_id: u32,
        max_uses: Option<u16>,
        expires_in_hours: Option<u32>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // 1. Get and validate request
        let request = self.get_request(request_id, user_id).await?;
        if request.status != AuthorizationRequestStatus::Pending {
            return Err("Request already processed".into());
        }
        
        // 2. Get app
        let app = Application::find_by_domain(&self.pool, &request.app_domain)
            .await?
            .ok_or("App not found")?;
        
        // 3. Generate bunker keys
        let bunker_keys = Keys::generate();
        let bunker_secret = bunker_keys.secret_key().as_secret_bytes();
        let encrypted_bunker_secret = self.key_manager.encrypt(bunker_secret).await?;
        
        // 4. Create authorization
        let connection_secret = Uuid::new_v4().to_string();
        let expires_at = expires_in_hours.map(|hours| {
            Utc::now() + chrono::Duration::hours(hours as i64)
        });
        
        let auth_id = sqlx::query!(
            r#"
            INSERT INTO authorizations (
                user_id, user_key_id, application_id, policy_id,
                secret, bunker_public_key, bunker_secret, relays,
                max_uses, expires_at, status, requested_at, approved_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 
                    'active', ?11, CURRENT_TIMESTAMP)
            RETURNING id
            "#,
            user_id,
            user_key_id,
            app.id,
            policy_id,
            connection_secret,
            bunker_keys.public_key().to_hex(),
            encrypted_bunker_secret,
            serde_json::to_string(&request.connection_metadata.relay_urls)?,
            max_uses,
            expires_at,
            request.created_at,
        )
        .fetch_one(&self.pool)
        .await?
        .id;
        
        // 5. Update request status
        AuthorizationRequest::update_status(
            &self.pool,
            request_id,
            AuthorizationRequestStatus::Approved,
        ).await?;
        
        // 6. Spawn signer daemon (via signer manager notification)
        self.notify_signer_manager(auth_id).await?;
        
        Ok(auth_id.to_string())
    }
    
    /// Reject authorization request
    pub async fn reject_request(
        &self,
        request_id: &str,
        user_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request = self.get_request(request_id, user_id).await?;
        if request.status != AuthorizationRequestStatus::Pending {
            return Err("Request already processed".into());
        }
        
        AuthorizationRequest::update_status(
            &self.pool,
            request_id,
            AuthorizationRequestStatus::Rejected,
        ).await?;
        
        Ok(())
    }
    
    // Helper methods
    async fn get_request(
        &self,
        request_id: &str,
        user_id: &str,
    ) -> Result<AuthorizationRequest, Box<dyn std::error::Error>> {
        // Implementation
    }
    
    async fn notify_user_of_request(
        &self,
        user: &UserEnhanced,
        request: &AuthorizationRequest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Send notification via websocket, push notification, etc.
        Ok(())
    }
    
    async fn notify_signer_manager(
        &self,
        auth_id: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Trigger signer manager to spawn new process
        // Could use database trigger, Redis pub/sub, etc.
        Ok(())
    }
}
```

### 4. policy_templates.rs

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyTemplate {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub icon: String,
}

/// Pre-defined policy templates for common app types
pub struct PolicyTemplates;

impl PolicyTemplates {
    /// Social media apps (Nostr clients)
    pub fn social_media() -> PolicyTemplate {
        PolicyTemplate {
            name: "Social Media".to_string(),
            description: "Post notes, update profile, interact with others".to_string(),
            permissions: vec![
                "sign_event:1".to_string(),     // Short text note
                "sign_event:0".to_string(),     // Metadata
                "sign_event:3".to_string(),     // Contacts
                "sign_event:6".to_string(),     // Repost
                "sign_event:7".to_string(),     // Reaction
                "nip04_encrypt".to_string(),    // Encrypt DMs
                "nip04_decrypt".to_string(),    // Decrypt DMs
                "get_public_key".to_string(),
            ],
            icon: "🗣️".to_string(),
        }
    }
    
    /// Read-only apps
    pub fn read_only() -> PolicyTemplate {
        PolicyTemplate {
            name: "Read Only".to_string(),
            description: "View content without posting".to_string(),
            permissions: vec![
                "get_public_key".to_string(),
                "nip04_decrypt".to_string(),    // Read DMs
            ],
            icon: "👁️".to_string(),
        }
    }
    
    /// Marketplace/commerce apps
    pub fn marketplace() -> PolicyTemplate {
        PolicyTemplate {
            name: "Marketplace".to_string(),
            description: "Buy, sell, and trade".to_string(),
            permissions: vec![
                "sign_event:30017".to_string(), // Stall
                "sign_event:30018".to_string(), // Product
                "sign_event:30019".to_string(), // Marketplace
                "sign_event:4".to_string(),     // Encrypted DM
                "sign_event:9734".to_string(),  // Zap request
                "nip04_encrypt".to_string(),
                "nip04_decrypt".to_string(),
                "get_public_key".to_string(),
            ],
            icon: "🛒".to_string(),
        }
    }
    
    /// Gaming apps
    pub fn gaming() -> PolicyTemplate {
        PolicyTemplate {
            name: "Gaming".to_string(),
            description: "Play games and track scores".to_string(),
            permissions: vec![
                "sign_event:30311".to_string(), // Live activity
                "sign_event:1".to_string(),     // Game updates
                "sign_event:30315".to_string(), // User status
                "get_public_key".to_string(),
            ],
            icon: "🎮".to_string(),
        }
    }
    
    /// Wallet/financial apps
    pub fn wallet() -> PolicyTemplate {
        PolicyTemplate {
            name: "Wallet".to_string(),
            description: "Send and receive payments".to_string(),
            permissions: vec![
                "sign_event:9734".to_string(),  // Zap request
                "sign_event:9735".to_string(),  // Zap
                "sign_event:57".to_string(),    // Lightning invoice
                "nip04_encrypt".to_string(),    // Encrypt payment info
                "nip04_decrypt".to_string(),
                "get_public_key".to_string(),
            ],
            icon: "💰".to_string(),
        }
    }
    
    /// Get all templates
    pub fn all() -> Vec<PolicyTemplate> {
        vec![
            Self::social_media(),
            Self::read_only(),
            Self::marketplace(),
            Self::gaming(),
            Self::wallet(),
        ]
    }
    
    /// Find template by name
    pub fn find_by_name(name: &str) -> Option<PolicyTemplate> {
        Self::all().into_iter().find(|t| t.name == name)
    }
}
```

### 5. mod.rs

```rust
// ABOUTME: Dynamic authorization flow for personal Nostr auth system
// ABOUTME: Handles app connection attempts, pending authorizations, and user approval flow

mod connection_attempt;
mod authorization_request;
mod flow_service;
mod policy_templates;

pub use connection_attempt::{AppConnectionAttempt, ConnectionMetadata};
pub use authorization_request::{AuthorizationRequest, AuthorizationRequestStatus};
pub use flow_service::AuthorizationFlowService;
pub use policy_templates::{PolicyTemplate, PolicyTemplates};

// Re-export error types
pub use flow_service::AuthorizationFlowError;
```

## Integration Points

### 1. NIP-46 Connection Handler
When an app tries to connect via NIP-46:
```rust
// In the NIP-46 handler
let flow_service = AuthorizationFlowService::new(pool, key_manager);
let request_id = flow_service.handle_connection_request(
    "app.example.com",
    Some("app_pubkey_hex"),
    "alice@keycast.app",
    ConnectionMetadata {
        app_name: "Example App".to_string(),
        app_description: Some("A demo Nostr client".to_string()),
        app_icon: Some("https://example.com/icon.png".to_string()),
        requested_permissions: vec!["sign_event:1".to_string()],
        user_agent: Some("ExampleApp/1.0".to_string()),
        relay_urls: vec!["wss://relay.damus.io".to_string()],
    }
).await?;
```

### 2. API Endpoints
```rust
// GET /api/auth/requests
pub async fn get_pending_requests(
    State(pool): State<SqlitePool>,
    user: User, // From auth middleware
) -> Result<Json<Vec<AuthorizationRequest>>, ApiError> {
    let requests = AuthorizationRequest::get_pending_for_user(&pool, &user.id).await?;
    Ok(Json(requests))
}

// POST /api/auth/requests/:id/approve
pub async fn approve_request(
    State(pool): State<SqlitePool>,
    Path(request_id): Path<String>,
    user: User,
    Json(params): Json<ApproveParams>,
) -> Result<Json<ApprovalResponse>, ApiError> {
    let flow_service = AuthorizationFlowService::new(pool, get_key_manager());
    let auth_id = flow_service.approve_request(
        &request_id,
        &user.id,
        &params.user_key_id,
        params.policy_id,
        params.max_uses,
        params.expires_in_hours,
    ).await?;
    
    Ok(Json(ApprovalResponse { 
        authorization_id: auth_id,
        bunker_url: generate_bunker_url(&auth_id).await?,
    }))
}
```

### 3. Signer Manager Integration
The signer manager needs to watch for new authorizations:
```rust
// In signer_manager health check
let new_auths = sqlx::query!(
    "SELECT id FROM authorizations WHERE id NOT IN (SELECT auth_id FROM running_signers)"
)
.fetch_all(&pool)
.await?;

for auth in new_auths {
    spawn_signer_process(auth.id).await?;
}
```

## Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_connection_attempt_creation() {
        let pool = create_test_db().await;
        let metadata = ConnectionMetadata {
            app_name: "Test App".to_string(),
            // ...
        };
        
        let attempt = AppConnectionAttempt::create(
            &pool,
            "test.app",
            None,
            "user@test.com",
            metadata,
        ).await.unwrap();
        
        assert_eq!(attempt.app_domain, "test.app");
        assert!(!attempt.processed);
    }
}
```

### Integration Tests
- Full flow from connection attempt to authorization
- Policy template application
- Multi-user scenarios
- Rejection flows
- Expiration handling

## Migration Notes

1. The authorization_flow module needs to be added to `core/src/lib.rs`
2. Update type imports in API handlers
3. Add flow service to application state
4. Wire up WebSocket/SSE for real-time notifications
5. Add database indexes for performance:
   ```sql
   CREATE INDEX idx_connection_attempts_nip05_unprocessed 
   ON app_connection_attempts(user_nip05, processed);
   
   CREATE INDEX idx_auth_requests_user_pending 
   ON authorization_requests(user_id, status);
   ```

## Next Steps

1. Create the module files
2. Implement basic types
3. Add unit tests
4. Wire up first API endpoint
5. Test with a real NIP-46 connection
6. Add WebSocket notifications
7. Implement policy template UI