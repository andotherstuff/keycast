// ABOUTME: Dynamic authorization flow for personal Nostr auth system
// ABOUTME: Handles app connection attempts, pending authorizations, and user approval flow

use crate::encryption::{KeyManager, KeyManagerError};
use crate::types::{
    application::{Application, AppMetadata, ApplicationError},
    authorization::AuthorizationError,
    user_enhanced::UserEnhanced,
    user_key::UserKeyError,
};
use chrono::{DateTime, Utc};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum AuthorizationFlowError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Application error: {0}")]
    Application(#[from] ApplicationError),
    #[error("Authorization error: {0}")]
    Authorization(#[from] AuthorizationError),
    #[error("User key error: {0}")]
    UserKey(#[from] UserKeyError),
    #[error("Encryption error: {0}")]
    Encryption(#[from] KeyManagerError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid NIP-05 identifier")]
    InvalidNip05,
    #[error("User not found")]
    UserNotFound,
    #[error("No primary key for user")]
    NoPrimaryKey,
    #[error("Authorization request not found")]
    RequestNotFound,
    #[error("Authorization request already processed")]
    RequestAlreadyProcessed,
    #[error("Invalid request status")]
    InvalidStatus,
}

/// Represents a connection attempt from an app
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

/// Metadata about the connection attempt
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConnectionMetadata {
    pub app_name: String,
    pub app_description: Option<String>,
    pub app_icon: Option<String>,
    pub requested_permissions: Vec<String>,
    pub user_agent: Option<String>,
    pub relay_urls: Vec<String>,
}

/// Authorization request pending user approval
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationRequestStatus {
    Pending,
    Approved,
    Rejected,
}

/// Service for managing the dynamic authorization flow
pub struct AuthorizationFlowService {
    pool: SqlitePool,
    key_manager: Box<dyn KeyManager>,
}

impl AuthorizationFlowService {
    pub fn new(pool: SqlitePool, key_manager: Box<dyn KeyManager>) -> Self {
        Self { pool, key_manager }
    }
    
    /// Record a connection attempt from an app
    pub async fn record_connection_attempt(
        &self,
        app_domain: &str,
        app_pubkey: Option<&str>,
        user_nip05: &str,
        metadata: ConnectionMetadata,
    ) -> Result<String, AuthorizationFlowError> {
        let id = Uuid::new_v4().to_string();
        let metadata_json = serde_json::to_string(&metadata)?;
        
        sqlx::query(
            r#"
            INSERT INTO app_connection_attempts (
                id, app_domain, app_pubkey, user_nip05, 
                connection_metadata, attempted_at, processed
            )
            VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP, FALSE)
            "#,
        )
        .bind(&id)
        .bind(app_domain)
        .bind(app_pubkey)
        .bind(user_nip05)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await?;
        
        // Create authorization request for user
        self.create_authorization_request_from_attempt(&id).await?;
        
        Ok(id)
    }
    
    /// Create an authorization request from a connection attempt
    async fn create_authorization_request_from_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<String, AuthorizationFlowError> {
        // Get the connection attempt
        let row = sqlx::query!(
            r#"
            SELECT id, app_domain, app_pubkey, user_nip05, 
                   connection_metadata, attempted_at, processed
            FROM app_connection_attempts
            WHERE id = ?1
            "#,
            attempt_id
        )
        .fetch_one(&self.pool)
        .await?;
        
        // Validate required fields
        let user_nip05 = row.user_nip05.ok_or(AuthorizationFlowError::InvalidNip05)?;
        let connection_metadata = row.connection_metadata.ok_or(AuthorizationFlowError::InvalidStatus)?;
        
        // Parse NIP-05 to get username
        let parts: Vec<&str> = user_nip05.split('@').collect();
        if parts.len() != 2 {
            return Err(AuthorizationFlowError::InvalidNip05);
        }
        
        // Find user by NIP-05
        let user = UserEnhanced::find_by_nip05(&self.pool, &user_nip05)
            .await
            .map_err(|_| AuthorizationFlowError::UserNotFound)?;
        
        // Parse metadata
        let metadata: ConnectionMetadata = serde_json::from_str(&connection_metadata)?;
        
        // Register or update app
        let app = Application::register_or_update(
            &self.pool,
            &row.app_domain,
            &metadata.app_name,
            AppMetadata {
                requested_permissions: metadata.requested_permissions.clone(),
                callback_url: None,
                version: None,
                developer: None,
                support_url: None,
                privacy_policy_url: None,
                terms_url: None,
                extra: serde_json::Map::new(),
            },
        ).await?;
        
        // Update app with additional info if available
        if metadata.app_description.is_some() || metadata.app_icon.is_some() || row.app_pubkey.is_some() {
            let mut updated_app = app.clone();
            updated_app.update_info(
                &self.pool,
                metadata.app_description.clone(),
                metadata.app_icon.clone(),
                row.app_pubkey.clone(),
            ).await?;
        }
        
        // Create authorization request
        let request_id = Uuid::new_v4().to_string();
        let permissions_json = serde_json::to_string(&metadata.requested_permissions)?;
        
        sqlx::query(
            r#"
            INSERT INTO authorization_requests (
                id, user_id, app_domain, app_name, 
                app_description, app_icon_url, requested_permissions,
                status, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', CURRENT_TIMESTAMP)
            "#,
        )
        .bind(&request_id)
        .bind(&user.id)
        .bind(&row.app_domain)
        .bind(&metadata.app_name)
        .bind(&metadata.app_description)
        .bind(&metadata.app_icon)
        .bind(&permissions_json)
        .execute(&self.pool)
        .await?;
        
        // Mark attempt as processed
        sqlx::query("UPDATE app_connection_attempts SET processed = TRUE WHERE id = ?1")
            .bind(attempt_id)
            .execute(&self.pool)
            .await?;
        
        Ok(request_id)
    }
    
    /// Get pending authorization requests for a user
    pub async fn get_pending_requests(
        &self,
        user_id: &str,
    ) -> Result<Vec<AuthorizationRequest>, AuthorizationFlowError> {
        let requests = sqlx::query!(
            r#"
            SELECT id, user_id, app_domain, app_name, 
                   app_description, app_icon_url, 
                   requested_permissions, status,
                   created_at, responded_at
            FROM authorization_requests
            WHERE user_id = ?1 AND status = 'pending'
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.pool)
        .await?;
        
        let mut result = Vec::new();
        for row in requests {
            let permissions: Vec<String> = if let Some(ref perms) = row.requested_permissions {
                serde_json::from_str(perms)?
            } else {
                Vec::new()
            };
            
            result.push(AuthorizationRequest {
                id: row.id.expect("id is PRIMARY KEY"),
                user_id: row.user_id.unwrap_or_default(),
                app_domain: row.app_domain,
                app_name: row.app_name.unwrap_or_default(),
                app_description: row.app_description,
                app_icon_url: row.app_icon_url,
                requested_permissions: permissions,
                status: AuthorizationRequestStatus::Pending,
                created_at: DateTime::<Utc>::from_naive_utc_and_offset(row.created_at, Utc),
                responded_at: row.responded_at.map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
            });
        }
        
        Ok(result)
    }
    
    /// Approve an authorization request
    pub async fn approve_request(
        &self,
        request_id: &str,
        user_id: &str,
        user_key_id: &str,
        policy_id: u32,
        max_uses: Option<u16>,
        expires_in_hours: Option<u32>,
    ) -> Result<String, AuthorizationFlowError> {
        let mut tx = self.pool.begin().await?;
        
        // Get the request
        let request = self.get_request(&mut *tx, request_id, user_id).await?;
        
        if request.status != AuthorizationRequestStatus::Pending {
            return Err(AuthorizationFlowError::RequestAlreadyProcessed);
        }
        
        // Get the app
        let app = Application::find_by_domain(&self.pool, &request.app_domain).await?;
        
        // Create authorization
        let auth_id = self.create_authorization_from_request(
            &mut tx,
            &request,
            &app,
            user_key_id,
            policy_id,
            max_uses,
            expires_in_hours,
        ).await?;
        
        // Update request status
        sqlx::query(
            r#"
            UPDATE authorization_requests 
            SET status = 'approved', responded_at = CURRENT_TIMESTAMP
            WHERE id = ?1
            "#,
        )
        .bind(request_id)
        .execute(&mut *tx)
        .await?;
        
        tx.commit().await?;
        
        Ok(auth_id)
    }
    
    /// Reject an authorization request
    pub async fn reject_request(
        &self,
        request_id: &str,
        user_id: &str,
    ) -> Result<(), AuthorizationFlowError> {
        let mut conn = self.pool.acquire().await?;
        let request = self.get_request(&mut *conn, request_id, user_id).await?;
        
        if request.status != AuthorizationRequestStatus::Pending {
            return Err(AuthorizationFlowError::RequestAlreadyProcessed);
        }
        
        sqlx::query(
            r#"
            UPDATE authorization_requests 
            SET status = 'rejected', responded_at = CURRENT_TIMESTAMP
            WHERE id = ?1
            "#,
        )
        .bind(request_id)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Create authorization from approved request
    async fn create_authorization_from_request(
        &self,
        tx: &mut Transaction<'_, sqlx::Sqlite>,
        request: &AuthorizationRequest,
        app: &Application,
        user_key_id: &str,
        policy_id: u32,
        max_uses: Option<u16>,
        expires_in_hours: Option<u32>,
    ) -> Result<String, AuthorizationFlowError> {
        // Generate bunker keypair
        let bunker_keys = Keys::generate();
        let bunker_public_key = bunker_keys.public_key().to_hex();
        let bunker_secret = bunker_keys.secret_key().as_secret_bytes();
        
        // Encrypt bunker secret
        let encrypted_bunker_secret = self.key_manager.encrypt(bunker_secret).await?;
        
        // Generate connection secret
        let connection_secret = Uuid::new_v4().to_string();
        
        // Calculate expiry
        let expires_at = expires_in_hours.map(|hours| {
            Utc::now() + chrono::Duration::hours(hours as i64)
        });
        
        // Default relays
        let relays = vec![
            "wss://relay.damus.io".to_string(),
            "wss://nos.lol".to_string(),
            "wss://relay.nostr.band".to_string(),
        ];
        let relays_json = serde_json::to_string(&relays)?;
        
        // Create authorization
        let policy_id_i32 = policy_id as i32;
        let max_uses_i32 = max_uses.map(|u| u as i32);
        let expires_at_naive = expires_at.map(|dt| dt.naive_utc());
        let app_id_i32 = app.id as i32;
        let requested_at_naive = request.created_at.naive_utc();
        
        let auth = sqlx::query!(
            r#"
            INSERT INTO authorizations (
                stored_key_id, secret, bunker_public_key, bunker_secret,
                relays, policy_id, max_uses, expires_at,
                status, user_id, user_key_id, application_id,
                requested_at, approved_at,
                created_at, updated_at
            )
            VALUES (
                0, ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                'active', ?8, ?9, ?10,
                ?11, CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            RETURNING id
            "#,
            connection_secret,
            bunker_public_key,
            encrypted_bunker_secret,
            relays_json,
            policy_id_i32,
            max_uses_i32,
            expires_at_naive,
            request.user_id,
            user_key_id,
            app_id_i32,
            requested_at_naive,
        )
        .fetch_one(&mut **tx)
        .await?;
        
        Ok(auth.id.to_string())
    }
    
    /// Get authorization request with validation
    async fn get_request<'e, E>(
        &self,
        executor: E,
        request_id: &str,
        user_id: &str,
    ) -> Result<AuthorizationRequest, AuthorizationFlowError>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        let row = sqlx::query!(
            r#"
            SELECT id, user_id, app_domain, app_name, 
                   app_description, app_icon_url, 
                   requested_permissions, status,
                   created_at, responded_at
            FROM authorization_requests
            WHERE id = ?1 AND user_id = ?2
            "#,
            request_id,
            user_id
        )
        .fetch_optional(executor)
        .await?
        .ok_or(AuthorizationFlowError::RequestNotFound)?;
        
        let permissions: Vec<String> = if let Some(ref perms) = row.requested_permissions {
            serde_json::from_str(perms)?
        } else {
            Vec::new()
        };
        
        let status = match row.status.as_str() {
            "pending" => AuthorizationRequestStatus::Pending,
            "approved" => AuthorizationRequestStatus::Approved,
            "rejected" => AuthorizationRequestStatus::Rejected,
            _ => return Err(AuthorizationFlowError::InvalidStatus),
        };
        
        Ok(AuthorizationRequest {
            id: row.id.expect("id is PRIMARY KEY"),
            user_id: row.user_id.unwrap_or_default(),
            app_domain: row.app_domain,
            app_name: row.app_name.unwrap_or_default(),
            app_description: row.app_description,
            app_icon_url: row.app_icon_url,
            requested_permissions: permissions,
            status,
            created_at: DateTime::<Utc>::from_naive_utc_and_offset(row.created_at, Utc),
            responded_at: row.responded_at.map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
        })
    }
}

/// Helper to generate default policies for common app types
pub struct PolicyTemplates;

impl PolicyTemplates {
    /// Social media app policy (posting, profile updates)
    pub fn social_media() -> Vec<String> {
        vec![
            "sign_event:1".to_string(),     // Short text note
            "sign_event:0".to_string(),     // Metadata
            "sign_event:3".to_string(),     // Contacts
            "sign_event:6".to_string(),     // Repost
            "sign_event:7".to_string(),     // Reaction
            "encrypt".to_string(),          // DMs
            "decrypt".to_string(),
        ]
    }
    
    /// Read-only app policy
    pub fn read_only() -> Vec<String> {
        vec![
            "get_public_key".to_string(),
            "nip04_decrypt".to_string(),    // Decrypt DMs
        ]
    }
    
    /// Marketplace app policy
    pub fn marketplace() -> Vec<String> {
        vec![
            "sign_event:30017".to_string(), // Stall
            "sign_event:30018".to_string(), // Product
            "sign_event:4".to_string(),     // Encrypted DM
            "encrypt".to_string(),
            "decrypt".to_string(),
        ]
    }
    
    /// Gaming app policy
    pub fn gaming() -> Vec<String> {
        vec![
            "sign_event:30311".to_string(), // Game metadata
            "sign_event:1".to_string(),     // Game updates
            "get_public_key".to_string(),
        ]
    }
}