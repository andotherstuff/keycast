// ABOUTME: User authentication methods for multi-auth support
// ABOUTME: Supports NIP-07, NIP-46, email/password, OAuth, and passkeys

use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::DateTime;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserAuthError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Authentication method not found")]
    NotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Method already exists")]
    MethodExists,
    #[error("Bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("Invalid auth data")]
    InvalidAuthData,
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Type of authentication method
#[derive(Debug, Serialize, Deserialize, sqlx::Type, Clone, Copy, PartialEq)]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
pub enum AuthType {
    /// NIP-07 browser extension
    Nip07,
    /// NIP-46 remote signer
    Nip46,
    /// Traditional email/password
    EmailPassword,
    /// OAuth provider (Google, GitHub, etc)
    Oauth,
    /// WebAuthn passkey
    Passkey,
}

/// User authentication method
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct UserAuthMethod {
    pub id: u32,
    /// User's public key
    pub user_public_key: String,
    /// Type of authentication
    pub auth_type: AuthType,
    /// JSON data specific to auth method
    pub auth_data: String,
    /// Whether this is the primary method
    pub is_primary: bool,
    /// Whether this method is active
    pub is_active: bool,
    /// Creation timestamp
    pub created_at: DateTime<chrono::Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<chrono::Utc>,
}

/// Email/password authentication data
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailPasswordData {
    pub email: String,
    pub password_hash: String,
    pub verified: bool,
    pub verification_token: Option<String>,
}

/// OAuth authentication data
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthData {
    pub provider: String, // google, github, etc
    pub provider_id: String,
    pub email: Option<String>,
    pub access_token: Option<String>, // encrypted
    pub refresh_token: Option<String>, // encrypted
}

/// Passkey authentication data
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyData {
    pub credential_id: String,
    pub public_key: String,
    pub counter: u32,
    pub device_name: Option<String>,
}

/// NIP-46 authentication data
#[derive(Debug, Serialize, Deserialize)]
pub struct Nip46Data {
    pub remote_pubkey: String,
    pub relay_url: String,
    pub secret: String,
}

impl UserAuthMethod {
    /// Add email/password authentication
    pub async fn add_email_password(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        email: &str,
        password: &str,
    ) -> Result<Self, UserAuthError> {
        // Check if email already exists
        let existing = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) FROM user_auth_methods 
            WHERE auth_type = 'email_password' 
            AND auth_data->>'email' = ?1
            "#
        )
        .bind(email)
        .fetch_one(pool)
        .await?;
        
        if existing > 0 {
            return Err(UserAuthError::MethodExists);
        }
        
        // Hash password
        let password_hash = hash(password.as_bytes(), DEFAULT_COST)?;
        
        let auth_data = EmailPasswordData {
            email: email.to_string(),
            password_hash,
            verified: false,
            verification_token: Some(uuid::Uuid::new_v4().to_string()),
        };
        
        let auth_data_json = serde_json::to_string(&auth_data)?;
        
        let method = sqlx::query_as::<_, UserAuthMethod>(
            r#"
            INSERT INTO user_auth_methods (
                user_public_key, auth_type, auth_data, is_primary, is_active,
                created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING *
            "#,
        )
        .bind(user_pubkey.to_hex())
        .bind(AuthType::EmailPassword)
        .bind(&auth_data_json)
        .bind(false) // Not primary by default
        .fetch_one(pool)
        .await?;
        
        Ok(method)
    }
    
    /// Verify email/password
    pub async fn verify_email_password(
        pool: &SqlitePool,
        email: &str,
        password: &str,
    ) -> Result<(Self, PublicKey), UserAuthError> {
        // Find auth method by email
        let method = sqlx::query_as::<_, UserAuthMethod>(
            r#"
            SELECT * FROM user_auth_methods 
            WHERE auth_type = 'email_password' 
            AND auth_data->>'email' = ?1
            AND is_active = true
            "#,
        )
        .bind(email)
        .fetch_one(pool)
        .await
        .map_err(|_| UserAuthError::InvalidCredentials)?;
        
        // Parse auth data
        let auth_data: EmailPasswordData = serde_json::from_str(&method.auth_data)
            .map_err(|_| UserAuthError::InvalidAuthData)?;
        
        // Verify password
        if !verify(password.as_bytes(), &auth_data.password_hash)? {
            return Err(UserAuthError::InvalidCredentials);
        }
        
        // Get user's public key
        let pubkey = PublicKey::from_hex(&method.user_public_key)
            .map_err(|_| UserAuthError::InvalidAuthData)?;
        
        Ok((method, pubkey))
    }
    
    /// Add OAuth method
    pub async fn add_oauth(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        provider: &str,
        provider_id: &str,
        email: Option<&str>,
    ) -> Result<Self, UserAuthError> {
        let auth_data = OAuthData {
            provider: provider.to_string(),
            provider_id: provider_id.to_string(),
            email: email.map(|e| e.to_string()),
            access_token: None,
            refresh_token: None,
        };
        
        let auth_data_json = serde_json::to_string(&auth_data)?;
        
        let method = sqlx::query_as::<_, UserAuthMethod>(
            r#"
            INSERT INTO user_auth_methods (
                user_public_key, auth_type, auth_data, is_primary, is_active,
                created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING *
            "#,
        )
        .bind(user_pubkey.to_hex())
        .bind(AuthType::Oauth)
        .bind(&auth_data_json)
        .bind(false)
        .fetch_one(pool)
        .await?;
        
        Ok(method)
    }
    
    /// Add passkey
    pub async fn add_passkey(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
        credential_id: &str,
        public_key: &str,
        device_name: Option<&str>,
    ) -> Result<Self, UserAuthError> {
        let auth_data = PasskeyData {
            credential_id: credential_id.to_string(),
            public_key: public_key.to_string(),
            counter: 0,
            device_name: device_name.map(|d| d.to_string()),
        };
        
        let auth_data_json = serde_json::to_string(&auth_data)?;
        
        let method = sqlx::query_as::<_, UserAuthMethod>(
            r#"
            INSERT INTO user_auth_methods (
                user_public_key, auth_type, auth_data, is_primary, is_active,
                created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING *
            "#,
        )
        .bind(user_pubkey.to_hex())
        .bind(AuthType::Passkey)
        .bind(&auth_data_json)
        .bind(false)
        .fetch_one(pool)
        .await?;
        
        Ok(method)
    }
    
    /// Get all auth methods for a user
    pub async fn list_for_user(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
    ) -> Result<Vec<Self>, UserAuthError> {
        let methods = sqlx::query_as::<_, UserAuthMethod>(
            r#"
            SELECT * FROM user_auth_methods 
            WHERE user_public_key = ?1
            ORDER BY is_primary DESC, created_at DESC
            "#,
        )
        .bind(user_pubkey.to_hex())
        .fetch_all(pool)
        .await?;
        
        Ok(methods)
    }
    
    /// Set primary auth method
    pub async fn set_primary(
        &mut self,
        pool: &SqlitePool,
    ) -> Result<(), UserAuthError> {
        // First, unset any existing primary
        sqlx::query(
            r#"
            UPDATE user_auth_methods 
            SET is_primary = false
            WHERE user_public_key = ?1
            "#,
        )
        .bind(&self.user_public_key)
        .execute(pool)
        .await?;
        
        // Then set this one as primary
        sqlx::query(
            r#"
            UPDATE user_auth_methods 
            SET is_primary = true, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?1
            "#,
        )
        .bind(self.id)
        .execute(pool)
        .await?;
        
        self.is_primary = true;
        Ok(())
    }
    
    /// Deactivate auth method
    pub async fn deactivate(
        &mut self,
        pool: &SqlitePool,
    ) -> Result<(), UserAuthError> {
        sqlx::query(
            r#"
            UPDATE user_auth_methods 
            SET is_active = false, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?1
            "#,
        )
        .bind(self.id)
        .execute(pool)
        .await?;
        
        self.is_active = false;
        Ok(())
    }
}