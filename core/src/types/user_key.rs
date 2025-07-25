// ABOUTME: User key management for personal Nostr keys
// ABOUTME: Supports primary keys, app-specific keys, and temporary keys with encryption

use crate::encryption::KeyManager;
use chrono::DateTime;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserKeyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Key not found")]
    NotFound,
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Key already exists")]
    AlreadyExists,
    #[error("Cannot delete primary key")]
    CannotDeletePrimary,
    #[error("User already has a primary key")]
    PrimaryKeyExists,
}

/// Type of user key
#[derive(Debug, Serialize, Deserialize, sqlx::Type, Clone, Copy, PartialEq)]
#[sqlx(type_name = "TEXT", rename_all = "snake_case")]
pub enum UserKeyType {
    /// Main key for the user
    Primary,
    /// Key specific to an application
    AppSpecific,
    /// Temporary key with expiration
    Temporary,
}

/// Represents a user's Nostr key
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct UserKey {
    pub id: u32,
    /// User's public key (owner)
    pub user_public_key: String,
    /// Name/label for this key
    pub name: String,
    /// Public key in hex format
    pub public_key: String,
    /// Encrypted secret key
    #[serde(skip)]
    pub secret_key: Vec<u8>,
    /// Type of key
    pub key_type: UserKeyType,
    /// Whether this key is active
    pub is_active: bool,
    /// Creation timestamp
    pub created_at: DateTime<chrono::Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<chrono::Utc>,
}

/// Public representation of a user key (without secret)
#[derive(Debug, Serialize, Deserialize)]
pub struct UserKeyPublic {
    pub id: u32,
    pub name: String,
    pub public_key: String,
    pub key_type: UserKeyType,
    pub is_active: bool,
    pub created_at: DateTime<chrono::Utc>,
}

impl From<UserKey> for UserKeyPublic {
    fn from(key: UserKey) -> Self {
        UserKeyPublic {
            id: key.id,
            name: key.name,
            public_key: key.public_key,
            key_type: key.key_type,
            is_active: key.is_active,
            created_at: key.created_at,
        }
    }
}

impl UserKey {
    /// Create a new user key
    pub async fn create(
        pool: &SqlitePool,
        key_manager: &dyn KeyManager,
        user_pubkey: &PublicKey,
        name: &str,
        key_type: UserKeyType,
        secret_key: Option<SecretKey>,
    ) -> Result<Self, UserKeyError> {
        // Check if user already has a primary key
        if key_type == UserKeyType::Primary {
            let existing = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_keys WHERE user_public_key = ?1 AND key_type = 'primary'"
            )
            .bind(user_pubkey.to_hex())
            .fetch_one(pool)
            .await?;
            
            if existing > 0 {
                return Err(UserKeyError::PrimaryKeyExists);
            }
        }
        
        // Generate or use provided key
        let keys = match secret_key {
            Some(sk) => Keys::new(sk),
            None => Keys::generate(),
        };
        let public_key = keys.public_key();
        
        // Check if key already exists
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_keys WHERE public_key = ?1"
        )
        .bind(public_key.to_hex())
        .fetch_one(pool)
        .await?;
        
        if existing > 0 {
            return Err(UserKeyError::AlreadyExists);
        }
        
        // Encrypt the secret key
        let secret_key_bytes = keys.secret_key().as_secret_bytes();
        let encrypted_secret = key_manager
            .encrypt(secret_key_bytes)
            .await
            .map_err(|e| UserKeyError::Encryption(e.to_string()))?;
        
        // Insert into database
        let key = sqlx::query_as::<_, UserKey>(
            r#"
            INSERT INTO user_keys (
                user_public_key, name, public_key, secret_key, 
                key_type, is_active, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING *
            "#,
        )
        .bind(user_pubkey.to_hex())
        .bind(name)
        .bind(public_key.to_hex())
        .bind(&encrypted_secret)
        .bind(key_type)
        .fetch_one(pool)
        .await?;
        
        Ok(key)
    }
    
    /// Find key by ID
    pub async fn find_by_id(
        pool: &SqlitePool,
        id: u32,
    ) -> Result<Self, UserKeyError> {
        match sqlx::query_as::<_, UserKey>(
            "SELECT * FROM user_keys WHERE id = ?1"
        )
        .bind(id)
        .fetch_one(pool)
        .await
        {
            Ok(key) => Ok(key),
            Err(sqlx::Error::RowNotFound) => Err(UserKeyError::NotFound),
            Err(e) => Err(UserKeyError::Database(e)),
        }
    }
    
    /// Find key by string ID and user ID (for new schema compatibility)
    pub async fn find(
        pool: &SqlitePool,
        id: &str,
        user_id: &str,
    ) -> Result<Self, UserKeyError> {
        match sqlx::query_as::<_, UserKey>(
            "SELECT * FROM user_keys WHERE id = ?1 AND user_id = ?2"
        )
        .bind(id)
        .bind(user_id)
        .fetch_one(pool)
        .await
        {
            Ok(key) => Ok(key),
            Err(sqlx::Error::RowNotFound) => Err(UserKeyError::NotFound),
            Err(e) => Err(UserKeyError::Database(e)),
        }
    }
    
    /// Find key by public key
    pub async fn find_by_public_key(
        pool: &SqlitePool,
        pubkey: &PublicKey,
    ) -> Result<Self, UserKeyError> {
        match sqlx::query_as::<_, UserKey>(
            "SELECT * FROM user_keys WHERE public_key = ?1"
        )
        .bind(pubkey.to_hex())
        .fetch_one(pool)
        .await
        {
            Ok(key) => Ok(key),
            Err(sqlx::Error::RowNotFound) => Err(UserKeyError::NotFound),
            Err(e) => Err(UserKeyError::Database(e)),
        }
    }
    
    /// Get all keys for a user
    pub async fn list_for_user(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
    ) -> Result<Vec<Self>, UserKeyError> {
        let keys = sqlx::query_as::<_, UserKey>(
            r#"
            SELECT * FROM user_keys 
            WHERE user_public_key = ?1 
            ORDER BY 
                CASE key_type 
                    WHEN 'primary' THEN 1 
                    WHEN 'app_specific' THEN 2 
                    WHEN 'temporary' THEN 3 
                END,
                created_at DESC
            "#,
        )
        .bind(user_pubkey.to_hex())
        .fetch_all(pool)
        .await?;
        
        Ok(keys)
    }
    
    /// Get user's primary key
    pub async fn get_primary_for_user(
        pool: &SqlitePool,
        user_pubkey: &PublicKey,
    ) -> Result<Self, UserKeyError> {
        match sqlx::query_as::<_, UserKey>(
            "SELECT * FROM user_keys WHERE user_public_key = ?1 AND key_type = 'primary'"
        )
        .bind(user_pubkey.to_hex())
        .fetch_one(pool)
        .await
        {
            Ok(key) => Ok(key),
            Err(sqlx::Error::RowNotFound) => Err(UserKeyError::NotFound),
            Err(e) => Err(UserKeyError::Database(e)),
        }
    }
    
    /// Decrypt the secret key
    pub async fn decrypt_secret_key(
        &self,
        key_manager: &dyn KeyManager,
    ) -> Result<SecretKey, UserKeyError> {
        let decrypted = key_manager
            .decrypt(&self.secret_key)
            .await
            .map_err(|e| UserKeyError::Decryption(e.to_string()))?;
        
        SecretKey::from_slice(&decrypted)
            .map_err(|e| UserKeyError::Decryption(e.to_string()))
    }
    
    /// Update key name
    pub async fn update_name(
        &mut self,
        pool: &SqlitePool,
        name: String,
    ) -> Result<(), UserKeyError> {
        sqlx::query(
            r#"
            UPDATE user_keys 
            SET name = ?1, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?2
            "#,
        )
        .bind(&name)
        .bind(self.id)
        .execute(pool)
        .await?;
        
        self.name = name;
        Ok(())
    }
    
    /// Deactivate key
    pub async fn deactivate(
        &mut self,
        pool: &SqlitePool,
    ) -> Result<(), UserKeyError> {
        if self.key_type == UserKeyType::Primary {
            return Err(UserKeyError::CannotDeletePrimary);
        }
        
        sqlx::query(
            r#"
            UPDATE user_keys 
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