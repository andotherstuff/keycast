// ABOUTME: Enhanced user type for personal auth system with backward compatibility
// ABOUTME: Extends the existing user model with email, display name, and NIP-05 support

use chrono::DateTime;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;
use uuid;

#[derive(Error, Debug)]
pub enum UserEnhancedError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("User not found")]
    NotFound,
    #[error("Email already exists")]
    EmailExists,
    #[error("NIP-05 identifier already exists")]
    Nip05Exists,
    #[error("Invalid email format")]
    InvalidEmail,
    #[error("Invalid NIP-05 format")]
    InvalidNip05,
}

/// Enhanced user model for personal auth system
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct UserEnhanced {
    /// Unique ID for the user
    pub id: String,
    /// The user's public key, in hex format
    pub public_key: String,
    /// Display name for the user
    pub display_name: Option<String>,
    /// Email address for traditional login
    pub email: Option<String>,
    /// NIP-05 identifier (user@domain.com)
    pub nip05_identifier: Option<String>,
    /// Profile picture URL
    pub profile_picture_url: Option<String>,
    /// The date and time the user was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the user was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

impl UserEnhanced {
    /// Create a new user with just a public key (backward compatible)
    pub async fn create_from_pubkey(
        pool: &SqlitePool,
        pubkey: &PublicKey,
    ) -> Result<Self, UserEnhancedError> {
        let public_key_hex = pubkey.to_hex();
        
        let user = sqlx::query_as::<_, UserEnhanced>(
            r#"
            INSERT INTO users (id, public_key, created_at, updated_at)
            VALUES (?1, ?2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING *
            "#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&public_key_hex)
        .fetch_one(pool)
        .await?;
        
        Ok(user)
    }
    
    /// Create a new user with email and password
    pub async fn create_with_email(
        pool: &SqlitePool,
        email: &str,
        display_name: Option<&str>,
    ) -> Result<(Self, PublicKey), UserEnhancedError> {
        // Validate email format
        if !email.contains('@') {
            return Err(UserEnhancedError::InvalidEmail);
        }
        
        // Check if email already exists
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE email = ?1"
        )
        .bind(email)
        .fetch_one(pool)
        .await?;
        
        if existing > 0 {
            return Err(UserEnhancedError::EmailExists);
        }
        
        // Generate a new keypair for this user
        let keys = Keys::generate();
        let public_key = keys.public_key();
        let public_key_hex = public_key.to_hex();
        
        let user = sqlx::query_as::<_, UserEnhanced>(
            r#"
            INSERT INTO users (id, public_key, email, display_name, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING *
            "#,
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&public_key_hex)
        .bind(email)
        .bind(display_name)
        .fetch_one(pool)
        .await?;
        
        Ok((user, public_key))
    }
    
    /// Find user by public key
    pub async fn find_by_pubkey(
        pool: &SqlitePool,
        pubkey: &PublicKey,
    ) -> Result<Self, UserEnhancedError> {
        match sqlx::query_as::<_, UserEnhanced>(
            "SELECT * FROM users WHERE public_key = ?1"
        )
        .bind(pubkey.to_hex())
        .fetch_one(pool)
        .await
        {
            Ok(user) => Ok(user),
            Err(sqlx::Error::RowNotFound) => Err(UserEnhancedError::NotFound),
            Err(e) => Err(UserEnhancedError::Database(e)),
        }
    }
    
    /// Find user by email
    pub async fn find_by_email(
        pool: &SqlitePool,
        email: &str,
    ) -> Result<Self, UserEnhancedError> {
        match sqlx::query_as::<_, UserEnhanced>(
            "SELECT * FROM users WHERE email = ?1"
        )
        .bind(email)
        .fetch_one(pool)
        .await
        {
            Ok(user) => Ok(user),
            Err(sqlx::Error::RowNotFound) => Err(UserEnhancedError::NotFound),
            Err(e) => Err(UserEnhancedError::Database(e)),
        }
    }
    
    /// Find user by ID
    pub async fn find_by_id(
        pool: &SqlitePool,
        id: &str,
    ) -> Result<Option<Self>, UserEnhancedError> {
        let user = sqlx::query_as::<_, UserEnhanced>(
            "SELECT * FROM users WHERE id = ?1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        
        Ok(user)
    }
    
    /// Find user by NIP-05 identifier
    pub async fn find_by_nip05(
        pool: &SqlitePool,
        nip05: &str,
    ) -> Result<Self, UserEnhancedError> {
        match sqlx::query_as::<_, UserEnhanced>(
            "SELECT * FROM users WHERE nip05_identifier = ?1"
        )
        .bind(nip05)
        .fetch_one(pool)
        .await
        {
            Ok(user) => Ok(user),
            Err(sqlx::Error::RowNotFound) => Err(UserEnhancedError::NotFound),
            Err(e) => Err(UserEnhancedError::Database(e)),
        }
    }
    
    /// Update user profile
    pub async fn update_profile(
        &mut self,
        pool: &SqlitePool,
        display_name: Option<String>,
        profile_picture_url: Option<String>,
    ) -> Result<(), UserEnhancedError> {
        sqlx::query(
            r#"
            UPDATE users 
            SET display_name = ?1, 
                profile_picture_url = ?2,
                updated_at = CURRENT_TIMESTAMP
            WHERE public_key = ?3
            "#,
        )
        .bind(&display_name)
        .bind(&profile_picture_url)
        .bind(&self.public_key)
        .execute(pool)
        .await?;
        
        self.display_name = display_name;
        self.profile_picture_url = profile_picture_url;
        
        Ok(())
    }
    
    /// Set or update NIP-05 identifier
    pub async fn set_nip05_identifier(
        &mut self,
        pool: &SqlitePool,
        nip05: &str,
    ) -> Result<(), UserEnhancedError> {
        // Validate NIP-05 format
        if !nip05.contains('@') {
            return Err(UserEnhancedError::InvalidNip05);
        }
        
        // Check if NIP-05 already exists for another user
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE nip05_identifier = ?1 AND public_key != ?2"
        )
        .bind(nip05)
        .bind(&self.public_key)
        .fetch_one(pool)
        .await?;
        
        if existing > 0 {
            return Err(UserEnhancedError::Nip05Exists);
        }
        
        sqlx::query(
            r#"
            UPDATE users 
            SET nip05_identifier = ?1,
                updated_at = CURRENT_TIMESTAMP
            WHERE public_key = ?2
            "#,
        )
        .bind(nip05)
        .bind(&self.public_key)
        .execute(pool)
        .await?;
        
        self.nip05_identifier = Some(nip05.to_string());
        
        Ok(())
    }
}