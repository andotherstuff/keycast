// ABOUTME: Application type for dynamically registered apps in the personal auth system
// ABOUTME: Apps are registered on-the-fly when they request authorization, no pre-registration needed

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApplicationError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Application not found")]
    NotFound,
    #[error("Invalid domain")]
    InvalidDomain,
    #[error("Failed to fetch metadata")]
    MetadataFetchFailed,
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Represents an application that can request authorization
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct Application {
    pub id: u32,
    /// Display name of the application
    pub name: String,
    /// Domain of the application (e.g., "twitter.nostr")
    pub domain: String,
    /// Description of the application
    pub description: Option<String>,
    /// Icon URL for the application
    pub icon_url: Option<String>,
    /// Public key of the application (if it has one)
    pub pubkey: Option<String>,
    /// Additional metadata as JSON
    pub metadata: String, // JSON string
    /// Whether this app has been verified
    pub is_verified: bool,
    /// When this app was first seen
    pub first_seen_at: DateTime<chrono::Utc>,
    /// When this app was last used
    pub last_used_at: Option<DateTime<chrono::Utc>>,
    /// Creation timestamp
    pub created_at: DateTime<chrono::Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<chrono::Utc>,
}

/// Metadata structure for applications
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppMetadata {
    /// Requested permissions/scopes
    pub requested_permissions: Vec<String>,
    /// Callback URL for authorization
    pub callback_url: Option<String>,
    /// App version
    pub version: Option<String>,
    /// Developer/company name
    pub developer: Option<String>,
    /// Support URL
    pub support_url: Option<String>,
    /// Privacy policy URL
    pub privacy_policy_url: Option<String>,
    /// Terms of service URL
    pub terms_url: Option<String>,
    /// Additional custom fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, JsonValue>,
}

impl Application {
    /// Register or update an application
    pub async fn register_or_update(
        pool: &SqlitePool,
        domain: &str,
        name: &str,
        metadata: AppMetadata,
    ) -> Result<Self, ApplicationError> {
        // Validate domain
        if domain.is_empty() {
            return Err(ApplicationError::InvalidDomain);
        }
        
        let metadata_json = serde_json::to_string(&metadata)?;
        
        // Try to find existing app
        let existing = sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE domain = ?1"
        )
        .bind(domain)
        .fetch_optional(pool)
        .await?;
        
        match existing {
            Some(mut app) => {
                // Update existing app
                app.name = name.to_string();
                app.metadata = metadata_json;
                app.last_used_at = Some(chrono::Utc::now());
                
                sqlx::query(
                    r#"
                    UPDATE applications 
                    SET name = ?1, 
                        metadata = ?2, 
                        last_used_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?3
                    "#,
                )
                .bind(&app.name)
                .bind(&app.metadata)
                .bind(app.id)
                .execute(pool)
                .await?;
                
                Ok(app)
            }
            None => {
                // Create new app
                let app = sqlx::query_as::<_, Application>(
                    r#"
                    INSERT INTO applications (
                        name, domain, metadata, 
                        first_seen_at, created_at, updated_at
                    )
                    VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    RETURNING *
                    "#,
                )
                .bind(name)
                .bind(domain)
                .bind(&metadata_json)
                .fetch_one(pool)
                .await?;
                
                Ok(app)
            }
        }
    }
    
    /// Find application by ID
    pub async fn find_by_id(
        pool: &SqlitePool,
        id: u32,
    ) -> Result<Self, ApplicationError> {
        match sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE id = ?1"
        )
        .bind(id)
        .fetch_one(pool)
        .await
        {
            Ok(app) => Ok(app),
            Err(sqlx::Error::RowNotFound) => Err(ApplicationError::NotFound),
            Err(e) => Err(ApplicationError::Database(e)),
        }
    }
    
    /// Find application by domain
    pub async fn find_by_domain(
        pool: &SqlitePool,
        domain: &str,
    ) -> Result<Self, ApplicationError> {
        match sqlx::query_as::<_, Application>(
            "SELECT * FROM applications WHERE domain = ?1"
        )
        .bind(domain)
        .fetch_one(pool)
        .await
        {
            Ok(app) => Ok(app),
            Err(sqlx::Error::RowNotFound) => Err(ApplicationError::NotFound),
            Err(e) => Err(ApplicationError::Database(e)),
        }
    }
    
    /// Get parsed metadata
    pub fn get_metadata(&self) -> Result<AppMetadata, serde_json::Error> {
        serde_json::from_str(&self.metadata)
    }
    
    /// Update app verification status
    pub async fn set_verified(
        &mut self,
        pool: &SqlitePool,
        verified: bool,
    ) -> Result<(), ApplicationError> {
        sqlx::query(
            r#"
            UPDATE applications 
            SET is_verified = ?1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?2
            "#,
        )
        .bind(verified)
        .bind(self.id)
        .execute(pool)
        .await?;
        
        self.is_verified = verified;
        Ok(())
    }
    
    /// Update app metadata (icon, description, etc)
    pub async fn update_info(
        &mut self,
        pool: &SqlitePool,
        description: Option<String>,
        icon_url: Option<String>,
        pubkey: Option<String>,
    ) -> Result<(), ApplicationError> {
        sqlx::query(
            r#"
            UPDATE applications 
            SET description = ?1,
                icon_url = ?2,
                pubkey = ?3,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?4
            "#,
        )
        .bind(&description)
        .bind(&icon_url)
        .bind(&pubkey)
        .bind(self.id)
        .execute(pool)
        .await?;
        
        self.description = description;
        self.icon_url = icon_url;
        self.pubkey = pubkey;
        
        Ok(())
    }
    
    /// Get all apps for user dashboard
    pub async fn list_all(
        pool: &SqlitePool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, ApplicationError> {
        let apps = sqlx::query_as::<_, Application>(
            r#"
            SELECT * FROM applications 
            ORDER BY last_used_at DESC, created_at DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        
        Ok(apps)
    }
}