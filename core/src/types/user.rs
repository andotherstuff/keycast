use crate::types::stored_key::StoredKey;
use crate::types::team::{Team, TeamWithRelations};
use chrono::DateTime;
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Couldn't fetch relations")]
    Relations,
    #[error("User not found")]
    NotFound,
}

/// A user is a representation of a Nostr user (based solely on a pubkey value)
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    /// The user's public key, in hex format
    pub public_key: String,
    /// The date and time the user was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the user was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

/// A team user is a representation of a user's membership in a team, this is a join table
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct TeamUser {
    /// The user's public key, in hex format
    pub user_public_key: String,
    /// The team id
    pub team_id: u32,
    /// The user's role in the team
    pub role: TeamUserRole,
    /// The date and time the user was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the user was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

/// The role of a user in a team
#[derive(Debug, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum TeamUserRole {
    Admin,
    Member,
}

impl User {
    pub async fn find_by_pubkey(pool: &SqlitePool, pubkey: &PublicKey) -> Result<Self, UserError> {
        match sqlx::query_as::<_, User>("SELECT * FROM users WHERE public_key = ?1")
            .bind(pubkey.to_hex())
            .fetch_one(pool)
            .await
        {
            Ok(user) => Ok(user),
            Err(sqlx::Error::RowNotFound) => Err(UserError::NotFound),
            Err(e) => {
                println!("Error fetching user: {:?}", e);
                Err(UserError::Database(e))
            }
        }
    }

    // DEPRECATED: Team functionality removed in favor of personal authentication
    pub async fn teams(&self, _pool: &SqlitePool) -> Result<Vec<TeamWithRelations>, UserError> {
        // Team functionality has been removed. All users now use personal authentication.
        // This method returns an empty list to maintain API compatibility during migration.
        Ok(Vec::new())
    }

    /// DEPRECATED: Team functionality removed
    pub async fn is_team_admin(
        _pool: &SqlitePool,
        _pubkey: &PublicKey,
        _team_id: u32,
    ) -> Result<bool, UserError> {
        Ok(false)
    }

    /// DEPRECATED: Team functionality removed
    pub async fn is_team_member(
        _pool: &SqlitePool,
        _pubkey: &PublicKey,
        _team_id: u32,
    ) -> Result<bool, UserError> {
        Ok(false)
    }

    /// DEPRECATED: Team functionality removed
    pub async fn is_team_teammate(
        _pool: &SqlitePool,
        _pubkey: &PublicKey,
        _team_id: u32,
    ) -> Result<bool, UserError> {
        Ok(false)
    }
}
