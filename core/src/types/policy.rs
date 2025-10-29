use crate::types::permission::Permission;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Policy not found")]
    NotFound,
}

/// A policy is a set of permissions. Teams have many policies, and policies have many permissions.
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Policy {
    /// The id of the policy
    pub id: i32,
    /// The name of the policy
    pub name: String,
    /// The id of the team the policy belongs to
    pub team_id: i32,
    /// The date and time the policy was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the policy was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

/// A policy with its permissions, this is a join table between a policy and its permissions
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct PolicyWithPermissions {
    #[sqlx(flatten)]
    pub policy: Policy,
    #[sqlx(default)]
    pub permissions: Vec<Permission>,
}
