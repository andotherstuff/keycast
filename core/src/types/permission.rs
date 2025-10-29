use crate::custom_permissions::{
    allowed_kinds::AllowedKinds, content_filter::ContentFilter, encrypt_to_self::EncryptToSelf,
};
use crate::traits::CustomPermission;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PermissionError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Unknown permission type: {0}")]
    UnknownPermission(String),
    #[error("Invalid permission configuration: {0}")]
    InvalidConfig(String),
}

/// A permission is database representation of a CustomPermission trait
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct Permission {
    /// The id of the permission
    pub id: i32,
    /// The identifier of the permission
    pub identifier: String,
    /// The configuration of the permission
    pub config: serde_json::Value,
    /// The date and time the permission was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the permission was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

impl Permission {
    /// Convert this database permission into a CustomPermission implementation
    pub fn to_custom_permission(&self) -> Result<Box<dyn CustomPermission>, PermissionError> {
        match self.identifier.as_str() {
            "allowed_kinds" => AllowedKinds::from_permission(self),
            "content_filter" => ContentFilter::from_permission(self),
            "encrypt_to_self" => EncryptToSelf::from_permission(self),
            _ => Err(PermissionError::UnknownPermission(self.identifier.clone())),
        }
    }
}

/// A policy permission is a join table between a policy and a permission
#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct PolicyPermission {
    /// The id of the policy permission
    pub id: i32,
    /// The id of the policy
    pub policy_id: i32,
    /// The id of the permission
    pub permission_id: i32,
    /// The date and time the policy permission was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the policy permission was last updated
    pub updated_at: DateTime<chrono::Utc>,
}
