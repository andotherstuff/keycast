// ABOUTME: Enhanced authorization type supporting both team-based (legacy) and user-based models
// ABOUTME: Provides compatibility layer for gradual migration from teams to personal auth

use crate::encryption::KeyManagerError;
use crate::traits::AuthorizationValidations;
use crate::types::authorization::AuthorizationError;
use crate::types::permission::Permission;
use crate::types::policy::Policy;
use crate::types::stored_key::StoredKey;
use crate::types::user_key::UserKey;
use chrono::DateTime;
use nostr::nips::nip46::Request;
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;
use urlencoding;

#[derive(Error, Debug)]
pub enum AuthorizationEnhancedError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] KeyManagerError),
    #[error("Invalid bunker secret key")]
    InvalidBunkerSecretKey,
    #[error("Authorization is expired")]
    Expired,
    #[error("Authorization is fully redeemed")]
    FullyRedeemed,
    #[error("Invalid secret")]
    InvalidSecret,
    #[error("Unauthorized by permission")]
    Unauthorized,
    #[error("Unsupported request")]
    UnsupportedRequest,
    #[error("No key found for authorization")]
    NoKeyFound,
}

/// Enhanced authorization supporting both team and user models
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct AuthorizationEnhanced {
    /// The id of the authorization
    pub id: u32,
    /// Legacy: The id of the stored key (team model)
    pub stored_key_id: Option<u32>,
    /// New: The id of the user who owns this authorization
    pub user_id: Option<String>,
    /// New: The id of the user key
    pub user_key_id: Option<String>,
    /// New: The id of the application
    pub application_id: Option<u32>,
    /// The generated secret connection uuid
    pub secret: String,
    /// The public key of the bunker nostr secret key
    pub bunker_public_key: String,
    /// The encrypted bunker nostr secret key
    pub bunker_secret: Vec<u8>,
    /// The list of relays the authorization will listen on (JSON string in DB)
    pub relays: String,
    /// The id of the policy the authorization belongs to
    pub policy_id: u32,
    /// The maximum number of uses for this authorization
    pub max_uses: Option<i32>,
    /// The date and time at which this authorization expires
    pub expires_at: Option<DateTime<chrono::Utc>>,
    /// Status of the authorization
    pub status: Option<String>,
    /// When the authorization was requested
    pub requested_at: Option<DateTime<chrono::Utc>>,
    /// When the authorization was approved
    pub approved_at: Option<DateTime<chrono::Utc>>,
    /// The date and time the authorization was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the authorization was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

impl AuthorizationEnhanced {
    /// Find an authorization by ID
    pub async fn find(pool: &SqlitePool, id: u32) -> Result<Self, AuthorizationEnhancedError> {
        let auth = sqlx::query_as::<_, AuthorizationEnhanced>(
            r#"
            SELECT 
                id,
                stored_key_id,
                user_id,
                user_key_id,
                application_id,
                secret,
                bunker_public_key,
                bunker_secret,
                relays,
                policy_id,
                max_uses,
                expires_at,
                status,
                requested_at,
                approved_at,
                created_at,
                updated_at
            FROM authorizations
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_one(pool)
        .await?;
        
        Ok(auth)
    }

    /// Check if this is a legacy team-based authorization
    pub fn is_legacy(&self) -> bool {
        self.stored_key_id.is_some() && self.stored_key_id != Some(0)
    }

    /// Check if this is a new user-based authorization
    pub fn is_user_based(&self) -> bool {
        self.user_id.is_some() && self.user_key_id.is_some()
    }

    /// Get the encryption key (either from stored_key or user_key)
    pub async fn get_key_secret(&self, pool: &SqlitePool) -> Result<Vec<u8>, AuthorizationEnhancedError> {
        if self.is_user_based() {
            // New user-based model
            if let (Some(user_key_id), Some(user_id)) = (&self.user_key_id, &self.user_id) {
                let user_key = UserKey::find(pool, user_key_id, user_id).await
                    .map_err(|_| AuthorizationEnhancedError::NoKeyFound)?;
                Ok(user_key.secret_key)
            } else {
                Err(AuthorizationEnhancedError::NoKeyFound)
            }
        } else if self.is_legacy() {
            // Legacy team-based model
            if let Some(stored_key_id) = self.stored_key_id {
                let stored_key = sqlx::query_as::<_, StoredKey>(
                    "SELECT * FROM stored_keys WHERE id = ?"
                )
                .bind(stored_key_id)
                .fetch_one(pool)
                .await
                .map_err(|_| AuthorizationEnhancedError::NoKeyFound)?;
                Ok(stored_key.secret_key)
            } else {
                Err(AuthorizationEnhancedError::NoKeyFound)
            }
        } else {
            Err(AuthorizationEnhancedError::NoKeyFound)
        }
    }

    /// Get the policy for this authorization
    pub async fn policy(&self, pool: &SqlitePool) -> Result<Policy, AuthorizationEnhancedError> {
        let policy = sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies WHERE id = ?"
        )
        .bind(self.policy_id)
        .fetch_one(pool)
        .await?;
        Ok(policy)
    }

    /// Get the number of redemptions used for this authorization
    pub fn redemptions_count_sync(&self, pool: &SqlitePool) -> Result<u16, AuthorizationError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let count = sqlx::query_scalar::<_, i64>(
                    r#"
                    SELECT COUNT(*) FROM user_authorizations WHERE authorization_id = ?
                    "#,
                )
                .bind(self.id)
                .fetch_one(pool)
                .await?;
                Ok(count as u16)
            })
        })
    }

    pub fn redemptions_pubkeys_sync(
        &self,
        pool: &SqlitePool,
    ) -> Result<Vec<PublicKey>, AuthorizationError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let pubkeys = sqlx::query_scalar::<_, String>(
                    r#"
                    SELECT user_public_key FROM user_authorizations WHERE authorization_id = ?
                    "#,
                )
                .bind(self.id)
                .fetch_all(pool)
                .await?;
                Ok(pubkeys
                    .iter()
                    .filter_map(|p| PublicKey::from_hex(p).ok())
                    .collect())
            })
        })
    }

    pub fn create_redemption_sync(
        &self,
        pool: &SqlitePool,
        pubkey: &PublicKey,
    ) -> Result<(), AuthorizationError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query(
                    r#"
                    INSERT INTO user_authorizations (user_public_key, authorization_id, created_at, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    "#,
                )
                .bind(pubkey.to_hex())
                .bind(self.id)
                .execute(pool)
                .await?;
                Ok(())
            })
        })
    }

    /// Get relays as vector
    pub fn get_relays(&self) -> Vec<String> {
        serde_json::from_str(&self.relays).unwrap_or_default()
    }

    /// Generate the bunker URL for this authorization
    pub fn bunker_url(&self, _domain: Option<&str>) -> String {
        let relays = self.get_relays();
        let relay_param = relays.join(",");
        
        format!(
            "bunker://{}?relay={}&secret={}",
            self.bunker_public_key,
            urlencoding::encode(&relay_param),
            self.secret
        )
    }
}

impl AuthorizationValidations for AuthorizationEnhanced {
    fn validate_policy(
        &self,
        pool: &SqlitePool,
        pubkey: &PublicKey,
        request: &Request,
    ) -> Result<bool, AuthorizationError> {
        // Check if authorization is expired
        if let Some(expires_at) = &self.expires_at {
            if chrono::Utc::now() > *expires_at {
                return Err(AuthorizationError::Expired);
            }
        }

        // Check max uses
        if let Some(max_uses) = self.max_uses {
            let redemptions = self.redemptions_count_sync(pool)?;
            if redemptions >= max_uses as u16 {
                return Err(AuthorizationError::FullyRedeemed);
            }
        }

        // Handle Connect requests
        if let Request::Connect { secret, .. } = request {
            // Validate secret
            match secret {
                Some(s) if s != &self.secret => return Err(AuthorizationError::InvalidSecret),
                _ => {}
            }

            // Check if this pubkey has already redeemed
            let redeemed_pubkeys = self.redemptions_pubkeys_sync(pool)?;
            if !redeemed_pubkeys.contains(pubkey) {
                self.create_redemption_sync(pool, pubkey)?;
            }
            
            return Ok(true);
        }

        // For other requests, validate against policy permissions
        let permissions = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query_as::<_, Permission>(
                    r#"
                    SELECT p.* FROM permissions p
                    JOIN policy_permissions pp ON p.id = pp.permission_id
                    WHERE pp.policy_id = ?
                    "#,
                )
                .bind(self.policy_id)
                .fetch_all(pool)
                .await
            })
        })
        .map_err(|e| AuthorizationError::Database(e))?;

        // Convert to custom permissions
        let custom_permissions: Result<Vec<Box<dyn crate::traits::CustomPermission>>, _> = permissions
            .iter()
            .map(|p| p.to_custom_permission())
            .collect();
        let custom_permissions = custom_permissions.map_err(|_| AuthorizationError::Unauthorized)?;

        // Validate based on request type
        match request {
            Request::GetPublicKey => {
                // Check that the pubkey has connected to this authorization
                Ok(self.redemptions_pubkeys_sync(pool)?.contains(pubkey))
            }
            Request::SignEvent(event) => {
                for permission in &custom_permissions {
                    if !permission.can_sign(event) {
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            Request::GetRelays => Ok(true),
            Request::Nip04Encrypt { public_key, text } | Request::Nip44Encrypt { public_key, text } => {
                for permission in &custom_permissions {
                    if !permission.can_encrypt(text, pubkey, public_key) {
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            Request::Nip04Decrypt { public_key, ciphertext } | Request::Nip44Decrypt { public_key, ciphertext } => {
                for permission in &custom_permissions {
                    if !permission.can_decrypt(ciphertext, public_key, pubkey) {
                        return Err(AuthorizationError::Unauthorized);
                    }
                }
                Ok(true)
            }
            Request::Ping => Ok(true),
            _ => Err(AuthorizationError::Unauthorized),
        }
    }
}