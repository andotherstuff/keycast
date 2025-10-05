// ABOUTME: OAuth authorization type for handling OAuth-based remote signing
// ABOUTME: Unlike regular authorizations, OAuth uses the user's personal key for both NIP-46 encryption and event signing

use crate::encryption::KeyManagerError;
use crate::traits::AuthorizationValidations;
use crate::types::authorization::{AuthorizationError, Relays};
use chrono::DateTime;
use nostr::nips::nip46::Request;
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};

/// An OAuth authorization where the user's personal key serves as both bunker key and signing key
#[derive(Debug, FromRow, Serialize, Deserialize, Clone)]
pub struct OAuthAuthorization {
    /// The id of the authorization
    pub id: u32,
    /// The user's public key (also used as bunker public key)
    pub user_public_key: String,
    /// The OAuth application id
    pub application_id: u32,
    /// The bunker public key (same as user_public_key)
    pub bunker_public_key: String,
    /// The encrypted user private key (used for both NIP-46 decryption and event signing)
    pub bunker_secret: Vec<u8>,
    /// The connection secret for NIP-46 authentication
    pub secret: String,
    #[sqlx(try_from = "String")]
    /// The list of relays the authorization will listen on
    pub relays: Relays,
    /// The date and time the authorization was created
    pub created_at: DateTime<chrono::Utc>,
    /// The date and time the authorization was last updated
    pub updated_at: DateTime<chrono::Utc>,
}

impl OAuthAuthorization {
    pub async fn find(pool: &SqlitePool, id: u32) -> Result<Self, AuthorizationError> {
        let authorization = sqlx::query_as::<_, OAuthAuthorization>(
            r#"
            SELECT * FROM oauth_authorizations WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(authorization)
    }

    pub async fn all_ids(pool: &SqlitePool) -> Result<Vec<u32>, AuthorizationError> {
        let authorizations = sqlx::query_scalar::<_, u32>(
            r#"
            SELECT id FROM oauth_authorizations
            "#,
        )
        .fetch_all(pool)
        .await?;
        Ok(authorizations)
    }
}

impl AuthorizationValidations for OAuthAuthorization {
    fn validate_policy(
        &self,
        pool: &SqlitePool,
        pubkey: &PublicKey,
        request: &Request,
    ) -> Result<bool, AuthorizationError> {
        // For OAuth, we allow all operations since the user authorized the app
        // The app itself should enforce its own restrictions
        match request {
            Request::Connect { public_key, secret } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Connect request received");
                // Check the public key matches
                if public_key.to_hex() != self.bunker_public_key {
                    return Err(AuthorizationError::Unauthorized);
                }
                // Check that secret is correct
                match secret {
                    Some(ref s) if s != &self.secret => {
                        return Err(AuthorizationError::InvalidSecret)
                    }
                    _ => {}
                }
                Ok(true)
            }
            Request::GetPublicKey => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Get public key request");
                Ok(true)
            }
            Request::SignEvent(_event) => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Sign event request");
                Ok(true)
            }
            Request::GetRelays => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Get relays request");
                Ok(true)
            }
            Request::Nip04Encrypt { .. } | Request::Nip44Encrypt { .. } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth NIP04/44 encrypt request");
                Ok(true)
            }
            Request::Nip04Decrypt { .. } | Request::Nip44Decrypt { .. } => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth NIP04/44 decrypt request");
                Ok(true)
            }
            Request::Ping => {
                tracing::info!(target: "keycast_signer::signer_daemon", "OAuth Ping request");
                Ok(true)
            }
        }
    }
}
