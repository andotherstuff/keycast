// ABOUTME: Unified signer daemon that handles multiple NIP-46 bunker connections in a single process
// ABOUTME: Listens for NIP-46 requests and routes them to the appropriate authorization/key

use dotenv::dotenv;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::gcp_key_manager::GcpKeyManager;
use keycast_core::encryption::KeyManager;
use keycast_core::traits::AuthorizationValidations;
use keycast_core::types::authorization::Authorization;
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use nostr_sdk::prelude::*;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Clone)]
struct AuthorizationHandler {
    bunker_keys: Keys,
    user_keys: Keys,
    secret: String,
    authorization_id: u32,
    is_oauth: bool,
    pool: SqlitePool,
}

pub struct UnifiedSigner {
    handlers: Arc<RwLock<HashMap<String, AuthorizationHandler>>>, // bunker_pubkey -> handler
    client: Client,
    pool: SqlitePool,
    key_manager: Arc<Box<dyn KeyManager>>,
}

impl UnifiedSigner {
    pub async fn new(pool: SqlitePool, key_manager: Box<dyn KeyManager>) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::default();

        Ok(Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
            client,
            pool,
            key_manager: Arc::new(key_manager),
        })
    }

    pub async fn load_authorizations(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut handlers = self.handlers.write().await;
        handlers.clear();

        // Load regular authorizations
        let regular_auths = Authorization::all_ids(&self.pool).await?;
        let regular_auth_count = regular_auths.len();
        for auth_id in regular_auths {
            let auth = Authorization::find(&self.pool, auth_id).await?;

            // Decrypt bunker secret
            let decrypted_bunker_secret = self.key_manager.decrypt(&auth.bunker_secret).await?;
            let bunker_secret_key = SecretKey::from_slice(&decrypted_bunker_secret)?;
            let bunker_keys = Keys::new(bunker_secret_key);

            // Decrypt user secret
            let stored_key = auth.stored_key(&self.pool).await?;
            let decrypted_user_secret = self.key_manager.decrypt(&stored_key.secret_key).await?;
            let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)?;
            let user_keys = Keys::new(user_secret_key);

            let bunker_pubkey = bunker_keys.public_key().to_hex();

            tracing::info!(
                "Loaded regular authorization {} with bunker pubkey: {}",
                auth_id,
                bunker_pubkey
            );

            handlers.insert(bunker_pubkey, AuthorizationHandler {
                bunker_keys,
                user_keys,
                secret: auth.secret.clone(),
                authorization_id: auth_id,
                is_oauth: false,
                pool: self.pool.clone(),
            });
        }

        // Load OAuth authorizations
        let oauth_auths = OAuthAuthorization::all_ids(&self.pool).await?;
        let oauth_auth_count = oauth_auths.len();
        for auth_id in oauth_auths {
            let auth = OAuthAuthorization::find(&self.pool, auth_id).await?;

            // Decrypt user secret (used for both bunker and signing in OAuth)
            let decrypted_user_secret = self.key_manager.decrypt(&auth.bunker_secret).await?;
            let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)?;
            let user_keys = Keys::new(user_secret_key.clone());

            let bunker_pubkey = user_keys.public_key().to_hex();

            tracing::info!(
                "Loaded OAuth authorization {} with bunker pubkey: {}",
                auth_id,
                bunker_pubkey
            );

            handlers.insert(bunker_pubkey, AuthorizationHandler {
                bunker_keys: user_keys.clone(),
                user_keys,
                secret: auth.secret.clone(),
                authorization_id: auth_id,
                is_oauth: true,
                pool: self.pool.clone(),
            });
        }

        tracing::info!(
            "Loaded {} total authorizations ({} regular + {} OAuth)",
            handlers.len(),
            regular_auth_count,
            oauth_auth_count
        );

        Ok(())
    }

    pub async fn connect_to_relays(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Connect to common relay
        self.client.add_relay("wss://relay.damus.io").await?;
        self.client.connect().await;

        tracing::info!("Connected to relays");
        Ok(())
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let handlers = self.handlers.clone();

        // Subscribe to NIP-46 events for all our bunker pubkeys
        let handler_pubkeys: Vec<String> = {
            let h = handlers.read().await;
            h.keys().cloned().collect()
        };

        if handler_pubkeys.is_empty() {
            tracing::warn!("No authorizations loaded, nothing to do");
            return Ok(());
        }

        tracing::info!("Subscribing to NIP-46 events for {} bunker pubkeys", handler_pubkeys.len());

        let filter = Filter::new()
            .kind(Kind::NostrConnect)
            .pubkeys(handler_pubkeys.iter().map(|pk| {
                PublicKey::from_hex(pk).unwrap()
            }));

        self.client.subscribe(vec![filter], None).await?;

        // Handle incoming events
        self.client
            .handle_notifications(|notification| async {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::NostrConnect {
                        let handlers_lock = handlers.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_nip46_request(handlers_lock, event).await {
                                tracing::error!("Error handling NIP-46 request: {}", e);
                            }
                        });
                    }
                }
                Ok(false) // Continue listening
            })
            .await?;

        Ok(())
    }

    async fn handle_nip46_request(
        handlers: Arc<RwLock<HashMap<String, AuthorizationHandler>>>,
        event: Box<Event>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get the bunker pubkey from p-tag
        let bunker_pubkey = event
            .tags
            .iter()
            .find(|tag| tag.kind() == TagKind::p())
            .and_then(|tag| tag.content())
            .ok_or("No p-tag found")?;

        tracing::debug!("Received NIP-46 request for bunker: {}", bunker_pubkey);

        // Find the handler for this bunker pubkey
        let handler = {
            let h = handlers.read().await;
            h.get(bunker_pubkey).cloned()
        };

        let handler = match handler {
            Some(h) => h,
            None => {
                tracing::warn!("No handler found for bunker pubkey: {}", bunker_pubkey);
                return Ok(());
            }
        };

        // Decrypt the request using NIP-04
        let bunker_secret = handler.bunker_keys.secret_key();
        let decrypted = nip04::decrypt(
            bunker_secret,
            &event.pubkey,
            &event.content,
        )?;

        tracing::debug!("Decrypted NIP-46 request: {}", decrypted);

        // Parse the JSON-RPC request
        let request: serde_json::Value = serde_json::from_str(&decrypted)?;
        let method = request["method"].as_str().ok_or("No method")?;

        // Handle different NIP-46 methods
        let response = match method {
            "sign_event" => {
                handler.handle_sign_event(&request).await?
            }
            "get_public_key" => {
                serde_json::json!({
                    "result": handler.user_keys.public_key().to_hex()
                })
            }
            "connect" => {
                // Validate secret
                if let Some(provided_secret) = request["params"][1].as_str() {
                    if provided_secret == handler.secret {
                        serde_json::json!({"result": "ack"})
                    } else {
                        serde_json::json!({"error": "Invalid secret"})
                    }
                } else {
                    serde_json::json!({"result": "ack"})
                }
            }
            _ => {
                tracing::warn!("Unsupported NIP-46 method: {}", method);
                serde_json::json!({"error": format!("Unsupported method: {}", method)})
            }
        };

        // Encrypt response
        let response_str = response.to_string();
        let encrypted_response = nip04::encrypt(
            bunker_secret,
            &event.pubkey,
            &response_str,
        )?;

        // Send response event
        // TODO: Build and publish response event

        Ok(())
    }
}

impl AuthorizationHandler {
    async fn handle_sign_event(&self, request: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Parse the unsigned event from params
        let event_json = request["params"][0].as_str().ok_or("No event in params")?;
        let unsigned_event: Event = serde_json::from_str(event_json)?;

        tracing::info!(
            "Signing event kind {} for authorization {}",
            unsigned_event.kind,
            self.authorization_id
        );

        // TODO: Validate permissions/policy

        // Sign the event with user keys
        let signed_event = EventBuilder::new(
            unsigned_event.kind,
            unsigned_event.content.clone()
        )
        .tags(unsigned_event.tags.clone())
        .sign(&self.user_keys).await?;

        Ok(serde_json::json!({
            "result": serde_json::to_string(&signed_event)?
        }))
    }
}

