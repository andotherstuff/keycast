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
        // Connect to relay
        self.client.add_relay("wss://relay3.openvine.co").await?;
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

        // Spawn background task to reload authorizations periodically or on signal
        let pool_clone = self.pool.clone();
        let key_manager_clone = self.key_manager.clone();
        let handlers_clone = self.handlers.clone();
        let client_clone = self.client.clone();
        tokio::spawn(async move {
            let signal_path = std::path::Path::new("database/.reload_signal");
            loop {
                // Check for signal file first
                if signal_path.exists() {
                    tracing::info!("Reload signal detected, reloading authorizations immediately");
                    let _ = std::fs::remove_file(signal_path); // Consume the signal

                    if let Err(e) = Self::reload_authorizations_if_needed(
                        &pool_clone,
                        &key_manager_clone,
                        &handlers_clone,
                        &client_clone
                    ).await {
                        tracing::error!("Error reloading authorizations: {}", e);
                    }
                }

                // Sleep briefly and check again (fast polling)
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        // Handle incoming events
        let client = self.client.clone();
        self.client
            .handle_notifications(|notification| async {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::NostrConnect {
                        let handlers_lock = handlers.clone();
                        let client_clone = client.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_nip46_request(handlers_lock, client_clone, event).await {
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

    async fn reload_authorizations_if_needed(
        pool: &SqlitePool,
        key_manager: &Arc<Box<dyn KeyManager>>,
        handlers: &Arc<RwLock<HashMap<String, AuthorizationHandler>>>,
        client: &Client,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get current count of authorizations in database
        let regular_count = Authorization::all_ids(pool).await?.len();
        let oauth_count = OAuthAuthorization::all_ids(pool).await?.len();
        let db_total = regular_count + oauth_count;

        // Get current count of loaded handlers
        let loaded_count = {
            let h = handlers.read().await;
            h.len()
        };

        // If counts differ, reload all authorizations
        if db_total != loaded_count {
            tracing::info!(
                "Authorization count changed (DB: {}, Loaded: {}), reloading...",
                db_total,
                loaded_count
            );

            let mut new_handlers = HashMap::new();

            // Load regular authorizations
            let regular_auths = Authorization::all_ids(pool).await?;
            for auth_id in regular_auths {
                let auth = Authorization::find(pool, auth_id).await?;

                // Decrypt bunker secret
                let decrypted_bunker_secret = key_manager.decrypt(&auth.bunker_secret).await?;
                let bunker_secret_key = SecretKey::from_slice(&decrypted_bunker_secret)?;
                let bunker_keys = Keys::new(bunker_secret_key);

                // Decrypt user secret
                let stored_key = auth.stored_key(pool).await?;
                let decrypted_user_secret = key_manager.decrypt(&stored_key.secret_key).await?;
                let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)?;
                let user_keys = Keys::new(user_secret_key);

                let bunker_pubkey = bunker_keys.public_key().to_hex();

                new_handlers.insert(bunker_pubkey.clone(), AuthorizationHandler {
                    bunker_keys,
                    user_keys,
                    secret: auth.secret.clone(),
                    authorization_id: auth_id,
                    is_oauth: false,
                    pool: pool.clone(),
                });
            }

            // Load OAuth authorizations
            let oauth_auths = OAuthAuthorization::all_ids(pool).await?;
            for auth_id in oauth_auths {
                let auth = OAuthAuthorization::find(pool, auth_id).await?;

                // Decrypt user secret (used for both bunker and signing in OAuth)
                let decrypted_user_secret = key_manager.decrypt(&auth.bunker_secret).await?;
                let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)?;
                let user_keys = Keys::new(user_secret_key.clone());

                let bunker_pubkey = user_keys.public_key().to_hex();

                new_handlers.insert(bunker_pubkey.clone(), AuthorizationHandler {
                    bunker_keys: user_keys.clone(),
                    user_keys,
                    secret: auth.secret.clone(),
                    authorization_id: auth_id,
                    is_oauth: true,
                    pool: pool.clone(),
                });
            }

            // Update handlers
            {
                let mut h = handlers.write().await;
                *h = new_handlers;
            }

            // Resubscribe with updated pubkeys
            let handler_pubkeys: Vec<String> = {
                let h = handlers.read().await;
                h.keys().cloned().collect()
            };

            if !handler_pubkeys.is_empty() {
                let filter = Filter::new()
                    .kind(Kind::NostrConnect)
                    .pubkeys(handler_pubkeys.iter().map(|pk| {
                        PublicKey::from_hex(pk).unwrap()
                    }));

                client.subscribe(vec![filter], None).await?;

                tracing::info!(
                    "Reloaded {} authorizations and updated subscriptions",
                    handler_pubkeys.len()
                );
            }
        }

        Ok(())
    }

    async fn handle_nip46_request(
        handlers: Arc<RwLock<HashMap<String, AuthorizationHandler>>>,
        client: Client,
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

        // Decrypt the request - try NIP-44 first, fall back to NIP-04
        let bunker_secret = handler.bunker_keys.secret_key();

        tracing::debug!(
            "Attempting to decrypt NIP-46 request - content_len: {}, from_pubkey: {}",
            event.content.len(),
            event.pubkey.to_hex()
        );

        // Try NIP-44 first (new standard), track which method worked
        let (decrypted, use_nip44) = match nip44::decrypt(
            bunker_secret,
            &event.pubkey,
            &event.content,
        ) {
            Ok(d) => {
                tracing::debug!("Successfully decrypted with NIP-44");
                (d, true)
            },
            Err(nip44_err) => {
                tracing::debug!("NIP-44 decrypt failed ({}), trying NIP-04...", nip44_err);
                // Fall back to NIP-04 for backwards compatibility
                match nip04::decrypt(
                    bunker_secret,
                    &event.pubkey,
                    &event.content,
                ) {
                    Ok(d) => {
                        tracing::debug!("Successfully decrypted with NIP-04");
                        (d, false)
                    },
                    Err(nip04_err) => {
                        tracing::error!(
                            "Both NIP-44 and NIP-04 decrypt failed - NIP-44: {}, NIP-04: {} | From: {}",
                            nip44_err,
                            nip04_err,
                            event.pubkey.to_hex()
                        );
                        return Err(nip04_err.into());
                    }
                }
            }
        };

        tracing::debug!("Decrypted NIP-46 request: {}", decrypted);

        // Parse the JSON-RPC request
        let request: serde_json::Value = serde_json::from_str(&decrypted)?;
        let method = request["method"].as_str().ok_or("No method")?;
        let request_id = request["id"].clone(); // Extract request ID for response

        // Handle different NIP-46 methods
        let result = match method {
            "sign_event" => {
                let signed = handler.handle_sign_event(&request).await?;
                // handle_sign_event already returns full response with id
                signed
            }
            "get_public_key" => {
                serde_json::json!({
                    "id": request_id,
                    "result": handler.user_keys.public_key().to_hex()
                })
            }
            "connect" => {
                // Validate secret
                if let Some(provided_secret) = request["params"][1].as_str() {
                    if provided_secret == handler.secret {
                        serde_json::json!({"id": request_id, "result": "ack"})
                    } else {
                        serde_json::json!({"id": request_id, "error": "Invalid secret"})
                    }
                } else {
                    serde_json::json!({"id": request_id, "result": "ack"})
                }
            }
            _ => {
                tracing::warn!("Unsupported NIP-46 method: {}", method);
                serde_json::json!({"id": request_id, "error": format!("Unsupported method: {}", method)})
            }
        };

        let response = result;

        // Encrypt response using the same method as the request
        let response_str = response.to_string();
        let encrypted_response = if use_nip44 {
            tracing::debug!("Encrypting response with NIP-44");
            nip44::encrypt(
                bunker_secret,
                &event.pubkey,
                &response_str,
                nip44::Version::V2,
            )?
        } else {
            tracing::debug!("Encrypting response with NIP-04");
            nip04::encrypt(
                bunker_secret,
                &event.pubkey,
                &response_str,
            )?
        };

        // Build and publish response event
        tracing::debug!("Sending NIP-46 response to {}", event.pubkey);

        let response_event = EventBuilder::new(
            Kind::NostrConnect,
            encrypted_response
        )
        .tags(vec![
            Tag::public_key(event.pubkey),  // Tag the original requester
            Tag::parse(vec!["e".to_string(), event.id.to_hex()])?,  // Reference the request event
        ])
        .sign(&handler.bunker_keys).await?;

        tracing::debug!("Sending response event {} (size: {} bytes)", response_event.id, response_event.content.len());

        let send_result = client.send_event(response_event.clone()).await.map_err(|e| {
            tracing::error!("Failed to send response event: {:?}", e);
            e
        })?;

        tracing::info!("Sent NIP-46 response for request {} (send_result: {:?})", event.id, send_result);

        Ok(())
    }
}

impl AuthorizationHandler {
    async fn handle_sign_event(&self, request: &serde_json::Value) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Parse the unsigned event from params
        let event_json = request["params"][0].as_str().ok_or("No event in params")?;
        let unsigned_event: serde_json::Value = serde_json::from_str(event_json)?;

        // Extract fields from unsigned event
        let kind = unsigned_event["kind"].as_u64().ok_or("Missing kind")? as u16;
        let content = unsigned_event["content"].as_str().ok_or("Missing content")?;
        let created_at = unsigned_event["created_at"].as_u64().ok_or("Missing created_at")?;
        let tags_json = unsigned_event["tags"].as_array().ok_or("Missing tags")?;

        // Parse tags
        let mut tags = Vec::new();
        for tag_arr in tags_json {
            if let Some(arr) = tag_arr.as_array() {
                let tag_strs: Vec<String> = arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if !tag_strs.is_empty() {
                    tags.push(Tag::parse(tag_strs)?);
                }
            }
        }

        tracing::info!(
            "Signing event kind {} for authorization {}",
            kind,
            self.authorization_id
        );

        // TODO: Validate permissions/policy

        tracing::debug!("Building event to sign: kind={}, content_len={}, tags_count={}", kind, content.len(), tags.len());

        // Sign the event with user keys
        let signed_event = EventBuilder::new(
            Kind::from(kind),
            content
        )
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at))
        .sign(&self.user_keys).await.map_err(|e| {
            tracing::error!("Failed to sign event: {:?}", e);
            e
        })?;

        tracing::debug!("Successfully signed event: {}", signed_event.id);

        // Extract request ID to include in response
        let request_id = request["id"].clone();

        Ok(serde_json::json!({
            "id": request_id,
            "result": serde_json::to_string(&signed_event)?
        }))
    }
}

