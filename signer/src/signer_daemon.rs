// ABOUTME: Unified signer daemon that handles multiple NIP-46 bunker connections in a single process
// ABOUTME: Listens for NIP-46 requests and routes them to the appropriate authorization/key

use keycast_core::encryption::KeyManager;
use keycast_core::types::authorization::Authorization;
use keycast_core::types::oauth_authorization::OAuthAuthorization;
use nostr_sdk::prelude::*;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
struct AuthorizationHandler {
    bunker_keys: Keys,
    user_keys: Keys,
    secret: String,
    authorization_id: u32,
    tenant_id: i64,
    is_oauth: bool,
    pool: SqlitePool,
}

pub struct UnifiedSigner {
    handlers: Arc<RwLock<HashMap<String, AuthorizationHandler>>>, // bunker_pubkey -> handler
    client: Client,
    pool: SqlitePool,
    key_manager: Arc<Box<dyn KeyManager>>,
    max_loaded_oauth_id: Arc<RwLock<u32>>,
    max_loaded_regular_id: Arc<RwLock<u32>>,
}

impl UnifiedSigner {
    pub async fn new(pool: SqlitePool, key_manager: Box<dyn KeyManager>) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::default();

        Ok(Self {
            handlers: Arc::new(RwLock::new(HashMap::new())),
            client,
            pool,
            key_manager: Arc::new(key_manager),
            max_loaded_oauth_id: Arc::new(RwLock::new(0)),
            max_loaded_regular_id: Arc::new(RwLock::new(0)),
        })
    }

    pub async fn load_authorizations(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut handlers = self.handlers.write().await;
        handlers.clear();

        // Load regular authorizations
        let regular_auths = Authorization::all_ids_for_all_tenants(&self.pool).await?;
        let regular_auth_count = regular_auths.len();
        for (tenant_id, auth_id) in regular_auths {
            let auth = Authorization::find(&self.pool, tenant_id, auth_id).await?;

            // Decrypt bunker secret
            let decrypted_bunker_secret = self.key_manager.decrypt(&auth.bunker_secret).await?;
            let bunker_secret_key = SecretKey::from_slice(&decrypted_bunker_secret)?;
            let bunker_keys = Keys::new(bunker_secret_key);

            // Decrypt user secret
            let stored_key = auth.stored_key(&self.pool, tenant_id).await?;
            let decrypted_user_secret = self.key_manager.decrypt(&stored_key.secret_key).await?;
            let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)?;
            let user_keys = Keys::new(user_secret_key);

            let bunker_pubkey = bunker_keys.public_key().to_hex();

            tracing::info!(
                "Loaded regular authorization {} (tenant {}) with bunker pubkey: {}",
                auth_id,
                tenant_id,
                bunker_pubkey
            );

            handlers.insert(bunker_pubkey, AuthorizationHandler {
                bunker_keys,
                user_keys,
                secret: auth.secret.clone(),
                authorization_id: auth_id,
                tenant_id,
                is_oauth: false,
                pool: self.pool.clone(),
            });
        }

        // Load OAuth authorizations
        let oauth_auths = OAuthAuthorization::all_ids_for_all_tenants(&self.pool).await?;
        let oauth_auth_count = oauth_auths.len();
        for (tenant_id, auth_id) in oauth_auths {
            let auth = OAuthAuthorization::find(&self.pool, tenant_id, auth_id).await?;

            // Decrypt user secret (used for both bunker and signing in OAuth)
            let decrypted_user_secret = self.key_manager.decrypt(&auth.bunker_secret).await?;
            let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)?;
            let user_keys = Keys::new(user_secret_key.clone());

            let bunker_pubkey = user_keys.public_key().to_hex();

            tracing::info!(
                "Loaded OAuth authorization {} (tenant {}) with bunker pubkey: {}",
                auth_id,
                tenant_id,
                bunker_pubkey
            );

            handlers.insert(bunker_pubkey, AuthorizationHandler {
                bunker_keys: user_keys.clone(),
                user_keys,
                secret: auth.secret.clone(),
                authorization_id: auth_id,
                tenant_id,
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
        // Connect to multiple relays for redundancy
        self.client.add_relay("wss://relay.damus.io").await?;
        self.client.add_relay("wss://relay.nsec.app").await?;
        self.client.add_relay("wss://nos.lol").await?;
        self.client.connect().await;

        tracing::info!("Connected to 3 relays for redundancy");
        Ok(())
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let handlers = self.handlers.clone();

        let handler_count = {
            let h = handlers.read().await;
            h.len()
        };

        if handler_count == 0 {
            tracing::info!("Starting with 0 authorizations, will reload when new ones are created");
        } else {
            tracing::info!(
                "Subscribing to ALL kind 24133 events on relay (managing {} bunker pubkeys)",
                handler_count
            );
        }

        // OPTIMIZATION: Single subscription for ALL kind 24133 events
        // We'll filter by bunker pubkey in the handler, not at relay level
        // This scales to millions of users with just ONE relay connection
        let filter = Filter::new().kind(Kind::NostrConnect);

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
        _client: &Client,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get current loaded pubkeys
        let loaded_pubkeys: std::collections::HashSet<String> = {
            let h = handlers.read().await;
            h.keys().cloned().collect()
        };

        // Load all authorization IDs from database
        let mut regular_auths = Authorization::all_ids_for_all_tenants(pool).await?;
        let mut oauth_auths = OAuthAuthorization::all_ids_for_all_tenants(pool).await?;

        // OPTIMIZATION: Only check the LAST 5 authorization IDs since new ones are at the end
        // This avoids decrypting all 67 authorizations with GCP KMS just to find 1 new one
        let regular_check_start = regular_auths.len().saturating_sub(5);
        let oauth_check_start = oauth_auths.len().saturating_sub(5);

        regular_auths = regular_auths.into_iter().skip(regular_check_start).collect();
        oauth_auths = oauth_auths.into_iter().skip(oauth_check_start).collect();

        tracing::debug!(
            "Fast reload: checking last {} regular + {} OAuth authorizations",
            regular_auths.len(),
            oauth_auths.len()
        );

        let mut added_count = 0;

        // Check for NEW regular authorizations
        for (tenant_id, auth_id) in regular_auths {
            let auth = Authorization::find(pool, tenant_id, auth_id).await?;

            // Decrypt bunker secret to get pubkey
            let decrypted_bunker_secret = key_manager.decrypt(&auth.bunker_secret).await?;
            let bunker_secret_key = SecretKey::from_slice(&decrypted_bunker_secret)?;
            let bunker_keys = Keys::new(bunker_secret_key);
            let bunker_pubkey = bunker_keys.public_key().to_hex();

            // Only load if not already loaded
            if !loaded_pubkeys.contains(&bunker_pubkey) {
                // Decrypt user secret
                let stored_key = auth.stored_key(pool, tenant_id).await?;
                let decrypted_user_secret = key_manager.decrypt(&stored_key.secret_key).await?;
                let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)?;
                let user_keys = Keys::new(user_secret_key);

                let handler = AuthorizationHandler {
                    bunker_keys,
                    user_keys,
                    secret: auth.secret.clone(),
                    authorization_id: auth_id,
                    tenant_id,
                    is_oauth: false,
                    pool: pool.clone(),
                };

                // Add to handlers immediately
                {
                    let mut h = handlers.write().await;
                    h.insert(bunker_pubkey.clone(), handler);
                }

                added_count += 1;

                tracing::info!(
                    "Added NEW regular authorization {} (tenant {}) with bunker pubkey: {}",
                    auth_id,
                    tenant_id,
                    bunker_pubkey
                );
            }
        }

        // Check for NEW OAuth authorizations
        for (tenant_id, auth_id) in oauth_auths {
            let auth = OAuthAuthorization::find(pool, tenant_id, auth_id).await?;

            // Decrypt user secret to get pubkey
            let decrypted_user_secret = key_manager.decrypt(&auth.bunker_secret).await?;
            let user_secret_key = SecretKey::from_slice(&decrypted_user_secret)?;
            let user_keys = Keys::new(user_secret_key.clone());
            let bunker_pubkey = user_keys.public_key().to_hex();

            // Only load if not already loaded
            if !loaded_pubkeys.contains(&bunker_pubkey) {
                let handler = AuthorizationHandler {
                    bunker_keys: user_keys.clone(),
                    user_keys,
                    secret: auth.secret.clone(),
                    authorization_id: auth_id,
                    tenant_id,
                    is_oauth: true,
                    pool: pool.clone(),
                };

                // Add to handlers immediately
                {
                    let mut h = handlers.write().await;
                    h.insert(bunker_pubkey.clone(), handler);
                }

                added_count += 1;

                tracing::info!(
                    "Added NEW OAuth authorization {} (tenant {}) with bunker pubkey: {}",
                    auth_id,
                    tenant_id,
                    bunker_pubkey
                );
            }
        }

        // No need to subscribe since we already get ALL kind 24133 events!
        if added_count > 0 {
            tracing::info!(
                "✅ Fast reload complete: Added {} new authorizations (no new subscription needed)",
                added_count
            );
        } else {
            tracing::debug!("No new authorizations to load");
        }

        Ok(())
    }

    async fn handle_nip46_request(
        handlers: Arc<RwLock<HashMap<String, AuthorizationHandler>>>,
        client: Client,
        event: Box<Event>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // SINGLE SUBSCRIPTION ARCHITECTURE:
        // We receive ALL kind 24133 events from the relay (no pubkey filter)
        // Now we check if the target bunker pubkey (in #p tag) is one we manage
        // If yes: decrypt and handle. If no: silently ignore
        // This scales to millions of users with just ONE relay connection!

        // Get the bunker pubkey from p-tag (target of the signing request)
        let bunker_pubkey = event
            .tags
            .iter()
            .find(|tag| tag.kind() == TagKind::p())
            .and_then(|tag| tag.content())
            .ok_or("No p-tag found")?;

        tracing::debug!("Received NIP-46 request for bunker: {}", bunker_pubkey);

        // Check if this bunker pubkey is one we manage
        let handler = {
            let h = handlers.read().await;
            h.get(bunker_pubkey).cloned()
        };

        let handler = match handler {
            Some(h) => h,
            None => {
                // Not our bunker, silently ignore (this is normal with single subscription)
                tracing::debug!("Ignoring NIP-46 request for unmanaged bunker: {}", bunker_pubkey);
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

        tracing::info!("Processing NIP-46 method: {}", method);

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
            "nip44_encrypt" => {
                // params: [third_party_pubkey, plaintext]
                let third_party_hex = request["params"][0].as_str().ok_or("Missing pubkey param")?;
                let plaintext = request["params"][1].as_str().ok_or("Missing plaintext param")?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)?;
                let ciphertext = nip44::encrypt(
                    handler.user_keys.secret_key(),
                    &third_party_pubkey,
                    plaintext,
                    nip44::Version::V2,
                )?;

                serde_json::json!({
                    "id": request_id,
                    "result": ciphertext
                })
            }
            "nip44_decrypt" => {
                // params: [third_party_pubkey, ciphertext]
                let third_party_hex = request["params"][0].as_str().ok_or("Missing pubkey param")?;
                let ciphertext = request["params"][1].as_str().ok_or("Missing ciphertext param")?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)?;
                let plaintext = nip44::decrypt(
                    handler.user_keys.secret_key(),
                    &third_party_pubkey,
                    ciphertext,
                )?;

                serde_json::json!({
                    "id": request_id,
                    "result": plaintext
                })
            }
            "nip04_encrypt" => {
                // params: [third_party_pubkey, plaintext]
                let third_party_hex = request["params"][0].as_str().ok_or("Missing pubkey param")?;
                let plaintext = request["params"][1].as_str().ok_or("Missing plaintext param")?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)?;
                let ciphertext = nip04::encrypt(
                    handler.user_keys.secret_key(),
                    &third_party_pubkey,
                    plaintext,
                )?;

                serde_json::json!({
                    "id": request_id,
                    "result": ciphertext
                })
            }
            "nip04_decrypt" => {
                // params: [third_party_pubkey, ciphertext]
                let third_party_hex = request["params"][0].as_str().ok_or("Missing pubkey param")?;
                let ciphertext = request["params"][1].as_str().ok_or("Missing ciphertext param")?;

                let third_party_pubkey = PublicKey::from_hex(third_party_hex)?;
                let plaintext = nip04::decrypt(
                    handler.user_keys.secret_key(),
                    &third_party_pubkey,
                    ciphertext,
                )?;

                serde_json::json!({
                    "id": request_id,
                    "result": plaintext
                })
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

        // Log signing activity to database
        if let Err(e) = self.log_signing_activity(kind, content, &signed_event.id.to_hex()).await {
            tracing::error!("Failed to log signing activity: {}", e);
            // Don't fail the signing request if activity logging fails
        }

        // Extract request ID to include in response
        let request_id = request["id"].clone();

        Ok(serde_json::json!({
            "id": request_id,
            "result": serde_json::to_string(&signed_event)?
        }))
    }

    async fn log_signing_activity(
        &self,
        event_kind: u16,
        event_content: &str,
        event_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Get user public key and application ID
        let (user_pubkey, application_id, client_pubkey, bunker_secret) = if self.is_oauth {
            // For OAuth, look up the oauth_authorization
            let oauth_auth: (String, Option<i64>, Option<String>, String) = sqlx::query_as(
                "SELECT user_public_key, application_id, client_public_key, secret
                 FROM oauth_authorizations
                 WHERE tenant_id = ?1 AND id = ?2"
            )
            .bind(self.tenant_id)
            .bind(self.authorization_id as i64)
            .fetch_one(&self.pool)
            .await?;
            oauth_auth
        } else {
            // For regular authorizations, look up via authorizations table
            let auth: (i64, String) = sqlx::query_as(
                "SELECT stored_key_id, secret FROM authorizations WHERE tenant_id = ?1 AND id = ?2"
            )
            .bind(self.tenant_id)
            .bind(self.authorization_id as i64)
            .fetch_one(&self.pool)
            .await?;

            let stored_key_id = auth.0;
            let bunker_secret = auth.1;

            // Get public_key from stored_keys
            let stored_key: (String,) = sqlx::query_as(
                "SELECT public_key FROM stored_keys WHERE tenant_id = ?1 AND id = ?2"
            )
            .bind(self.tenant_id)
            .bind(stored_key_id)
            .fetch_one(&self.pool)
            .await?;

            (stored_key.0, None, None, bunker_secret)
        };

        // Truncate content for storage (don't store huge amounts of text)
        let truncated_content = if event_content.len() > 500 {
            format!("{}... (truncated)", &event_content[..500])
        } else {
            event_content.to_string()
        };

        // Insert signing activity
        sqlx::query(
            "INSERT INTO signing_activity
             (tenant_id, user_public_key, application_id, bunker_secret, event_kind, event_content, event_id, client_public_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP)"
        )
        .bind(self.tenant_id)
        .bind(&user_pubkey)
        .bind(application_id)
        .bind(&bunker_secret)
        .bind(event_kind as i64)
        .bind(&truncated_content)
        .bind(event_id)
        .bind(&client_pubkey)
        .execute(&self.pool)
        .await?;

        tracing::debug!("Logged signing activity for tenant {} user {} kind {}", self.tenant_id, user_pubkey, event_kind);

        Ok(())
    }
}

