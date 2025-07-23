// ABOUTME: User key management endpoints
// ABOUTME: CRUD operations for user's Nostr keys

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::api::error::ApiError;
use crate::api::http::auth::get_user_from_session;
use crate::state::get_key_manager;
use keycast_core::types::{
    user_key::{UserKey, UserKeyType, UserKeyPublic},
    user_enhanced::UserEnhanced,
};
use nostr_sdk::PublicKey;

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub key_type: UserKeyType,
    #[serde(default)]
    pub generate: bool,
    pub secret_key: Option<String>, // Hex encoded if importing
}

#[derive(Debug, Deserialize)]
pub struct UpdateKeyRequest {
    pub name: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct KeyListResponse {
    pub keys: Vec<UserKeyPublic>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyResponse {
    pub key: UserKeyPublic,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

// ============ Routes ============

pub fn routes() -> Router {
    Router::new()
        .route("/", get(list_keys).post(create_key))
        .route("/:id", get(get_key).put(update_key).delete(delete_key))
        .route("/:id/rotate", post(rotate_key))
        .route("/:id/set-primary", post(set_primary_key))
}

// ============ Handlers ============

/// GET /api/users/keys
/// List all keys for the authenticated user
pub async fn list_keys(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    let public_key = PublicKey::from_hex(&user.public_key)
        .map_err(|_| ApiError::internal("Invalid user public key"))?;
    
    let keys = UserKey::list_for_user(&pool, &public_key)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to list keys: {}", e)))?;
    
    let public_keys: Vec<UserKeyPublic> = keys.into_iter().map(Into::into).collect();
    let total = public_keys.len();
    
    Ok(Json(KeyListResponse {
        keys: public_keys,
        total,
    }).into_response())
}

/// POST /api/users/keys
/// Create a new key for the user
pub async fn create_key(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateKeyRequest>,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    let public_key = PublicKey::from_hex(&user.public_key)
        .map_err(|_| ApiError::internal("Invalid user public key"))?;
    
    // Validate key name
    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("Key name cannot be empty"));
    }
    
    // Parse secret key if importing
    let secret_key = if let Some(hex) = req.secret_key {
        if !req.generate {
            Some(nostr_sdk::SecretKey::from_hex(&hex)
                .map_err(|_| ApiError::bad_request("Invalid secret key format"))?)
        } else {
            return Err(ApiError::bad_request("Cannot both generate and import a key"));
        }
    } else if !req.generate {
        return Err(ApiError::bad_request("Must either generate or provide a secret key"));
    } else {
        None
    };
    
    // Get key manager
    let key_manager = get_key_manager()?;
    
    // Create the key
    let key = UserKey::create(
        &pool,
        key_manager.as_ref(),
        &public_key,
        &req.name,
        req.key_type,
        secret_key,
    )
    .await
    .map_err(|e| match e {
        keycast_core::types::user_key::UserKeyError::PrimaryKeyExists => {
            ApiError::bad_request("User already has a primary key")
        }
        keycast_core::types::user_key::UserKeyError::AlreadyExists => {
            ApiError::bad_request("A key with this public key already exists")
        }
        _ => ApiError::internal(format!("Failed to create key: {}", e)),
    })?;
    
    let mut warning = None;
    if req.key_type == UserKeyType::Primary && !req.generate {
        warning = Some("Importing your own primary key may reduce security. Consider generating a new one.".to_string());
    }
    
    Ok((
        StatusCode::CREATED,
        Json(CreateKeyResponse {
            key: key.into(),
            warning,
        }),
    ).into_response())
}

/// GET /api/users/keys/:id
/// Get details of a specific key
pub async fn get_key(
    State(pool): State<SqlitePool>,
    Path(key_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Find the key and verify ownership
    let key = UserKey::find(&pool, &key_id, &user.id)
        .await
        .map_err(|e| match e {
            keycast_core::types::user_key::UserKeyError::NotFound => {
                ApiError::not_found("Key not found")
            }
            _ => ApiError::internal(format!("Failed to get key: {}", e)),
        })?;
    
    Ok(Json(UserKeyPublic::from(key)).into_response())
}

/// PUT /api/users/keys/:id
/// Update key details (name, active status)
pub async fn update_key(
    State(pool): State<SqlitePool>,
    Path(key_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<UpdateKeyRequest>,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Verify the key exists and belongs to the user
    let mut key = UserKey::find(&pool, &key_id, &user.id)
        .await
        .map_err(|_| ApiError::not_found("Key not found"))?;
    
    // Update fields if provided
    let mut updated = false;
    
    if let Some(name) = req.name {
        if name.trim().is_empty() {
            return Err(ApiError::bad_request("Key name cannot be empty"));
        }
        key.name = name;
        updated = true;
    }
    
    if let Some(is_active) = req.is_active {
        // Don't allow deactivating primary key if it's the only one
        if !is_active && key.key_type == UserKeyType::Primary {
            return Err(ApiError::bad_request("Cannot deactivate primary key"));
        }
        key.is_active = is_active;
        updated = true;
    }
    
    if !updated {
        return Err(ApiError::bad_request("No fields to update"));
    }
    
    // Update in database
    sqlx::query(
        r#"
        UPDATE user_keys 
        SET name = ?1, is_active = ?2, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?3 AND user_id = ?4
        "#,
    )
    .bind(&key.name)
    .bind(key.is_active)
    .bind(&key_id)
    .bind(&user.id)
    .execute(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to update key: {}", e)))?;
    
    Ok(Json(UserKeyPublic::from(key)).into_response())
}

/// DELETE /api/users/keys/:id
/// Delete a key (cannot delete primary key)
pub async fn delete_key(
    State(pool): State<SqlitePool>,
    Path(key_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Get the key to check its type
    let key = UserKey::find(&pool, &key_id, &user.id)
        .await
        .map_err(|_| ApiError::not_found("Key not found"))?;
    
    if key.key_type == UserKeyType::Primary {
        return Err(ApiError::bad_request("Cannot delete primary key"));
    }
    
    // Check if key is used in any authorizations
    let auth_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM authorizations WHERE user_key_id = ?1 AND status = 'active'"
    )
    .bind(&key_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check authorizations: {}", e)))?;
    
    if auth_count > 0 {
        return Err(ApiError::bad_request(
            "Cannot delete key that has active authorizations. Revoke them first."
        ));
    }
    
    // Delete the key
    sqlx::query("DELETE FROM user_keys WHERE id = ?1 AND user_id = ?2")
        .bind(&key_id)
        .bind(&user.id)
        .execute(&pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to delete key: {}", e)))?;
    
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// POST /api/users/keys/:id/rotate
/// Rotate a key (generate new key, keep metadata)
pub async fn rotate_key(
    State(pool): State<SqlitePool>,
    Path(key_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    let key_manager = get_key_manager()?;
    
    // Get the existing key
    let old_key = UserKey::find(&pool, &key_id, &user.id)
        .await
        .map_err(|_| ApiError::not_found("Key not found"))?;
    
    // Generate new key pair
    let new_keys = nostr_sdk::Keys::generate();
    let new_secret = new_keys.secret_key().as_secret_bytes();
    let encrypted_secret = key_manager
        .encrypt(new_secret)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to encrypt key: {}", e)))?;
    
    // Update the key with new values
    sqlx::query(
        r#"
        UPDATE user_keys 
        SET public_key = ?1, secret_key = ?2, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?3 AND user_id = ?4
        "#,
    )
    .bind(new_keys.public_key().to_hex())
    .bind(&encrypted_secret)
    .bind(&key_id)
    .bind(&user.id)
    .execute(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to rotate key: {}", e)))?;
    
    // Get updated key
    let rotated_key = UserKey::find(&pool, &key_id, &user.id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get rotated key: {}", e)))?;
    
    Ok(Json(UserKeyPublic::from(rotated_key)).into_response())
}

/// POST /api/users/keys/:id/set-primary
/// Set a key as the primary key
pub async fn set_primary_key(
    State(pool): State<SqlitePool>,
    Path(key_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Verify the key exists and belongs to the user
    let key = UserKey::find(&pool, &key_id, &user.id)
        .await
        .map_err(|_| ApiError::not_found("Key not found"))?;
    
    if key.key_type == UserKeyType::Primary {
        return Err(ApiError::bad_request("Key is already the primary key"));
    }
    
    if key.key_type == UserKeyType::Temporary {
        return Err(ApiError::bad_request("Temporary keys cannot be set as primary"));
    }
    
    // Start transaction
    let mut tx = pool.begin().await
        .map_err(|e| ApiError::internal(format!("Failed to start transaction: {}", e)))?;
    
    // Demote current primary key to app_specific
    sqlx::query(
        r#"
        UPDATE user_keys 
        SET key_type = 'app_specific', updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?1 AND key_type = 'primary'
        "#,
    )
    .bind(&user.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to demote primary key: {}", e)))?;
    
    // Promote selected key to primary
    sqlx::query(
        r#"
        UPDATE user_keys 
        SET key_type = 'primary', updated_at = CURRENT_TIMESTAMP
        WHERE id = ?1 AND user_id = ?2
        "#,
    )
    .bind(&key_id)
    .bind(&user.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to promote key: {}", e)))?;
    
    // Commit transaction
    tx.commit().await
        .map_err(|e| ApiError::internal(format!("Failed to commit transaction: {}", e)))?;
    
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}