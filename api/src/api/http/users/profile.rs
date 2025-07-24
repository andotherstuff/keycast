// ABOUTME: User profile management endpoints
// ABOUTME: Get and update user profile information

use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::api::error::ApiError;
use crate::api::http::auth::get_user_from_session;
use keycast_core::types::{
    user_enhanced::UserEnhanced,
    user_auth::UserAuthMethod,
    user_key::UserKey,
};

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub nip05_identifier: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub nip05_identifier: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub auth_methods: Vec<AuthMethodResponse>,
    pub primary_key: Option<UserKeyResponse>,
    pub keys_count: usize,
    pub policies_count: usize,
    pub active_authorizations_count: usize,
    pub email_verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuthMethodResponse {
    pub auth_type: String,
    pub identifier: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct UserKeyResponse {
    pub id: String,
    pub name: String,
    pub public_key: String,
}

// ============ Routes ============

pub fn routes() -> Router {
    Router::new()
        .route("/profile", get(get_profile).put(update_profile))
}

// ============ Handlers ============

/// GET /api/users/profile
/// Get the authenticated user's profile with all details
pub async fn get_profile(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Get auth methods
    let auth_methods = sqlx::query_as::<_, UserAuth>(
        "SELECT * FROM user_auth WHERE user_id = ? ORDER BY created_at"
    )
    .bind(&user.id)
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch auth methods: {}", e)))?;
    
    let auth_method_responses: Vec<AuthMethodResponse> = auth_methods
        .into_iter()
        .map(|auth| AuthMethodResponse {
            auth_type: auth.auth_type,
            identifier: auth.identifier,
            created_at: auth.created_at,
        })
        .collect();
    
    // Get primary key
    let primary_key = sqlx::query_as::<_, UserKey>(
        "SELECT * FROM user_keys WHERE user_id = ? AND is_primary = TRUE"
    )
    .bind(&user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch primary key: {}", e)))?;
    
    let primary_key_response = primary_key.map(|key| UserKeyResponse {
        id: key.id,
        name: key.name,
        public_key: key.public_key,
    });
    
    // Get counts
    let keys_count = sqlx::query!(
        "SELECT COUNT(*) as count FROM user_keys WHERE user_id = ?",
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to count keys: {}", e)))?
    .count as usize;
    
    let policies_count = sqlx::query!(
        "SELECT COUNT(*) as count FROM policies WHERE user_id = ?",
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to count policies: {}", e)))?
    .count as usize;
    
    let active_authorizations_count = sqlx::query!(
        r#"
        SELECT COUNT(*) as count 
        FROM authorizations 
        WHERE user_id = ? 
        AND status = 'active'
        AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        "#,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to count authorizations: {}", e)))?
    .count as usize;
    
    // Parse additional profile fields from metadata
    let metadata = user.metadata
        .and_then(|m| serde_json::from_str::<serde_json::Value>(&m).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    
    let avatar_url = metadata.get("avatar_url")
        .and_then(|v| v.as_str())
        .map(String::from);
    
    let bio = metadata.get("bio")
        .and_then(|v| v.as_str())
        .map(String::from);
    
    Ok(Json(UserProfileResponse {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        nip05_identifier: user.nip05_identifier,
        avatar_url,
        bio,
        auth_methods: auth_method_responses,
        primary_key: primary_key_response,
        keys_count,
        policies_count,
        active_authorizations_count,
        email_verified: user.email_verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }).into_response())
}

/// PUT /api/users/profile
/// Update the authenticated user's profile
pub async fn update_profile(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Response, ApiError> {
    let mut user = get_user_from_session(&pool, headers).await?;
    
    // Validate NIP-05 identifier if provided
    if let Some(ref nip05) = req.nip05_identifier {
        if !nip05.is_empty() {
            // Basic NIP-05 format validation
            let parts: Vec<&str> = nip05.split('@').collect();
            if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
                return Err(ApiError::bad_request("Invalid NIP-05 identifier format"));
            }
            
            // Check if NIP-05 is already taken by another user
            let exists = sqlx::query!(
                "SELECT COUNT(*) as count FROM users WHERE nip05_identifier = ? AND id != ?",
                nip05,
                user.id
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to check NIP-05: {}", e)))?
            .count > 0;
            
            if exists {
                return Err(ApiError::bad_request("NIP-05 identifier already taken"));
            }
        }
    }
    
    // Update basic fields
    let mut updates = Vec::new();
    let mut bindings: Vec<String> = Vec::new();
    
    if let Some(display_name) = req.display_name {
        updates.push("display_name = ?");
        bindings.push(display_name);
    }
    
    if let Some(nip05) = req.nip05_identifier {
        updates.push("nip05_identifier = ?");
        bindings.push(if nip05.is_empty() { 
            "NULL".to_string() 
        } else { 
            format!("'{}'", nip05) 
        });
    }
    
    // Handle metadata fields (avatar_url, bio)
    let mut metadata = user.metadata
        .clone()
        .and_then(|m| serde_json::from_str::<serde_json::Value>(&m).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    
    let mut metadata_updated = false;
    
    if let Some(avatar_url) = req.avatar_url {
        if avatar_url.is_empty() {
            metadata.as_object_mut().unwrap().remove("avatar_url");
        } else {
            metadata["avatar_url"] = serde_json::Value::String(avatar_url);
        }
        metadata_updated = true;
    }
    
    if let Some(bio) = req.bio {
        if bio.is_empty() {
            metadata.as_object_mut().unwrap().remove("bio");
        } else {
            metadata["bio"] = serde_json::Value::String(bio);
        }
        metadata_updated = true;
    }
    
    if metadata_updated {
        updates.push("metadata = ?");
        bindings.push(serde_json::to_string(&metadata)
            .map_err(|e| ApiError::internal(format!("Failed to serialize metadata: {}", e)))?);
    }
    
    if updates.is_empty() {
        return Err(ApiError::bad_request("No fields to update"));
    }
    
    updates.push("updated_at = CURRENT_TIMESTAMP");
    
    // Build and execute query
    let query = format!(
        "UPDATE users SET {} WHERE id = ?",
        updates.join(", ")
    );
    
    let mut query_builder = sqlx::query(&query);
    
    // Bind parameters based on what was updated
    if req.display_name.is_some() {
        query_builder = query_builder.bind(&bindings[0]);
    }
    
    let mut bind_idx = if req.display_name.is_some() { 1 } else { 0 };
    
    if req.nip05_identifier.is_some() {
        let nip05_value = req.nip05_identifier.unwrap();
        if nip05_value.is_empty() {
            query_builder = query_builder.bind::<Option<String>>(None);
        } else {
            query_builder = query_builder.bind(Some(nip05_value));
        }
        bind_idx += 1;
    }
    
    if metadata_updated {
        query_builder = query_builder.bind(&bindings[bind_idx]);
    }
    
    query_builder = query_builder.bind(&user.id);
    
    query_builder
        .execute(&pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update profile: {}", e)))?;
    
    // Fetch and return updated profile
    get_profile(State(pool), headers).await
}