// ABOUTME: User authorization management endpoints
// ABOUTME: Create and manage NIP-46 authorizations for apps

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
use keycast_core::types::{
    authorization_enhanced::AuthorizationEnhanced,
    application::Application,
    policy::Policy,
    user_key::UserKey,
};

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
pub struct CreateAuthorizationRequest {
    pub user_key_id: String,
    pub application_id: u32,
    pub policy_id: u32,
    pub max_uses: Option<u16>,
    pub expires_in_hours: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAuthorizationRequest {
    pub max_uses: Option<u16>,
    pub expires_in_hours: Option<u32>,
    pub status: Option<AuthorizationStatus>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Serialize)]
pub struct AuthorizationResponse {
    pub id: u32,
    pub user_id: String,
    pub user_key_id: String,
    pub application: ApplicationSummary,
    pub policy: PolicySummary,
    pub bunker_public_key: String,
    pub max_uses: Option<u16>,
    pub current_uses: u16,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: AuthorizationStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ApplicationSummary {
    pub id: u32,
    pub domain: String,
    pub name: String,
    pub icon_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub id: u32,
    pub name: String,
    pub permissions_count: usize,
}

#[derive(Debug, Serialize)]
pub struct AuthorizationListResponse {
    pub authorizations: Vec<AuthorizationResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct BunkerUrlResponse {
    pub bunker_url: String,
    pub relay_urls: Vec<String>,
}

// ============ Routes ============

pub fn routes() -> Router {
    Router::new()
        .route("/", get(list_authorizations).post(create_authorization))
        .route("/:id", get(get_authorization).put(update_authorization).delete(revoke_authorization))
        .route("/:id/bunker", get(get_bunker_url))
}

// ============ Handlers ============

/// GET /api/users/authorizations
/// List all authorizations for the authenticated user
pub async fn list_authorizations(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Get authorizations with enhanced type
    let authorizations = sqlx::query_as::<_, AuthorizationEnhanced>(
        r#"
        SELECT * FROM authorizations 
        WHERE user_id = ? 
        ORDER BY created_at DESC
        "#
    )
    .bind(&user.id)
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch authorizations: {}", e)))?;
    
    // Convert to response format with related data
    let mut auth_responses = Vec::new();
    for auth in authorizations {
        // Get application
        let app = Application::find_by_id(&pool, auth.application_id.unwrap_or(0) as u32)
            .await
            .ok();
        
        // Get policy
        let policy = sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies WHERE id = ?"
        )
        .bind(auth.policy_id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch policy: {}", e)))?;
        
        // Get permissions count for policy
        let perm_count = sqlx::query!(
            "SELECT COUNT(*) as count FROM policy_permissions WHERE policy_id = ?",
            auth.policy_id
        )
        .fetch_one(&pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to count permissions: {}", e)))?
        .count as usize;
        
        // Determine status
        let status = if auth.status == "revoked" {
            AuthorizationStatus::Revoked
        } else if let Some(expires_at) = auth.expires_at {
            if expires_at < chrono::Utc::now() {
                AuthorizationStatus::Expired
            } else {
                AuthorizationStatus::Active
            }
        } else {
            AuthorizationStatus::Active
        };
        
        if let (Some(app), Some(policy)) = (app, policy) {
            auth_responses.push(AuthorizationResponse {
                id: auth.id,
                user_id: auth.user_id.clone().unwrap_or_default(),
                user_key_id: auth.user_key_id.clone().unwrap_or_default(),
                application: ApplicationSummary {
                    id: app.id,
                    domain: app.domain,
                    name: app.name,
                    icon_url: app.icon_url,
                },
                policy: PolicySummary {
                    id: policy.id,
                    name: policy.name,
                    permissions_count: perm_count,
                },
                bunker_public_key: auth.bunker_public_key,
                max_uses: auth.max_uses.map(|u| u as u16),
                current_uses: auth.current_uses as u16,
                expires_at: auth.expires_at,
                status,
                created_at: auth.created_at,
                updated_at: auth.updated_at,
            });
        }
    }
    
    let total = auth_responses.len();
    
    Ok(Json(AuthorizationListResponse {
        authorizations: auth_responses,
        total,
    }).into_response())
}

/// POST /api/users/authorizations
/// Create a new authorization
pub async fn create_authorization(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateAuthorizationRequest>,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Validate user owns the key
    let key = sqlx::query_as::<_, UserKey>(
        "SELECT * FROM user_keys WHERE id = ? AND user_id = ?"
    )
    .bind(&req.user_key_id)
    .bind(&user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch key: {}", e)))?
    .ok_or_else(|| ApiError::not_found("User key not found"))?;
    
    // Validate user owns the policy
    let policy = sqlx::query_as::<_, Policy>(
        "SELECT * FROM policies WHERE id = ? AND user_id = ?"
    )
    .bind(req.policy_id)
    .bind(&user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch policy: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Policy not found"))?;
    
    // Validate application exists
    let app = Application::find_by_id(&pool, req.application_id)
        .await
        .map_err(|_| ApiError::not_found("Application not found"))?;
    
    // Generate bunker keypair
    use nostr_sdk::prelude::*;
    let bunker_keys = Keys::generate();
    let bunker_public_key = bunker_keys.public_key().to_hex();
    let bunker_secret = bunker_keys.secret_key().as_secret_bytes();
    
    // Encrypt bunker secret
    use keycast_core::encryption::file_key_manager::FileKeyManager;
    let key_manager = FileKeyManager::new()
        .map_err(|e| ApiError::internal(format!("Failed to create key manager: {}", e)))?;
    let encrypted_bunker_secret = key_manager.encrypt(bunker_secret).await
        .map_err(|e| ApiError::internal(format!("Failed to encrypt bunker secret: {}", e)))?;
    
    // Generate connection secret
    let connection_secret = uuid::Uuid::new_v4().to_string();
    
    // Calculate expiry
    let expires_at = req.expires_in_hours.map(|hours| {
        chrono::Utc::now() + chrono::Duration::hours(hours as i64)
    });
    
    // Default relays
    let relays = vec![
        "wss://relay.damus.io".to_string(),
        "wss://nos.lol".to_string(),
        "wss://relay.nostr.band".to_string(),
    ];
    let relays_json = serde_json::to_string(&relays)
        .map_err(|e| ApiError::internal(format!("Failed to serialize relays: {}", e)))?;
    
    // Create authorization
    let auth_id = sqlx::query!(
        r#"
        INSERT INTO authorizations (
            stored_key_id, secret, bunker_public_key, bunker_secret,
            relays, policy_id, max_uses, expires_at,
            status, user_id, user_key_id, application_id,
            requested_at, approved_at,
            created_at, updated_at
        )
        VALUES (
            0, ?1, ?2, ?3, ?4, ?5, ?6, ?7,
            'active', ?8, ?9, ?10,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING id
        "#,
        connection_secret,
        bunker_public_key,
        encrypted_bunker_secret,
        relays_json,
        req.policy_id as i32,
        req.max_uses.map(|u| u as i32),
        expires_at.map(|dt| dt.naive_utc()),
        user.id,
        req.user_key_id,
        req.application_id as i32,
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create authorization: {}", e)))?
    .id;
    
    // Fetch the created authorization
    let created_auth = get_authorization_with_details(&pool, auth_id as u32, &user.id).await?;
    
    Ok((StatusCode::CREATED, Json(created_auth)).into_response())
}

/// GET /api/users/authorizations/:id
/// Get a specific authorization
pub async fn get_authorization(
    State(pool): State<SqlitePool>,
    Path(auth_id): Path<u32>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    let auth = get_authorization_with_details(&pool, auth_id, &user.id).await?;
    
    Ok(Json(auth).into_response())
}

/// PUT /api/users/authorizations/:id
/// Update an authorization
pub async fn update_authorization(
    State(pool): State<SqlitePool>,
    Path(auth_id): Path<u32>,
    headers: axum::http::HeaderMap,
    Json(req): Json<UpdateAuthorizationRequest>,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Check authorization exists and belongs to user
    let exists = sqlx::query!(
        "SELECT COUNT(*) as count FROM authorizations WHERE id = ? AND user_id = ?",
        auth_id,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check authorization: {}", e)))?
    .count > 0;
    
    if !exists {
        return Err(ApiError::not_found("Authorization not found"));
    }
    
    // Build update query dynamically
    let mut updates = Vec::new();
    let mut bindings = Vec::new();
    
    if let Some(max_uses) = req.max_uses {
        updates.push("max_uses = ?");
        bindings.push(max_uses.to_string());
    }
    
    if let Some(expires_in_hours) = req.expires_in_hours {
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_in_hours as i64);
        updates.push("expires_at = ?");
        bindings.push(expires_at.naive_utc().to_string());
    }
    
    if let Some(status) = req.status {
        let status_str = match status {
            AuthorizationStatus::Active => "active",
            AuthorizationStatus::Revoked => "revoked",
            AuthorizationStatus::Expired => "expired",
        };
        updates.push("status = ?");
        bindings.push(status_str.to_string());
    }
    
    if updates.is_empty() {
        return Err(ApiError::bad_request("No fields to update"));
    }
    
    updates.push("updated_at = CURRENT_TIMESTAMP");
    
    // Execute update
    let query = format!(
        "UPDATE authorizations SET {} WHERE id = ? AND user_id = ?",
        updates.join(", ")
    );
    
    let mut query_builder = sqlx::query(&query);
    for binding in bindings {
        query_builder = query_builder.bind(binding);
    }
    query_builder = query_builder.bind(auth_id).bind(&user.id);
    
    query_builder
        .execute(&pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update authorization: {}", e)))?;
    
    // Return updated authorization
    let auth = get_authorization_with_details(&pool, auth_id, &user.id).await?;
    
    Ok(Json(auth).into_response())
}

/// DELETE /api/users/authorizations/:id
/// Revoke an authorization
pub async fn revoke_authorization(
    State(pool): State<SqlitePool>,
    Path(auth_id): Path<u32>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Update status to revoked
    let result = sqlx::query!(
        r#"
        UPDATE authorizations 
        SET status = 'revoked', updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND user_id = ? AND status != 'revoked'
        "#,
        auth_id,
        user.id
    )
    .execute(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to revoke authorization: {}", e)))?;
    
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Authorization not found or already revoked"));
    }
    
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// GET /api/users/authorizations/:id/bunker
/// Get bunker URL for an authorization
pub async fn get_bunker_url(
    State(pool): State<SqlitePool>,
    Path(auth_id): Path<u32>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Get authorization
    let auth = sqlx::query!(
        r#"
        SELECT bunker_public_key, secret, relays, status
        FROM authorizations
        WHERE id = ? AND user_id = ?
        "#,
        auth_id,
        user.id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch authorization: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Authorization not found"))?;
    
    // Check if active
    if auth.status != "active" {
        return Err(ApiError::bad_request("Authorization is not active"));
    }
    
    // Parse relays
    let relays: Vec<String> = if let Some(relays_json) = auth.relays {
        serde_json::from_str(&relays_json)
            .map_err(|e| ApiError::internal(format!("Failed to parse relays: {}", e)))?
    } else {
        vec![]
    };
    
    // Build bunker URL
    // Format: bunker://<pubkey>?relay=<relay1>&relay=<relay2>&secret=<secret>
    let relay_params: Vec<String> = relays.iter()
        .map(|r| format!("relay={}", urlencoding::encode(r)))
        .collect();
    
    let bunker_url = format!(
        "bunker://{}?{}&secret={}",
        auth.bunker_public_key,
        relay_params.join("&"),
        auth.secret
    );
    
    Ok(Json(BunkerUrlResponse {
        bunker_url,
        relay_urls: relays,
    }).into_response())
}

// ============ Helper Functions ============

async fn get_authorization_with_details(
    pool: &SqlitePool,
    auth_id: u32,
    user_id: &str,
) -> Result<AuthorizationResponse, ApiError> {
    // Get authorization
    let auth = sqlx::query_as::<_, AuthorizationEnhanced>(
        "SELECT * FROM authorizations WHERE id = ? AND user_id = ?"
    )
    .bind(auth_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch authorization: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Authorization not found"))?;
    
    // Get application
    let app = Application::find_by_id(pool, auth.application_id.unwrap_or(0) as u32)
        .await
        .map_err(|_| ApiError::internal("Failed to fetch application"))?;
    
    // Get policy
    let policy = sqlx::query_as::<_, Policy>(
        "SELECT * FROM policies WHERE id = ?"
    )
    .bind(auth.policy_id)
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch policy: {}", e)))?;
    
    // Get permissions count
    let perm_count = sqlx::query!(
        "SELECT COUNT(*) as count FROM policy_permissions WHERE policy_id = ?",
        auth.policy_id
    )
    .fetch_one(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to count permissions: {}", e)))?
    .count as usize;
    
    // Determine status
    let status = if auth.status == "revoked" {
        AuthorizationStatus::Revoked
    } else if let Some(expires_at) = auth.expires_at {
        if expires_at < chrono::Utc::now() {
            AuthorizationStatus::Expired
        } else {
            AuthorizationStatus::Active
        }
    } else {
        AuthorizationStatus::Active
    };
    
    Ok(AuthorizationResponse {
        id: auth.id,
        user_id: auth.user_id.clone().unwrap_or_default(),
        user_key_id: auth.user_key_id.clone().unwrap_or_default(),
        application: ApplicationSummary {
            id: app.id,
            domain: app.domain,
            name: app.name,
            icon_url: app.icon_url,
        },
        policy: PolicySummary {
            id: policy.id,
            name: policy.name,
            permissions_count: perm_count,
        },
        bunker_public_key: auth.bunker_public_key,
        max_uses: auth.max_uses.map(|u| u as u16),
        current_uses: auth.current_uses as u16,
        expires_at: auth.expires_at,
        status,
        created_at: auth.created_at,
        updated_at: auth.updated_at,
    })
}