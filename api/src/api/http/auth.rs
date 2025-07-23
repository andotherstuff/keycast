// ABOUTME: Authentication endpoints for personal auth system
// ABOUTME: Handles registration, login, logout, and multi-auth methods

use axum::{
    extract::{Json, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use nostr_sdk::PublicKey;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid;

use crate::api::error::ApiError;
use crate::state::get_key_manager;
use keycast_core::types::{
    user_auth::UserAuthMethod,
    user_enhanced::{UserEnhanced, UserEnhancedError},
    user_key::{UserKey, UserKeyType},
};

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
    pub generate_key: bool,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserEnhanced,
    pub session_token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterRequest {
    pub credential: serde_json::Value, // WebAuthn credential
    pub device_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginRequest {
    pub credential: serde_json::Value, // WebAuthn assertion
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
}

// ============ Handlers ============

/// POST /api/auth/register
/// Register a new user with email/password
pub async fn register(
    State(pool): State<SqlitePool>,
    Json(req): Json<RegisterRequest>,
) -> Result<Response, ApiError> {
    // Validate email format
    if !req.email.contains('@') {
        return Err(ApiError::bad_request("Invalid email format"));
    }
    
    // Validate password strength
    if req.password.len() < 8 {
        return Err(ApiError::bad_request("Password must be at least 8 characters"));
    }
    
    // Start transaction
    let tx = pool.begin().await?;
    
    // Create user with email
    let (user, public_key) = match UserEnhanced::create_with_email(
        &pool,
        &req.email,
        req.display_name.as_deref(),
    ).await {
        Ok(result) => result,
        Err(UserEnhancedError::EmailExists) => {
            return Err(ApiError::bad_request("Email already registered"));
        }
        Err(e) => return Err(ApiError::internal(e.to_string())),
    };
    
    // Add email/password auth method
    UserAuthMethod::add_email_password(
        &pool,
        &public_key,
        &req.email,
        &req.password,
    ).await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    
    // Generate primary key if requested
    if req.generate_key {
        let key_manager = get_key_manager()
            .map_err(|e| ApiError::internal(e.to_string()))?;
        
        UserKey::create(
            &pool,
            key_manager,
            &public_key,
            "Primary Key",
            UserKeyType::Primary,
            None,
        ).await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    }
    
    // Create session
    let session_token = generate_session_token();
    let expires_at = Utc::now() + Duration::days(14);
    
    sqlx::query(
        r#"
        INSERT INTO user_sessions (id, user_id, token, expires_at, created_at)
        VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .bind(&session_token)
    .bind(expires_at)
    .execute(&pool)
    .await?;
    
    // Commit transaction
    tx.commit().await?;
    
    // Return response
    let response = AuthResponse {
        user,
        session_token: session_token.clone(),
        expires_at,
    };
    
    Ok((
        StatusCode::CREATED,
        Json(response),
    ).into_response())
}

/// POST /api/auth/login
/// Login with email/password
pub async fn login(
    State(pool): State<SqlitePool>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    // Verify credentials
    let (_auth_method, public_key) = UserAuthMethod::verify_email_password(
        &pool,
        &req.email,
        &req.password,
    ).await
    .map_err(|_| ApiError::auth("Invalid email or password"))?;
    
    // Get user
    let user = UserEnhanced::find_by_pubkey(&pool, &public_key)
        .await
        .map_err(|_| ApiError::internal("User not found"))?;
    
    // Create session
    let session_token = generate_session_token();
    let expires_at = Utc::now() + Duration::days(14);
    
    sqlx::query(
        r#"
        INSERT INTO user_sessions (id, user_id, token, expires_at, created_at)
        VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user.id)
    .bind(&session_token)
    .bind(expires_at)
    .execute(&pool)
    .await?;
    
    // Log activity
    log_activity(
        &pool,
        &public_key,
        "login",
        serde_json::json!({
            "method": "email_password",
            "email": req.email
        }),
    ).await?;
    
    // Return response
    let response = AuthResponse {
        user,
        session_token,
        expires_at,
    };
    
    Ok(Json(response).into_response())
}

/// POST /api/auth/logout
/// Logout and invalidate session
pub async fn logout(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // Get session token from Authorization header
    let session_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::auth("Missing session token"))?;
    
    // Delete session
    sqlx::query("DELETE FROM user_sessions WHERE token = ?1")
        .bind(session_token)
        .execute(&pool)
        .await?;
    
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// GET /api/auth/me
/// Get current user from session
pub async fn get_current_user(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // Get session token
    let session_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::auth("Missing session token"))?;
    
    // Get user from session
    let user_id = sqlx::query_scalar::<_, String>(
        r#"
        SELECT user_id FROM user_sessions 
        WHERE token = ?1 AND expires_at > CURRENT_TIMESTAMP
        "#,
    )
    .bind(session_token)
    .fetch_optional(&pool)
    .await?
    .ok_or_else(|| ApiError::auth("Invalid or expired session"))?;
    
    let user = UserEnhanced::find_by_id(&pool, &user_id)
        .await
        .map_err(|_| ApiError::internal("Database error"))?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    
    Ok(Json(user).into_response())
}

/// POST /api/auth/passkey/register
/// Register a new passkey
pub async fn register_passkey(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    Json(_req): Json<PasskeyRegisterRequest>,
) -> Result<Response, ApiError> {
    // Get current user
    let _user_pubkey = get_user_from_session(&pool, &headers).await?;
    
    // TODO: Implement WebAuthn registration
    // This is a placeholder - you'll need to integrate a WebAuthn library
    
    Ok((StatusCode::NOT_IMPLEMENTED, "Passkey registration not yet implemented").into_response())
}

/// POST /api/auth/passkey/login
/// Login with passkey
pub async fn login_passkey(
    State(_pool): State<SqlitePool>,
    Json(_req): Json<PasskeyLoginRequest>,
) -> Result<Response, ApiError> {
    // TODO: Implement WebAuthn authentication
    // This is a placeholder - you'll need to integrate a WebAuthn library
    
    Ok((StatusCode::NOT_IMPLEMENTED, "Passkey login not yet implemented").into_response())
}

/// GET /api/auth/oauth/:provider
/// Initiate OAuth flow
pub async fn oauth_init(
    State(_pool): State<SqlitePool>,
    Path(provider): Path<String>,
) -> Result<Response, ApiError> {
    // TODO: Implement OAuth provider integration
    // Support providers like Google, GitHub, etc.
    
    Ok((StatusCode::NOT_IMPLEMENTED, format!("OAuth provider {} not yet implemented", provider)).into_response())
}

/// GET /api/auth/oauth/:provider/callback
/// OAuth callback handler
pub async fn oauth_callback(
    State(_pool): State<SqlitePool>,
    Path(_provider): Path<String>,
    Query(_params): Query<OAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    // TODO: Implement OAuth callback handling
    
    Ok((StatusCode::NOT_IMPLEMENTED, "OAuth callback not yet implemented").into_response())
}

// ============ Helper Functions ============

/// Generate a secure session token
fn generate_session_token() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Get user from session token
async fn get_user_from_session(
    pool: &SqlitePool,
    headers: &HeaderMap,
) -> Result<UserEnhanced, ApiError> {
    let session_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::auth("Missing session token"))?;
    
    let user_id = sqlx::query_scalar::<_, String>(
        r#"
        SELECT user_id FROM user_sessions 
        WHERE token = ?1 AND expires_at > CURRENT_TIMESTAMP
        "#,
    )
    .bind(session_token)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::auth("Invalid or expired session"))?;
    
    UserEnhanced::find_by_id(pool, &user_id)
        .await
        .map_err(|_| ApiError::internal("Database error"))?
        .ok_or_else(|| ApiError::not_found("User not found"))
}

/// Extract user from session token in Authorization header
pub async fn get_user_from_session(
    pool: &SqlitePool,
    headers: axum::http::HeaderMap,
) -> Result<UserEnhanced, ApiError> {
    // Get session token
    let session_token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::auth("Missing or invalid authorization header"))?;
    
    // Get user from session
    let user_id = sqlx::query_scalar::<_, String>(
        r#"
        SELECT user_id FROM user_sessions 
        WHERE token = ?1 AND expires_at > CURRENT_TIMESTAMP
        "#,
    )
    .bind(session_token)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::auth("Invalid or expired session"))?;
    
    let user = UserEnhanced::find_by_id(pool, &user_id)
        .await
        .map_err(|_| ApiError::internal("Database error"))?
        .ok_or_else(|| ApiError::not_found("User not found"))?;
    
    Ok(user)
}

/// Log user activity
async fn log_activity(
    pool: &SqlitePool,
    user_pubkey: &PublicKey,
    action: &str,
    details: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO activity_logs (user_public_key, action_type, action_details, created_at)
        VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(user_pubkey.to_hex())
    .bind(action)
    .bind(details.to_string())
    .execute(pool)
    .await?;
    
    Ok(())
}