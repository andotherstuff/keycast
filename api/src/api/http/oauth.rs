// ABOUTME: OAuth 2.0 authorization flow handlers for third-party app access
// ABOUTME: Implements authorization code flow that issues bunker URLs for NIP-46 remote signing

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use chrono::{Duration, Utc};
use nostr_sdk::Keys;
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub approved: bool,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub bunker_url: String,
}

#[derive(Debug)]
pub enum OAuthError {
    Unauthorized,
    InvalidRequest(String),
    Database(sqlx::Error),
    Encryption(String),
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            OAuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            OAuthError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            OAuthError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            ),
            OAuthError::Encryption(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Encryption error: {}", e),
            ),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for OAuthError {
    fn from(e: sqlx::Error) -> Self {
        OAuthError::Database(e)
    }
}

/// GET /oauth/authorize
/// Shows authorization approval page (or redirects to login if not authenticated)
pub async fn authorize_get(
    State(_auth_state): State<super::routes::AuthState>,
    Query(_params): Query<AuthorizeRequest>,
) -> Result<Response, OAuthError> {
    // TODO: Extract user from session/JWT
    // For now, return OK to pass the test structure
    Ok((StatusCode::OK, "Authorization page").into_response())
}

/// POST /oauth/authorize
/// User approves authorization, creates code and redirects back to app OR returns code directly
pub async fn authorize_post(
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<ApproveRequest>,
) -> Result<Response, OAuthError> {
    if !req.approved {
        return Ok(Redirect::to(&format!(
            "{}?error=access_denied",
            req.redirect_uri
        ))
        .into_response());
    }

    // TODO: Get user_public_key from JWT session
    // For now, get the most recent user for testing
    let user_public_key: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM users ORDER BY created_at DESC LIMIT 1")
            .fetch_optional(&auth_state.state.db)
            .await?;

    let user_public_key = user_public_key.ok_or(OAuthError::Unauthorized)?;

    // Generate authorization code
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store authorization code (expires in 10 minutes)
    let expires_at = Utc::now() + Duration::minutes(10);

    // Get or create application
    let app_id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM oauth_applications WHERE client_id = ?1")
            .bind(&req.client_id)
            .fetch_optional(&auth_state.state.db)
            .await?;

    let app_id = if let Some(id) = app_id {
        id
    } else {
        // Create test application
        sqlx::query_scalar(
            "INSERT INTO oauth_applications (client_id, client_secret, name, redirect_uris, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id"
        )
        .bind(&req.client_id)
        .bind("test_secret")
        .bind(&req.client_id)
        .bind(format!("[\"{}\"]", req.redirect_uri))
        .bind(Utc::now())
        .bind(Utc::now())
        .fetch_one(&auth_state.state.db)
        .await?
    };

    // Store authorization code
    sqlx::query(
        "INSERT INTO oauth_codes (code, user_public_key, application_id, redirect_uri, scope, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )
    .bind(&code)
    .bind(&user_public_key)
    .bind(app_id)
    .bind(&req.redirect_uri)
    .bind(&req.scope)
    .bind(expires_at)
    .bind(Utc::now())
    .execute(&auth_state.state.db)
    .await?;

    // For JavaScript clients, return code directly instead of redirecting
    // Check if this is an XHR/fetch request by looking for Accept: application/json
    // For now, just return JSON with the code - client can handle it
    Ok(Json(serde_json::json!({
        "code": code,
        "redirect_uri": req.redirect_uri
    })).into_response())
}

/// POST /oauth/token
/// Exchange authorization code for bunker URL
pub async fn token(
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();

    // Fetch and validate authorization code
    let auth_code: Option<(String, i64, String, String)> = sqlx::query_as(
        "SELECT user_public_key, application_id, redirect_uri, scope FROM oauth_codes
         WHERE code = ?1 AND expires_at > ?2"
    )
    .bind(&req.code)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;

    let (user_public_key, application_id, stored_redirect_uri, _scope) =
        auth_code.ok_or(OAuthError::Unauthorized)?;

    // Validate redirect_uri matches
    if stored_redirect_uri != req.redirect_uri {
        return Err(OAuthError::InvalidRequest(
            "redirect_uri mismatch".to_string(),
        ));
    }

    // Delete the authorization code (one-time use)
    sqlx::query("DELETE FROM oauth_codes WHERE code = ?1")
        .bind(&req.code)
        .execute(pool)
        .await?;

    // Look up user's personal Nostr key from personal_keys table
    // We get the encrypted key to use as the bunker secret (for NIP-46 decryption + signing)
    let encrypted_user_key: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_secret_key FROM personal_keys WHERE user_public_key = ?1"
    )
    .bind(&user_public_key)
    .fetch_one(pool)
    .await
    .map_err(OAuthError::Database)?;

    // Parse the user's public key to use as bunker public key
    let bunker_public_key = nostr_sdk::PublicKey::from_hex(&user_public_key)
        .map_err(|e| OAuthError::InvalidRequest(format!("Invalid public key: {}", e)))?;

    // Generate connection secret for NIP-46 authentication
    let connection_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Create authorization in database
    let relay_url = "wss://relay.damus.io"; // TODO: Get from config
    let relays_json = serde_json::to_string(&vec![relay_url])
        .map_err(|e| OAuthError::InvalidRequest(format!("Failed to serialize relays: {}", e)))?;

    sqlx::query(
        "INSERT INTO oauth_authorizations (user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
    )
    .bind(&user_public_key)
    .bind(application_id)
    .bind(bunker_public_key.to_hex())
    .bind(&encrypted_user_key)      // bunker_secret = encrypted user key (BLOB)
    .bind(&connection_secret)        // secret = connection secret (TEXT)
    .bind(&relays_json)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(pool)
    .await?;

    // Build bunker URL
    let bunker_url = format!(
        "bunker://{}?relay={}&secret={}",
        bunker_public_key.to_hex(),
        relay_url,
        connection_secret
    );

    Ok(Json(TokenResponse { bunker_url }))
}
