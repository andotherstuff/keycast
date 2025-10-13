// ABOUTME: Personal authentication handlers for email/password registration and login
// ABOUTME: Implements JWT-based authentication and NIP-46 bunker URL generation

use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use nostr_sdk::Keys;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::env;

const TOKEN_EXPIRY_HOURS: i64 = 24;

fn get_jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| {
        eprintln!("WARNING: JWT_SECRET not set in environment, using insecure default");
        "insecure-dev-secret-change-in-production".to_string()
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,  // user public key
    exp: usize,   // expiration time
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub email: String,
    pub pubkey: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct BunkerUrlResponse {
    pub bunker_url: String,
}

#[derive(Debug)]
pub enum AuthError {
    Database(sqlx::Error),
    PasswordHash(bcrypt::BcryptError),
    InvalidCredentials,
    EmailAlreadyExists,
    UserNotFound,
    Encryption(String),
    Internal(String),
    MissingToken,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::Database(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::PasswordHash(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Password hashing error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "Invalid email or password. Please check your credentials and try again.".to_string(),
            ),
            AuthError::EmailAlreadyExists => (
                StatusCode::CONFLICT,
                "This email is already registered. Please log in instead.".to_string(),
            ),
            AuthError::UserNotFound => (
                StatusCode::NOT_FOUND,
                "No account found with this email. Please register first.".to_string(),
            ),
            AuthError::Encryption(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Encryption error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::Internal(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Internal error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Service temporarily unavailable. Please try again in a few minutes.".to_string(),
                )
            },
            AuthError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "Authentication required. Please provide a valid token.".to_string(),
            ),
            AuthError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired token. Please log in again.".to_string(),
            ),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        AuthError::Database(e)
    }
}

impl From<bcrypt::BcryptError> for AuthError {
    fn from(e: bcrypt::BcryptError) -> Self {
        AuthError::PasswordHash(e)
    }
}

/// Extract user public key from JWT token in Authorization header
pub(crate) fn extract_user_from_token(headers: &HeaderMap) -> Result<String, AuthError> {
    // Get Authorization header
    let auth_header = headers
        .get("Authorization")
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::InvalidToken)?;

    // Extract token from "Bearer TOKEN" format
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(AuthError::InvalidToken)?;

    // Decode and validate JWT
    let jwt_secret = get_jwt_secret();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|e| {
        tracing::warn!("JWT decode error: {}", e);
        AuthError::InvalidToken
    })?;

    Ok(token_data.claims.sub)
}

/// Register a new user with email and password
pub async fn register(
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    tracing::info!("Registering new user with email: {}", req.email);

    // Check if email already exists
    let existing: Option<(String,)> = sqlx::query_as("SELECT public_key FROM users WHERE email = ?1")
        .bind(&req.email)
        .fetch_optional(pool)
        .await?;

    if existing.is_some() {
        return Err(AuthError::EmailAlreadyExists);
    }

    // Hash password
    let password_hash = hash(&req.password, DEFAULT_COST)?;

    // Generate new Nostr keypair for this user
    let keys = Keys::generate();
    let public_key = keys.public_key();
    let secret_key = keys.secret_key();

    // Encrypt the secret key
    let encrypted_secret = key_manager
        .encrypt(secret_key.as_ref())
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    // Generate bunker secret (random 32 bytes hex)
    let bunker_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    // Start transaction
    let mut tx = pool.begin().await?;

    // Insert user
    sqlx::query(
        "INSERT INTO users (public_key, email, password_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )
    .bind(public_key.to_hex())
    .bind(&req.email)
    .bind(&password_hash)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    // Insert personal key
    sqlx::query(
        "INSERT INTO personal_keys (user_public_key, encrypted_secret_key, bunker_secret, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )
    .bind(public_key.to_hex())
    .bind(&encrypted_secret)
    .bind(&bunker_secret)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    // Create default OAuth application if it doesn't exist
    sqlx::query(
        "INSERT OR IGNORE INTO oauth_applications (name, client_id, client_secret, redirect_uris, created_at, updated_at)
         VALUES ('keycast-login', 'keycast-login', 'auto-approved', '[]', ?1, ?2)"
    )
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    // Get the application ID
    let app_id: (i64,) = sqlx::query_as(
        "SELECT id FROM oauth_applications WHERE client_id = 'keycast-login'"
    )
    .fetch_one(&mut *tx)
    .await?;

    // Generate bunker keypair for OAuth authorization
    let bunker_keys = Keys::generate();
    let bunker_pubkey = bunker_keys.public_key();
    let bunker_secret_key = bunker_keys.secret_key();

    // Encrypt the bunker secret key
    let encrypted_bunker_secret = key_manager
        .encrypt(bunker_secret_key.as_ref())
        .await
        .map_err(|e| AuthError::Encryption(e.to_string()))?;

    // Generate connection secret (this is what's in the bunker URL)
    let connection_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();

    // Create OAuth authorization for seamless keycast-login access
    sqlx::query(
        "INSERT INTO oauth_authorizations
         (user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
    )
    .bind(public_key.to_hex())
    .bind(app_id.0)
    .bind(bunker_pubkey.to_hex())
    .bind(&encrypted_bunker_secret)
    .bind(&connection_secret)
    .bind(r#"["wss://relay.damus.io"]"#)
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Signal signer daemon to reload authorizations
    let signal_file = std::path::Path::new("database/.reload_signal");
    if let Err(e) = std::fs::File::create(signal_file) {
        tracing::error!("Failed to create reload signal file: {}", e);
    } else {
        tracing::info!("Created reload signal for signer daemon");
    }

    // Generate JWT token for automatic login
    let exp = (Utc::now() + chrono::Duration::hours(TOKEN_EXPIRY_HOURS)).timestamp() as usize;
    let claims = Claims {
        sub: public_key.to_hex(),
        exp,
    };

    let jwt_secret = get_jwt_secret();
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|e| AuthError::Internal(format!("JWT encoding error: {}", e)))?;

    tracing::info!("Successfully registered user: {}", public_key.to_hex());

    Ok(Json(RegisterResponse {
        user_id: public_key.to_hex(),
        email: req.email,
        pubkey: public_key.to_hex(),
        token,
    }))
}

/// Login with email and password, returns JWT token
pub async fn login(
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    let pool = &auth_state.state.db;
    tracing::info!("Login attempt for email: {}", req.email);

    // Fetch user with password hash
    let user: (String, String) = sqlx::query_as(
        "SELECT public_key, password_hash FROM users WHERE email = ?1 AND password_hash IS NOT NULL"
    )
    .bind(&req.email)
    .fetch_optional(pool)
    .await?
    .ok_or(AuthError::InvalidCredentials)?;

    let (public_key, password_hash) = user;

    // Verify password
    let valid = verify(&req.password, &password_hash)?;
    if !valid {
        return Err(AuthError::InvalidCredentials);
    }

    // Generate JWT token
    let exp = (Utc::now() + chrono::Duration::hours(TOKEN_EXPIRY_HOURS)).timestamp() as usize;
    let claims = Claims {
        sub: public_key.clone(),
        exp,
    };

    let jwt_secret = get_jwt_secret();
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|e| AuthError::Internal(format!("JWT encoding error: {}", e)))?;

    tracing::info!("Successfully logged in user: {}", public_key);

    Ok(Json(LoginResponse {
        token,
        pubkey: public_key,
    }))
}

/// Get bunker URL for the authenticated user
pub async fn get_bunker_url(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
) -> Result<Json<BunkerUrlResponse>, AuthError> {
    // Extract user pubkey from JWT token
    let user_pubkey = extract_user_from_token(&headers)?;
    tracing::info!("Fetching bunker URL for user: {}", user_pubkey);

    // Get the user's OAuth authorization bunker URL for keycast-login
    let result: Option<(String, String)> = sqlx::query_as(
        "SELECT bunker_public_key, secret FROM oauth_authorizations
         WHERE user_public_key = ?1
         AND application_id = (SELECT id FROM oauth_applications WHERE client_id = 'keycast-login')
         ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&user_pubkey)
    .fetch_optional(&pool)
    .await?;

    let (bunker_pubkey, connection_secret) = result.ok_or(AuthError::UserNotFound)?;

    let relay_url = "wss://relay.damus.io";

    let bunker_url = format!(
        "bunker://{}?relay={}&secret={}",
        bunker_pubkey, relay_url, connection_secret
    );

    tracing::info!("Returning bunker URL with pubkey: {}", bunker_pubkey);

    Ok(Json(BunkerUrlResponse { bunker_url }))
}
