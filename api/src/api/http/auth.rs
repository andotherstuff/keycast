// ABOUTME: Personal authentication handlers for email/password registration and login
// ABOUTME: Implements JWT-based authentication and NIP-46 bunker URL generation

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
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
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            ),
            AuthError::PasswordHash(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password hashing error".to_string(),
            ),
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "Invalid email or password".to_string(),
            ),
            AuthError::EmailAlreadyExists => (
                StatusCode::CONFLICT,
                "Email already registered".to_string(),
            ),
            AuthError::UserNotFound => (
                StatusCode::NOT_FOUND,
                "User not found".to_string(),
            ),
            AuthError::Encryption(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Encryption error: {}", e),
            ),
            AuthError::Internal(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal error: {}", e),
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

    tx.commit().await?;

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
    // TODO: Extract user from JWT token in Authorization header
    // For now, we'll need to pass pubkey somehow - will add auth middleware
) -> Result<Json<BunkerUrlResponse>, AuthError> {
    // TODO: This needs proper authentication middleware
    // For now, this is a placeholder implementation

    // This should get the pubkey from the JWT token
    // let pubkey = extract_from_jwt()?;

    // Temporary: get the most recent personal key
    let result: Option<(String, String)> = sqlx::query_as(
        "SELECT user_public_key, bunker_secret FROM personal_keys ORDER BY created_at DESC LIMIT 1"
    )
    .fetch_optional(&pool)
    .await?;

    let (public_key, bunker_secret) = result.ok_or(AuthError::UserNotFound)?;

    // TODO: Get relay URL from config
    let relay_url = "wss://relay.damus.io";

    let bunker_url = format!(
        "bunker://{}?relay={}&secret={}",
        public_key, relay_url, bunker_secret
    );

    Ok(Json(BunkerUrlResponse { bunker_url }))
}
