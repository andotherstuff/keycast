// ABOUTME: Personal authentication handlers for email/password registration and login
// ABOUTME: Implements JWT-based authentication and NIP-46 bunker URL generation

use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
    Json,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use nostr_sdk::Keys;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::env;

const TOKEN_EXPIRY_HOURS: i64 = 24;
const EMAIL_VERIFICATION_EXPIRY_HOURS: i64 = 24;
const PASSWORD_RESET_EXPIRY_HOURS: i64 = 1;

fn get_jwt_secret() -> String {
    env::var("JWT_SECRET").unwrap_or_else(|_| {
        eprintln!("WARNING: JWT_SECRET not set in environment, using insecure default");
        "insecure-dev-secret-change-in-production".to_string()
    })
}

fn generate_secure_token() -> String {
    use rand::distributions::Alphanumeric;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
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

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct ForgotPasswordResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ResetPasswordResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProfileData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nip05: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lud16: Option<String>,
}

#[derive(Debug)]
pub enum AuthError {
    Database(sqlx::Error),
    PasswordHash(bcrypt::BcryptError),
    InvalidCredentials,
    EmailAlreadyExists,
    EmailNotVerified,
    UserNotFound,
    Encryption(String),
    Internal(String),
    MissingToken,
    InvalidToken,
    EmailSendFailed(String),
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
            AuthError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                "Please verify your email address before continuing. Check your inbox for the verification link.".to_string(),
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
            AuthError::EmailSendFailed(e) => {
                // Log the real error but return generic message to user
                tracing::error!("Email send error: {}", e);
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unable to send email. Please try again in a few minutes.".to_string(),
                )
            },
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
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AuthError> {
    let pool = &auth_state.state.db;
    let key_manager = auth_state.state.key_manager.as_ref();
    let tenant_id = tenant.0.id;
    tracing::info!("Registering new user with email: {} for tenant: {}", req.email, tenant_id);

    // Check if email already exists in this tenant
    let existing: Option<(String,)> = sqlx::query_as("SELECT public_key FROM users WHERE email = ?1 AND tenant_id = ?2")
        .bind(&req.email)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

    if existing.is_some() {
        return Err(AuthError::EmailAlreadyExists);
    }

    // Hash password
    let password_hash = hash(&req.password, DEFAULT_COST)?;

    // Generate email verification token
    let verification_token = generate_secure_token();
    let verification_expires = Utc::now() + Duration::hours(EMAIL_VERIFICATION_EXPIRY_HOURS);

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

    // Insert user with email verification token
    sqlx::query(
        "INSERT INTO users (public_key, tenant_id, email, password_hash, email_verified, email_verification_token, email_verification_expires_at, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
    )
    .bind(public_key.to_hex())
    .bind(tenant_id)
    .bind(&req.email)
    .bind(&password_hash)
    .bind(false) // email_verified
    .bind(&verification_token)
    .bind(&verification_expires)
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

    // Send verification email (optional - don't fail if email service unavailable)
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service.send_verification_email(&req.email, &verification_token).await {
                tracing::error!("Failed to send verification email to {}: {}", req.email, e);
            } else {
                tracing::info!("Sent verification email to {}", req.email);
            }
        },
        Err(e) => {
            tracing::warn!("Email service unavailable, skipping verification email: {}", e);
        }
    }

    // Signal signer daemon to reload authorizations
    let signal_file = std::path::Path::new("database/.reload_signal");
    // Ensure directory exists
    if let Some(parent) = signal_file.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::error!("Failed to create signal file directory: {}", e);
        }
    }
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
    tenant: crate::api::tenant::TenantExtractor,
    State(auth_state): State<super::routes::AuthState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    let pool = &auth_state.state.db;
    let tenant_id = tenant.0.id;
    tracing::info!("Login attempt for email: {} in tenant: {}", req.email, tenant_id);

    // Fetch user with password hash from this tenant
    let user: (String, String) = sqlx::query_as(
        "SELECT public_key, password_hash FROM users WHERE email = ?1 AND tenant_id = ?2 AND password_hash IS NOT NULL"
    )
    .bind(&req.email)
    .bind(tenant_id)
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
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
) -> Result<Json<BunkerUrlResponse>, AuthError> {
    // Extract user pubkey from JWT token
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Fetching bunker URL for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Get the user's OAuth authorization bunker URL for keycast-login
    let result: Option<(String, String)> = sqlx::query_as(
        "SELECT oa.bunker_public_key, oa.secret FROM oauth_authorizations oa
         JOIN users u ON oa.user_public_key = u.public_key
         WHERE oa.user_public_key = ?1
         AND u.tenant_id = ?2
         AND oa.application_id = (SELECT id FROM oauth_applications WHERE client_id = 'keycast-login')
         ORDER BY oa.created_at DESC LIMIT 1"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
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

/// Verify email address with token
pub async fn verify_email(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<Json<VerifyEmailResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    tracing::info!("Email verification attempt with token: {}... for tenant: {}", &req.token[..10], tenant_id);

    // Find user with this verification token in this tenant
    let user: Option<(String, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT public_key, email_verification_expires_at FROM users
         WHERE email_verification_token = ?1 AND tenant_id = ?2"
    )
    .bind(&req.token)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let (public_key, expires_at) = user.ok_or(AuthError::InvalidToken)?;

    // Check if token is expired
    if let Some(expires) = expires_at {
        if expires < Utc::now() {
            return Ok(Json(VerifyEmailResponse {
                success: false,
                message: "Verification link has expired. Please request a new one.".to_string(),
            }));
        }
    }

    // Mark email as verified and clear verification token
    sqlx::query(
        "UPDATE users
         SET email_verified = ?1,
             email_verification_token = NULL,
             email_verification_expires_at = NULL,
             updated_at = ?2
         WHERE public_key = ?3"
    )
    .bind(true)
    .bind(Utc::now())
    .bind(&public_key)
    .execute(&pool)
    .await?;

    tracing::info!("Email verified successfully for user: {}", public_key);

    Ok(Json(VerifyEmailResponse {
        success: true,
        message: "Email verified successfully! You can now use all features.".to_string(),
    }))
}

/// Request password reset email
pub async fn forgot_password(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    tracing::info!("Password reset requested for email: {} in tenant: {}", req.email, tenant_id);

    // Check if user exists in this tenant
    let user: Option<(String,)> = sqlx::query_as(
        "SELECT public_key FROM users WHERE email = ?1 AND tenant_id = ?2"
    )
    .bind(&req.email)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    // Always return success even if email doesn't exist (security best practice)
    if user.is_none() {
        tracing::info!("Password reset requested for non-existent email: {}", req.email);
        return Ok(Json(ForgotPasswordResponse {
            success: true,
            message: "If an account exists with that email, a password reset link has been sent.".to_string(),
        }));
    }

    let (public_key,) = user.unwrap();

    // Generate reset token
    let reset_token = generate_secure_token();
    let reset_expires = Utc::now() + Duration::hours(PASSWORD_RESET_EXPIRY_HOURS);

    // Store reset token
    sqlx::query(
        "UPDATE users
         SET password_reset_token = ?1,
             password_reset_expires_at = ?2,
             updated_at = ?3
         WHERE public_key = ?4"
    )
    .bind(&reset_token)
    .bind(&reset_expires)
    .bind(Utc::now())
    .bind(&public_key)
    .execute(&pool)
    .await?;

    // Send password reset email (optional - don't fail if email service unavailable)
    match crate::email_service::EmailService::new() {
        Ok(email_service) => {
            if let Err(e) = email_service.send_password_reset_email(&req.email, &reset_token).await {
                tracing::error!("Failed to send password reset email to {}: {}", req.email, e);
            } else {
                tracing::info!("Sent password reset email to {}", req.email);
            }
        },
        Err(e) => {
            tracing::warn!("Email service unavailable, skipping password reset email: {}", e);
        }
    }

    Ok(Json(ForgotPasswordResponse {
        success: true,
        message: "If an account exists with that email, a password reset link has been sent.".to_string(),
    }))
}

/// Reset password with token
pub async fn reset_password(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, AuthError> {
    let tenant_id = tenant.0.id;
    tracing::info!("Password reset attempt with token: {}... for tenant: {}", &req.token[..10], tenant_id);

    // Find user with this reset token in this tenant
    let user: Option<(String, Option<chrono::DateTime<Utc>>)> = sqlx::query_as(
        "SELECT public_key, password_reset_expires_at FROM users
         WHERE password_reset_token = ?1 AND tenant_id = ?2"
    )
    .bind(&req.token)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let (public_key, expires_at) = user.ok_or(AuthError::InvalidToken)?;

    // Check if token is expired
    if let Some(expires) = expires_at {
        if expires < Utc::now() {
            return Ok(Json(ResetPasswordResponse {
                success: false,
                message: "Password reset link has expired. Please request a new one.".to_string(),
            }));
        }
    }

    // Hash new password
    let password_hash = hash(&req.new_password, DEFAULT_COST)?;

    // Update password and clear reset token
    sqlx::query(
        "UPDATE users
         SET password_hash = ?1,
             password_reset_token = NULL,
             password_reset_expires_at = NULL,
             updated_at = ?2
         WHERE public_key = ?3"
    )
    .bind(&password_hash)
    .bind(Utc::now())
    .bind(&public_key)
    .execute(&pool)
    .await?;

    tracing::info!("Password reset successfully for user: {}", public_key);

    Ok(Json(ResetPasswordResponse {
        success: true,
        message: "Password reset successfully! You can now log in with your new password.".to_string(),
    }))
}

/// Get username for NIP-05 - the only profile data we store server-side
pub async fn get_profile(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
) -> Result<Json<ProfileData>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Fetching username for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Get username from users table - this is the ONLY thing we store
    // The client should fetch actual kind 0 profile data from Nostr relays via bunker
    let username: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT username FROM users WHERE public_key = ?1 AND tenant_id = ?2"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    let username = username.and_then(|(u,)| u);

    // Return only username - client fetches rest from relays
    Ok(Json(ProfileData {
        username,
        name: None,
        about: None,
        picture: None,
        banner: None,
        nip05: None,
        website: None,
        lud16: None,
    }))
}

/// Update username (for NIP-05) - the only profile data we store server-side
/// Client should publish kind 0 profile events to relays via bunker URL
pub async fn update_profile(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    Json(profile): Json<ProfileData>,
) -> Result<Json<serde_json::Value>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;

    tracing::info!("Updating username for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Only update username - everything else is stored on Nostr relays
    if let Some(ref username) = profile.username {
        // Validate username (alphanumeric, dash, underscore only)
        if !username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(AuthError::Internal("Username can only contain letters, numbers, dashes, and underscores".to_string()));
        }

        // Check if username is already taken in this tenant
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT public_key FROM users WHERE username = ?1 AND public_key != ?2 AND tenant_id = ?3"
        )
        .bind(username)
        .bind(&user_pubkey)
        .bind(tenant_id)
        .fetch_optional(&pool)
        .await?;

        if existing.is_some() {
            return Err(AuthError::Internal("Username already taken".to_string()));
        }

        // Update username in users table
        sqlx::query(
            "UPDATE users SET username = ?1, updated_at = ?2 WHERE public_key = ?3 AND tenant_id = ?4"
        )
        .bind(username)
        .bind(Utc::now())
        .bind(&user_pubkey)
        .bind(tenant_id)
        .execute(&pool)
        .await?;

        tracing::info!("Username updated to '{}' for user: {}", username, user_pubkey);
    }

    // Client should publish profile to relays via bunker URL
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Username saved. Client should publish kind 0 event to relays via bunker."
    })))
}

#[derive(Debug, Serialize)]
pub struct BunkerSession {
    pub application_name: String,
    pub application_id: Option<i64>,
    pub bunker_pubkey: String,
    pub secret: String,
    pub client_pubkey: Option<String>,
    pub created_at: String,
    pub last_activity: Option<String>,
    pub activity_count: i64,
}

#[derive(Debug, Serialize)]
pub struct BunkerSessionsResponse {
    pub sessions: Vec<BunkerSession>,
}

/// List all active bunker sessions for the authenticated user
pub async fn list_sessions(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
) -> Result<Json<BunkerSessionsResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Listing bunker sessions for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Get OAuth authorizations with application details and activity stats
    let oauth_sessions: Vec<(String, i64, String, String, Option<String>, String, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT
            COALESCE(a.name, 'Personal Bunker') as name,
            oa.application_id,
            oa.bunker_public_key,
            oa.secret,
            oa.client_public_key,
            oa.created_at,
            (SELECT MAX(created_at) FROM signing_activity WHERE bunker_secret = oa.secret) as last_activity,
            (SELECT COUNT(*) FROM signing_activity WHERE bunker_secret = oa.secret) as activity_count
         FROM oauth_authorizations oa
         LEFT JOIN oauth_applications a ON oa.application_id = a.id
         JOIN users u ON oa.user_public_key = u.public_key
         WHERE oa.user_public_key = ?1
           AND u.tenant_id = ?2
           AND oa.revoked_at IS NULL
         ORDER BY oa.created_at DESC"
    )
    .bind(&user_pubkey)
    .bind(tenant_id)
    .fetch_all(&pool)
    .await?;

    let sessions = oauth_sessions
        .into_iter()
        .map(|(name, app_id, bunker_pubkey, secret, client_pubkey, created_at, last_activity, activity_count)| BunkerSession {
            application_name: name,
            application_id: Some(app_id),
            bunker_pubkey,
            secret,
            client_pubkey,
            created_at,
            last_activity,
            activity_count: activity_count.unwrap_or(0),
        })
        .collect();

    Ok(Json(BunkerSessionsResponse { sessions }))
}

#[derive(Debug, Serialize)]
pub struct SessionActivity {
    pub event_kind: i64,
    pub event_content: Option<String>,
    pub event_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct SessionActivityResponse {
    pub activities: Vec<SessionActivity>,
}

/// Get activity log for a specific bunker session
pub async fn get_session_activity(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    axum::extract::Path(secret): axum::extract::Path<String>,
) -> Result<Json<SessionActivityResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Fetching activity for bunker secret: {} in tenant: {}", secret, tenant_id);

    // Verify this bunker session belongs to the user in this tenant
    let session: Option<(String,)> = sqlx::query_as(
        "SELECT oa.user_public_key FROM oauth_authorizations oa
         JOIN users u ON oa.user_public_key = u.public_key
         WHERE oa.secret = ?1 AND u.tenant_id = ?2"
    )
    .bind(&secret)
    .bind(tenant_id)
    .fetch_optional(&pool)
    .await?;

    if session.is_none() || session.unwrap().0 != user_pubkey {
        return Err(AuthError::InvalidToken);
    }

    // Get activity log
    let activities: Vec<(i64, Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT event_kind, event_content, event_id, created_at
         FROM signing_activity
         WHERE bunker_secret = ?1
         ORDER BY created_at DESC
         LIMIT 100"
    )
    .bind(&secret)
    .fetch_all(&pool)
    .await?;

    let activities = activities
        .into_iter()
        .map(|(kind, content, event_id, created_at)| SessionActivity {
            event_kind: kind,
            event_content: content,
            event_id,
            created_at,
        })
        .collect();

    Ok(Json(SessionActivityResponse { activities }))
}

#[derive(Debug, Deserialize)]
pub struct RevokeSessionRequest {
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct RevokeSessionResponse {
    pub success: bool,
    pub message: String,
}

/// Revoke a bunker session
pub async fn revoke_session(
    tenant: crate::api::tenant::TenantExtractor,
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    Json(req): Json<RevokeSessionRequest>,
) -> Result<Json<RevokeSessionResponse>, AuthError> {
    let user_pubkey = extract_user_from_token(&headers)?;
    let tenant_id = tenant.0.id;
    tracing::info!("Revoking bunker session for user: {} in tenant: {}", user_pubkey, tenant_id);

    // Verify this bunker session belongs to the user in this tenant and revoke it
    let result = sqlx::query(
        "UPDATE oauth_authorizations
         SET revoked_at = ?1, updated_at = ?2
         WHERE secret = ?3 AND user_public_key = ?4 AND revoked_at IS NULL
         AND user_public_key IN (SELECT public_key FROM users WHERE tenant_id = ?5)"
    )
    .bind(Utc::now())
    .bind(Utc::now())
    .bind(&req.secret)
    .bind(&user_pubkey)
    .bind(tenant_id)
    .execute(&pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AuthError::InvalidToken);
    }

    tracing::info!("Successfully revoked bunker session for user: {}", user_pubkey);

    Ok(Json(RevokeSessionResponse {
        success: true,
        message: "Session revoked successfully".to_string(),
    }))
}

