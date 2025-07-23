// ABOUTME: Implements NIP-05 discovery endpoints for Nostr public key resolution
// ABOUTME: Provides .well-known/nostr.json endpoint and domain management

use axum::{
    extract::{Query, State, Path},
    http::{StatusCode, HeaderMap},
    response::Json,
    Router,
    routing::{get, post, delete},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, SqlitePool};
use std::collections::HashMap;
use tower_http::cors::CorsLayer;

use crate::api::error::ApiError;
use keycast_core::types::user_enhanced::UserEnhanced;

// Helper function to get user from session
async fn get_user_from_session(
    pool: &SqlitePool,
    headers: &HeaderMap,
) -> Result<UserEnhanced, ApiError> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::auth("Missing authorization header"))?;
    
    if !auth_header.starts_with("Bearer ") {
        return Err(ApiError::auth("Invalid authorization format"));
    }
    
    let token = auth_header.trim_start_matches("Bearer ");
    
    // Get user from session token
    let session = sqlx::query!(
        "SELECT user_id FROM user_sessions WHERE token = ? AND expires_at > datetime('now')",
        token
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| ApiError::internal("Database error"))?
    .ok_or_else(|| ApiError::auth("Invalid or expired session"))?;
    
    // Get user details
    let user_id = session.user_id.ok_or_else(|| ApiError::internal("No user_id in session"))?;
    UserEnhanced::find_by_id(pool, &user_id)
        .await
        .map_err(|_| ApiError::internal("Failed to fetch user"))?
        .ok_or_else(|| ApiError::not_found("User not found"))
}

#[derive(Debug, Deserialize)]
pub struct Nip05Query {
    name: String,
}

#[derive(Debug, Serialize)]
pub struct Nip05Response {
    names: HashMap<String, String>,
    relays: HashMap<String, Vec<String>>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct Nip05Domain {
    pub id: String,
    pub domain: String,
    pub user_id: String,
    pub verification_type: String,
    pub verification_value: Option<String>,
    pub verified: Option<bool>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct AddDomainRequest {
    domain: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNip05Request {
    nip05_identifier: Option<String>,
}

pub async fn nip05_discovery(
    Query(params): Query<Nip05Query>,
    State(pool): State<SqlitePool>,
) -> Result<Json<Nip05Response>, ApiError> {
    let parts: Vec<&str> = params.name.split('@').collect();
    if parts.len() != 2 {
        return Err(ApiError::bad_request("Invalid NIP-05 identifier format"));
    }
    
    let username = parts[0];
    let domain = parts[1];
    
    // Check if this domain is managed by us
    let domain_record = sqlx::query!(
        "SELECT verified FROM nip05_domains WHERE domain = ? AND verified = 1",
        domain
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| ApiError::internal("Database error"))?;
    
    if domain_record.is_none() {
        return Err(ApiError::not_found("Domain not found"));
    }
    
    // Look up user by nip05_identifier
    let user = sqlx::query!(
        r#"
        SELECT u.public_key, u.nip05_identifier
        FROM users u
        WHERE u.nip05_identifier = ?
        "#,
        params.name
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| ApiError::internal("Database error"))?;
    
    match user {
        Some(user) => {
            let mut names = HashMap::new();
            names.insert(username.to_string(), user.public_key);
            
            // TODO: Add relay information when we implement relay management
            let relays = HashMap::new();
            
            Ok(Json(Nip05Response { names, relays }))
        }
        None => {
            // Return empty response if user not found
            Ok(Json(Nip05Response {
                names: HashMap::new(),
                relays: HashMap::new(),
            }))
        }
    }
}

pub async fn list_domains(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
) -> Result<Json<Vec<Nip05Domain>>, ApiError> {
    let user = get_user_from_session(&pool, &headers).await?;
    
    let domains = sqlx::query_as!(
        Nip05Domain,
        r#"
        SELECT id as "id!", domain as "domain!", user_id as "user_id!", 
               verification_type as "verification_type!", verification_value, 
               verified as "verified: bool", created_at as "created_at!", updated_at as "updated_at!"
        FROM nip05_domains
        WHERE user_id = ?
        ORDER BY created_at DESC
        "#,
        user.id
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| ApiError::internal("Failed to fetch domains"))?;
    
    Ok(Json(domains))
}

pub async fn add_domain(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    Json(req): Json<AddDomainRequest>,
) -> Result<(StatusCode, Json<Nip05Domain>), ApiError> {
    let user = get_user_from_session(&pool, &headers).await?;
    
    // Validate domain format
    if req.domain.is_empty() || req.domain.contains('/') || req.domain.contains('@') {
        return Err(ApiError::bad_request("Invalid domain format"));
    }
    
    // Check if domain already exists
    let existing = sqlx::query!(
        "SELECT id FROM nip05_domains WHERE domain = ?",
        req.domain
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| ApiError::internal("Database error"))?;
    
    if existing.is_some() {
        return Err(ApiError::bad_request("Domain already registered"));
    }
    
    // Generate verification TXT record value
    let verification_value = format!("keycast-verify-{}", uuid::Uuid::new_v4());
    let domain_id = uuid::Uuid::new_v4().to_string();
    
    let domain = sqlx::query_as!(
        Nip05Domain,
        r#"
        INSERT INTO nip05_domains (id, domain, user_id, verification_type, verification_value, verified)
        VALUES (?, ?, ?, 'dns_txt', ?, 0)
        RETURNING id as "id!", domain as "domain!", user_id as "user_id!", 
                  verification_type as "verification_type!", verification_value, 
                  verified as "verified: bool", created_at as "created_at!", updated_at as "updated_at!"
        "#,
        domain_id,
        req.domain,
        user.id,
        verification_value
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| ApiError::internal("Failed to add domain"))?;
    
    Ok((StatusCode::CREATED, Json(domain)))
}

pub async fn verify_domain(
    State(pool): State<SqlitePool>,
    Path(domain_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Nip05Domain>, ApiError> {
    let user = get_user_from_session(&pool, &headers).await?;
    
    let domain = sqlx::query_as!(
        Nip05Domain,
        r#"
        SELECT id as "id!", domain as "domain!", user_id as "user_id!", 
               verification_type as "verification_type!", verification_value, 
               verified as "verified: bool", created_at as "created_at!", updated_at as "updated_at!"
        FROM nip05_domains
        WHERE id = ? AND user_id = ?
        "#,
        domain_id,
        user.id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| ApiError::internal("Database error"))?
    .ok_or_else(|| ApiError::not_found("Domain not found"))?;
    
    if domain.verified.unwrap_or(false) {
        return Ok(Json(domain));
    }
    
    // TODO: Implement actual DNS verification
    // For now, we'll auto-verify for testing
    let verified_domain = sqlx::query_as!(
        Nip05Domain,
        r#"
        UPDATE nip05_domains
        SET verified = 1, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        RETURNING id as "id!", domain as "domain!", user_id as "user_id!", 
                  verification_type as "verification_type!", verification_value, 
                  verified as "verified: bool", created_at as "created_at!", updated_at as "updated_at!"
        "#,
        domain_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| ApiError::internal("Failed to verify domain"))?;
    
    Ok(Json(verified_domain))
}

pub async fn delete_domain(
    State(pool): State<SqlitePool>,
    Path(domain_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let user = get_user_from_session(&pool, &headers).await?;
    
    let result = sqlx::query!(
        "DELETE FROM nip05_domains WHERE id = ? AND user_id = ?",
        domain_id,
        user.id
    )
    .execute(&pool)
    .await
    .map_err(|_| ApiError::internal("Failed to delete domain"))?;
    
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Domain not found"));
    }
    
    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_user_nip05(
    State(pool): State<SqlitePool>,
    headers: HeaderMap,
    Json(req): Json<UpdateNip05Request>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = get_user_from_session(&pool, &headers).await?;
    
    // Validate NIP-05 identifier if provided
    if let Some(ref identifier) = req.nip05_identifier {
        let parts: Vec<&str> = identifier.split('@').collect();
        if parts.len() != 2 {
            return Err(ApiError::bad_request("Invalid NIP-05 identifier format"));
        }
        
        let domain = parts[1];
        
        // Check if domain is verified for this user
        let domain_verified = sqlx::query!(
            r#"
            SELECT verified
            FROM nip05_domains
            WHERE domain = ? AND user_id = ? AND verified = 1
            "#,
            domain,
            user.id
        )
        .fetch_optional(&pool)
        .await
        .map_err(|_| ApiError::internal("Database error"))?;
        
        if domain_verified.is_none() {
            return Err(ApiError::bad_request("Domain not verified for this user"));
        }
    }
    
    // Update user's NIP-05 identifier
    sqlx::query!(
        "UPDATE users SET nip05_identifier = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        req.nip05_identifier,
        user.id
    )
    .execute(&pool)
    .await
    .map_err(|_| ApiError::internal("Failed to update NIP-05 identifier"))?;
    
    Ok(Json(json!({
        "success": true,
        "nip05_identifier": req.nip05_identifier
    })))
}

pub fn routes(pool: SqlitePool) -> Router {
    // Public NIP-05 discovery endpoint
    let public_routes = Router::new()
        .route("/.well-known/nostr.json", get(nip05_discovery))
        .layer(CorsLayer::permissive())
        .with_state(pool.clone());
        
    // Protected domain management endpoints
    let protected_routes = Router::new()
        .route("/domains", get(list_domains).post(add_domain))
        .route("/domains/:id/verify", post(verify_domain))
        .route("/domains/:id", delete(delete_domain))
        .route("/identifier", post(update_user_nip05))
        .layer(axum::middleware::from_fn(super::auth_middleware))
        .with_state(pool);
    
    Router::new()
        .merge(public_routes)
        .nest("/api/nip05", protected_routes)
}