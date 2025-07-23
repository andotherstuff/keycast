// ABOUTME: Application management API endpoints for listing, viewing, and managing applications
// ABOUTME: Includes both user-specific app management and public app discovery endpoints

use crate::api::http::auth::Protected;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, put},
    Router,
};
use keycast_core::types::Application;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;

pub fn routes() -> Router<SqlitePool> {
    Router::new()
        // Public endpoints
        .route("/", get(list_applications))
        .route("/:id", get(get_application))
        // Admin endpoints
        .route("/:id/verify", put(verify_application).layer(axum::middleware::from_fn(require_admin)))
}

pub fn user_app_routes() -> Router<SqlitePool> {
    Router::new()
        .route("/", get(list_user_applications))
        .route("/:id", get(get_user_application))
        .route("/:id/revoke", delete(revoke_app_authorizations))
}

#[derive(Debug, Serialize, Deserialize)]
struct ListApplicationsParams {
    #[serde(default = "default_page")]
    page: u32,
    #[serde(default = "default_per_page")]
    per_page: u32,
    #[serde(default)]
    verified_only: bool,
}

fn default_page() -> u32 { 1 }
fn default_per_page() -> u32 { 50 }

#[derive(Debug, Serialize)]
struct ApplicationListResponse {
    applications: Vec<ApplicationInfo>,
    total: u64,
    page: u32,
    per_page: u32,
}

#[derive(Debug, Serialize)]
struct ApplicationInfo {
    id: Uuid,
    name: String,
    domain: String,
    description: Option<String>,
    icon_url: Option<String>,
    is_verified: bool,
    first_seen_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
struct UserApplicationInfo {
    #[serde(flatten)]
    app: ApplicationInfo,
    active_authorizations: u32,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    total_requests: u64,
}

// Public endpoints

async fn list_applications(
    State(pool): State<SqlitePool>,
    Query(params): Query<ListApplicationsParams>,
) -> Result<Json<ApplicationListResponse>, StatusCode> {
    
    let offset = ((params.page - 1) * params.per_page) as i64;
    let limit = params.per_page as i64;
    
    let applications = Application::list_all(pool, Some(limit), Some(offset))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let total = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM applications WHERE ($1 = false OR is_verified = true)",
        params.verified_only
    )
    .fetch_one(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .unwrap_or(0) as u64;
    
    let app_infos: Vec<ApplicationInfo> = applications
        .into_iter()
        .filter(|app| !params.verified_only || app.is_verified)
        .map(|app| ApplicationInfo {
            id: app.id,
            name: app.name,
            domain: app.domain,
            description: app.description,
            icon_url: app.icon_url,
            is_verified: app.is_verified,
            first_seen_at: app.first_seen_at,
        })
        .collect();
    
    Ok(Json(ApplicationListResponse {
        applications: app_infos,
        total,
        page: params.page,
        per_page: params.per_page,
    }))
}

async fn get_application(
    State(pool): State<SqlitePool>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApplicationInfo>, StatusCode> {
    
    let app = Application::find_by_id(pool, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(ApplicationInfo {
        id: app.id,
        name: app.name,
        domain: app.domain,
        description: app.description,
        icon_url: app.icon_url,
        is_verified: app.is_verified,
        first_seen_at: app.first_seen_at,
    }))
}

// User-specific endpoints

async fn list_user_applications(
    State(pool): State<SqlitePool>,
    Protected(user_id): Protected,
) -> Result<Json<Vec<UserApplicationInfo>>, StatusCode> {
    
    // Get all applications that have authorizations for this user
    let user_apps = sqlx::query!(
        r#"
        SELECT DISTINCT
            a.id,
            a.name,
            a.domain,
            a.description,
            a.icon_url,
            a.is_verified,
            a.first_seen_at,
            a.last_used_at,
            COUNT(auth.id) as active_authorizations,
            COUNT(ar.id) as total_requests
        FROM applications a
        INNER JOIN authorizations auth ON auth.app_id = a.id
        LEFT JOIN authorization_requests ar ON ar.app_id = a.id AND ar.user_id = $1
        WHERE auth.user_id = $1 AND auth.revoked_at IS NULL
        GROUP BY a.id
        ORDER BY a.last_used_at DESC NULLS LAST
        "#,
        user_id
    )
    .fetch_all(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let app_infos: Vec<UserApplicationInfo> = user_apps
        .into_iter()
        .map(|row| UserApplicationInfo {
            app: ApplicationInfo {
                id: row.id,
                name: row.name,
                domain: row.domain,
                description: row.description,
                icon_url: row.icon_url,
                is_verified: row.is_verified,
                first_seen_at: row.first_seen_at,
            },
            active_authorizations: row.active_authorizations.unwrap_or(0) as u32,
            last_used_at: row.last_used_at,
            total_requests: row.total_requests.unwrap_or(0) as u64,
        })
        .collect();
    
    Ok(Json(app_infos))
}

async fn get_user_application(
    State(pool): State<SqlitePool>,
    Protected(user_id): Protected,
    Path(app_id): Path<Uuid>,
) -> Result<Json<UserApplicationInfo>, StatusCode> {
    
    // Check if user has any authorizations for this app
    let user_app = sqlx::query!(
        r#"
        SELECT 
            a.id,
            a.name,
            a.domain,
            a.description,
            a.icon_url,
            a.is_verified,
            a.first_seen_at,
            a.last_used_at,
            COUNT(auth.id) as active_authorizations,
            COUNT(ar.id) as total_requests
        FROM applications a
        INNER JOIN authorizations auth ON auth.app_id = a.id
        LEFT JOIN authorization_requests ar ON ar.app_id = a.id AND ar.user_id = $1
        WHERE a.id = $2 AND auth.user_id = $1 AND auth.revoked_at IS NULL
        GROUP BY a.id
        "#,
        user_id,
        app_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(UserApplicationInfo {
        app: ApplicationInfo {
            id: user_app.id,
            name: user_app.name,
            domain: user_app.domain,
            description: user_app.description,
            icon_url: user_app.icon_url,
            is_verified: user_app.is_verified,
            first_seen_at: user_app.first_seen_at,
        },
        active_authorizations: user_app.active_authorizations.unwrap_or(0) as u32,
        last_used_at: user_app.last_used_at,
        total_requests: user_app.total_requests.unwrap_or(0) as u64,
    }))
}

async fn revoke_app_authorizations(
    State(pool): State<SqlitePool>,
    Protected(user_id): Protected,
    Path(app_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    
    // Revoke all active authorizations for this app
    let result = sqlx::query!(
        r#"
        UPDATE authorizations 
        SET revoked_at = NOW() 
        WHERE user_id = $1 AND app_id = $2 AND revoked_at IS NULL
        "#,
        user_id,
        app_id
    )
    .execute(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    
    Ok(StatusCode::NO_CONTENT)
}

// Admin endpoints

#[derive(Debug, Serialize, Deserialize)]
struct VerifyApplicationRequest {
    verified: bool,
}

async fn verify_application(
    State(pool): State<SqlitePool>,
    Path(id): Path<Uuid>,
    Json(req): Json<VerifyApplicationRequest>,
) -> Result<StatusCode, StatusCode> {
    
    let mut app = Application::find_by_id(pool, id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    app.set_verified(pool, req.verified)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(StatusCode::NO_CONTENT)
}

// Middleware to check if user is admin
async fn require_admin(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    // TODO: Implement proper admin check
    // For now, this is a placeholder that always returns forbidden
    Err(StatusCode::FORBIDDEN)
}