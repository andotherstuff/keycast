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
    
    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM applications WHERE (? = false OR is_verified = true)"
    )
    .bind(params.verified_only)
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
    #[derive(sqlx::FromRow)]
    struct UserAppRow {
        id: String,
        name: String,
        domain: String,
        description: Option<String>,
        icon_url: Option<String>,
        is_verified: bool,
        first_seen_at: chrono::DateTime<chrono::Utc>,
        last_used_at: Option<chrono::DateTime<chrono::Utc>>,
        active_authorizations: Option<i64>,
        total_requests: Option<i64>,
    }
    
    let user_apps = sqlx::query_as::<_, UserAppRow>(
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
        LEFT JOIN authorization_requests ar ON ar.app_id = a.id AND ar.user_id = ?
        WHERE auth.user_id = ? AND auth.revoked_at IS NULL
        GROUP BY a.id
        ORDER BY a.last_used_at DESC NULLS LAST
        "#
    )
    .bind(user_id.to_string())
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let app_infos: Vec<UserApplicationInfo> = user_apps
        .into_iter()
        .map(|row| UserApplicationInfo {
            app: ApplicationInfo {
                id: Uuid::parse_str(&row.id).unwrap_or_default(),
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
    let user_app = sqlx::query_as::<_, UserAppRow>(
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
        LEFT JOIN authorization_requests ar ON ar.app_id = a.id AND ar.user_id = ?
        WHERE a.id = ? AND auth.user_id = ? AND auth.revoked_at IS NULL
        GROUP BY a.id
        "#
    )
    .bind(user_id.to_string())
    .bind(app_id.to_string())
    .bind(user_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(UserApplicationInfo {
        app: ApplicationInfo {
            id: Uuid::parse_str(&user_app.id).unwrap_or_default(),
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
    let result = sqlx::query(
        r#"
        UPDATE authorizations 
        SET revoked_at = datetime('now') 
        WHERE user_id = ? AND app_id = ? AND revoked_at IS NULL
        "#
    )
    .bind(user_id.to_string())
    .bind(app_id.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    
    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        // Create necessary tables for testing
        sqlx::query(
            r#"
            CREATE TABLE applications (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT NOT NULL UNIQUE,
                description TEXT,
                icon_url TEXT,
                pubkey TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                is_verified BOOLEAN NOT NULL DEFAULT FALSE,
                first_seen_at TEXT NOT NULL,
                last_used_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create applications table");
        
        sqlx::query(
            r#"
            CREATE TABLE authorizations (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                app_id TEXT NOT NULL,
                user_key_id TEXT NOT NULL,
                policy_id INTEGER NOT NULL,
                max_uses INTEGER,
                used_count INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (app_id) REFERENCES applications(id)
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create authorizations table");
        
        sqlx::query(
            r#"
            CREATE TABLE authorization_requests (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                app_id TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                approved_at TEXT,
                rejected_at TEXT,
                created_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create authorization_requests table");
        
        pool
    }
    
    async fn create_test_app(pool: &SqlitePool, domain: &str, verified: bool) -> Application {
        let app = Application {
            id: Uuid::new_v4(),
            name: format!("Test App {}", domain),
            domain: domain.to_string(),
            description: Some("Test application".to_string()),
            icon_url: Some("https://example.com/icon.png".to_string()),
            pubkey: None,
            metadata: serde_json::json!({"test": true}).to_string(),
            is_verified: verified,
            first_seen_at: chrono::Utc::now(),
            last_used_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        
        sqlx::query(
            r#"
            INSERT INTO applications (
                id, name, domain, description, icon_url, pubkey, 
                metadata, is_verified, first_seen_at, last_used_at, 
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(app.id.to_string())
        .bind(&app.name)
        .bind(&app.domain)
        .bind(&app.description)
        .bind(&app.icon_url)
        .bind(&app.pubkey)
        .bind(&app.metadata)
        .bind(app.is_verified)
        .bind(app.first_seen_at)
        .bind(app.last_used_at)
        .bind(app.created_at)
        .bind(app.updated_at)
        .execute(pool)
        .await
        .expect("Failed to create test app");
        
        app
    }
    
    #[tokio::test]
    async fn test_list_applications_query_logic() {
        let pool = setup_test_db().await;
        
        // Create test apps
        create_test_app(&pool, "app1.com", true).await;
        create_test_app(&pool, "app2.com", false).await;
        create_test_app(&pool, "app3.com", true).await;
        
        // Test listing all apps
        let all_apps = Application::list_all(&pool, Some(10), Some(0))
            .await
            .expect("Failed to list apps");
        
        assert_eq!(all_apps.len(), 3);
        
        // Test verified count
        let verified_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM applications WHERE is_verified = true"
        )
        .fetch_one(&pool)
        .await
        .expect("Failed to count verified apps")
        .unwrap_or(0);
        
        assert_eq!(verified_count, 2);
    }
    
    #[tokio::test]
    async fn test_user_applications_query() {
        let pool = setup_test_db().await;
        let user_id = Uuid::new_v4();
        
        // Create apps and authorizations
        let app1 = create_test_app(&pool, "userapp1.com", true).await;
        let app2 = create_test_app(&pool, "userapp2.com", false).await;
        
        // Create authorization for user
        sqlx::query(
            r#"
            INSERT INTO authorizations (
                id, user_id, app_id, user_key_id, policy_id,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            "#
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id.to_string())
        .bind(app1.id.to_string())
        .bind(Uuid::new_v4().to_string())
        .bind(1)
        .execute(&pool)
        .await
        .expect("Failed to create authorization");
        
        // Query user apps
        #[derive(sqlx::FromRow)]
        struct TestUserApp {
            id: String,
            name: String,
            domain: String,
            active_authorizations: Option<i64>,
        }
        
        let user_apps = sqlx::query_as::<_, TestUserApp>(
            r#"
            SELECT DISTINCT
                a.id,
                a.name,
                a.domain,
                COUNT(auth.id) as active_authorizations
            FROM applications a
            INNER JOIN authorizations auth ON auth.app_id = a.id
            WHERE auth.user_id = ? AND auth.revoked_at IS NULL
            GROUP BY a.id
            "#
        )
        .bind(user_id.to_string())
        .fetch_all(&pool)
        .await
        .expect("Failed to query user apps");
        
        assert_eq!(user_apps.len(), 1);
        assert_eq!(user_apps[0].domain, "userapp1.com");
    }
    
    #[tokio::test]
    async fn test_revoke_authorization() {
        let pool = setup_test_db().await;
        let user_id = Uuid::new_v4();
        let app = create_test_app(&pool, "revoke-test.com", true).await;
        
        // Create authorization
        sqlx::query(
            r#"
            INSERT INTO authorizations (
                id, user_id, app_id, user_key_id, policy_id,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            "#
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id.to_string())
        .bind(app.id.to_string())
        .bind(Uuid::new_v4().to_string())
        .bind(1)
        .execute(&pool)
        .await
        .expect("Failed to create authorization");
        
        // Revoke it
        let result = sqlx::query(
            r#"
            UPDATE authorizations 
            SET revoked_at = datetime('now') 
            WHERE user_id = ? AND app_id = ? AND revoked_at IS NULL
            "#
        )
        .bind(user_id.to_string())
        .bind(app.id.to_string())
        .execute(&pool)
        .await
        .expect("Failed to revoke authorization");
        
        assert_eq!(result.rows_affected(), 1);
        
        // Verify it's revoked
        let active_count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*) 
            FROM authorizations 
            WHERE user_id = ? AND app_id = ? AND revoked_at IS NULL
            "#
        )
        .bind(user_id.to_string())
        .bind(app.id.to_string())
        .fetch_one(&pool)
        .await
        .expect("Failed to count active authorizations")
        .unwrap_or(0);
        
        assert_eq!(active_count, 0);
    }
}