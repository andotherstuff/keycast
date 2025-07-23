// ABOUTME: User authorization request management endpoints
// ABOUTME: View and respond to pending authorization requests from apps

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::api::error::ApiError;
use crate::api::http::auth::get_user_from_session;
use keycast_core::authorization_flow::{
    AuthorizationFlowService, AuthorizationRequest, AuthorizationRequestStatus,
};
use keycast_core::encryption::MasterKeyManager;

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
pub struct ApproveRequestBody {
    pub user_key_id: String,
    pub policy_id: u32,
    pub max_uses: Option<u16>,
    pub expires_in_hours: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct RejectRequestBody {
    pub reason: Option<String>, // Optional reason for rejection (for future logging)
}

#[derive(Debug, Serialize)]
pub struct AuthorizationRequestResponse {
    pub id: String,
    pub app_domain: String,
    pub app_name: String,
    pub app_description: Option<String>,
    pub app_icon_url: Option<String>,
    pub requested_permissions: Vec<String>,
    pub status: AuthorizationRequestStatusResponse,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub responded_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationRequestStatusResponse {
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Serialize)]
pub struct AuthorizationRequestListResponse {
    pub requests: Vec<AuthorizationRequestResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct ApproveResponse {
    pub authorization_id: String,
    pub message: String,
}

// ============ Routes ============

pub fn routes() -> Router {
    Router::new()
        .route("/", get(list_authorization_requests))
        .route("/:id", get(get_authorization_request))
        .route("/:id/approve", post(approve_request))
        .route("/:id/reject", post(reject_request))
}

// ============ Handlers ============

/// GET /api/auth/requests
/// List pending authorization requests for the authenticated user
pub async fn list_authorization_requests(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Initialize authorization flow service
    let key_manager = Box::new(MasterKeyManager::new());
    let auth_service = AuthorizationFlowService::new(pool.clone(), key_manager);
    
    // Get pending requests
    let requests = auth_service
        .get_pending_requests(&user.id)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to get pending requests: {}", e)))?;
    
    // Convert to response format
    let response_requests: Vec<AuthorizationRequestResponse> = requests
        .into_iter()
        .map(|req| AuthorizationRequestResponse {
            id: req.id,
            app_domain: req.app_domain,
            app_name: req.app_name,
            app_description: req.app_description,
            app_icon_url: req.app_icon_url,
            requested_permissions: req.requested_permissions,
            status: match req.status {
                AuthorizationRequestStatus::Pending => AuthorizationRequestStatusResponse::Pending,
                AuthorizationRequestStatus::Approved => AuthorizationRequestStatusResponse::Approved,
                AuthorizationRequestStatus::Rejected => AuthorizationRequestStatusResponse::Rejected,
            },
            created_at: req.created_at,
            responded_at: req.responded_at,
        })
        .collect();
    
    let total = response_requests.len();
    
    Ok(Json(AuthorizationRequestListResponse {
        requests: response_requests,
        total,
    }).into_response())
}

/// GET /api/auth/requests/:id
/// Get a specific authorization request
pub async fn get_authorization_request(
    State(pool): State<SqlitePool>,
    Path(request_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Query the specific request
    #[derive(sqlx::FromRow)]
    struct AuthRequestRow {
        id: Option<String>,
        user_id: String,
        app_domain: String,
        app_name: Option<String>,
        app_description: Option<String>,
        app_icon_url: Option<String>,
        requested_permissions: Option<String>,
        status: String,
        created_at: chrono::NaiveDateTime,
        responded_at: Option<chrono::NaiveDateTime>,
    }
    
    let row = sqlx::query_as::<_, AuthRequestRow>(
        r#"
        SELECT id, user_id, app_domain, app_name, 
               app_description, app_icon_url, 
               requested_permissions, status,
               created_at, responded_at
        FROM authorization_requests
        WHERE id = ? AND user_id = ?
        "#
    )
    .bind(&request_id)
    .bind(&user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch request: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Authorization request not found"))?;
    
    // Parse permissions
    let permissions: Vec<String> = if let Some(perms) = row.requested_permissions.as_deref() {
        serde_json::from_str(perms)
            .map_err(|e| ApiError::internal(format!("Failed to parse permissions: {}", e)))?
    } else {
        Vec::new()
    };
    
    // Parse status
    let status = match row.status.as_str() {
        "pending" => AuthorizationRequestStatusResponse::Pending,
        "approved" => AuthorizationRequestStatusResponse::Approved,
        "rejected" => AuthorizationRequestStatusResponse::Rejected,
        _ => return Err(ApiError::internal("Invalid status in database")),
    };
    
    let response = AuthorizationRequestResponse {
        id: row.id.expect("id is PRIMARY KEY"),
        app_domain: row.app_domain,
        app_name: row.app_name.unwrap_or_default(),
        app_description: row.app_description,
        app_icon_url: row.app_icon_url,
        requested_permissions: permissions,
        status,
        created_at: chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(row.created_at, chrono::Utc),
        responded_at: row.responded_at.map(|dt| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc)),
    };
    
    Ok(Json(response).into_response())
}

/// POST /api/auth/requests/:id/approve
/// Approve an authorization request
pub async fn approve_request(
    State(pool): State<SqlitePool>,
    Path(request_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ApproveRequestBody>,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Validate user owns the key
    let key_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM user_keys WHERE id = ? AND user_id = ?"
    )
    .bind(&body.user_key_id)
    .bind(&user.id)
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check user key: {}", e)))?;
    
    let key_exists = key_count > 0;
    
    if !key_exists {
        return Err(ApiError::not_found("User key not found"));
    }
    
    // Validate user owns the policy
    let policy_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM policies WHERE id = ? AND user_id = ?"
    )
    .bind(body.policy_id)
    .bind(&user.id)
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check policy: {}", e)))?;
    
    let policy_exists = policy_count > 0;
    
    if !policy_exists {
        return Err(ApiError::not_found("Policy not found"));
    }
    
    // Initialize authorization flow service
    let key_manager = Box::new(MasterKeyManager::new());
    let auth_service = AuthorizationFlowService::new(pool.clone(), key_manager);
    
    // Approve the request
    let authorization_id = auth_service
        .approve_request(
            &request_id,
            &user.id,
            &body.user_key_id,
            body.policy_id,
            body.max_uses,
            body.expires_in_hours,
        )
        .await
        .map_err(|e| match e {
            keycast_core::authorization_flow::AuthorizationFlowError::RequestNotFound => {
                ApiError::not_found("Authorization request not found")
            }
            keycast_core::authorization_flow::AuthorizationFlowError::RequestAlreadyProcessed => {
                ApiError::bad_request("Request has already been processed")
            }
            _ => ApiError::internal(format!("Failed to approve request: {}", e)),
        })?;
    
    Ok((
        StatusCode::OK,
        Json(ApproveResponse {
            authorization_id,
            message: "Authorization request approved successfully".to_string(),
        }),
    ).into_response())
}

/// POST /api/auth/requests/:id/reject
/// Reject an authorization request
pub async fn reject_request(
    State(pool): State<SqlitePool>,
    Path(request_id): Path<String>,
    headers: axum::http::HeaderMap,
    Json(_body): Json<RejectRequestBody>, // Reason for future use
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Initialize authorization flow service
    let key_manager = Box::new(MasterKeyManager::new());
    let auth_service = AuthorizationFlowService::new(pool.clone(), key_manager);
    
    // Reject the request
    auth_service
        .reject_request(&request_id, &user.id)
        .await
        .map_err(|e| match e {
            keycast_core::authorization_flow::AuthorizationFlowError::RequestNotFound => {
                ApiError::not_found("Authorization request not found")
            }
            keycast_core::authorization_flow::AuthorizationFlowError::RequestAlreadyProcessed => {
                ApiError::bad_request("Request has already been processed")
            }
            _ => ApiError::internal(format!("Failed to reject request: {}", e)),
        })?;
    
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    
    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        // Create necessary tables
        sqlx::query(
            r#"
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create users table");
        
        sqlx::query(
            r#"
            CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create sessions table");
        
        sqlx::query(
            r#"
            CREATE TABLE authorization_requests (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                app_domain TEXT NOT NULL,
                app_name TEXT,
                app_description TEXT,
                app_icon_url TEXT,
                requested_permissions TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                responded_at TEXT
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create authorization_requests table");
        
        sqlx::query(
            r#"
            CREATE TABLE user_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create user_keys table");
        
        sqlx::query(
            r#"
            CREATE TABLE policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create policies table");
        
        pool
    }
    
    async fn create_test_user_with_session(pool: &SqlitePool) -> (Uuid, String) {
        let user_id = Uuid::new_v4();
        let session_token = format!("test_session_{}", Uuid::new_v4());
        
        // Create user
        sqlx::query(
            r#"
            INSERT INTO users (id, email, display_name, created_at, updated_at)
            VALUES (?, ?, ?, datetime('now'), datetime('now'))
            "#
        )
        .bind(user_id.to_string())
        .bind("test@example.com")
        .bind("Test User")
        .execute(pool)
        .await
        .expect("Failed to create test user");
        
        // Create session
        sqlx::query(
            r#"
            INSERT INTO sessions (id, user_id, token, expires_at, created_at)
            VALUES (?, ?, ?, datetime('now', '+1 day'), datetime('now'))
            "#
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id.to_string())
        .bind(&session_token)
        .execute(pool)
        .await
        .expect("Failed to create test session");
        
        (user_id, session_token)
    }
    
    async fn create_test_request(pool: &SqlitePool, user_id: Uuid, app_domain: &str) -> String {
        let request_id = Uuid::new_v4().to_string();
        
        sqlx::query(
            r#"
            INSERT INTO authorization_requests (
                id, user_id, app_domain, app_name, app_description,
                app_icon_url, requested_permissions, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))
            "#
        )
        .bind(&request_id)
        .bind(user_id.to_string())
        .bind(app_domain)
        .bind(format!("App {}", app_domain))
        .bind("Test app description")
        .bind("https://example.com/icon.png")
        .bind(serde_json::json!(["sign_event", "nip04_encrypt"]).to_string())
        .execute(pool)
        .await
        .expect("Failed to create test request");
        
        request_id
    }
    
    #[tokio::test]
    async fn test_get_authorization_request_found() {
        let pool = setup_test_db().await;
        let (user_id, _session) = create_test_user_with_session(&pool).await;
        let request_id = create_test_request(&pool, user_id, "test.com").await;
        
        // Query the request directly
        let row = sqlx::query_as::<_, AuthRequestRow>(
            r#"
            SELECT id, user_id, app_domain, app_name, 
                   app_description, app_icon_url, 
                   requested_permissions, status,
                   created_at, responded_at
            FROM authorization_requests
            WHERE id = ? AND user_id = ?
            "#
        )
        .bind(&request_id)
        .bind(&user_id.to_string())
        .fetch_optional(&pool)
        .await
        .expect("Failed to fetch request");
        
        assert!(row.is_some());
        let row = row.unwrap();
        assert_eq!(row.app_domain, "test.com");
        assert_eq!(row.status, "pending");
    }
    
    #[tokio::test]
    async fn test_get_authorization_request_wrong_user() {
        let pool = setup_test_db().await;
        let (user1, _) = create_test_user_with_session(&pool).await;
        let (user2, _) = create_test_user_with_session(&pool).await;
        let request_id = create_test_request(&pool, user1, "test.com").await;
        
        // Try to fetch user1's request as user2
        let row = sqlx::query(
            r#"
            SELECT id FROM authorization_requests
            WHERE id = ? AND user_id = ?
            "#
        )
        .bind(&request_id)
        .bind(&user2.to_string())
        .fetch_optional(&pool)
        .await
        .expect("Failed to fetch request");
        
        assert!(row.is_none());
    }
    
    #[tokio::test]
    async fn test_approve_request_validations() {
        let pool = setup_test_db().await;
        let (user_id, _) = create_test_user_with_session(&pool).await;
        
        // Create user key
        let key_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO user_keys (id, user_id, name, public_key, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            "#
        )
        .bind(&key_id)
        .bind(user_id.to_string())
        .bind("Test Key")
        .bind("npub1test")
        .execute(&pool)
        .await
        .expect("Failed to create test key");
        
        // Create policy
        sqlx::query(
            r#"
            INSERT INTO policies (user_id, name, created_at)
            VALUES (?, ?, datetime('now'))
            "#
        )
        .bind(user_id.to_string())
        .bind("Test Policy")
        .execute(&pool)
        .await
        .expect("Failed to create test policy");
        
        let policy_id = sqlx::query_scalar::<_, i32>("SELECT last_insert_rowid()")
            .fetch_one(&pool)
            .await
            .expect("Failed to get policy id");
        
        // Verify key exists for user
        let key_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM user_keys WHERE id = ? AND user_id = ?"
        )
        .bind(&key_id)
        .bind(user_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("Failed to count keys");
        
        assert_eq!(key_count, 1);
        
        // Verify policy exists for user
        let policy_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM policies WHERE id = ? AND user_id = ?"
        )
        .bind(policy_id)
        .bind(user_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("Failed to count policies");
        
        assert_eq!(policy_count, 1);
    }
}