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
    let row = sqlx::query!(
        r#"
        SELECT id, user_id, app_domain, app_name, 
               app_description, app_icon_url, 
               requested_permissions, status,
               created_at, responded_at
        FROM authorization_requests
        WHERE id = ?1 AND user_id = ?2
        "#,
        request_id,
        user.id
    )
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
    let key_exists = sqlx::query!(
        "SELECT COUNT(*) as count FROM user_keys WHERE id = ?1 AND user_id = ?2",
        body.user_key_id,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check user key: {}", e)))?
    .count > 0;
    
    if !key_exists {
        return Err(ApiError::not_found("User key not found"));
    }
    
    // Validate user owns the policy
    let policy_exists = sqlx::query!(
        "SELECT COUNT(*) as count FROM policies WHERE id = ?1 AND user_id = ?2",
        body.policy_id,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check policy: {}", e)))?
    .count > 0;
    
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