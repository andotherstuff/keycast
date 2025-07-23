// ABOUTME: User policy management endpoints
// ABOUTME: CRUD operations for user policies and permissions

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::api::error::ApiError;
use crate::api::http::auth::get_user_from_session;
use keycast_core::authorization_flow::PolicyTemplates;
use keycast_core::types::{
    permission::Permission,
    policy::Policy,
};

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub permissions: Vec<CreatePermissionRequest>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub identifier: String,
    pub permission_data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub id: u32,
    pub user_id: String,
    pub name: String,
    pub permissions: Vec<PermissionResponse>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct PermissionResponse {
    pub id: u32,
    pub identifier: String,
    pub name: String,
    pub permission_data: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct PolicyListResponse {
    pub policies: Vec<PolicyResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct PolicyTemplateResponse {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub icon: String,
}

// ============ Routes ============

pub fn routes() -> Router {
    Router::new()
        .route("/", get(list_policies).post(create_policy))
        .route("/templates", get(get_policy_templates))
        .route("/:id", get(get_policy).put(update_policy).delete(delete_policy))
        .route("/:id/permissions", get(list_permissions).post(add_permission))
        .route("/:id/permissions/:perm_id", delete(remove_permission))
}

// ============ Handlers ============

/// GET /api/users/policies
/// List all policies for the authenticated user
pub async fn list_policies(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Get policies for user
    let policies = sqlx::query_as::<_, Policy>(
        "SELECT * FROM policies WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(&user.id)
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch policies: {}", e)))?;
    
    // For each policy, get its permissions
    let mut policy_responses = Vec::new();
    for policy in policies {
        let permissions = sqlx::query!(
            r#"
            SELECT p.id, p.identifier, p.name, pp.permission_data
            FROM permissions p
            JOIN policy_permissions pp ON p.id = pp.permission_id
            WHERE pp.policy_id = ?
            "#,
            policy.id
        )
        .fetch_all(&pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to fetch permissions: {}", e)))?;
        
        let permission_responses: Vec<PermissionResponse> = permissions
            .into_iter()
            .map(|p| PermissionResponse {
                id: p.id as u32,
                identifier: p.identifier,
                name: p.name,
                permission_data: serde_json::from_str(&p.permission_data).unwrap_or(serde_json::Value::Null),
            })
            .collect();
        
        policy_responses.push(PolicyResponse {
            id: policy.id,
            user_id: user.id.clone(),
            name: policy.name.clone(),
            permissions: permission_responses,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        });
    }
    
    let total = policy_responses.len();
    
    Ok(Json(PolicyListResponse {
        policies: policy_responses,
        total,
    }).into_response())
}

/// POST /api/users/policies
/// Create a new policy
pub async fn create_policy(
    State(pool): State<SqlitePool>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Validate policy name
    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("Policy name cannot be empty"));
    }
    
    // Start transaction
    let mut tx = pool.begin().await
        .map_err(|e| ApiError::internal(format!("Failed to start transaction: {}", e)))?;
    
    // Create policy
    let policy_id = sqlx::query!(
        r#"
        INSERT INTO policies (user_id, name, created_at, updated_at)
        VALUES (?1, ?2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING id
        "#,
        user.id,
        req.name
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to create policy: {}", e)))?
    .id;
    
    // Add permissions
    for perm_req in req.permissions {
        // First, find or create the permission type
        let permission = sqlx::query!(
            r#"
            SELECT id FROM permissions WHERE identifier = ?
            "#,
            perm_req.identifier
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to find permission: {}", e)))?;
        
        let permission_id = match permission {
            Some(p) => p.id,
            None => {
                // Create new permission type
                sqlx::query!(
                    r#"
                    INSERT INTO permissions (identifier, name, type, created_at, updated_at)
                    VALUES (?1, ?2, 'custom', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    RETURNING id
                    "#,
                    perm_req.identifier,
                    perm_req.identifier
                )
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| ApiError::internal(format!("Failed to create permission: {}", e)))?
                .id
            }
        };
        
        // Link permission to policy
        sqlx::query!(
            r#"
            INSERT INTO policy_permissions (policy_id, permission_id, permission_data, created_at, updated_at)
            VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            "#,
            policy_id,
            permission_id,
            perm_req.permission_data.to_string()
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to link permission: {}", e)))?;
    }
    
    // Commit transaction
    tx.commit().await
        .map_err(|e| ApiError::internal(format!("Failed to commit transaction: {}", e)))?;
    
    // Fetch the created policy with permissions
    let policy = get_policy_with_permissions(&pool, policy_id as u32, &user.id).await?;
    
    Ok((StatusCode::CREATED, Json(policy)).into_response())
}

/// GET /api/users/policies/templates
/// Get available policy templates
pub async fn get_policy_templates() -> Result<Response, ApiError> {
    let templates = PolicyTemplates::all();
    
    let template_responses: Vec<PolicyTemplateResponse> = templates
        .into_iter()
        .map(|t| PolicyTemplateResponse {
            name: t.name,
            description: t.description,
            permissions: t.permissions,
            icon: t.icon,
        })
        .collect();
    
    Ok(Json(template_responses).into_response())
}

/// GET /api/users/policies/:id
/// Get a specific policy with permissions
pub async fn get_policy(
    State(pool): State<SqlitePool>,
    Path(policy_id): Path<u32>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    let policy = get_policy_with_permissions(&pool, policy_id, &user.id).await?;
    
    Ok(Json(policy).into_response())
}

/// PUT /api/users/policies/:id
/// Update a policy
pub async fn update_policy(
    State(pool): State<SqlitePool>,
    Path(policy_id): Path<u32>,
    headers: axum::http::HeaderMap,
    Json(req): Json<UpdatePolicyRequest>,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Check if policy exists and belongs to user
    let exists = sqlx::query!(
        "SELECT COUNT(*) as count FROM policies WHERE id = ? AND user_id = ?",
        policy_id,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check policy: {}", e)))?
    .count > 0;
    
    if !exists {
        return Err(ApiError::not_found("Policy not found"));
    }
    
    // Update policy if name provided
    if let Some(name) = req.name {
        if name.trim().is_empty() {
            return Err(ApiError::bad_request("Policy name cannot be empty"));
        }
        
        sqlx::query!(
            r#"
            UPDATE policies SET name = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
            "#,
            name,
            policy_id,
            user.id
        )
        .execute(&pool)
        .await
        .map_err(|e| ApiError::internal(format!("Failed to update policy: {}", e)))?;
    }
    
    let policy = get_policy_with_permissions(&pool, policy_id, &user.id).await?;
    
    Ok(Json(policy).into_response())
}

/// DELETE /api/users/policies/:id
/// Delete a policy
pub async fn delete_policy(
    State(pool): State<SqlitePool>,
    Path(policy_id): Path<u32>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Check if policy is used in any authorizations
    let auth_count = sqlx::query!(
        r#"
        SELECT COUNT(*) as count FROM authorizations 
        WHERE policy_id = ? AND user_id = ? AND status = 'active'
        "#,
        policy_id,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check authorizations: {}", e)))?
    .count;
    
    if auth_count > 0 {
        return Err(ApiError::bad_request(
            "Cannot delete policy that has active authorizations"
        ));
    }
    
    // Delete policy (cascade will delete policy_permissions)
    let result = sqlx::query!(
        "DELETE FROM policies WHERE id = ? AND user_id = ?",
        policy_id,
        user.id
    )
    .execute(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to delete policy: {}", e)))?;
    
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Policy not found"));
    }
    
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

/// GET /api/users/policies/:id/permissions
/// List permissions for a policy
pub async fn list_permissions(
    State(pool): State<SqlitePool>,
    Path(policy_id): Path<u32>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Verify policy belongs to user
    let exists = sqlx::query!(
        "SELECT COUNT(*) as count FROM policies WHERE id = ? AND user_id = ?",
        policy_id,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check policy: {}", e)))?
    .count > 0;
    
    if !exists {
        return Err(ApiError::not_found("Policy not found"));
    }
    
    let permissions = sqlx::query!(
        r#"
        SELECT p.id, p.identifier, p.name, pp.permission_data
        FROM permissions p
        JOIN policy_permissions pp ON p.id = pp.permission_id
        WHERE pp.policy_id = ?
        "#,
        policy_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch permissions: {}", e)))?;
    
    let permission_responses: Vec<PermissionResponse> = permissions
        .into_iter()
        .map(|p| PermissionResponse {
            id: p.id as u32,
            identifier: p.identifier,
            name: p.name,
            permission_data: serde_json::from_str(&p.permission_data).unwrap_or(serde_json::Value::Null),
        })
        .collect();
    
    Ok(Json(permission_responses).into_response())
}

/// POST /api/users/policies/:id/permissions
/// Add a permission to a policy
pub async fn add_permission(
    State(pool): State<SqlitePool>,
    Path(policy_id): Path<u32>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Verify policy belongs to user
    let exists = sqlx::query!(
        "SELECT COUNT(*) as count FROM policies WHERE id = ? AND user_id = ?",
        policy_id,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check policy: {}", e)))?
    .count > 0;
    
    if !exists {
        return Err(ApiError::not_found("Policy not found"));
    }
    
    // Find or create permission type
    let permission = sqlx::query!(
        "SELECT id FROM permissions WHERE identifier = ?",
        req.identifier
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to find permission: {}", e)))?;
    
    let permission_id = match permission {
        Some(p) => p.id,
        None => {
            sqlx::query!(
                r#"
                INSERT INTO permissions (identifier, name, type, created_at, updated_at)
                VALUES (?1, ?2, 'custom', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                RETURNING id
                "#,
                req.identifier,
                req.identifier
            )
            .fetch_one(&pool)
            .await
            .map_err(|e| ApiError::internal(format!("Failed to create permission: {}", e)))?
            .id
        }
    };
    
    // Add permission to policy
    sqlx::query!(
        r#"
        INSERT INTO policy_permissions (policy_id, permission_id, permission_data, created_at, updated_at)
        VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        "#,
        policy_id,
        permission_id,
        req.permission_data.to_string()
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            ApiError::bad_request("Permission already exists in policy")
        } else {
            ApiError::internal(format!("Failed to add permission: {}", e))
        }
    })?;
    
    Ok((StatusCode::CREATED, ()).into_response())
}

/// DELETE /api/users/policies/:id/permissions/:perm_id
/// Remove a permission from a policy
pub async fn remove_permission(
    State(pool): State<SqlitePool>,
    Path((policy_id, perm_id)): Path<(u32, u32)>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let user = get_user_from_session(&pool, headers).await?;
    
    // Verify policy belongs to user
    let exists = sqlx::query!(
        "SELECT COUNT(*) as count FROM policies WHERE id = ? AND user_id = ?",
        policy_id,
        user.id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to check policy: {}", e)))?
    .count > 0;
    
    if !exists {
        return Err(ApiError::not_found("Policy not found"));
    }
    
    let result = sqlx::query!(
        "DELETE FROM policy_permissions WHERE policy_id = ? AND permission_id = ?",
        policy_id,
        perm_id
    )
    .execute(&pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to remove permission: {}", e)))?;
    
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Permission not found in policy"));
    }
    
    Ok((StatusCode::NO_CONTENT, ()).into_response())
}

// ============ Helper Functions ============

async fn get_policy_with_permissions(
    pool: &SqlitePool,
    policy_id: u32,
    user_id: &str,
) -> Result<PolicyResponse, ApiError> {
    // Get policy
    let policy = sqlx::query_as::<_, Policy>(
        "SELECT * FROM policies WHERE id = ? AND user_id = ?"
    )
    .bind(policy_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch policy: {}", e)))?
    .ok_or_else(|| ApiError::not_found("Policy not found"))?;
    
    // Get permissions
    let permissions = sqlx::query!(
        r#"
        SELECT p.id, p.identifier, p.name, pp.permission_data
        FROM permissions p
        JOIN policy_permissions pp ON p.id = pp.permission_id
        WHERE pp.policy_id = ?
        "#,
        policy_id
    )
    .fetch_all(pool)
    .await
    .map_err(|e| ApiError::internal(format!("Failed to fetch permissions: {}", e)))?;
    
    let permission_responses: Vec<PermissionResponse> = permissions
        .into_iter()
        .map(|p| PermissionResponse {
            id: p.id as u32,
            identifier: p.identifier,
            name: p.name,
            permission_data: serde_json::from_str(&p.permission_data).unwrap_or(serde_json::Value::Null),
        })
        .collect();
    
    Ok(PolicyResponse {
        id: policy.id,
        user_id: user_id.to_string(),
        name: policy.name,
        permissions: permission_responses,
        created_at: policy.created_at,
        updated_at: policy.updated_at,
    })
}