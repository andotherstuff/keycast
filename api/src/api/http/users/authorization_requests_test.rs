// ABOUTME: Unit tests for authorization request endpoints  
// ABOUTME: Tests list, approve, and reject functionality for app authorization requests

#[cfg(test)]
mod tests {
    use crate::api::http::auth::Protected;
    use axum::{
        extract::{Json, Path, State},
        http::StatusCode,
    };
    use keycast_core::{
        authorization_flow::{AuthorizationFlowService, AuthorizationRequest},
        types::{Application, UserKey, Policy},
    };
    use serde_json::json;
    use sqlx::SqlitePool;
    use uuid::Uuid;
    
    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database");
        
        // Create minimal tables for testing
        sqlx::query(
            r#"
            CREATE TABLE applications (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                domain TEXT NOT NULL UNIQUE,
                is_verified BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create applications table");
        
        sqlx::query(
            r#"
            CREATE TABLE authorization_requests (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                app_domain TEXT NOT NULL,
                app_name TEXT NOT NULL,
                app_description TEXT,
                app_icon_url TEXT,
                requested_permissions TEXT NOT NULL,
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
        
        sqlx::query(
            r#"
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create users table");
        
        sqlx::query(
            r#"
            CREATE TABLE user_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                is_primary BOOLEAN NOT NULL DEFAULT FALSE,
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
                id INTEGER PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create policies table");
        
        sqlx::query(
            r#"
            CREATE TABLE authorizations (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                app_id TEXT NOT NULL,
                user_key_id TEXT NOT NULL,
                policy_id INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
            "#
        )
        .execute(&pool)
        .await
        .expect("Failed to create authorizations table");
        
        pool
    }
    
    async fn create_test_user(pool: &SqlitePool) -> Uuid {
        let user_id = Uuid::new_v4();
        
        sqlx::query(
            "INSERT INTO users (id, email, created_at) VALUES (?, ?, datetime('now'))"
        )
        .bind(user_id.to_string())
        .bind("test@example.com")
        .execute(pool)
        .await
        .expect("Failed to create test user");
        
        user_id
    }
    
    async fn create_test_key(pool: &SqlitePool, user_id: Uuid) -> Uuid {
        let key_id = Uuid::new_v4();
        
        sqlx::query(
            r#"
            INSERT INTO user_keys (id, user_id, name, public_key, is_primary, created_at) 
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            "#
        )
        .bind(key_id.to_string())
        .bind(user_id.to_string())
        .bind("Test Key")
        .bind("npub1testkey")
        .bind(true)
        .execute(pool)
        .await
        .expect("Failed to create test key");
        
        key_id
    }
    
    async fn create_test_policy(pool: &SqlitePool, user_id: Uuid) -> i64 {
        sqlx::query(
            "INSERT INTO policies (user_id, name, created_at) VALUES (?, ?, datetime('now'))"
        )
        .bind(user_id.to_string())
        .bind("Test Policy")
        .execute(pool)
        .await
        .expect("Failed to create test policy");
        
        sqlx::query_scalar::<_, i64>("SELECT last_insert_rowid()")
            .fetch_one(pool)
            .await
            .expect("Failed to get policy id")
    }
    
    async fn create_test_auth_request(
        pool: &SqlitePool, 
        user_id: Uuid,
        app_domain: &str
    ) -> Uuid {
        let request_id = Uuid::new_v4();
        
        sqlx::query(
            r#"
            INSERT INTO authorization_requests (
                id, user_id, app_domain, app_name, app_description, 
                app_icon_url, requested_permissions, requested_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            "#
        )
        .bind(request_id.to_string())
        .bind(user_id.to_string())
        .bind(app_domain)
        .bind(format!("App {}", app_domain))
        .bind("Test app description")
        .bind("https://example.com/icon.png")
        .bind(json!(["sign_event", "nip04_encrypt"]).to_string())
        .execute(pool)
        .await
        .expect("Failed to create auth request");
        
        request_id
    }
    
    #[tokio::test]
    async fn test_list_pending_requests_empty() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool).await;
        
        // Test with no requests
        let service = AuthorizationFlowService::new(pool.clone());
        let requests = service.get_pending_requests(user_id)
            .await
            .expect("Failed to get pending requests");
        
        assert_eq!(requests.len(), 0);
    }
    
    #[tokio::test]
    async fn test_list_pending_requests_with_data() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool).await;
        
        // Create some test requests
        create_test_auth_request(&pool, user_id, "app1.com").await;
        create_test_auth_request(&pool, user_id, "app2.com").await;
        
        // Create a request for a different user (shouldn't appear)
        let other_user = create_test_user(&pool).await;
        create_test_auth_request(&pool, other_user, "app3.com").await;
        
        let service = AuthorizationFlowService::new(pool.clone());
        let requests = service.get_pending_requests(user_id)
            .await
            .expect("Failed to get pending requests");
        
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().any(|r| r.app_domain == "app1.com"));
        assert!(requests.iter().any(|r| r.app_domain == "app2.com"));
    }
    
    #[tokio::test]
    async fn test_approve_request_success() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool).await;
        let key_id = create_test_key(&pool, user_id).await;
        let policy_id = create_test_policy(&pool, user_id).await;
        let request_id = create_test_auth_request(&pool, user_id, "approve.com").await;
        
        // Create the app
        sqlx::query(
            r#"
            INSERT INTO applications (id, name, domain, created_at) 
            VALUES (?, ?, ?, datetime('now'))
            "#
        )
        .bind(Uuid::new_v4().to_string())
        .bind("Approve App")
        .bind("approve.com")
        .execute(&pool)
        .await
        .expect("Failed to create app");
        
        let service = AuthorizationFlowService::new(pool.clone());
        
        // Approve the request
        let auth = service.approve_request(
            request_id,
            user_id,
            key_id,
            policy_id as u32,
            Some(100),
            30 * 24, // 30 days in hours
        )
        .await
        .expect("Failed to approve request");
        
        assert_eq!(auth.user_id, user_id);
        
        // Verify request is no longer pending
        let pending = service.get_pending_requests(user_id)
            .await
            .expect("Failed to get pending requests");
        
        assert_eq!(pending.len(), 0);
    }
    
    #[tokio::test]
    async fn test_approve_request_not_found() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool).await;
        let key_id = create_test_key(&pool, user_id).await;
        let policy_id = create_test_policy(&pool, user_id).await;
        
        let service = AuthorizationFlowService::new(pool.clone());
        
        // Try to approve non-existent request
        let result = service.approve_request(
            Uuid::new_v4(),
            user_id,
            key_id,
            policy_id as u32,
            Some(100),
            720,
        )
        .await;
        
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_reject_request_success() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool).await;
        let request_id = create_test_auth_request(&pool, user_id, "reject.com").await;
        
        let service = AuthorizationFlowService::new(pool.clone());
        
        // Reject the request
        let rejected = service.reject_request(request_id, user_id)
            .await
            .expect("Failed to reject request");
        
        assert_eq!(rejected.id, request_id);
        assert!(rejected.rejected_at.is_some());
        
        // Verify request is no longer pending
        let pending = service.get_pending_requests(user_id)
            .await
            .expect("Failed to get pending requests");
        
        assert_eq!(pending.len(), 0);
    }
    
    #[tokio::test]
    async fn test_cannot_approve_other_users_request() {
        let pool = setup_test_db().await;
        let user1 = create_test_user(&pool).await;
        let user2 = create_test_user(&pool).await;
        let key_id = create_test_key(&pool, user2).await;
        let policy_id = create_test_policy(&pool, user2).await;
        
        // Create request for user1
        let request_id = create_test_auth_request(&pool, user1, "other.com").await;
        
        let service = AuthorizationFlowService::new(pool.clone());
        
        // Try to approve as user2
        let result = service.approve_request(
            request_id,
            user2, // Wrong user!
            key_id,
            policy_id as u32,
            Some(100),
            720,
        )
        .await;
        
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_already_approved_request() {
        let pool = setup_test_db().await;
        let user_id = create_test_user(&pool).await;
        let request_id = create_test_auth_request(&pool, user_id, "already.com").await;
        
        // Mark as already approved
        sqlx::query(
            "UPDATE authorization_requests SET approved_at = datetime('now') WHERE id = ?"
        )
        .bind(request_id.to_string())
        .execute(&pool)
        .await
        .expect("Failed to mark as approved");
        
        let service = AuthorizationFlowService::new(pool.clone());
        
        // Should not appear in pending requests
        let pending = service.get_pending_requests(user_id)
            .await
            .expect("Failed to get pending requests");
        
        assert_eq!(pending.len(), 0);
    }
}