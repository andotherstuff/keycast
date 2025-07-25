// ABOUTME: Integration tests for application management API endpoints
// ABOUTME: Tests public app discovery, user app management, and admin verification

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use keycast_api::api::http::routes;
use keycast_core::types::{Application, UserEnhanced};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tower::ServiceExt;
use uuid::Uuid;

// Test helpers
async fn setup_test_db() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database");
    
    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    
    pool
}

async fn create_test_user(pool: &SqlitePool) -> Uuid {
    let user_id = Uuid::new_v4();
    
    sqlx::query!(
        r#"
        INSERT INTO users (id, email, display_name, nip05_identifier, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, datetime('now'), datetime('now'))
        "#,
        user_id,
        "test@example.com",
        "Test User",
        "test@keycast.app"
    )
    .execute(pool)
    .await
    .expect("Failed to create test user");
    
    user_id
}

async fn create_test_session(pool: &SqlitePool, user_id: Uuid) -> String {
    let session_token = format!("test_session_{}", Uuid::new_v4());
    
    sqlx::query!(
        r#"
        INSERT INTO sessions (id, user_id, token, expires_at, created_at)
        VALUES (?1, ?2, ?3, datetime('now', '+1 day'), datetime('now'))
        "#,
        Uuid::new_v4(),
        user_id,
        session_token
    )
    .execute(pool)
    .await
    .expect("Failed to create test session");
    
    session_token
}

async fn create_test_app(pool: &SqlitePool, domain: &str, verified: bool) -> Application {
    let app = Application {
        id: Uuid::new_v4(),
        name: format!("Test App {}", domain),
        domain: domain.to_string(),
        description: Some("Test application".to_string()),
        icon_url: Some("https://example.com/icon.png".to_string()),
        pubkey: None,
        metadata: json!({"test": true}).to_string(),
        is_verified: verified,
        first_seen_at: chrono::Utc::now(),
        last_used_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    
    sqlx::query!(
        r#"
        INSERT INTO applications (
            id, name, domain, description, icon_url, pubkey, 
            metadata, is_verified, first_seen_at, last_used_at, 
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
        app.id,
        app.name,
        app.domain,
        app.description,
        app.icon_url,
        app.pubkey,
        app.metadata,
        app.is_verified,
        app.first_seen_at,
        app.last_used_at,
        app.created_at,
        app.updated_at
    )
    .execute(pool)
    .await
    .expect("Failed to create test app");
    
    app
}

async fn create_test_authorization(
    pool: &SqlitePool, 
    user_id: Uuid, 
    app_id: Uuid
) -> Uuid {
    let auth_id = Uuid::new_v4();
    
    sqlx::query!(
        r#"
        INSERT INTO authorizations (
            id, user_id, app_id, user_key_id, policy_id,
            max_uses, used_count, expires_at, revoked_at,
            created_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now', '+30 days'), NULL, datetime('now'), datetime('now'))
        "#,
        auth_id,
        user_id,
        app_id,
        Uuid::new_v4(), // dummy key id
        1, // dummy policy id
        100,
        0
    )
    .execute(pool)
    .await
    .expect("Failed to create test authorization");
    
    auth_id
}

fn app() -> Router<SqlitePool> {
    routes
}

// Public endpoint tests

#[tokio::test]
async fn test_list_applications_empty() {
    let pool = setup_test_db().await;
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/applications")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(json["applications"].as_array().unwrap().len(), 0);
    assert_eq!(json["total"], 0);
    assert_eq!(json["page"], 1);
    assert_eq!(json["per_page"], 50);
}

#[tokio::test]
async fn test_list_applications_with_data() {
    let pool = setup_test_db().await;
    
    // Create test apps
    create_test_app(&pool, "app1.com", true).await;
    create_test_app(&pool, "app2.com", false).await;
    create_test_app(&pool, "app3.com", true).await;
    
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/applications")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(json["applications"].as_array().unwrap().len(), 3);
    assert_eq!(json["total"], 3);
}

#[tokio::test]
async fn test_list_applications_verified_only() {
    let pool = setup_test_db().await;
    
    // Create mix of verified and unverified apps
    create_test_app(&pool, "verified1.com", true).await;
    create_test_app(&pool, "unverified.com", false).await;
    create_test_app(&pool, "verified2.com", true).await;
    
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/applications?verified_only=true")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    let apps = json["applications"].as_array().unwrap();
    assert_eq!(apps.len(), 2);
    
    // All apps should be verified
    for app in apps {
        assert_eq!(app["is_verified"], true);
    }
}

#[tokio::test]
async fn test_list_applications_pagination() {
    let pool = setup_test_db().await;
    
    // Create 5 apps
    for i in 1..=5 {
        create_test_app(&pool, &format!("app{}.com", i), true).await;
    }
    
    let app = app().with_state(pool.clone());
    
    // Test page 1 with 2 items per page
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/applications?page=1&per_page=2")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(json["applications"].as_array().unwrap().len(), 2);
    assert_eq!(json["total"], 5);
    assert_eq!(json["page"], 1);
    assert_eq!(json["per_page"], 2);
}

#[tokio::test]
async fn test_get_application_not_found() {
    let pool = setup_test_db().await;
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/applications/{}", Uuid::new_v4()))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_application_success() {
    let pool = setup_test_db().await;
    let test_app = create_test_app(&pool, "test.com", true).await;
    
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/applications/{}", test_app.id))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    assert_eq!(json["id"], test_app.id.to_string());
    assert_eq!(json["name"], test_app.name);
    assert_eq!(json["domain"], test_app.domain);
    assert_eq!(json["is_verified"], true);
}

// User-specific endpoint tests

#[tokio::test]
async fn test_list_user_applications_unauthorized() {
    let pool = setup_test_db().await;
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/users/applications")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_list_user_applications_empty() {
    let pool = setup_test_db().await;
    let user_id = create_test_user(&pool).await;
    let session = create_test_session(&pool, user_id).await;
    
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/users/applications")
                .header("Cookie", format!("session={}", session))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_list_user_applications_with_authorizations() {
    let pool = setup_test_db().await;
    let user_id = create_test_user(&pool).await;
    let session = create_test_session(&pool, user_id).await;
    
    // Create apps and authorizations
    let app1 = create_test_app(&pool, "app1.com", true).await;
    let app2 = create_test_app(&pool, "app2.com", false).await;
    
    create_test_authorization(&pool, user_id, app1.id).await;
    create_test_authorization(&pool, user_id, app2.id).await;
    
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/users/applications")
                .header("Cookie", format!("session={}", session))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    let apps = json.as_array().unwrap();
    assert_eq!(apps.len(), 2);
}

#[tokio::test]
async fn test_revoke_app_authorizations() {
    let pool = setup_test_db().await;
    let user_id = create_test_user(&pool).await;
    let session = create_test_session(&pool, user_id).await;
    
    let test_app = create_test_app(&pool, "revoke.com", true).await;
    create_test_authorization(&pool, user_id, test_app.id).await;
    
    let app = app().with_state(pool.clone());
    
    // Revoke authorization
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(&format!("/api/users/applications/{}/revoke", test_app.id))
                .header("Cookie", format!("session={}", session))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    
    // Verify it's gone
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/users/applications")
                .header("Cookie", format!("session={}", session))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    
    assert!(json.as_array().unwrap().is_empty());
}

// Admin endpoint tests

#[tokio::test]
async fn test_verify_application_forbidden() {
    let pool = setup_test_db().await;
    let user_id = create_test_user(&pool).await;
    let session = create_test_session(&pool, user_id).await;
    let test_app = create_test_app(&pool, "verify.com", false).await;
    
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&format!("/api/applications/{}/verify", test_app.id))
                .header("Cookie", format!("session={}", session))
                .header("Content-Type", "application/json")
                .body(Body::from(json!({"verified": true}).to_string()))
                .unwrap()
        )
        .await
        .unwrap();
    
    // Should be forbidden since we don't have admin middleware implemented
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// Error handling tests

#[tokio::test]
async fn test_invalid_uuid_format() {
    let pool = setup_test_db().await;
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/applications/not-a-uuid")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_database_error_handling() {
    // Test with a closed database connection
    let pool = setup_test_db().await;
    pool.close().await;
    
    let app = app().with_state(pool.clone());
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/applications")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}