// ABOUTME: Integration tests for HTTP API endpoints with real HTTP requests
// ABOUTME: Tests complete request/response cycle including authentication and signing

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;  // For collecting body bytes
use keycast_core::database::Database;
use keycast_core::encryption::file_key_manager::FileKeyManager;
use keycast_core::encryption::KeyManager;
use nostr_sdk::{Keys, UnsignedEvent, Kind, Timestamp};
use serde_json::json;
use sqlx::SqlitePool;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;

/// Helper to create test database with full schema and migrations
async fn create_test_database() -> Database {
    // Use in-memory database for tests
    let db_path = PathBuf::from(":memory:");

    // Get migrations path relative to test
    let migrations_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("database/migrations");

    let db = Database::new(db_path, migrations_path).await.unwrap();

    // Create localhost tenant for tests (id=2, since id=1 is oauth.divine.video from migration)
    sqlx::query(
        "INSERT INTO tenants (domain, name, settings, created_at, updated_at)
         VALUES ('localhost', 'Localhost Test', '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
    )
    .execute(&db.pool)
    .await
    .unwrap();

    db
}

/// Helper to get localhost tenant ID from database
async fn get_localhost_tenant_id(pool: &SqlitePool) -> i64 {
    let (id,): (i64,) = sqlx::query_as("SELECT id FROM tenants WHERE domain = 'localhost'")
        .fetch_one(pool)
        .await
        .unwrap();
    id
}

/// Helper to create JWT token for testing
fn create_test_jwt(user_pubkey: &str) -> String {
    use jsonwebtoken::{encode, Header, EncodingKey};
    use serde::{Serialize, Deserialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    let claims = Claims {
        sub: user_pubkey.to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
    };

    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "insecure-dev-secret-change-in-production".to_string());
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap()
}

/// Helper to generate a test bunker secret (64 char alphanumeric)
fn generate_test_bunker_secret() -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

#[tokio::test]
async fn test_root_endpoint() {
    // Arrange: Create test database and app
    let database = create_test_database().await;
    let key_manager = Arc::new(Box::new(FileKeyManager::new().unwrap()) as Box<dyn KeyManager>);

    let state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager,
        signer_handlers: None,
    });

    // Set global state for routes that use it
    keycast_api::state::KEYCAST_STATE.set(state.clone()).ok();

    let app = keycast_api::api::http::routes::routes(database.pool.clone(), state);

    // Act: Make request to root endpoint (landing page)
    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("host", "localhost")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    // Assert: Should return 200 OK
    assert_eq!(response.status(), StatusCode::OK);

    println!("✅ Root endpoint integration test passed");
}

#[tokio::test]
async fn test_register_user_endpoint() {
    // Arrange: Create test database and app
    let database = create_test_database().await;
    let key_manager = Arc::new(Box::new(FileKeyManager::new().unwrap()) as Box<dyn KeyManager>);

    let state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager,
        signer_handlers: None,
    });

    keycast_api::state::KEYCAST_STATE.set(state.clone()).ok();

    let app = keycast_api::api::http::routes::routes(database.pool.clone(), state);

    // Act: Register new user
    let register_request = json!({
        "email": "test@example.com",
        "password": "secure_password_123"
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/auth/register")
                .method("POST")
                .header("content-type", "application/json")
                .header("host", "localhost")
                .body(Body::from(serde_json::to_string(&register_request).unwrap()))
                .unwrap()
        )
        .await
        .unwrap();

    // Assert: Should return 200 with token
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    if status != StatusCode::OK {
        let body_str = String::from_utf8_lossy(&body);
        eprintln!("Registration failed with status {}: {}", status, body_str);
    }
    assert_eq!(status, StatusCode::OK);

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["token"].is_string(), "Response should include JWT token");
    assert!(json["pubkey"].is_string(), "Response should include user pubkey");

    println!("✅ User registration integration test passed");
}

#[tokio::test]
async fn test_sign_event_endpoint_slow_path() {
    // Arrange: Create user with personal keys (slow path)
    let database = create_test_database().await;
    let tenant_id = get_localhost_tenant_id(&database.pool).await;
    let key_manager = FileKeyManager::new().unwrap();

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();
    let user_secret = user_keys.secret_key().to_secret_hex();

    // Encrypt and store user keys
    let encrypted_secret = key_manager.encrypt(user_secret.as_bytes()).await.unwrap();

    // Insert user into database with current timestamp
    sqlx::query("INSERT INTO users (public_key, tenant_id, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))")
        .bind(&user_pubkey)
        .bind(tenant_id)
        .execute(&database.pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO personal_keys (user_public_key, encrypted_secret_key, bunker_secret, tenant_id) VALUES (?, ?, ?, ?)")
        .bind(&user_pubkey)
        .bind(&encrypted_secret)
        .bind(generate_test_bunker_secret())
        .bind(tenant_id)
        .execute(&database.pool)
        .await
        .unwrap();

    // Create app state WITHOUT signer handlers (slow path)
    let state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager: Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
        signer_handlers: None,
    });

    keycast_api::state::KEYCAST_STATE.set(state.clone()).ok();

    let app = keycast_api::api::http::routes::routes(database.pool.clone(), state);

    // Create unsigned event
    let unsigned = UnsignedEvent::new(
        user_keys.public_key(),
        Timestamp::now(),
        Kind::TextNote,
        vec![],
        "Integration test message"
    );

    let sign_request = json!({
        "event": unsigned
    });

    // Create JWT token for authentication
    let token = create_test_jwt(&user_pubkey);

    // Act: Sign event via HTTP
    let response = app
        .oneshot(
            Request::builder()
                .uri("/user/sign")
                .method("POST")
                .header("content-type", "application/json")
                .header("host", "localhost")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::from(serde_json::to_string(&sign_request).unwrap()))
                .unwrap()
        )
        .await
        .unwrap();

    // Assert: Should return 200 with signed event
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();

    if status != StatusCode::OK {
        let body_str = String::from_utf8_lossy(&body);
        eprintln!("Sign event failed with status {}: {}", status, body_str);
    }
    assert_eq!(status, StatusCode::OK);

    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["signed_event"].is_object(), "Response should include signed event");
    assert!(json["signed_event"]["sig"].is_string(), "Signed event should have signature");

    println!("✅ Sign event (slow path) integration test passed");
}

#[tokio::test]
async fn test_sign_event_requires_authentication() {
    // Arrange: Create database and app
    let database = create_test_database().await;
    let key_manager = Arc::new(Box::new(FileKeyManager::new().unwrap()) as Box<dyn KeyManager>);

    let state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager,
        signer_handlers: None,
    });

    keycast_api::state::KEYCAST_STATE.set(state.clone()).ok();

    let app = keycast_api::api::http::routes::routes(database.pool.clone(), state);

    let user_keys = Keys::generate();
    let unsigned = UnsignedEvent::new(
        user_keys.public_key(),
        Timestamp::now(),
        Kind::TextNote,
        vec![],
        "Test message"
    );

    let sign_request = json!({
        "event": unsigned
    });

    // Act: Try to sign WITHOUT authentication token
    let response = app
        .oneshot(
            Request::builder()
                .uri("/user/sign")
                .method("POST")
                .header("content-type", "application/json")
                .header("host", "localhost")
                // No Authorization header
                .body(Body::from(serde_json::to_string(&sign_request).unwrap()))
                .unwrap()
        )
        .await
        .unwrap();

    // Assert: Should return 401 Unauthorized
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    println!("✅ Authentication requirement integration test passed");
}

#[tokio::test]
async fn test_nostr_discovery_endpoint() {
    // Arrange: Create user in database
    let database = create_test_database().await;
    let tenant_id = get_localhost_tenant_id(&database.pool).await;
    let key_manager = Arc::new(Box::new(FileKeyManager::new().unwrap()) as Box<dyn KeyManager>);

    let user_keys = Keys::generate();
    let user_pubkey = user_keys.public_key().to_hex();

    // Insert user with username
    sqlx::query("INSERT INTO users (public_key, tenant_id, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))")
        .bind(&user_pubkey)
        .bind(tenant_id)
        .execute(&database.pool)
        .await
        .unwrap();

    sqlx::query("UPDATE users SET username = 'testuser' WHERE public_key = ?")
        .bind(&user_pubkey)
        .execute(&database.pool)
        .await
        .unwrap();

    let state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager,
        signer_handlers: None,
    });

    keycast_api::state::KEYCAST_STATE.set(state.clone()).ok();

    let app = keycast_api::api::http::routes::routes(database.pool.clone(), state);

    // Act: Query NIP-05 discovery endpoint
    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/nostr.json?name=testuser")
                .header("host", "localhost")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    // Assert: Should return user's public key
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["names"]["testuser"], user_pubkey);

    println!("✅ Nostr discovery integration test passed");
}

#[tokio::test]
async fn test_concurrent_signing_requests() {
    // Test that multiple concurrent signing requests work correctly
    let database = create_test_database().await;
    let tenant_id = get_localhost_tenant_id(&database.pool).await;
    let key_manager = FileKeyManager::new().unwrap();

    // Create multiple users
    let mut users = vec![];
    for _i in 0..5 {
        let user_keys = Keys::generate();
        let user_pubkey = user_keys.public_key().to_hex();
        let user_secret = user_keys.secret_key().to_secret_hex();
        let encrypted_secret = key_manager.encrypt(user_secret.as_bytes()).await.unwrap();

        sqlx::query("INSERT INTO users (public_key, tenant_id, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))")
            .bind(&user_pubkey)
            .bind(tenant_id)
            .execute(&database.pool)
            .await
            .unwrap();

        sqlx::query("INSERT INTO personal_keys (user_public_key, encrypted_secret_key, bunker_secret, tenant_id) VALUES (?, ?, ?, ?)")
            .bind(&user_pubkey)
            .bind(&encrypted_secret)
            .bind(generate_test_bunker_secret())
            .bind(tenant_id)
            .execute(&database.pool)
            .await
            .unwrap();

        users.push((user_keys, user_pubkey));
    }

    let state = Arc::new(keycast_api::state::KeycastState {
        db: database.pool.clone(),
        key_manager: Arc::new(Box::new(key_manager) as Box<dyn KeyManager>),
        signer_handlers: None,
    });

    keycast_api::state::KEYCAST_STATE.set(state.clone()).ok();

    // Spawn concurrent signing requests
    let mut handles = vec![];
    for (user_keys, user_pubkey) in users {
        let pool = database.pool.clone();
        let state_clone = state.clone();

        let handle = tokio::spawn(async move {
            let app = keycast_api::api::http::routes::routes(pool, state_clone);

            let unsigned = UnsignedEvent::new(
                user_keys.public_key(),
                Timestamp::now(),
                Kind::TextNote,
                vec![],
                "Concurrent test"
            );

            let sign_request = json!({ "event": unsigned });
            let token = create_test_jwt(&user_pubkey);

            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/user/sign")
                        .method("POST")
                        .header("content-type", "application/json")
                        .header("host", "localhost")
                        .header("authorization", format!("Bearer {}", token))
                        .body(Body::from(serde_json::to_string(&sign_request).unwrap()))
                        .unwrap()
                )
                .await
                .unwrap();

            response.status()
        });

        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        let status = handle.await.unwrap();
        assert_eq!(status, StatusCode::OK);
    }

    println!("✅ Concurrent signing requests integration test passed");
}
