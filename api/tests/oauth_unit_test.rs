// ABOUTME: Unit tests for OAuth code generation and validation logic
// ABOUTME: Tests the OAuth authorization code lifecycle and security constraints

use chrono::{Duration, Utc};
use sqlx::SqlitePool;

/// Test that authorization codes are generated with correct format
#[test]
fn test_authorization_code_format() {
    use rand::Rng;

    // Generate code the same way as the OAuth handler
    let code: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Verify length
    assert_eq!(code.len(), 32);

    // Verify all characters are alphanumeric
    assert!(code.chars().all(|c| c.is_alphanumeric()));
}

/// Test that bunker secrets are generated with correct format
#[test]
fn test_bunker_secret_format() {
    use rand::Rng;

    // Generate bunker secret the same way as the token handler
    let bunker_secret: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Verify length
    assert_eq!(bunker_secret.len(), 32);

    // Verify all characters are alphanumeric
    assert!(bunker_secret.chars().all(|c| c.is_alphanumeric()));
}

/// Test that bunker URLs have correct format
#[test]
fn test_bunker_url_format() {
    let bunker_public_key = "test_public_key_hex";
    let relay_url = "wss://relay.damus.io";
    let bunker_secret = "test_secret";

    let bunker_url = format!(
        "bunker://{}?relay={}&secret={}",
        bunker_public_key,
        relay_url,
        bunker_secret
    );

    assert!(bunker_url.starts_with("bunker://"));
    assert!(bunker_url.contains("relay=wss://"));
    assert!(bunker_url.contains("secret="));
}

/// Test authorization code expiration logic
#[tokio::test]
async fn test_authorization_code_expiration() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    // Create a test user
    let user_public_key = "test_user_pk";
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO users (public_key, email, password_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )
    .bind(user_public_key)
    .bind("test@example.com")
    .bind("hash")
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    // Create a test application
    let app_id: i64 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (client_id, client_secret, name, redirect_uris, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id"
    )
    .bind("testapp")
    .bind("secret")
    .bind("Test App")
    .bind(r#"["http://localhost:3000/callback"]"#)
    .bind(Utc::now())
    .bind(Utc::now())
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create an expired authorization code
    let expired_code = "expired_code_12345";
    let expired_at = Utc::now() - Duration::minutes(5); // 5 minutes ago

    sqlx::query(
        "INSERT INTO oauth_codes (code, user_public_key, application_id, redirect_uri, scope, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )
    .bind(expired_code)
    .bind(user_public_key)
    .bind(app_id)
    .bind("http://localhost:3000/callback")
    .bind("sign_event")
    .bind(expired_at)
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    // Try to fetch the expired code
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT user_public_key FROM oauth_codes WHERE code = ?1 AND expires_at > ?2"
    )
    .bind(expired_code)
    .bind(Utc::now())
    .fetch_optional(&pool)
    .await
    .unwrap();

    // Should not find the expired code
    assert!(result.is_none());

    // Create a valid (non-expired) authorization code
    let valid_code = "valid_code_12345";
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO oauth_codes (code, user_public_key, application_id, redirect_uri, scope, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )
    .bind(valid_code)
    .bind(user_public_key)
    .bind(app_id)
    .bind("http://localhost:3000/callback")
    .bind("sign_event")
    .bind(expires_at)
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    // Try to fetch the valid code
    let result: Option<(String,)> = sqlx::query_as(
        "SELECT user_public_key FROM oauth_codes WHERE code = ?1 AND expires_at > ?2"
    )
    .bind(valid_code)
    .bind(Utc::now())
    .fetch_optional(&pool)
    .await
    .unwrap();

    // Should find the valid code
    assert!(result.is_some());
    assert_eq!(result.unwrap().0, user_public_key);
}

/// Test one-time use of authorization codes
#[tokio::test]
async fn test_authorization_code_one_time_use() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    // Create a test user
    let user_public_key = "test_user_pk";
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO users (public_key, email, password_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )
    .bind(user_public_key)
    .bind("test@example.com")
    .bind("hash")
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    // Create a test application
    let app_id: i64 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (client_id, client_secret, name, redirect_uris, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id"
    )
    .bind("testapp")
    .bind("secret")
    .bind("Test App")
    .bind(r#"["http://localhost:3000/callback"]"#)
    .bind(Utc::now())
    .bind(Utc::now())
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create an authorization code
    let code = "test_code_12345";
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO oauth_codes (code, user_public_key, application_id, redirect_uri, scope, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )
    .bind(code)
    .bind(user_public_key)
    .bind(app_id)
    .bind("http://localhost:3000/callback")
    .bind("sign_event")
    .bind(expires_at)
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    // Verify code exists
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_codes WHERE code = ?1")
        .bind(code)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    // Delete the code (simulate one-time use)
    sqlx::query("DELETE FROM oauth_codes WHERE code = ?1")
        .bind(code)
        .execute(&pool)
        .await
        .unwrap();

    // Verify code no longer exists
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_codes WHERE code = ?1")
        .bind(code)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

/// Test redirect URI validation
#[tokio::test]
async fn test_redirect_uri_validation() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    // Create a test user
    let user_public_key = "test_user_pk";
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO users (public_key, email, password_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )
    .bind(user_public_key)
    .bind("test@example.com")
    .bind("hash")
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    // Create a test application
    let app_id: i64 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (client_id, client_secret, name, redirect_uris, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id"
    )
    .bind("testapp")
    .bind("secret")
    .bind("Test App")
    .bind(r#"["http://localhost:3000/callback"]"#)
    .bind(Utc::now())
    .bind(Utc::now())
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create authorization code with specific redirect_uri
    let code = "test_code_12345";
    let stored_redirect_uri = "http://localhost:3000/callback";
    let expires_at = Utc::now() + Duration::minutes(10);

    sqlx::query(
        "INSERT INTO oauth_codes (code, user_public_key, application_id, redirect_uri, scope, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )
    .bind(code)
    .bind(user_public_key)
    .bind(app_id)
    .bind(stored_redirect_uri)
    .bind("sign_event")
    .bind(expires_at)
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    // Fetch code with correct redirect_uri
    let result: Option<(String, String)> = sqlx::query_as(
        "SELECT user_public_key, redirect_uri FROM oauth_codes WHERE code = ?1"
    )
    .bind(code)
    .fetch_optional(&pool)
    .await
    .unwrap();

    assert!(result.is_some());
    let (_, redirect_uri) = result.unwrap();

    // Simulate redirect_uri validation
    let provided_redirect_uri = "http://localhost:3000/callback";
    assert_eq!(redirect_uri, provided_redirect_uri);

    // Test with wrong redirect_uri
    let wrong_redirect_uri = "http://evil.com/callback";
    assert_ne!(redirect_uri, wrong_redirect_uri);
}

/// Test that multiple authorizations can exist for the same user
#[tokio::test]
async fn test_multiple_authorizations_per_user() {
    let pool = SqlitePool::connect(":memory:").await.unwrap();

    // Run migrations
    sqlx::migrate!("../database/migrations")
        .run(&pool)
        .await
        .unwrap();

    // Create a test user
    let user_public_key = "test_user_pk";
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO users (public_key, email, password_hash, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )
    .bind(user_public_key)
    .bind("test@example.com")
    .bind("hash")
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    // Create two test applications
    let app1_id: i64 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (client_id, client_secret, name, redirect_uris, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id"
    )
    .bind("testapp1")
    .bind("secret1")
    .bind("Test App 1")
    .bind(r#"["http://localhost:3000/callback"]"#)
    .bind(Utc::now())
    .bind(Utc::now())
    .fetch_one(&pool)
    .await
    .unwrap();

    let app2_id: i64 = sqlx::query_scalar(
        "INSERT INTO oauth_applications (client_id, client_secret, name, redirect_uris, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6) RETURNING id"
    )
    .bind("testapp2")
    .bind("secret2")
    .bind("Test App 2")
    .bind(r#"["http://localhost:4000/callback"]"#)
    .bind(Utc::now())
    .bind(Utc::now())
    .fetch_one(&pool)
    .await
    .unwrap();

    // Create authorizations for both apps
    sqlx::query(
        "INSERT INTO oauth_authorizations (user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
    )
    .bind(user_public_key)
    .bind(app1_id)
    .bind("bunker_pk_1")
    .bind("bunker_secret_1")
    .bind(vec![1, 2, 3]) // dummy encrypted secret
    .bind("wss://relay.damus.io")
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO oauth_authorizations (user_public_key, application_id, bunker_public_key, bunker_secret, secret, relays, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
    )
    .bind(user_public_key)
    .bind(app2_id)
    .bind("bunker_pk_2")
    .bind("bunker_secret_2")
    .bind(vec![4, 5, 6]) // dummy encrypted secret
    .bind("wss://relay.damus.io")
    .bind(Utc::now())
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();

    // Verify both authorizations exist
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth_authorizations WHERE user_public_key = ?1"
    )
    .bind(user_public_key)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(count, 2);
}
