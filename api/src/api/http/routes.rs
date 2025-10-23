use super::auth_middleware;
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::api::http::{auth, oauth, teams};
use crate::state::KeycastState;
use axum::response::{Html, Json as AxumJson};
use serde_json::Value as JsonValue;

// State wrapper to pass state to auth handlers
#[derive(Clone)]
pub struct AuthState {
    pub state: Arc<KeycastState>,
}

async fn landing_page() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Keycast OAuth Server</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
               max-width: 800px; margin: 50px auto; padding: 20px; background: #1a1a1a; color: #e0e0e0; }
        h1 { color: #bb86fc; }
        h2 { color: #03dac6; margin-top: 30px; }
        a { color: #03dac6; }
        code { background: #2a2a2a; padding: 2px 6px; border-radius: 3px; }
        .endpoint { background: #2a2a2a; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .method { color: #bb86fc; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🔑 Keycast OAuth Server</h1>
    <p>NIP-46 remote signing with OAuth 2.0 authorization</p>

    <h2>Authentication Endpoints</h2>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/auth/register</code><br>
        Register a new user with email/password
    </div>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/auth/login</code><br>
        Login and receive JWT token
    </div>
    <div class="endpoint">
        <span class="method">GET</span> <code>/api/user/bunker</code><br>
        Get personal NIP-46 bunker URL (requires auth)
    </div>

    <h2>OAuth 2.0 Endpoints</h2>
    <div class="endpoint">
        <span class="method">GET</span> <code>/api/oauth/authorize</code><br>
        Authorization request (shows approval page)
    </div>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/oauth/authorize</code><br>
        User approves/denies authorization
    </div>
    <div class="endpoint">
        <span class="method">POST</span> <code>/api/oauth/token</code><br>
        Exchange authorization code for bunker URL
    </div>

    <h2>Test Clients</h2>
    <p>Example OAuth clients available at <a href="http://localhost:8080">localhost:8080</a></p>
</body>
</html>
    "#)
}

/// Build routes with explicit state - the proper way to structure an Axum app
pub fn routes(pool: SqlitePool, state: Arc<KeycastState>) -> Router {
    tracing::debug!("Building routes");

    let auth_state = AuthState {
        state,
    };

    // Landing page
    let root_route = Router::new()
        .route("/", get(landing_page));

    // Public auth routes (no authentication required)
    // Register and login need AuthState, email verification needs SqlitePool
    let register_login_routes = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .with_state(auth_state.clone());

    let email_routes = Router::new()
        .route("/auth/verify-email", post(auth::verify_email))
        .route("/auth/forgot-password", post(auth::forgot_password))
        .route("/auth/reset-password", post(auth::reset_password))
        .with_state(pool.clone());

    // OAuth routes (no authentication required for initial authorize request)
    let oauth_routes = Router::new()
        .route("/oauth/authorize", get(oauth::authorize_get))
        .route("/oauth/authorize", post(oauth::authorize_post))
        .route("/oauth/token", post(oauth::token))
        .route("/oauth/connect", post(oauth::connect_post))
        .with_state(auth_state.clone());

    // nostr-login connect routes (wildcard path to capture nostrconnect:// URI)
    let connect_routes = Router::new()
        .route("/connect/*nostrconnect", get(oauth::connect_get))
        .with_state(auth_state.clone());

    // Fast signing endpoint (needs AuthState for key_manager access)
    let signing_routes = Router::new()
        .route("/user/sign", post(auth::sign_event))
        .with_state(auth_state.clone());

    // Protected user routes (authentication required)
    let user_routes = Router::new()
        .route("/user/bunker", get(auth::get_bunker_url))
        .route("/user/pubkey", get(auth::get_pubkey))
        .route("/user/profile", get(auth::get_profile))
        .route("/user/sessions", get(auth::list_sessions))
        .route("/user/permissions", get(auth::list_permissions))
        .route("/user/sessions/:secret/activity", get(auth::get_session_activity))
        .with_state(pool.clone());

    let profile_update_routes = Router::new()
        .route("/user/profile", post(auth::update_profile))
        .route("/user/sessions/revoke", post(auth::revoke_session))
        .layer(middleware::from_fn(auth_middleware))
        .with_state(pool.clone());

    // Key export routes (needs both pool and key_manager)
    let key_export_routes = Router::new()
        .route("/user/verify-password", post(auth::verify_password_for_export))
        .route("/user/request-key-export", post(auth::request_key_export))
        .route("/user/verify-export-code", post(auth::verify_export_code))
        .with_state(pool.clone())
        .layer(middleware::from_fn(auth_middleware));

    let key_export_final = Router::new()
        .route("/user/export-key", post(auth::export_key))
        .layer(middleware::from_fn(auth_middleware))
        .with_state(auth_state.clone());

    // NIP-05 discovery route (public, no auth required)
    let discovery_route = Router::new()
        .route("/.well-known/nostr.json", get(nostr_discovery_public))
        .with_state(pool.clone());

    // API documentation route (public)
    let docs_route = Router::new()
        .route("/docs/openapi.json", get(openapi_spec));

    // Protected team routes (authentication required)
    let team_routes = Router::new()
        .route("/teams", get(teams::list_teams))
        .route("/teams", post(teams::create_team))
        .route("/teams/:id", get(teams::get_team))
        .route("/teams/:id", put(teams::update_team))
        .route("/teams/:id", delete(teams::delete_team))
        .route("/teams/:id/users", post(teams::add_user))
        .route(
            "/teams/:id/users/:user_public_key",
            delete(teams::remove_user),
        )
        .route("/teams/:id/keys", post(teams::add_key))
        .route("/teams/:id/keys/:pubkey", get(teams::get_key))
        .route("/teams/:id/keys/:pubkey", delete(teams::remove_key))
        .route(
            "/teams/:id/keys/:pubkey/authorizations",
            post(teams::add_authorization),
        )
        .route("/teams/:id/policies", post(teams::add_policy))
        .layer(middleware::from_fn(auth_middleware))
        .with_state(pool);

    // Combine routes
    Router::new()
        .merge(root_route)
        .merge(register_login_routes)
        .merge(email_routes)
        .merge(oauth_routes)
        .merge(connect_routes)
        .merge(signing_routes)
        .merge(user_routes)
        .merge(profile_update_routes)
        .merge(key_export_routes)
        .merge(key_export_final)
        .merge(team_routes)
        .merge(discovery_route)
        .merge(docs_route)
}

/// Serve OpenAPI specification as JSON
async fn openapi_spec() -> AxumJson<JsonValue> {
    let yaml_content = include_str!("../../../openapi.yaml");
    let spec: JsonValue = serde_yaml::from_str(yaml_content)
        .expect("Failed to parse OpenAPI spec");
    AxumJson(spec)
}

/// NIP-05 discovery endpoint for nostr-login integration
/// This should be mounted at root level in main.rs, not under /api
pub async fn nostr_discovery_public(
    tenant: crate::api::tenant::TenantExtractor,
    axum::extract::State(pool): axum::extract::State<SqlitePool>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl axum::response::IntoResponse {
    use axum::http::{header, StatusCode};
    use axum::body::Body;
    use axum::response::Response;

    let tenant_id = tenant.0.id;

    // Check if "name" query parameter is provided
    if let Some(name) = params.get("name") {
        // Look up user by username in this tenant
        let result: Option<(String,)> = sqlx::query_as(
            "SELECT public_key FROM users WHERE username = ?1 AND tenant_id = ?2"
        )
        .bind(name)
        .bind(tenant_id)
        .fetch_optional(&pool)
        .await
        .ok()
        .flatten();

        if let Some((pubkey,)) = result {
            // Return NIP-05 response with user's pubkey
            let response = serde_json::json!({
                "names": {
                    name: pubkey
                }
            });

            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(serde_json::to_string(&response).unwrap()))
                .unwrap();
        }
    }

    // Return default nostr-login discovery info if no name or name not found
    let discovery = serde_json::json!({
        "nip46": {
            "relay": "wss://relay.damus.io",
            "nostrconnect_url": "http://localhost:3000/api/connect/<nostrconnect>"
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(Body::from(serde_json::to_string(&discovery).unwrap()))
        .unwrap()
}
