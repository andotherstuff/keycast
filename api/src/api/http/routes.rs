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
use axum::response::Html;

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
    let auth_routes = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .with_state(auth_state.clone());

    // OAuth routes (no authentication required for initial authorize request)
    let oauth_routes = Router::new()
        .route("/oauth/authorize", get(oauth::authorize_get))
        .route("/oauth/authorize", post(oauth::authorize_post))
        .route("/oauth/token", post(oauth::token))
        .with_state(auth_state);

    // Protected user routes (authentication required)
    let user_routes = Router::new()
        .route("/user/bunker", get(auth::get_bunker_url))
        .with_state(pool.clone());

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
        .merge(auth_routes)
        .merge(oauth_routes)
        .merge(user_routes)
        .merge(team_routes)
}
