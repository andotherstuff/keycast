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

// State wrapper to pass state to auth handlers
#[derive(Clone)]
pub struct AuthState {
    pub state: Arc<KeycastState>,
}

/// Build routes with explicit state - the proper way to structure an Axum app
pub fn routes(pool: SqlitePool, state: Arc<KeycastState>) -> Router {
    tracing::debug!("Building routes");

    let auth_state = AuthState {
        state,
    };

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
        .merge(auth_routes)
        .merge(oauth_routes)
        .merge(user_routes)
        .merge(team_routes)
}
