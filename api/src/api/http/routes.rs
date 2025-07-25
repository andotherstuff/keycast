use super::auth_middleware;
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use sqlx::SqlitePool;

use crate::api::http::{applications, auth, nip05, teams, users};
use crate::api::http::users::authorization_requests;

pub fn routes(pool: SqlitePool) -> Router {
    tracing::debug!("Building routes");
    
    // Auth routes (no auth middleware required)
    let auth_routes = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::get_current_user))
        .route("/auth/passkey/register", post(auth::register_passkey))
        .route("/auth/passkey/login", post(auth::login_passkey))
        .route("/auth/oauth/:provider", get(auth::oauth_init))
        .route("/auth/oauth/:provider/callback", get(auth::oauth_callback))
        .nest("/auth/requests", authorization_requests::routes())
        .with_state(pool.clone());
    
    // Protected routes (require auth middleware)
    let protected_routes = Router::new()
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
        .with_state(pool.clone());
    
    // NIP-05 routes (includes both public and protected endpoints)
    let nip05_routes = nip05::routes(pool.clone());
    
    // User routes (protected by session auth)
    let user_routes = Router::new()
        .nest("/users", users::routes())
        .with_state(pool.clone());
    
    // Application routes (public and protected)
    let app_routes = Router::new()
        .nest("/applications", applications::routes())
        .with_state(pool.clone());
    
    // Combine routes
    Router::new()
        .merge(auth_routes)
        .merge(protected_routes)
        .merge(nip05_routes)
        .merge(user_routes)
        .merge(app_routes)
}
