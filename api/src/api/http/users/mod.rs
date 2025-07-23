// ABOUTME: User management API endpoints for personal auth system
// ABOUTME: Handles user profiles, keys, policies, and authorizations

pub mod keys;
pub mod policies;
pub mod authorizations;
pub mod authorization_requests;
pub mod profile;

use axum::Router;

pub fn routes() -> Router {
    Router::new()
        .nest("/keys", keys::routes())
        .nest("/policies", policies::routes())
        .nest("/authorizations", authorizations::routes())
        .merge(profile::routes())
}