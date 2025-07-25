// ABOUTME: User management API endpoints for personal auth system
// ABOUTME: Handles user profiles, keys, policies, and authorizations

pub mod keys;
pub mod policies;
pub mod authorizations;
pub mod authorization_requests;
pub mod profile;

use axum::Router;
use crate::api::http::applications;

pub fn routes() -> Router<sqlx::SqlitePool> {
    Router::new()
        .nest("/keys", keys::routes())
        .nest("/policies", policies::routes())
        .nest("/authorizations", authorizations::routes())
        .nest("/applications", applications::user_app_routes())
        .merge(profile::routes())
}