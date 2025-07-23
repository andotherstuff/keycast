// ABOUTME: User authorization management endpoints
// ABOUTME: Create and manage NIP-46 authorizations for apps

use axum::{
    routing::{get, post},
    Router,
};

pub fn routes() -> Router {
    Router::new()
        .route("/", get(list_authorizations).post(create_authorization))
        .route("/:id/bunker", get(get_bunker_url))
}

// Placeholder handlers
async fn list_authorizations() -> &'static str {
    "Authorization endpoints not yet implemented"
}

async fn create_authorization() -> &'static str {
    "Authorization endpoints not yet implemented"
}

async fn get_bunker_url() -> &'static str {
    "Bunker URL endpoint not yet implemented"
}