// ABOUTME: User profile management endpoints
// ABOUTME: Get and update user profile information

use axum::{
    routing::{get, put},
    Router,
};

pub fn routes() -> Router {
    Router::new()
        .route("/profile", get(get_profile).put(update_profile))
}

// Placeholder handlers
async fn get_profile() -> &'static str {
    "Profile endpoints not yet implemented"
}

async fn update_profile() -> &'static str {
    "Profile update not yet implemented"
}