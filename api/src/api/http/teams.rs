// DEPRECATED: This file contains the old team-based authentication endpoints
// These have been replaced by personal authentication endpoints in the users module
// This file is kept for reference during migration but should not be used

use axum::http::StatusCode;

pub async fn list_teams() -> StatusCode {
    StatusCode::GONE // 410 Gone - Feature has been removed
}

pub async fn create_team() -> StatusCode {
    StatusCode::GONE
}

pub async fn get_team() -> StatusCode {
    StatusCode::GONE
}

pub async fn update_team() -> StatusCode {
    StatusCode::GONE
}

pub async fn delete_team() -> StatusCode {
    StatusCode::GONE
}

pub async fn add_user() -> StatusCode {
    StatusCode::GONE
}

pub async fn remove_user() -> StatusCode {
    StatusCode::GONE
}

pub async fn add_key() -> StatusCode {
    StatusCode::GONE
}

pub async fn get_key() -> StatusCode {
    StatusCode::GONE
}

pub async fn remove_key() -> StatusCode {
    StatusCode::GONE
}

pub async fn add_authorization() -> StatusCode {
    StatusCode::GONE
}

pub async fn add_policy() -> StatusCode {
    StatusCode::GONE
}