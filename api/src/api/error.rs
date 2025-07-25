use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use keycast_core::types::team::TeamError;
use keycast_core::types::user::UserError;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Invalid input: {0}")]
    BadRequest(String),

    #[error("Permission denied: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("User error: {0}")]
    User(#[from] UserError),

    #[error("Team error: {0}")]
    Team(#[from] TeamError),
}

impl ApiError {
    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::Database(e) => {
                tracing::error!("Database error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ApiError::Auth(_) => StatusCode::UNAUTHORIZED,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                StatusCode::INTERNAL_SERVER_ERROR
            }
            ApiError::User(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Team(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({
            "error": self.to_string()
        }));

        (status, body).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

impl From<crate::state::StateError> for ApiError {
    fn from(err: crate::state::StateError) -> Self {
        ApiError::Internal(err.to_string())
    }
}
