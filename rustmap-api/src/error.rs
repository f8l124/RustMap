// ---------------------------------------------------------------------------
// API error types
// ---------------------------------------------------------------------------

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub error: String,
    pub message: String,
}

#[derive(Debug)]
pub enum ApiError {
    /// 400 Bad Request — invalid input.
    BadRequest(String),
    /// 401 Unauthorized — missing or invalid token.
    Unauthorized(String),
    /// 404 Not Found — scan or resource not found.
    NotFound(String),
    /// 409 Conflict — operation not valid in current state.
    Conflict(String),
    /// 422 Unprocessable Entity — valid JSON but invalid semantics.
    InvalidConfig(String),
    /// 500 Internal Server Error.
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_key, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
            ApiError::InvalidConfig(msg) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "invalid_config", msg)
            }
            ApiError::Internal(msg) => {
                // Log the real error server-side, return a generic message to
                // the client to avoid leaking internal details.
                tracing::error!(details = %msg, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".to_string(),
                )
            }
        };

        (
            status,
            Json(ApiErrorBody {
                error: error_key.into(),
                message,
            }),
        )
            .into_response()
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::BadRequest(msg) => write!(f, "bad request: {msg}"),
            ApiError::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
            ApiError::NotFound(msg) => write!(f, "not found: {msg}"),
            ApiError::Conflict(msg) => write!(f, "conflict: {msg}"),
            ApiError::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            ApiError::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}
