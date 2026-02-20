// ---------------------------------------------------------------------------
// Authentication middleware
// ---------------------------------------------------------------------------

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::ApiErrorBody;
use crate::state::AppState;

/// Middleware that validates the optional bearer token.
///
/// If the server was started without `--api-key`, all requests are allowed.
/// If `--api-key` was provided, requests must include a matching
/// `Authorization: Bearer <token>` header.
///
/// Uses SHA-256 hash comparison to avoid timing side-channels on token length.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ApiErrorBody>)> {
    let Some(ref expected_hash) = state.api_key_hash else {
        return Ok(next.run(request).await);
    };

    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            // Hash the provided token and compare against the stored hash
            // using constant-time comparison to avoid timing side-channels.
            let provided_hash = Sha256::digest(token.as_bytes());
            if bool::from(expected_hash.ct_eq(provided_hash.as_slice())) {
                Ok(next.run(request).await)
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ApiErrorBody {
                        error: "invalid_token".into(),
                        message: "Invalid API key".into(),
                    }),
                ))
            }
        }
        Some(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorBody {
                error: "invalid_scheme".into(),
                message: "Expected 'Bearer <token>' authorization".into(),
            }),
        )),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(ApiErrorBody {
                error: "missing_token".into(),
                message: "Authorization header required".into(),
            }),
        )),
    }
}
