// ---------------------------------------------------------------------------
// Scan diff route
// ---------------------------------------------------------------------------

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use rustmap_db::ScanDiff;
use tracing::warn;

use crate::error::ApiError;
use crate::state::AppState;

pub async fn diff_scans(
    State(state): State<Arc<AppState>>,
    Path((scan_id, other_id)): Path<(String, String)>,
) -> Result<Json<ScanDiff>, ApiError> {
    let store = state.store.lock().await;
    store
        .diff_scans(&scan_id, &other_id)
        .map(Json)
        .map_err(|e| {
            warn!(error = %e, scan_a = %scan_id, scan_b = %other_id, "diff error");
            ApiError::NotFound("one or both scans not found".into())
        })
}
