// ---------------------------------------------------------------------------
// Scan CRUD routes
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rustmap_core::ScanEngine;
use rustmap_types::ScanResult;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::ApiScanConfig;
use crate::error::ApiError;
use crate::state::{AppState, ScanStatus, TrackedScan, WsEvent, now_ms};

// ---------------------------------------------------------------------------
// POST /api/scans — start a new scan
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct StartScanResponse {
    pub scan_id: String,
    pub status: String,
}

const MAX_CONCURRENT_SCANS: usize = 10;

/// Minimum interval between scan creation requests (per rate-limit key).
const SCAN_RATE_LIMIT_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(1);

pub async fn start_scan(
    State(state): State<Arc<AppState>>,
    Json(config): Json<ApiScanConfig>,
) -> Result<(StatusCode, Json<StartScanResponse>), ApiError> {
    // Simple rate limiter: reject if a scan was created within the last second.
    // Uses the first target as a rate-limit key, falling back to "_global".
    {
        let rate_key = config
            .targets
            .first()
            .cloned()
            .unwrap_or_else(|| "_global".into());
        let mut rate_map = state.rate_limit_map.lock().await;
        let now = Instant::now();
        if let Some(last) = rate_map.get(&rate_key)
            && now.duration_since(*last) < SCAN_RATE_LIMIT_INTERVAL
        {
            return Err(ApiError::Conflict(
                "rate limit exceeded; wait before creating another scan".into(),
            ));
        }
        rate_map.insert(rate_key, now);
    }

    let scan_config = config
        .into_scan_config()
        .map_err(ApiError::InvalidConfig)?;

    let scan_id = format!("scan-{}", uuid::Uuid::new_v4());
    let started_at = now_ms();

    let (event_tx, _) = broadcast::channel::<Arc<WsEvent>>(256);
    let cancel = CancellationToken::new();

    let tracked = TrackedScan {
        scan_id: scan_id.clone(),
        status: ScanStatus::Running,
        started_at,
        finished_at: None,
        cancel: cancel.clone(),
        event_tx: event_tx.clone(),
    };

    // Atomically check the concurrent scan limit and insert under a single
    // write lock to avoid a TOCTOU race where two requests both pass the
    // count check before either inserts.
    {
        let mut scans = state.scans.write().await;
        let running = scans.values().filter(|s| matches!(s.status, ScanStatus::Running)).count();
        if running >= MAX_CONCURRENT_SCANS {
            return Err(ApiError::Conflict(format!(
                "maximum concurrent scans reached ({MAX_CONCURRENT_SCANS}); stop a running scan first"
            )));
        }
        scans.insert(scan_id.clone(), tracked);
    }

    // Spawn scan engine task
    let (tx, rx) = mpsc::channel(64);
    let cancel_for_engine = cancel.clone();
    tokio::spawn(async move {
        if let Err(e) =
            ScanEngine::run_streaming(&scan_config, tx.clone(), cancel_for_engine).await
        {
            warn!(error = %e, "scan engine error");
            let _ = tx
                .send(rustmap_core::ScanEvent::Error(e.to_string()))
                .await;
        }
    });

    // Spawn relay task
    let state_for_relay = state.clone();
    let scan_id_for_relay = scan_id.clone();
    tokio::spawn(async move {
        relay_scan_events(
            rx,
            event_tx,
            state_for_relay,
            scan_id_for_relay,
            started_at,
        )
        .await;
    });

    info!(scan_id = %scan_id, "scan started");

    Ok((
        StatusCode::CREATED,
        Json(StartScanResponse {
            scan_id,
            status: "running".into(),
        }),
    ))
}

async fn relay_scan_events(
    mut rx: mpsc::Receiver<rustmap_core::ScanEvent>,
    event_tx: broadcast::Sender<Arc<WsEvent>>,
    state: Arc<AppState>,
    scan_id: String,
    started_at: u64,
) {
    while let Some(event) = rx.recv().await {
        let ws_event = match event {
            rustmap_core::ScanEvent::DiscoveryComplete { hosts_total } => {
                WsEvent::DiscoveryComplete { hosts_total }
            }
            rustmap_core::ScanEvent::HostResult {
                index,
                result,
                hosts_completed,
                hosts_total,
            } => WsEvent::HostResult {
                index,
                result,
                hosts_completed,
                hosts_total,
            },
            rustmap_core::ScanEvent::Complete(result) => {
                let finished_at = now_ms();

                // Save to database
                {
                    let store = state.store.lock().await;
                    if let Err(e) = store.save_scan(
                        &scan_id,
                        &result,
                        started_at,
                        finished_at,
                        None,
                    ) {
                        warn!(error = %e, "failed to save scan to database");
                    }
                }

                // Update tracked scan status
                {
                    let mut scans = state.scans.write().await;
                    if let Some(tracked) = scans.get_mut(&scan_id) {
                        tracked.status = ScanStatus::Completed;
                        tracked.finished_at = Some(finished_at);
                    }
                }

                WsEvent::Complete { result }
            }
            rustmap_core::ScanEvent::Error(msg) => {
                // Update status and finished_at
                {
                    let mut scans = state.scans.write().await;
                    if let Some(tracked) = scans.get_mut(&scan_id) {
                        tracked.status = ScanStatus::Error(msg.clone());
                        tracked.finished_at = Some(now_ms());
                    }
                }
                WsEvent::Error { message: msg }
            }
        };

        // Broadcast to all WebSocket subscribers (ignore errors — no receivers is fine)
        let _ = event_tx.send(Arc::new(ws_event));
    }

    // If the channel closed while the scan was still Running, the engine panicked or
    // dropped the sender without sending a terminal event. Mark as error.
    {
        let mut scans = state.scans.write().await;
        if let Some(tracked) = scans.get_mut(&scan_id)
            && matches!(tracked.status, ScanStatus::Running)
        {
            warn!(scan_id = %scan_id, "scan terminated unexpectedly");
            tracked.status =
                ScanStatus::Error("scan terminated unexpectedly".into());
            tracked.finished_at = Some(now_ms());
        }
    }

}

/// Maximum age (in seconds) of a completed scan before it is swept from memory.
const COMPLETED_SCAN_TTL_SECS: u64 = 300;

/// Interval between background sweep runs.
const SWEEP_INTERVAL_SECS: u64 = 60;

/// Spawns a single background task that periodically removes completed/
/// errored/cancelled scans older than `COMPLETED_SCAN_TTL_SECS` from memory.
pub fn spawn_scan_sweep_task(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(SWEEP_INTERVAL_SECS),
        );
        loop {
            interval.tick().await;
            let now = now_ms();
            let mut scans = state.scans.write().await;
            scans.retain(|_id, tracked| {
                if matches!(tracked.status, ScanStatus::Running) {
                    return true; // keep running scans
                }
                match tracked.finished_at {
                    Some(finished) => {
                        let age_secs = now.saturating_sub(finished) / 1000;
                        age_secs < COMPLETED_SCAN_TTL_SECS
                    }
                    None => true, // keep if no finished_at recorded
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// GET /api/scans — list scans
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListScansQuery {
    pub status: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ListScansResponse {
    pub scans: Vec<ScanSummaryResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct ScanSummaryResponse {
    pub scan_id: String,
    pub status: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub scan_type: Option<String>,
    pub num_hosts: Option<usize>,
    pub num_services: Option<usize>,
    pub total_duration_ms: Option<u64>,
}

pub async fn list_scans(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListScansQuery>,
) -> Result<Json<ListScansResponse>, ApiError> {
    const MAX_PAGE_SIZE: usize = 200;
    let limit = params.limit.unwrap_or(50).min(MAX_PAGE_SIZE);
    let offset = params.offset.unwrap_or(0);

    let mut summaries = Vec::new();

    // Get running scans from in-memory state
    {
        let scans = state.scans.read().await;
        for tracked in scans.values() {
            let status_str = match &tracked.status {
                ScanStatus::Running => "running",
                ScanStatus::Completed => "completed",
                ScanStatus::Cancelled => "cancelled",
                ScanStatus::Error(_) => "error",
            };

            if let Some(ref filter) = params.status
                && filter != status_str
            {
                continue;
            }

            summaries.push(ScanSummaryResponse {
                scan_id: tracked.scan_id.clone(),
                status: status_str.into(),
                started_at: tracked.started_at,
                finished_at: tracked.finished_at,
                scan_type: None,
                num_hosts: None,
                num_services: None,
                total_duration_ms: None,
            });
        }
    }

    // Get completed scans from database
    if params.status.as_deref() != Some("running") {
        let store = state.store.lock().await;
        match store.list_scans() {
            Ok(db_scans) => {
                let in_memory_ids: std::collections::HashSet<_> = summaries
                    .iter()
                    .map(|s| s.scan_id.clone())
                    .collect();

                for scan in db_scans {
                    if in_memory_ids.contains(&scan.scan_id) {
                        continue; // Already included from in-memory state
                    }
                    summaries.push(ScanSummaryResponse {
                        scan_id: scan.scan_id,
                        status: "completed".into(),
                        started_at: scan.started_at,
                        finished_at: Some(scan.finished_at),
                        scan_type: Some(scan.scan_type),
                        num_hosts: Some(scan.num_hosts),
                        num_services: Some(scan.num_services),
                        total_duration_ms: Some(scan.total_duration_ms),
                    });
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to list scans from database");
            }
        }
    }

    // Sort by started_at descending
    summaries.sort_by(|a, b| b.started_at.cmp(&a.started_at));

    let total = summaries.len();
    let page: Vec<_> = summaries.into_iter().skip(offset).take(limit).collect();

    Ok(Json(ListScansResponse {
        scans: page,
        total,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/scans/{id} — get scan result
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ScanResultResponse {
    pub scan_id: String,
    pub status: String,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub result: Option<ScanResult>,
}

pub async fn get_scan(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanResultResponse>, ApiError> {
    // Check in-memory state first
    {
        let scans = state.scans.read().await;
        if let Some(tracked) = scans.get(&scan_id) {
            let status_str = match &tracked.status {
                ScanStatus::Running => "running",
                ScanStatus::Completed => "completed",
                ScanStatus::Cancelled => "cancelled",
                ScanStatus::Error(_) => "error",
            };

            // Return immediately for non-completed in-memory scans.
            // Running/Cancelled/Error scans don't have DB results yet.
            // Completed scans fall through to DB lookup for the full result.
            if !matches!(tracked.status, ScanStatus::Completed) {
                return Ok(Json(ScanResultResponse {
                    scan_id: tracked.scan_id.clone(),
                    status: status_str.into(),
                    started_at: tracked.started_at,
                    finished_at: tracked.finished_at,
                    result: None,
                }));
            }
        }
    }

    // Try loading from database
    let store = state.store.lock().await;
    match store.load_scan(&scan_id) {
        Ok(Some(result)) => {
            // Get the summary for metadata
            let summary = store.list_scans().ok().and_then(|scans| {
                scans.into_iter().find(|s| s.scan_id == scan_id)
            });

            Ok(Json(ScanResultResponse {
                scan_id: scan_id.clone(),
                status: "completed".into(),
                started_at: summary
                    .as_ref()
                    .map(|s| s.started_at)
                    .unwrap_or(0),
                finished_at: summary.as_ref().map(|s| s.finished_at),
                result: Some(result),
            }))
        }
        Ok(None) => Err(ApiError::NotFound(format!(
            "scan not found: {scan_id}"
        ))),
        Err(e) => {
            warn!(error = %e, scan_id = %scan_id, "database error loading scan");
            Err(ApiError::Internal(
                "failed to load scan from database".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// DELETE /api/scans/{id} — delete scan
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub deleted: bool,
}

pub async fn delete_scan(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    // Use a single write lock to check status and remove atomically (avoids TOCTOU race)
    {
        let mut scans = state.scans.write().await;
        if let Some(tracked) = scans.get(&scan_id)
            && matches!(tracked.status, ScanStatus::Running)
        {
            return Err(ApiError::Conflict(
                "cannot delete a running scan; stop it first".into(),
            ));
        }
        scans.remove(&scan_id);
    }

    // Delete from database
    let store = state.store.lock().await;
    match store.delete_scan(&scan_id) {
        Ok(true) => Ok(Json(DeleteResponse { deleted: true })),
        Ok(false) => Err(ApiError::NotFound(format!(
            "scan not found: {scan_id}"
        ))),
        Err(e) => {
            warn!(error = %e, scan_id = %scan_id, "database error deleting scan");
            Err(ApiError::Internal(
                "failed to delete scan from database".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/scans/{id}/stop — stop a running scan
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct StopResponse {
    pub scan_id: String,
    pub stopped: bool,
}

pub async fn stop_scan(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> Result<Json<StopResponse>, ApiError> {
    let mut scans = state.scans.write().await;

    let tracked = scans.get_mut(&scan_id).ok_or_else(|| {
        ApiError::NotFound(format!("scan not found: {scan_id}"))
    })?;

    if !matches!(tracked.status, ScanStatus::Running) {
        return Err(ApiError::Conflict(
            "scan is not running".into(),
        ));
    }

    tracked.cancel.cancel();
    tracked.status = ScanStatus::Cancelled;
    tracked.finished_at = Some(now_ms());

    info!(scan_id = %scan_id, "scan stopped");

    Ok(Json(StopResponse {
        scan_id,
        stopped: true,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/scans/{id}/export — export scan result
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    pub format: String,
}

pub async fn export_scan(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
    Query(params): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    let store = state.store.lock().await;
    let result = store
        .load_scan(&scan_id)
        .map_err(|e| {
            warn!(error = %e, scan_id = %scan_id, "database error exporting scan");
            ApiError::Internal("failed to load scan for export".into())
        })?
        .ok_or_else(|| {
            ApiError::NotFound(format!("scan not found: {scan_id}"))
        })?;
    drop(store);

    let (content_type, body) = format_scan_result(&result, &params.format)?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, content_type)],
        body,
    )
        .into_response())
}

fn format_scan_result(
    result: &ScanResult,
    format: &str,
) -> Result<(&'static str, String), ApiError> {
    use rustmap_output::OutputFormatter;

    match format {
        "json" => {
            let formatter = rustmap_output::JsonFormatter;
            let body = formatter
                .format(result)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(("application/json", body))
        }
        "xml" => {
            let formatter = rustmap_output::XmlFormatter;
            let body = formatter
                .format(result)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(("application/xml", body))
        }
        "grepable" => {
            let formatter = rustmap_output::GrepableFormatter;
            let body = formatter
                .format(result)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(("text/plain", body))
        }
        "normal" => {
            let formatter =
                rustmap_output::StdoutFormatter::new(false, result.scan_type);
            let body = formatter
                .format(result)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(("text/plain", body))
        }
        "yaml" => {
            let formatter = rustmap_output::YamlFormatter;
            let body = formatter
                .format(result)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(("application/yaml", body))
        }
        "csv" => {
            let formatter = rustmap_output::CsvFormatter;
            let body = formatter
                .format(result)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(("text/csv", body))
        }
        other => Err(ApiError::BadRequest(format!(
            "unknown export format: {other}; supported: json, xml, grepable, normal, yaml, csv"
        ))),
    }
}
