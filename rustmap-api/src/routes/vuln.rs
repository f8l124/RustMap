// ---------------------------------------------------------------------------
// Vulnerability routes
// ---------------------------------------------------------------------------

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// POST /api/vuln/check — run vulnerability check on stored scan
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct VulnCheckRequest {
    pub scan_id: String,
    pub min_cvss: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct VulnCheckResponse {
    pub results: Vec<rustmap_vuln::HostVulnResult>,
}

pub async fn vuln_check(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VulnCheckRequest>,
) -> Result<Json<VulnCheckResponse>, ApiError> {
    // Validate min_cvss: must be a finite number in the CVSS range [0.0, 10.0]
    if let Some(cvss) = req.min_cvss
        && (!cvss.is_finite() || !(0.0..=10.0).contains(&cvss))
    {
        return Err(ApiError::BadRequest(
            "min_cvss must be a number between 0.0 and 10.0".into(),
        ));
    }

    let store = state.store.lock().await;

    // Seed bundled CVEs if not already done
    rustmap_vuln::seed_bundled_cves(&store)
        .map_err(|e| {
            warn!(error = %e, "failed to seed CVEs");
            ApiError::Internal("failed to initialize vulnerability database".into())
        })?;

    let result = store
        .load_scan(&req.scan_id)
        .map_err(|e| {
            warn!(error = %e, scan_id = %req.scan_id, "database error loading scan for vuln check");
            ApiError::Internal("failed to load scan from database".into())
        })?
        .ok_or_else(|| {
            ApiError::NotFound(format!("scan not found: {}", req.scan_id))
        })?;

    let min_cvss = req.min_cvss;

    let mut results = Vec::new();
    for host in &result.hosts {
        let host_result = rustmap_vuln::check_host_vulns(
            &store,
            &host.host.ip.to_string(),
            &host.ports,
            min_cvss,
        );
        if !host_result.port_vulns.is_empty() {
            results.push(host_result);
        }
    }

    Ok(Json(VulnCheckResponse { results }))
}

// ---------------------------------------------------------------------------
// POST /api/vuln/update — update CVE database
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct VulnUpdateResponse {
    pub total_cves: u64,
    pub updated: bool,
}

pub async fn vuln_update(
    State(state): State<Arc<AppState>>,
) -> Result<Json<VulnUpdateResponse>, ApiError> {
    let store = state.store.lock().await;

    // Seed bundled CVEs
    rustmap_vuln::seed_bundled_cves(&store)
        .map_err(|e| {
            warn!(error = %e, "failed to seed CVEs during update");
            ApiError::Internal("failed to update vulnerability database".into())
        })?;

    let count = store
        .count_cves()
        .map_err(|e| {
            warn!(error = %e, "failed to count CVEs");
            ApiError::Internal("failed to query vulnerability database".into())
        })?;

    info!(total_cves = count, "CVE database updated");

    Ok(Json(VulnUpdateResponse {
        total_cves: count,
        updated: true,
    }))
}
