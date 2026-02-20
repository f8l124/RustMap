// ---------------------------------------------------------------------------
// System routes: health check + privileges
// ---------------------------------------------------------------------------

use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
}

/// Health check endpoint — intentionally minimal to avoid leaking version,
/// uptime, or active scan count to unauthenticated callers.
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

#[derive(Debug, Serialize)]
pub struct PrivilegeInfo {
    pub raw_socket: bool,
    pub npcap_installed: bool,
}

pub async fn get_privileges() -> Json<PrivilegeInfo> {
    let level = rustmap_packet::check_privileges();

    #[cfg(windows)]
    let npcap = rustmap_packet::npcap_installed();
    #[cfg(not(windows))]
    let npcap = false;

    Json(PrivilegeInfo {
        raw_socket: level.has_raw_socket_access(),
        npcap_installed: npcap,
    })
}
