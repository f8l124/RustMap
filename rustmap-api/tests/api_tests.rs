// ---------------------------------------------------------------------------
// Integration tests for the REST API
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use rustmap_api::state::AppState;
use rustmap_types::{
    DetectionMethod, Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanResult,
    ScanType, ServiceInfo,
};

fn test_state() -> Arc<AppState> {
    Arc::new(AppState::new_in_memory(None))
}

fn test_state_with_key(key: &str) -> Arc<AppState> {
    Arc::new(AppState::new_in_memory(Some(key.to_string())))
}

fn minimal_scan_result() -> ScanResult {
    ScanResult {
        hosts: vec![],
        scan_type: ScanType::TcpConnect,
        total_duration: Duration::from_millis(100),
        start_time: None,
        command_args: Some("rustmap 127.0.0.1".into()),
        num_services: 0,
        pre_script_results: vec![],
        post_script_results: vec![],
    }
}

fn scan_result_with_host() -> ScanResult {
    ScanResult {
        hosts: vec![HostScanResult {
            host: Host {
                ip: "127.0.0.1".parse().unwrap(),
                hostname: Some("localhost".into()),
                geo_info: None,
            },
            host_status: HostStatus::Up,
            ports: vec![Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("http".into()),
                service_info: Some(ServiceInfo {
                    name: "http".into(),
                    product: None,
                    version: None,
                    info: None,
                    method: DetectionMethod::Probe,
                }),
                reason: None,
                script_results: vec![],
                tls_info: None,
            }],
            scan_duration: Duration::from_millis(50),
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: None,
            timing_snapshot: None,
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        }],
        scan_type: ScanType::TcpConnect,
        total_duration: Duration::from_millis(500),
        start_time: None,
        command_args: Some("rustmap 127.0.0.1".into()),
        num_services: 1,
        pre_script_results: vec![],
        post_script_results: vec![],
    }
}

async fn parse_json(body: Body) -> serde_json::Value {
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_check_returns_ok() {
    let state = test_state();
    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/system/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["status"], "ok");
    // Health endpoint intentionally minimal — no version, uptime, or active scans
    assert!(json.get("version").is_none());
    assert!(json.get("active_scans").is_none());
}

// ---------------------------------------------------------------------------
// Privileges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_privileges_returns_info() {
    let state = test_state();
    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/system/privileges")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = parse_json(resp.into_body()).await;
    assert!(json["raw_socket"].is_boolean());
    assert!(json["npcap_installed"].is_boolean());
}

// ---------------------------------------------------------------------------
// List scans
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_scans_empty() {
    let state = test_state();
    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans").body(Body::empty()).unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["scans"].as_array().unwrap().len(), 0);
    assert_eq!(json["total"], 0);
}

// ---------------------------------------------------------------------------
// Get scan (not found)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_scan_not_found_404() {
    let state = test_state();
    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans/nonexistent-id")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["error"], "not_found");
}

// ---------------------------------------------------------------------------
// Delete scan (not found)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_delete_scan_not_found_404() {
    let state = test_state();
    let app = rustmap_api::build_router(state);

    let req = Request::delete("/api/scans/nonexistent-id")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["error"], "not_found");
}

// ---------------------------------------------------------------------------
// Stop scan (not found)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_stop_scan_not_found_404() {
    let state = test_state();
    let app = rustmap_api::build_router(state);

    let req = Request::post("/api/scans/nonexistent-id/stop")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Get scan from DB (saved scan)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_scan_from_database() {
    let state = test_state();
    let result = scan_result_with_host();

    // Save a scan directly to the DB
    {
        let store = state.store.lock().await;
        store
            .save_scan("scan-test-1", &result, 1000, 2000, None)
            .unwrap();
    }

    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans/scan-test-1")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["scan_id"], "scan-test-1");
    assert_eq!(json["status"], "completed");
    assert!(json["result"].is_object());
    assert_eq!(json["result"]["hosts"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// List scans from DB
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_list_scans_from_database() {
    let state = test_state();
    let result = minimal_scan_result();

    {
        let store = state.store.lock().await;
        store
            .save_scan("scan-a", &result, 1000, 2000, None)
            .unwrap();
        store
            .save_scan("scan-b", &result, 3000, 4000, None)
            .unwrap();
    }

    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans").body(Body::empty()).unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["total"], 2);
    let scans = json["scans"].as_array().unwrap();
    assert_eq!(scans.len(), 2);
    // Should be sorted by started_at descending
    assert!(scans[0]["started_at"].as_u64() >= scans[1]["started_at"].as_u64());
}

// ---------------------------------------------------------------------------
// Export scan formats
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_export_scan_json() {
    let state = test_state();
    let result = scan_result_with_host();

    {
        let store = state.store.lock().await;
        store
            .save_scan("scan-export", &result, 1000, 2000, None)
            .unwrap();
    }

    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans/scan-export/export?format=json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body.is_object());
}

#[tokio::test]
async fn test_export_scan_xml() {
    let state = test_state();
    let result = scan_result_with_host();

    {
        let store = state.store.lock().await;
        store
            .save_scan("scan-xml", &result, 1000, 2000, None)
            .unwrap();
    }

    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans/scan-xml/export?format=xml")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/xml"
    );

    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(body.contains("<?xml"));
}

#[tokio::test]
async fn test_export_scan_unknown_format_400() {
    let state = test_state();
    let result = minimal_scan_result();

    {
        let store = state.store.lock().await;
        store
            .save_scan("scan-bad-fmt", &result, 1000, 2000, None)
            .unwrap();
    }

    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans/scan-bad-fmt/export?format=msgpack")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auth_rejects_without_token() {
    let state = test_state_with_key("secret123");
    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans").body(Body::empty()).unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["error"], "missing_token");
}

#[tokio::test]
async fn test_auth_rejects_wrong_token() {
    let state = test_state_with_key("secret123");
    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans")
        .header("Authorization", "Bearer wrong-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["error"], "invalid_token");
}

#[tokio::test]
async fn test_auth_accepts_correct_token() {
    let state = test_state_with_key("secret123");
    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans")
        .header("Authorization", "Bearer secret123")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_health_bypasses_auth() {
    let state = test_state_with_key("secret123");
    let app = rustmap_api::build_router(state);

    // Health check should NOT require auth
    let req = Request::get("/api/system/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Diff scans (not found)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_diff_scans_missing_returns_empty_diff() {
    let state = test_state();
    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans/scan-a/diff/scan-b")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // diff_scans returns an empty diff when scans don't exist (no error)
    assert_eq!(resp.status(), StatusCode::OK);

    let json = parse_json(resp.into_body()).await;
    assert!(json.is_object());
}

// ---------------------------------------------------------------------------
// Diff scans (success)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_diff_scans_success() {
    let state = test_state();

    let result1 = scan_result_with_host();
    let result2 = minimal_scan_result();

    {
        let store = state.store.lock().await;
        store
            .save_scan("scan-diff-1", &result1, 1000, 2000, None)
            .unwrap();
        store
            .save_scan("scan-diff-2", &result2, 3000, 4000, None)
            .unwrap();
    }

    let app = rustmap_api::build_router(state);

    let req = Request::get("/api/scans/scan-diff-1/diff/scan-diff-2")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = parse_json(resp.into_body()).await;
    assert!(json.is_object());
}

// ---------------------------------------------------------------------------
// Vuln update endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_vuln_update_returns_count() {
    let state = test_state();
    let app = rustmap_api::build_router(state);

    let req = Request::post("/api/vuln/update")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = parse_json(resp.into_body()).await;
    assert_eq!(json["updated"], true);
    assert!(json["total_cves"].as_u64().unwrap() > 0);
}
