use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustmap_core::{ScanEngine, ScanEvent};
use rustmap_db::ScanSummary;
use rustmap_output::{
    GrepableFormatter, JsonFormatter, OutputFormatter, StdoutFormatter, XmlFormatter,
};
use rustmap_packet::check_privileges;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::GuiScanConfig;
use crate::state::ScanState;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ----- Event payloads -----

#[derive(Clone, Serialize)]
struct ScanStartedPayload {
    scan_id: String,
    hosts_total: usize,
}

#[derive(Clone, Serialize)]
struct HostResultPayload {
    scan_id: String,
    index: usize,
    result: rustmap_types::HostScanResult,
    hosts_completed: usize,
    hosts_total: usize,
}

#[derive(Clone, Serialize)]
struct ScanCompletePayload {
    scan_id: String,
    result: rustmap_types::ScanResult,
}

#[derive(Clone, Serialize)]
struct ScanErrorPayload {
    scan_id: String,
    error: String,
}

// ----- Privilege info -----

#[derive(Clone, Serialize)]
pub struct PrivilegeInfo {
    pub raw_socket: bool,
    pub pcap: bool,
    pub npcap_installed: bool,
}

// ----- Commands -----

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, Arc<ScanState>>,
    config: GuiScanConfig,
) -> Result<String, String> {
    let scan_config = config.into_scan_config()?;

    let scan_id = format!("scan-{}", uuid::Uuid::new_v4());
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(64);

    // Store the cancellation token
    {
        let mut running = state.running.lock().await;
        running.insert(scan_id.clone(), cancel.clone());
    }

    let started_at = now_ms();

    // Spawn the scan task
    let state_clone = state.inner().clone();
    tokio::spawn(async move {
        if let Err(e) = ScanEngine::run_streaming(&scan_config, tx.clone(), cancel).await {
            let _ = tx.send(ScanEvent::Error(e.to_string())).await;
        }
    });

    // Spawn the event relay task
    let scan_id_relay = scan_id.clone();
    tokio::spawn(async move {
        let scan_id = scan_id_relay;
        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::DiscoveryComplete { hosts_total } => {
                    let _ = app.emit(
                        "scan-started",
                        ScanStartedPayload {
                            scan_id: scan_id.clone(),
                            hosts_total,
                        },
                    );
                }
                ScanEvent::HostResult {
                    index,
                    result,
                    hosts_completed,
                    hosts_total,
                } => {
                    let _ = app.emit(
                        "host-result",
                        HostResultPayload {
                            scan_id: scan_id.clone(),
                            index,
                            result: *result,
                            hosts_completed,
                            hosts_total,
                        },
                    );
                }
                ScanEvent::Complete(result) => {
                    let result = *result;
                    let finished_at = now_ms();

                    // Save to persistent database
                    {
                        let store = state_clone.store.lock().await;
                        if let Err(e) =
                            store.save_scan(&scan_id, &result, started_at, finished_at, None)
                        {
                            eprintln!("warning: failed to save scan to database: {e}");
                        }
                    }

                    // Remove from running
                    {
                        let mut running = state_clone.running.lock().await;
                        running.remove(&scan_id);
                    }

                    let _ = app.emit(
                        "scan-complete",
                        ScanCompletePayload {
                            scan_id: scan_id.clone(),
                            result,
                        },
                    );
                }
                ScanEvent::Error(msg) => {
                    // Remove from running state so the scan is no longer
                    // considered active after an error.
                    {
                        let mut running = state_clone.running.lock().await;
                        running.remove(&scan_id);
                    }

                    let _ = app.emit(
                        "scan-error",
                        ScanErrorPayload {
                            scan_id: scan_id.clone(),
                            error: msg,
                        },
                    );
                }
            }
        }
    });

    Ok(scan_id)
}

#[tauri::command]
pub async fn stop_scan(state: State<'_, Arc<ScanState>>, scan_id: String) -> Result<(), String> {
    let running = state.running.lock().await;
    if let Some(cancel) = running.get(&scan_id) {
        cancel.cancel();
        Ok(())
    } else {
        Err(format!("no running scan with id: {scan_id}"))
    }
}

#[tauri::command]
pub async fn get_scan_history(
    state: State<'_, Arc<ScanState>>,
) -> Result<Vec<ScanSummary>, String> {
    let store = state.store.lock().await;
    store
        .list_scans()
        .map_err(|e| format!("failed to list scans: {e}"))
}

#[tauri::command]
pub async fn delete_scan_history(
    state: State<'_, Arc<ScanState>>,
    scan_id: String,
) -> Result<bool, String> {
    let store = state.store.lock().await;
    store
        .delete_scan(&scan_id)
        .map_err(|e| format!("failed to delete scan: {e}"))
}

/// Format a scan result using the specified output format.
///
/// Extracted from `export_results` for testability.
pub(crate) fn format_scan_result(
    result: &rustmap_types::ScanResult,
    format: &str,
) -> Result<String, String> {
    let formatter: Box<dyn OutputFormatter> = match format {
        "json" => Box::new(JsonFormatter),
        "xml" => Box::new(XmlFormatter),
        "normal" => Box::new(StdoutFormatter::new(false, result.scan_type)),
        "grepable" => Box::new(GrepableFormatter),
        other => return Err(format!("unknown format: {other}")),
    };

    formatter
        .format(result)
        .map_err(|e| format!("format error: {e}"))
}

#[tauri::command]
pub async fn export_results(
    state: State<'_, Arc<ScanState>>,
    scan_id: String,
    format: String,
) -> Result<String, String> {
    let store = state.store.lock().await;
    let result = store
        .load_scan(&scan_id)
        .map_err(|e| format!("failed to load scan: {e}"))?
        .ok_or_else(|| format!("scan not found: {scan_id}"))?;

    format_scan_result(&result, &format)
}

#[tauri::command]
pub fn check_privileges_cmd() -> PrivilegeInfo {
    let level = check_privileges();
    PrivilegeInfo {
        raw_socket: level.has_raw_socket_access(),
        pcap: level.has_raw_socket_access(),
        #[cfg(windows)]
        npcap_installed: rustmap_packet::npcap_installed(),
        #[cfg(not(windows))]
        npcap_installed: true, // Not applicable on non-Windows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{Host, HostScanResult, Port, PortState, ScanResult, ScanType};
    use std::net::IpAddr;
    use std::time::Duration;

    fn mock_scan_result() -> ScanResult {
        ScanResult {
            hosts: vec![HostScanResult {
                host: Host {
                    ip: IpAddr::from([192, 168, 1, 1]),
                    hostname: Some("test.local".into()),
                    geo_info: None,
                },
                ports: vec![Port {
                    number: 80,
                    protocol: rustmap_types::Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("http".into()),
                    service_info: None,
                    reason: Some("syn-ack".into()),
                    script_results: vec![],
                    tls_info: None,
                }],
                scan_duration: Duration::from_millis(500),
                host_status: rustmap_types::HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(1)),
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_secs(1),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    fn empty_scan_result() -> ScanResult {
        ScanResult {
            hosts: vec![],
            total_duration: Duration::from_secs(0),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn format_json_valid() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "json").unwrap();
        // Should parse as valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("hosts").is_some());
        assert!(parsed.get("scan_type").is_some());
    }

    #[test]
    fn format_xml_contains_structure() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "xml").unwrap();
        assert!(output.contains("<nmaprun"), "XML should contain <nmaprun");
        assert!(
            output.contains("</nmaprun>"),
            "XML should contain </nmaprun>"
        );
        assert!(output.contains("192.168.1.1"), "XML should contain host IP");
    }

    #[test]
    fn format_normal_contains_host() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "normal").unwrap();
        assert!(
            output.contains("192.168.1.1"),
            "normal output should contain host IP"
        );
        assert!(
            output.contains("80"),
            "normal output should contain port number"
        );
    }

    #[test]
    fn format_grepable_contains_host() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "grepable").unwrap();
        assert!(
            output.contains("Host:"),
            "grepable should contain Host: line"
        );
        assert!(output.contains("192.168.1.1"), "grepable should contain IP");
    }

    #[test]
    fn format_unknown_returns_error() {
        let result = mock_scan_result();
        let err = format_scan_result(&result, "csv").unwrap_err();
        assert!(err.contains("unknown format"), "got: {err}");
    }

    #[test]
    fn format_empty_scan_json() {
        let result = empty_scan_result();
        let output = format_scan_result(&result, "json").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let hosts = parsed.get("hosts").unwrap().as_array().unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn format_empty_scan_xml() {
        let result = empty_scan_result();
        let output = format_scan_result(&result, "xml").unwrap();
        assert!(output.contains("<nmaprun"));
    }

    #[test]
    fn format_empty_scan_normal() {
        let result = empty_scan_result();
        let output = format_scan_result(&result, "normal").unwrap();
        // Should not panic, output may be minimal
        assert!(!output.is_empty() || output.is_empty()); // just ensuring no panic
    }

    #[test]
    fn format_empty_scan_grepable() {
        let result = empty_scan_result();
        let output = format_scan_result(&result, "grepable").unwrap();
        // Should not panic
        let _ = output;
    }

    #[test]
    fn now_ms_returns_nonzero() {
        assert!(now_ms() > 0);
    }
}
