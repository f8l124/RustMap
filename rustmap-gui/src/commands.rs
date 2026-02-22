use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustmap_core::{ScanEngine, ScanEvent};
use rustmap_db::ScanSummary;
use rustmap_output::{
    GrepableFormatter, JsonFormatter, OutputFormatter, StdoutFormatter, XmlFormatter,
};
use rustmap_packet::check_privileges;
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Serialize)]
struct ScanLogPayload {
    scan_id: String,
    message: String,
}

// ----- Privilege info -----

#[derive(Clone, Serialize)]
pub struct PrivilegeInfo {
    pub raw_socket: bool,
    pub pcap: bool,
    pub npcap_installed: bool,
}

// ----- Script info -----

#[derive(Clone, Serialize)]
pub struct ScriptInfo {
    id: String,
    description: String,
    categories: Vec<String>,
    language: String,
}

// ----- Preset info -----

#[derive(Clone, Serialize, Deserialize)]
pub struct PresetInfo {
    pub name: String,
    pub targets: String,
    pub scan_type: String,
    pub port_summary: String,
}

// ----- Helpers -----

fn gui_presets_dir() -> std::path::PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_else(|_| {
        std::env::var("HOME")
            .map(|h| format!("{h}/.config"))
            .unwrap_or_else(|_| ".".to_string())
    });
    std::path::PathBuf::from(base)
        .join("rustmap")
        .join("gui-presets")
}

fn validate_preset_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("preset name cannot be empty".into());
    }
    if name.len() > 100 {
        return Err("preset name too long (max 100 characters)".into());
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ' ')
    {
        return Err(
            "preset name may only contain letters, numbers, hyphens, underscores, and spaces"
                .into(),
        );
    }
    if name.contains("..") {
        return Err("preset name cannot contain '..'".into());
    }
    Ok(())
}

fn preset_filename(name: &str) -> String {
    name.replace(' ', "_")
}

fn summarize_config(config: &GuiScanConfig) -> PresetInfo {
    let targets = if config.targets.len() == 1 {
        config.targets[0].clone()
    } else if config.targets.is_empty() {
        "no targets".to_string()
    } else {
        format!("{} targets", config.targets.len())
    };
    let port_summary = match &config.ports {
        Some(p) if p.len() <= 30 => p.clone(),
        Some(p) => format!("{}...", &p[..20]),
        None => "top 1000".to_string(),
    };
    let scan_type = match config.scan_type.as_str() {
        "T" => "TCP Connect",
        "S" => "TCP SYN",
        "U" => "UDP",
        "F" => "TCP FIN",
        "N" => "TCP Null",
        "X" => "TCP Xmas",
        "A" => "TCP ACK",
        "W" => "TCP Window",
        "M" => "TCP Maimon",
        "Z" => "SCTP Init",
        other => other,
    };
    PresetInfo {
        name: String::new(),
        targets,
        scan_type: scan_type.to_string(),
        port_summary,
    }
}

/// Parse script args string "key1=val1,key2=val2" into key-value pairs.
fn parse_script_args(s: Option<&str>) -> Vec<(String, String)> {
    s.map(|s| {
        s.split(',')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?.trim();
                let val = parts.next()?.trim();
                if key.is_empty() {
                    None
                } else {
                    Some((key.to_string(), val.to_string()))
                }
            })
            .collect()
    })
    .unwrap_or_default()
}

// ----- Commands -----

fn script_meta_to_info(s: &rustmap_script::ScriptMeta) -> ScriptInfo {
    ScriptInfo {
        id: s.id.clone(),
        description: s.description.clone(),
        categories: s.categories.iter().map(|c| c.to_string()).collect(),
        language: match s.language {
            rustmap_script::ScriptLanguage::Lua => "lua".to_string(),
            rustmap_script::ScriptLanguage::Python => "python".to_string(),
            #[allow(unreachable_patterns)]
            _ => "unknown".to_string(),
        },
    }
}

#[tauri::command]
pub async fn list_scripts() -> Result<Vec<ScriptInfo>, String> {
    let dirs = rustmap_script::find_script_dirs();
    let mut discovery = rustmap_script::ScriptDiscovery::new(dirs);
    let scripts = discovery.discover().map_err(|e| e.to_string())?;
    Ok(scripts.iter().map(script_meta_to_info).collect())
}

/// Return the first existing script directory (for the file-picker default path).
#[tauri::command]
pub async fn get_scripts_dir() -> Option<String> {
    // Runtime search (next to exe, CWD/scripts, CWD/rustmap-script/scripts)
    if let Some(dir) = rustmap_script::find_script_dirs().into_iter().next() {
        return Some(dir.to_string_lossy().into_owned());
    }
    // Development fallback: resolve from workspace root at compile time.
    // CARGO_MANIFEST_DIR points to rustmap-gui/; the scripts live in
    // the sibling crate rustmap-script/scripts/.
    let workspace_scripts = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("rustmap-script").join("scripts"));
    workspace_scripts
        .filter(|p| p.is_dir())
        .map(|p| p.to_string_lossy().into_owned())
}

/// Parse metadata from user-selected script files on disk.
#[tauri::command]
pub async fn parse_custom_scripts(paths: Vec<String>) -> Result<Vec<ScriptInfo>, String> {
    let discovery = rustmap_script::ScriptDiscovery::new(vec![]);
    let mut infos = Vec::new();
    for p in &paths {
        let path = std::path::Path::new(p);
        match discovery.parse_file(path) {
            Ok(meta) => infos.push(script_meta_to_info(&meta)),
            Err(e) => return Err(format!("failed to parse {}: {e}", path.display())),
        }
    }
    Ok(infos)
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, Arc<ScanState>>,
    config: GuiScanConfig,
) -> Result<String, String> {
    // Capture config fields before consuming config
    let script_enabled = config.script_enabled;
    let script_patterns = config.scripts.clone();
    let script_args_str = config.script_args.clone();
    let custom_script_paths = config.custom_script_paths.clone();
    let geoip_enabled = config.geoip_enabled;

    let scan_config = config.into_scan_config().await?;
    let initial_hosts_total = scan_config.targets.len();

    let scan_id = format!("scan-{}", uuid::Uuid::new_v4());
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(64);

    // Store the cancellation token
    {
        let mut running = state.running.lock().await;
        running.insert(scan_id.clone(), cancel.clone());
    }

    let started_at = now_ms();

    // Emit initial scan-started immediately so the GUI shows 0/N instead of 0/0
    // while discovery is still running. The DiscoveryComplete event will update
    // the count if it changes (e.g. CIDR expansion was already done in config).
    let _ = app.emit(
        "scan-started",
        ScanStartedPayload {
            scan_id: scan_id.clone(),
            hosts_total: initial_hosts_total,
        },
    );

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

                    // Run scripts if enabled (via spawn_blocking since ScriptRunner is sync)
                    let has_scripts =
                        !script_patterns.is_empty() || !custom_script_paths.is_empty();
                    let run_scripts = script_enabled && has_scripts;
                    let patterns = script_patterns.clone();
                    let custom_paths = custom_script_paths.clone();
                    let args_str = script_args_str.clone();
                    let emit_log = |app: &AppHandle, scan_id: &str, msg: &str| {
                        let _ = app.emit(
                            "scan-log",
                            ScanLogPayload {
                                scan_id: scan_id.to_string(),
                                message: msg.to_string(),
                            },
                        );
                    };

                    let result = if run_scripts {
                        emit_log(&app, &scan_id, "Running scripts...");
                        let script_args = parse_script_args(args_str.as_deref());
                        let script_config = rustmap_types::ScriptConfig {
                            enabled: true,
                            scripts: patterns,
                            script_args,
                        };
                        match tokio::task::spawn_blocking(move || {
                            let mut result = result;
                            let dirs = rustmap_script::find_script_dirs();
                            let mut discovery = rustmap_script::ScriptDiscovery::new(dirs);
                            let _ = discovery.discover();

                            let mut resolved = discovery.resolve_scripts(&script_config.scripts);

                            // Append user-browsed custom scripts
                            for p in &custom_paths {
                                let path = std::path::Path::new(p);
                                match discovery.parse_file(path) {
                                    Ok(meta) => resolved.push(meta),
                                    Err(e) => {
                                        eprintln!(
                                            "warning: skipping custom script {}: {e}",
                                            path.display()
                                        );
                                    }
                                }
                            }

                            if !resolved.is_empty() {
                                let runner =
                                    rustmap_script::ScriptRunner::new(script_config, resolved);
                                if let Err(e) = runner.run_all(&mut result) {
                                    eprintln!("warning: script execution error: {e}");
                                }
                                rustmap_detect::enrich_os_from_scripts(&mut result);
                            }
                            result
                        })
                        .await
                        {
                            Ok(r) => r,
                            Err(e) => {
                                eprintln!("warning: script task panicked: {e}");
                                let _ = app.emit(
                                    "scan-error",
                                    ScanErrorPayload {
                                        scan_id: scan_id.clone(),
                                        error: format!("script execution panicked: {e}"),
                                    },
                                );
                                continue;
                            }
                        }
                    } else {
                        result
                    };

                    // GeoIP enrichment
                    let mut result = result;
                    if geoip_enabled {
                        emit_log(&app, &scan_id, "GeoIP enrichment...");
                        rustmap_geoip::enrich_auto(&mut result, None).await;
                    }

                    // Save to persistent database (includes script results)
                    emit_log(&app, &scan_id, "Saving to database...");
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
                ScanEvent::Log(msg) => {
                    let _ = app.emit(
                        "scan-log",
                        ScanLogPayload {
                            scan_id: scan_id.clone(),
                            message: msg,
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

#[tauri::command]
pub async fn clear_scan_history(state: State<'_, Arc<ScanState>>) -> Result<usize, String> {
    let store = state.store.lock().await;
    store
        .clear_all_scans()
        .map_err(|e| format!("failed to clear history: {e}"))
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
pub async fn export_to_file(
    state: State<'_, Arc<ScanState>>,
    scan_id: String,
    format: String,
    path: String,
) -> Result<(), String> {
    let store = state.store.lock().await;
    let result = store
        .load_scan(&scan_id)
        .map_err(|e| format!("failed to load scan: {e}"))?
        .ok_or_else(|| format!("scan not found: {scan_id}"))?;

    let output = format_scan_result(&result, &format)?;
    std::fs::write(&path, output).map_err(|e| format!("failed to write file: {e}"))
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

// ----- Preset commands -----

#[tauri::command]
pub async fn list_presets() -> Result<Vec<PresetInfo>, String> {
    let dir = gui_presets_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("failed to read presets dir: {e}"))?;
    let mut presets = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .replace('_', " ");
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    if let Ok(config) = serde_json::from_str::<GuiScanConfig>(&content) {
                        let mut info = summarize_config(&config);
                        info.name = name;
                        presets.push(info);
                    }
                }
                Err(e) => {
                    eprintln!("warning: skipping preset {}: {e}", path.display());
                }
            }
        }
    }
    presets.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(presets)
}

#[tauri::command]
pub async fn save_preset(name: String, config: GuiScanConfig) -> Result<(), String> {
    validate_preset_name(&name)?;
    let dir = gui_presets_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("failed to create presets directory: {e}"))?;
    let filename = preset_filename(&name);
    let path = dir.join(format!("{filename}.json"));
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("failed to serialize preset: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("failed to save preset: {e}"))
}

#[tauri::command]
pub async fn load_preset(name: String) -> Result<GuiScanConfig, String> {
    validate_preset_name(&name)?;
    let filename = preset_filename(&name);
    let path = gui_presets_dir().join(format!("{filename}.json"));
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("preset '{name}' not found: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("failed to parse preset '{name}': {e}"))
}

#[tauri::command]
pub async fn delete_preset(name: String) -> Result<(), String> {
    validate_preset_name(&name)?;
    let filename = preset_filename(&name);
    let path = gui_presets_dir().join(format!("{filename}.json"));
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("failed to delete preset: {e}"))?;
    }
    Ok(())
}

// ----- Import command -----

#[tauri::command]
pub async fn import_scan_from_file(
    state: State<'_, Arc<ScanState>>,
    path: String,
) -> Result<ScanSummary, String> {
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("failed to read file: {e}"))?;

    let result: rustmap_types::ScanResult = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse scan result (only JSON format is supported): {e}"))?;

    let scan_id = format!("import-{}", uuid::Uuid::new_v4());
    let now = now_ms();

    let started_at = result
        .start_time
        .and_then(|st| st.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(now);
    let finished_at =
        started_at.saturating_add(result.total_duration.as_millis().min(u64::MAX as u128) as u64);

    let store = state.store.lock().await;
    store
        .save_scan(&scan_id, &result, started_at, finished_at, None)
        .map_err(|e| format!("failed to save imported scan: {e}"))?;

    Ok(ScanSummary {
        scan_id,
        started_at,
        finished_at,
        scan_type: format!("{}", result.scan_type),
        num_hosts: result.hosts.len(),
        num_services: result.num_services,
        total_duration_ms: result.total_duration.as_millis().min(u64::MAX as u128) as u64,
        command_args: result.command_args,
    })
}

#[tauri::command]
pub fn get_app_version() -> String {
    option_env!("RUSTMAP_VERSION")
        .unwrap_or(env!("CARGO_PKG_VERSION"))
        .to_string()
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
