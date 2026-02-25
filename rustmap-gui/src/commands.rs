use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustmap_core::{ScanEngine, ScanEvent};
use rustmap_db::{ScanCheckpoint, ScanSummary};
use rustmap_output::{
    CefFormatter, CsvFormatter, GrepableFormatter, HtmlFormatter, JsonFormatter, LeefFormatter,
    OutputFormatter, StdoutFormatter, XmlFormatter, YamlFormatter,
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

#[derive(Clone, Serialize)]
struct WatchIterationPayload {
    scan_id: String,
    iteration: u64,
    diff: Option<rustmap_db::ScanDiff>,
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
        Some(p) => {
            // Safe truncation: find a char boundary at or before byte 20
            let end = p.floor_char_boundary(20);
            format!("{}...", &p[..end])
        }
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

    // Serialize full GUI config for checkpoint (before into_scan_config consumes it)
    let config_json = serde_json::to_string(&config).unwrap_or_default();
    let original_targets = config.targets.clone();
    let timing_val = config.timing;

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

    // Create checkpoint for resume support
    {
        let store = state.store.lock().await;
        let cp = ScanCheckpoint {
            scan_id: scan_id.clone(),
            created_at: started_at,
            updated_at: started_at,
            command_args: config_json,
            targets: original_targets,
            status: "in_progress".into(),
            completed_hosts: vec![],
            partial_results: vec![],
            total_hosts: initial_hosts_total,
            timing_template: Some(timing_val),
        };
        if let Err(e) = store.create_checkpoint(&cp) {
            eprintln!("warning: failed to create checkpoint: {e}");
        }
    }

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
                    // Update checkpoint per-host for resume support
                    let host_ip = result.host.ip.to_string();
                    {
                        let store = state_clone.store.lock().await;
                        if let Err(e) = store.update_checkpoint(&scan_id, &host_ip, &result) {
                            eprintln!("warning: failed to update checkpoint: {e}");
                        }
                    }

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

                    // Keep a fallback copy in case scripts panic
                    let pre_script_result = if run_scripts {
                        Some(result.clone())
                    } else {
                        None
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
                                // Script task panicked — save the un-scripted
                                // result instead of losing data entirely.
                                eprintln!("warning: script task panicked: {e}");
                                let _ = app.emit(
                                    "scan-error",
                                    ScanErrorPayload {
                                        scan_id: scan_id.clone(),
                                        error: format!("script execution panicked (results saved without scripts): {e}"),
                                    },
                                );
                                // SAFETY: pre_script_result is always Some when run_scripts is true
                                pre_script_result.unwrap()
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
                        // Delete checkpoint on successful completion
                        if let Err(e) = store.delete_checkpoint(&scan_id) {
                            eprintln!("warning: failed to delete checkpoint: {e}");
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
    // Clone the token and drop the lock before cancelling, so the relay
    // task can acquire the lock to clean up when it processes the cancel.
    let token = {
        let running = state.running.lock().await;
        running.get(&scan_id).cloned()
    };
    if let Some(cancel) = token {
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
        "yaml" => Box::new(YamlFormatter),
        "csv" => Box::new(CsvFormatter),
        "html" => Box::new(HtmlFormatter),
        "cef" => Box::new(CefFormatter),
        "leef" => Box::new(LeefFormatter),
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

#[tauri::command]
pub async fn diff_scans(
    state: State<'_, Arc<ScanState>>,
    old_scan_id: String,
    new_scan_id: String,
) -> Result<rustmap_db::ScanDiff, String> {
    let store = state.store.lock().await;
    store
        .diff_scans(&old_scan_id, &new_scan_id)
        .map_err(|e| format!("diff failed: {e}"))
}

#[tauri::command]
pub async fn check_vulns(
    state: State<'_, Arc<ScanState>>,
    scan_id: String,
    min_cvss: Option<f64>,
) -> Result<Vec<rustmap_vuln::HostVulnResult>, String> {
    let store = state.store.lock().await;
    let result = store
        .load_scan(&scan_id)
        .map_err(|e| format!("failed to load scan: {e}"))?
        .ok_or_else(|| format!("scan not found: {scan_id}"))?;
    let mut results = Vec::new();
    for host_result in &result.hosts {
        let open_ports: Vec<_> = host_result
            .ports
            .iter()
            .filter(|p| matches!(p.state, rustmap_types::PortState::Open))
            .cloned()
            .collect();
        if open_ports.is_empty() {
            continue;
        }
        let ip_str = host_result.host.ip.to_string();
        let vuln_result = rustmap_vuln::check_host_vulns(&store, &ip_str, &open_ports, min_cvss);
        if !vuln_result.port_vulns.is_empty() {
            results.push(vuln_result);
        }
    }
    Ok(results)
}

#[tauri::command]
pub async fn seed_vuln_db(state: State<'_, Arc<ScanState>>) -> Result<(), String> {
    let store = state.store.lock().await;
    rustmap_vuln::seed_bundled_cves(&store).map_err(|e| format!("failed to seed CVEs: {e}"))
}

// ----- Checkpoint / Resume commands -----

#[derive(Clone, Serialize)]
pub struct CheckpointInfo {
    pub scan_id: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub total_hosts: usize,
    pub completed_count: usize,
}

#[tauri::command]
pub async fn list_checkpoints(
    state: State<'_, Arc<ScanState>>,
) -> Result<Vec<CheckpointInfo>, String> {
    let store = state.store.lock().await;
    let cps = store
        .list_checkpoints()
        .map_err(|e| format!("failed to list checkpoints: {e}"))?;
    Ok(cps
        .into_iter()
        .map(|cp| CheckpointInfo {
            scan_id: cp.scan_id,
            created_at: cp.created_at,
            updated_at: cp.updated_at,
            total_hosts: cp.total_hosts,
            completed_count: cp.completed_hosts.len(),
        })
        .collect())
}

#[tauri::command]
pub async fn resume_scan(
    app: AppHandle,
    state: State<'_, Arc<ScanState>>,
    scan_id: String,
) -> Result<String, String> {
    // Load checkpoint
    let cp = {
        let store = state.store.lock().await;
        store
            .load_checkpoint(&scan_id)
            .map_err(|e| format!("failed to load checkpoint: {e}"))?
            .ok_or_else(|| format!("no checkpoint found for: {scan_id}"))?
    };

    // Deserialize GuiScanConfig from stored command_args
    let gui_config: GuiScanConfig = serde_json::from_str(&cp.command_args)
        .map_err(|e| format!("failed to parse saved config: {e}"))?;

    // Capture script/geoip fields before consuming config
    let script_enabled = gui_config.script_enabled;
    let script_patterns = gui_config.scripts.clone();
    let script_args_str = gui_config.script_args.clone();
    let custom_script_paths = gui_config.custom_script_paths.clone();
    let geoip_enabled = gui_config.geoip_enabled;

    let mut scan_config = gui_config.into_scan_config().await?;

    // Filter out completed hosts
    let completed_set: std::collections::HashSet<std::net::IpAddr> = cp
        .completed_hosts
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let remaining_count_before = scan_config.targets.len();
    scan_config
        .targets
        .retain(|h| !completed_set.contains(&h.ip));
    let remaining = scan_config.targets.len();

    if remaining == 0 {
        // All hosts already scanned — merge and save
        let store = state.store.lock().await;
        let result = rustmap_types::ScanResult {
            hosts: cp.partial_results,
            total_duration: std::time::Duration::from_millis(
                now_ms().saturating_sub(cp.created_at),
            ),
            scan_type: scan_config.scan_type,
            start_time: Some(
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(cp.created_at),
            ),
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };
        let finished_at = now_ms();
        if let Err(e) = store.save_scan(&scan_id, &result, cp.created_at, finished_at, None) {
            eprintln!("warning: failed to save resumed scan: {e}");
        }
        let _ = store.delete_checkpoint(&scan_id);
        return Ok(scan_id);
    }

    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(64);

    {
        let mut running = state.running.lock().await;
        running.insert(scan_id.clone(), cancel.clone());
    }

    let _ = app.emit(
        "scan-started",
        ScanStartedPayload {
            scan_id: scan_id.clone(),
            hosts_total: remaining_count_before,
        },
    );

    // Emit existing results immediately so the GUI shows progress
    for (i, hr) in cp.partial_results.iter().enumerate() {
        let _ = app.emit(
            "host-result",
            HostResultPayload {
                scan_id: scan_id.clone(),
                index: i,
                result: hr.clone(),
                hosts_completed: i + 1,
                hosts_total: remaining_count_before,
            },
        );
    }

    let _ = app.emit(
        "scan-log",
        ScanLogPayload {
            scan_id: scan_id.clone(),
            message: format!(
                "Resuming scan: {} of {} hosts remaining",
                remaining, remaining_count_before
            ),
        },
    );

    // Spawn the scan for remaining hosts
    let state_clone = state.inner().clone();
    tokio::spawn(async move {
        if let Err(e) = ScanEngine::run_streaming(&scan_config, tx.clone(), cancel).await {
            let _ = tx.send(ScanEvent::Error(e.to_string())).await;
        }
    });

    // Spawn event relay with checkpoint updates and result merging
    let scan_id_relay = scan_id.clone();
    let partial_results = cp.partial_results;
    let created_at = cp.created_at;
    tokio::spawn(async move {
        let scan_id = scan_id_relay;
        while let Some(event) = rx.recv().await {
            match event {
                ScanEvent::DiscoveryComplete { hosts_total } => {
                    let _ = app.emit(
                        "scan-started",
                        ScanStartedPayload {
                            scan_id: scan_id.clone(),
                            hosts_total: hosts_total + partial_results.len(),
                        },
                    );
                }
                ScanEvent::HostResult {
                    index,
                    result,
                    hosts_completed,
                    hosts_total,
                } => {
                    let host_ip = result.host.ip.to_string();
                    {
                        let store = state_clone.store.lock().await;
                        if let Err(e) = store.update_checkpoint(&scan_id, &host_ip, &result) {
                            eprintln!("warning: failed to update checkpoint: {e}");
                        }
                    }

                    let _ = app.emit(
                        "host-result",
                        HostResultPayload {
                            scan_id: scan_id.clone(),
                            index: index + partial_results.len(),
                            result: *result,
                            hosts_completed: hosts_completed + partial_results.len(),
                            hosts_total: hosts_total + partial_results.len(),
                        },
                    );
                }
                ScanEvent::Complete(new_result) => {
                    let mut new_result = *new_result;
                    let finished_at = now_ms();

                    // Merge: checkpoint results + new results (IP dedup)
                    let new_ips: std::collections::HashSet<std::net::IpAddr> =
                        new_result.hosts.iter().map(|h| h.host.ip).collect();
                    let mut merged = new_result.hosts;
                    for prev in &partial_results {
                        if !new_ips.contains(&prev.host.ip) {
                            merged.push(prev.clone());
                        }
                    }
                    let num_services = merged
                        .iter()
                        .flat_map(|h| &h.ports)
                        .filter(|p| {
                            matches!(p.state, rustmap_types::PortState::Open) && p.service.is_some()
                        })
                        .count();
                    new_result.hosts = merged;
                    new_result.num_services = num_services;
                    new_result.total_duration =
                        std::time::Duration::from_millis(finished_at.saturating_sub(created_at));
                    new_result.start_time =
                        Some(std::time::UNIX_EPOCH + std::time::Duration::from_millis(created_at));

                    // Run scripts if enabled
                    let has_scripts =
                        !script_patterns.is_empty() || !custom_script_paths.is_empty();
                    let run_scripts = script_enabled && has_scripts;
                    let emit_log = |app: &AppHandle, scan_id: &str, msg: &str| {
                        let _ = app.emit(
                            "scan-log",
                            ScanLogPayload {
                                scan_id: scan_id.to_string(),
                                message: msg.to_string(),
                            },
                        );
                    };
                    let pre_script_result = if run_scripts {
                        Some(new_result.clone())
                    } else {
                        None
                    };
                    let new_result = if run_scripts {
                        emit_log(&app, &scan_id, "Running scripts...");
                        let patterns = script_patterns.clone();
                        let custom_paths = custom_script_paths.clone();
                        let args_str = script_args_str.clone();
                        let script_config = rustmap_types::ScriptConfig {
                            enabled: true,
                            scripts: patterns,
                            script_args: parse_script_args(args_str.as_deref()),
                        };
                        match tokio::task::spawn_blocking(move || {
                            let mut result = new_result;
                            let dirs = rustmap_script::find_script_dirs();
                            let mut discovery = rustmap_script::ScriptDiscovery::new(dirs);
                            let _ = discovery.discover();
                            let mut resolved = discovery.resolve_scripts(&script_config.scripts);
                            for p in &custom_paths {
                                let path = std::path::Path::new(p);
                                if let Ok(meta) = discovery.parse_file(path) {
                                    resolved.push(meta);
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
                                        error: format!("script execution panicked (results saved without scripts): {e}"),
                                    },
                                );
                                // SAFETY: pre_script_result is always Some when run_scripts is true
                                pre_script_result.unwrap()
                            }
                        }
                    } else {
                        new_result
                    };

                    // GeoIP enrichment
                    let mut result = new_result;
                    if geoip_enabled {
                        emit_log(&app, &scan_id, "GeoIP enrichment...");
                        rustmap_geoip::enrich_auto(&mut result, None).await;
                    }

                    // Save merged result and delete checkpoint
                    emit_log(&app, &scan_id, "Saving to database...");
                    {
                        let store = state_clone.store.lock().await;
                        if let Err(e) =
                            store.save_scan(&scan_id, &result, created_at, finished_at, None)
                        {
                            eprintln!("warning: failed to save resumed scan: {e}");
                        }
                        if let Err(e) = store.delete_checkpoint(&scan_id) {
                            eprintln!("warning: failed to delete checkpoint: {e}");
                        }
                    }

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
pub async fn start_watch(
    app: AppHandle,
    state: State<'_, Arc<ScanState>>,
    config: GuiScanConfig,
) -> Result<String, String> {
    let interval_secs = config.watch_interval_secs;
    let scan_config = config.into_scan_config().await?;

    let watch_id = format!("watch-{}", uuid::Uuid::new_v4());
    let cancel = CancellationToken::new();

    {
        let mut running = state.running.lock().await;
        running.insert(watch_id.clone(), cancel.clone());
    }

    let _ = app.emit(
        "scan-started",
        ScanStartedPayload {
            scan_id: watch_id.clone(),
            hosts_total: scan_config.targets.len(),
        },
    );

    let state_clone = state.inner().clone();
    let watch_id_inner = watch_id.clone();
    tokio::spawn(async move {
        let watch_id = watch_id_inner;
        let mut iteration: u64 = 0;
        let mut prev_scan_id: Option<String> = None;

        loop {
            if cancel.is_cancelled() {
                break;
            }

            let iter_id = format!("{watch_id}-iter{iteration}");
            let started_at = now_ms();

            let _ = app.emit(
                "scan-log",
                ScanLogPayload {
                    scan_id: watch_id.clone(),
                    message: format!("Watch iteration {iteration}..."),
                },
            );

            let scan_result = tokio::select! {
                r = ScanEngine::run(&scan_config) => r,
                () = cancel.cancelled() => break,
            };

            let result = match scan_result {
                Ok(r) => r,
                Err(e) => {
                    let _ = app.emit(
                        "scan-log",
                        ScanLogPayload {
                            scan_id: watch_id.clone(),
                            message: format!("Watch iteration {iteration} failed: {e}"),
                        },
                    );
                    iteration += 1;
                    // Wait before retry
                    tokio::select! {
                        () = cancel.cancelled() => break,
                        () = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {},
                    }
                    continue;
                }
            };

            let finished_at = now_ms();

            // Save to DB
            {
                let store = state_clone.store.lock().await;
                if let Err(e) = store.save_scan(&iter_id, &result, started_at, finished_at, None) {
                    eprintln!("warning: failed to save watch scan: {e}");
                }
            }

            // Compute diff against previous iteration
            let diff = if let Some(prev_id) = &prev_scan_id {
                let store = state_clone.store.lock().await;
                store.diff_scans(prev_id, &iter_id).ok()
            } else {
                None
            };

            // Emit iteration complete
            let _ = app.emit(
                "watch-iteration",
                WatchIterationPayload {
                    scan_id: watch_id.clone(),
                    iteration,
                    diff,
                },
            );

            // On first iteration, also emit the full result so the GUI shows it
            if iteration == 0 {
                let _ = app.emit(
                    "scan-complete",
                    ScanCompletePayload {
                        scan_id: watch_id.clone(),
                        result,
                    },
                );
            }

            // Cleanup policy: keep only the last 10 iterations in the DB
            // to prevent unbounded growth from long-running watch sessions.
            if iteration >= 10 {
                let old_iter_id = format!("{watch_id}-iter{}", iteration - 10);
                let store = state_clone.store.lock().await;
                if let Err(e) = store.delete_scan(&old_iter_id) {
                    eprintln!("warning: failed to clean up old watch iteration: {e}");
                }
            }

            prev_scan_id = Some(iter_id);
            iteration += 1;

            // Sleep until next iteration or cancellation
            tokio::select! {
                () = cancel.cancelled() => break,
                () = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {},
            }
        }

        // Remove from running
        {
            let mut running = state_clone.running.lock().await;
            running.remove(&watch_id);
        }
    });

    Ok(watch_id)
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
        let err = format_scan_result(&result, "binary").unwrap_err();
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
    fn format_yaml_valid() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "yaml").unwrap();
        assert!(
            output.contains("192.168.1.1"),
            "YAML should contain host IP"
        );
    }

    #[test]
    fn format_csv_valid() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "csv").unwrap();
        assert!(output.contains("192.168.1.1"), "CSV should contain host IP");
    }

    #[test]
    fn format_html_valid() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "html").unwrap();
        assert!(
            output.contains("<html") || output.contains("<table"),
            "HTML should contain HTML tags"
        );
    }

    #[test]
    fn format_cef_valid() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "cef").unwrap();
        assert!(!output.is_empty(), "CEF output should not be empty");
    }

    #[test]
    fn format_leef_valid() {
        let result = mock_scan_result();
        let output = format_scan_result(&result, "leef").unwrap();
        assert!(!output.is_empty(), "LEEF output should not be empty");
    }

    #[test]
    fn now_ms_returns_nonzero() {
        assert!(now_ms() > 0);
    }
}
