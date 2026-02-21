// ---------------------------------------------------------------------------
// Watch / Continuous Mode
// ---------------------------------------------------------------------------
//
// Periodically rescans targets, detects changes, and optionally sends
// webhook notifications or runs shell commands when the network state changes.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use rustmap_core::ScanEngine;
use rustmap_db::{ScanDiff, ScanStore, ServiceChange};
use rustmap_output::{OutputConfig, OutputManager, filter_open_ports};
use rustmap_types::{ScanConfig, ScanType, ScriptConfig};

use crate::{find_script_dirs, save_scan_to_db};

/// Configuration for watch mode.
pub struct WatchConfig {
    pub interval: Duration,
    pub webhook_url: Option<String>,
    pub on_change_cmd: Option<String>,
    pub no_db: bool,
    pub timing: Option<u8>,
}

/// JSON payload sent to webhooks and set as env for on-change commands.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangePayload {
    pub iteration: u64,
    pub scan_id: String,
    pub previous_scan_id: Option<String>,
    pub timestamp: u64,
    pub diff: Option<ScanDiff>,
    pub service_changes: Vec<ServiceChange>,
}

/// Run the watch loop: scan → detect changes → notify → sleep → repeat.
pub async fn run_watch_loop(
    config: ScanConfig,
    output_config: OutputConfig,
    watch_config: WatchConfig,
    script_config: ScriptConfig,
    cancel: CancellationToken,
    additional_scan_types: Vec<ScanType>,
) -> Result<()> {
    let config = Arc::new(config);
    let mut iteration: u64 = 0;
    let mut previous_scan_id: Option<String> = None;

    eprintln!(
        "Watch mode active — scanning every {}s. Press Ctrl+C to stop.",
        watch_config.interval.as_secs()
    );

    loop {
        if cancel.is_cancelled() {
            break;
        }

        eprintln!("\n=== Watch iteration {} ===", iteration);

        let start_time = SystemTime::now();

        // Run the primary scan
        let mut result = match ScanEngine::run(&config).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, iteration, "scan failed in watch mode");
                eprintln!("Warning: scan failed: {e}");
                // Wait and retry
                if wait_or_cancel(&cancel, watch_config.interval).await {
                    break;
                }
                iteration += 1;
                continue;
            }
        };

        // Run additional scan types (e.g., UDP in -sSU)
        for &extra_type in &additional_scan_types {
            let mut extra_config = (*config).clone();
            extra_config.scan_type = extra_type;
            match ScanEngine::run(&extra_config).await {
                Ok(extra_result) => crate::merge_results(&mut result, &extra_result),
                Err(e) => warn!(error = %e, scan_type = ?extra_type, "additional scan failed"),
            }
        }

        // Attach metadata
        let command_args = std::env::args()
            .map(|a| shlex::try_quote(&a).map_or_else(|_| a.clone(), |q| q.into_owned()))
            .collect::<Vec<_>>()
            .join(" ");
        result.start_time = Some(start_time);
        result.command_args = Some(command_args);
        result.num_services = config.ports.len();

        // Run scripts if enabled
        if script_config.enabled {
            run_scripts(&script_config, config.proxy.as_ref(), &mut result);
        }

        // First iteration: full output; subsequent: compact summary only
        if iteration == 0 {
            let display_result = if output_config.open_only {
                filter_open_ports(&result)
            } else {
                result.clone()
            };
            let manager = OutputManager::new(output_config.clone());
            if let Err(e) = manager.run(&display_result) {
                warn!(error = %e, "output error in watch mode");
            }
        } else {
            // Compact summary for subsequent scans
            let open_count: usize = result
                .hosts
                .iter()
                .map(|h| {
                    h.ports
                        .iter()
                        .filter(|p| p.state == rustmap_types::PortState::Open)
                        .count()
                })
                .sum();
            eprintln!(
                "Scanned {} host(s), {} open port(s) in {:.1}s",
                result.hosts.len(),
                open_count,
                result.total_duration.as_secs_f64()
            );
        }

        // Save to database
        let scan_id = if !watch_config.no_db {
            save_scan_to_db(&result, start_time, watch_config.timing)
        } else {
            // Generate an ephemeral ID for the payload
            let ts = start_time
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            Some(format!("watch-{ts}-{iteration}"))
        };

        let current_scan_id = scan_id.unwrap_or_else(|| format!("watch-{iteration}"));

        // Detect changes if we have a previous scan
        if let Some(ref prev_id) = previous_scan_id {
            let (diff, svc_changes) = detect_changes(prev_id, &current_scan_id, &result);

            let has_changes = diff.as_ref().is_some_and(|d| {
                !d.new_hosts.is_empty() || !d.removed_hosts.is_empty() || !d.port_changes.is_empty()
            }) || !svc_changes.is_empty();

            if has_changes {
                let summary = format_change_summary(diff.as_ref(), &svc_changes);
                eprintln!("{summary}");

                let payload = ChangePayload {
                    iteration,
                    scan_id: current_scan_id.clone(),
                    previous_scan_id: previous_scan_id.clone(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    diff,
                    service_changes: svc_changes,
                };

                // Send webhook notification
                if let Some(ref url) = watch_config.webhook_url {
                    send_webhook(url, &payload).await;
                }

                // Execute on-change command
                if let Some(ref cmd) = watch_config.on_change_cmd {
                    exec_on_change(cmd, &payload).await;
                }
            } else {
                eprintln!("No changes detected.");
            }
        }

        previous_scan_id = Some(current_scan_id);
        iteration += 1;

        // Sleep or cancel
        if wait_or_cancel(&cancel, watch_config.interval).await {
            break;
        }
    }

    eprintln!("\nWatch mode stopped after {iteration} iteration(s).");
    Ok(())
}

/// Wait for the interval duration, returning true if cancelled.
async fn wait_or_cancel(cancel: &CancellationToken, interval: Duration) -> bool {
    tokio::select! {
        () = cancel.cancelled() => true,
        () = tokio::time::sleep(interval) => false,
    }
}

/// Run scripts against the scan result (best-effort).
fn run_scripts(
    script_config: &ScriptConfig,
    proxy: Option<&rustmap_types::ProxyConfig>,
    result: &mut rustmap_types::ScanResult,
) {
    use rustmap_script::{ScriptDiscovery, ScriptRunner};

    let script_dirs = find_script_dirs();
    let mut discovery = ScriptDiscovery::new(script_dirs);
    match discovery.discover() {
        Err(e) => warn!(error = %e, "script discovery failed in watch mode"),
        Ok(_) => {
            let scripts = discovery.resolve_scripts(&script_config.scripts);
            if !scripts.is_empty() {
                let runner =
                    ScriptRunner::new(script_config.clone(), scripts).with_proxy(proxy.cloned());
                if let Err(e) = runner.run_all(result) {
                    warn!(error = %e, "script execution error in watch mode");
                }
                rustmap_detect::enrich_os_from_scripts(result);
            }
        }
    }
}

/// Detect changes between previous and current scans using the database.
fn detect_changes(
    prev_id: &str,
    current_id: &str,
    result: &rustmap_types::ScanResult,
) -> (Option<ScanDiff>, Vec<ServiceChange>) {
    let store = match ScanStore::open_default() {
        Ok(s) => s,
        Err(_) => return (None, vec![]),
    };

    let diff = store.diff_scans(prev_id, current_id).ok();

    let mut all_svc_changes = Vec::new();
    for host in &result.hosts {
        let ip = host.host.ip.to_string();
        if let Ok(changes) = store.detect_service_changes(&ip, &host.ports) {
            all_svc_changes.extend(changes);
        }
    }

    (diff, all_svc_changes)
}

/// Format a human-readable change summary.
pub fn format_change_summary(diff: Option<&ScanDiff>, svc_changes: &[ServiceChange]) -> String {
    let mut out = String::from("\n--- Changes Detected ---\n");

    if let Some(diff) = diff {
        for host in &diff.new_hosts {
            out.push_str(&format!("  + New host: {host}\n"));
        }
        for host in &diff.removed_hosts {
            out.push_str(&format!("  - Removed host: {host}\n"));
        }
        for change in &diff.port_changes {
            let old = change.old_state.as_deref().unwrap_or("(none)");
            let new = change.new_state.as_deref().unwrap_or("(removed)");
            out.push_str(&format!(
                "  ~ {}:{}/{}: {} -> {}\n",
                change.ip, change.port, change.protocol, old, new
            ));
        }
    }

    for change in svc_changes {
        let old = change.old_service.as_deref().unwrap_or("(none)");
        let new = change.new_service.as_deref().unwrap_or("(none)");
        out.push_str(&format!(
            "  SERVICE {}:{} -- {} -> {}\n",
            change.ip, change.port, old, new
        ));
    }

    out
}

/// Send a webhook notification (best-effort, logs errors).
#[allow(unused_variables)]
async fn send_webhook(url: &str, payload: &ChangePayload) {
    #[cfg(feature = "watch")]
    {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build();

        let client = match client {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to create HTTP client for webhook");
                return;
            }
        };

        match client.post(url).json(payload).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(
                        status = %resp.status(),
                        url,
                        "webhook returned non-success status"
                    );
                } else {
                    info!(url, "webhook notification sent");
                }
            }
            Err(e) => {
                warn!(error = %e, url, "failed to send webhook notification");
            }
        }
    }

    #[cfg(not(feature = "watch"))]
    {
        warn!("webhook support requires the 'watch' feature (reqwest)");
    }
}

/// Execute the on-change shell command with scan metadata as env vars.
async fn exec_on_change(cmd: &str, payload: &ChangePayload) {
    let json = match serde_json::to_string(payload) {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "failed to serialize change payload");
            return;
        }
    };

    let result = if cfg!(windows) {
        tokio::process::Command::new("cmd")
            .args(["/C", cmd])
            .env("RUSTMAP_CHANGES_JSON", &json)
            .env("RUSTMAP_SCAN_ID", &payload.scan_id)
            .env("RUSTMAP_ITERATION", payload.iteration.to_string())
            .output()
            .await
    } else {
        tokio::process::Command::new("sh")
            .args(["-c", cmd])
            .env("RUSTMAP_CHANGES_JSON", &json)
            .env("RUSTMAP_SCAN_ID", &payload.scan_id)
            .env("RUSTMAP_ITERATION", payload.iteration.to_string())
            .output()
            .await
    };

    match result {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(
                    cmd,
                    exit_code = output.status.code(),
                    stderr = %stderr,
                    "on-change command failed"
                );
            } else {
                info!(cmd, "on-change command executed");
            }
        }
        Err(e) => {
            warn!(error = %e, cmd, "failed to execute on-change command");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_db::{PortChange, ServiceChangeType};

    #[test]
    fn change_payload_serializes() {
        let payload = ChangePayload {
            iteration: 3,
            scan_id: "scan-123".into(),
            previous_scan_id: Some("scan-122".into()),
            timestamp: 1700000000,
            diff: None,
            service_changes: vec![],
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"iteration\":3"));
        assert!(json.contains("\"scan_id\":\"scan-123\""));
    }

    #[test]
    fn format_change_summary_no_changes() {
        let diff = ScanDiff {
            old_scan_id: "a".into(),
            new_scan_id: "b".into(),
            new_hosts: vec![],
            removed_hosts: vec![],
            port_changes: vec![],
        };
        let summary = format_change_summary(Some(&diff), &[]);
        assert!(summary.contains("Changes Detected"));
        // No actual change lines beyond the header
        let lines: Vec<&str> = summary.lines().filter(|l| l.starts_with("  ")).collect();
        assert!(lines.is_empty());
    }

    #[test]
    fn format_change_summary_with_changes() {
        let diff = ScanDiff {
            old_scan_id: "a".into(),
            new_scan_id: "b".into(),
            new_hosts: vec!["10.0.0.5".into()],
            removed_hosts: vec!["10.0.0.9".into()],
            port_changes: vec![PortChange {
                ip: "10.0.0.1".into(),
                port: 80,
                protocol: "tcp".into(),
                old_state: Some("closed".into()),
                new_state: Some("open".into()),
            }],
        };
        let summary = format_change_summary(Some(&diff), &[]);
        assert!(summary.contains("+ New host: 10.0.0.5"));
        assert!(summary.contains("- Removed host: 10.0.0.9"));
        assert!(summary.contains("10.0.0.1:80/tcp: closed -> open"));
    }

    #[test]
    fn format_change_summary_service_changes() {
        let changes = vec![ServiceChange {
            ip: "10.0.0.1".into(),
            port: 22,
            change_type: ServiceChangeType::VersionChanged,
            old_service: Some("OpenSSH 8.9".into()),
            new_service: Some("OpenSSH 9.0".into()),
        }];
        let summary = format_change_summary(None, &changes);
        assert!(summary.contains("SERVICE 10.0.0.1:22"));
        assert!(summary.contains("OpenSSH 8.9 -> OpenSSH 9.0"));
    }

    #[test]
    fn watch_config_default_interval() {
        let config = WatchConfig {
            interval: Duration::from_secs(300),
            webhook_url: None,
            on_change_cmd: None,
            no_db: false,
            timing: None,
        };
        assert_eq!(config.interval.as_secs(), 300);
    }

    #[test]
    fn change_payload_with_diff() {
        let diff = ScanDiff {
            old_scan_id: "old".into(),
            new_scan_id: "new".into(),
            new_hosts: vec!["192.168.1.100".into()],
            removed_hosts: vec![],
            port_changes: vec![],
        };
        let payload = ChangePayload {
            iteration: 1,
            scan_id: "new".into(),
            previous_scan_id: Some("old".into()),
            timestamp: 1700000000,
            diff: Some(diff),
            service_changes: vec![],
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("\"new_hosts\""));
    }

    #[test]
    fn format_change_summary_none_diff() {
        let summary = format_change_summary(None, &[]);
        assert!(summary.contains("Changes Detected"));
        let lines: Vec<&str> = summary.lines().filter(|l| l.starts_with("  ")).collect();
        assert!(lines.is_empty());
    }
}
