use std::sync::Arc;
use std::time::{Duration, Instant};

use rustmap_detect::{
    OsDetector, ServiceDetector, infer_os_from_services, is_tls_port, probe_tls_server,
};
use rustmap_packet::check_privileges;
use rustmap_scan::{
    DiscoveryResult, HostDiscovery, RawTcpScanner, Scanner, SctpInitScanner, TcpConnectScanner,
    TcpSynScanner, UdpScanner, find_closed_port, find_open_port, run_os_probes,
};
use rustmap_types::{
    DiscoveryMode, Host, HostScanResult, HostStatus, OsProbeResults, PortState, ScanConfig,
    ScanResult, ScanType,
};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("no targets specified")]
    NoTargets,
    #[error("no ports specified")]
    NoPorts,
    #[error("scan error: {0}")]
    ScanError(#[from] rustmap_scan::ScanError),
    #[error("unsupported scan type: {0:?}")]
    UnsupportedScanType(ScanType),
    #[error("task join error: {0}")]
    TaskJoinError(String),
}

/// Event emitted during a streaming scan.
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Discovery phase completed.
    DiscoveryComplete { hosts_total: usize },
    /// One host's scan completed.
    HostResult {
        index: usize,
        result: Box<HostScanResult>,
        hosts_completed: usize,
        hosts_total: usize,
    },
    /// Entire scan completed.
    Complete(Box<ScanResult>),
    /// Non-fatal error during scan.
    Error(String),
    /// Informational log message for activity tracking.
    Log(String),
}

pub struct ScanEngine;

impl ScanEngine {
    /// Execute a full scan according to the provided configuration.
    ///
    /// Thin wrapper around [`run_streaming`](Self::run_streaming) that collects
    /// events internally and returns the final result.
    pub async fn run(config: &ScanConfig) -> Result<ScanResult, EngineError> {
        let (tx, mut rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let config = config.clone();

        let handle = tokio::spawn(async move { Self::run_streaming(&config, tx, cancel).await });

        let mut final_result = None;
        while let Some(event) = rx.recv().await {
            if let ScanEvent::Complete(result) = event {
                final_result = Some(*result);
            }
        }

        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => return Err(EngineError::TaskJoinError(e.to_string())),
        }

        final_result.ok_or(EngineError::NoTargets)
    }

    /// Execute a streaming scan, emitting [`ScanEvent`]s as hosts complete.
    ///
    /// The caller provides a channel sender and a cancellation token. Events
    /// are sent best-effort (send errors are silently ignored so that a dropped
    /// receiver doesn't crash the scan).
    ///
    /// The final [`ScanEvent::Complete`] is always the last event emitted on
    /// success. On cancellation, partial results are still assembled and sent.
    pub async fn run_streaming(
        config: &ScanConfig,
        tx: mpsc::Sender<ScanEvent>,
        cancel: CancellationToken,
    ) -> Result<(), EngineError> {
        if config.targets.is_empty() {
            return Err(EngineError::NoTargets);
        }

        let overall_start = Instant::now();
        let hosts_total = config.targets.len();

        // Step 1: Host discovery (respects cancellation)
        let _ = tx
            .send(ScanEvent::Log("Starting host discovery...".into()))
            .await;
        let discovery_results = tokio::select! {
            _ = cancel.cancelled() => {
                let _ = tx.send(ScanEvent::Error("scan cancelled".into())).await;
                return Ok(());
            }
            result = run_discovery(config) => result?,
        };
        let up_count = discovery_results
            .iter()
            .filter(|d| d.status == HostStatus::Up || d.status == HostStatus::Unknown)
            .count();
        let _ = tx
            .send(ScanEvent::Log(format!(
                "Discovery complete: {up_count}/{hosts_total} hosts up"
            )))
            .await;
        let _ = tx.send(ScanEvent::DiscoveryComplete { hosts_total }).await;

        // Step 2: If ping-only, return discovery results without port scan
        let is_ping_only = config.discovery.mode == DiscoveryMode::PingOnly;
        if is_ping_only {
            let host_results = build_discovery_only_results(config, &discovery_results);

            for (index, result) in host_results.iter().enumerate() {
                let _ = tx
                    .send(ScanEvent::HostResult {
                        index,
                        result: Box::new(result.clone()),
                        hosts_completed: index + 1,
                        hosts_total,
                    })
                    .await;
            }

            let scan_result = ScanResult {
                hosts: host_results,
                total_duration: overall_start.elapsed(),
                scan_type: config.scan_type,
                start_time: None,
                command_args: None,
                num_services: config.ports.len(),
                pre_script_results: vec![],
                post_script_results: vec![],
            };
            let _ = tx.send(ScanEvent::Complete(Box::new(scan_result))).await;
            return Ok(());
        }

        // Step 3: Port scan + service detection + OS detection (parallel across hosts)
        if config.ports.is_empty() {
            return Err(EngineError::NoPorts);
        }

        let scanner: Arc<dyn Scanner> = match config.scan_type {
            ScanType::TcpConnect => Arc::new(TcpConnectScanner::new()),
            ScanType::TcpSyn => Arc::new(TcpSynScanner::new()),
            ScanType::TcpFin => Arc::new(RawTcpScanner::fin()),
            ScanType::TcpNull => Arc::new(RawTcpScanner::null()),
            ScanType::TcpXmas => Arc::new(RawTcpScanner::xmas()),
            ScanType::TcpAck => Arc::new(RawTcpScanner::ack()),
            ScanType::TcpWindow => Arc::new(RawTcpScanner::window()),
            ScanType::TcpMaimon => Arc::new(RawTcpScanner::maimon()),
            ScanType::Udp => Arc::new(UdpScanner::new()),
            ScanType::SctpInit => Arc::new(SctpInitScanner::new()),
            other => return Err(EngineError::UnsupportedScanType(other)),
        };

        // Shared detectors
        let service_detector = Arc::new(ServiceDetector::new());
        let os_detector = Arc::new(OsDetector::new());

        // Determine effective hostgroup size
        let num_targets = config.targets.len();
        let hostgroup_size = config
            .max_hostgroup
            .min(num_targets)
            .max(config.min_hostgroup)
            .min(num_targets);

        info!(
            targets = num_targets,
            hostgroup_size,
            host_timeout_ms = config.host_timeout.as_millis(),
            "scanning hosts in parallel"
        );

        // Use a semaphore to bound concurrent host scans
        let host_semaphore = Arc::new(tokio::sync::Semaphore::new(hostgroup_size));

        // Build a HashMap for O(1) discovery lookup
        let discovery_map: std::collections::HashMap<std::net::IpAddr, &DiscoveryResult> =
            discovery_results.iter().map(|d| (d.ip, d)).collect();

        // Spawn all host scans into a JoinSet
        let mut join_set: JoinSet<(usize, HostScanResult)> = JoinSet::new();

        for (index, target) in config.targets.iter().enumerate() {
            let disc = discovery_map.get(&target.ip).copied();
            let is_pre_resolved = config.pre_resolved_up.contains(&target.ip);
            let (status, latency) = match disc {
                Some(d) if d.status == HostStatus::Down && !is_pre_resolved => {
                    info!(target = %target.ip, "host is down, skipping port scan");
                    let result = HostScanResult {
                        host: target.clone(),
                        ports: vec![],
                        scan_duration: Duration::ZERO,
                        host_status: HostStatus::Down,
                        discovery_latency: None,
                        os_fingerprint: None,
                        traceroute: None,
                        timing_snapshot: None,
                        host_script_results: vec![],
                        scan_error: None,
                        uptime_estimate: None,
                        risk_score: None,
                        mtu: None,
                    };
                    join_set.spawn(async move { (index, result) });
                    continue;
                }
                Some(d) if d.status == HostStatus::Down && is_pre_resolved => {
                    info!(target = %target.ip, "pre-resolved as Up (overriding discovery)");
                    (HostStatus::Up, None)
                }
                Some(d) => (d.status, d.latency),
                None if is_pre_resolved => {
                    info!(target = %target.ip, "pre-resolved as Up (skipped discovery)");
                    (HostStatus::Up, None)
                }
                None => (HostStatus::Unknown, None),
            };

            let target = target.clone();
            let config = config.clone();
            let scanner = scanner.clone();
            let service_detector = service_detector.clone();
            let os_detector = os_detector.clone();
            let host_semaphore = host_semaphore.clone();
            let tx = tx.clone();

            join_set.spawn(async move {
                let _permit = match host_semaphore.acquire().await {
                    Ok(permit) => permit,
                    Err(e) => {
                        warn!("semaphore acquire failed for {}: {}", target.ip, e);
                        return (
                            index,
                            HostScanResult {
                                host: target,
                                ports: vec![],
                                scan_duration: Duration::ZERO,
                                host_status: status,
                                discovery_latency: latency,
                                os_fingerprint: None,
                                traceroute: None,
                                timing_snapshot: None,
                                host_script_results: vec![],
                                scan_error: Some(format!("semaphore acquire failed: {e}")),
                                uptime_estimate: None,
                                risk_score: None,
                                mtu: None,
                            },
                        );
                    }
                };

                let result = scan_single_host(
                    &target,
                    &config,
                    &*scanner,
                    &service_detector,
                    &os_detector,
                    status,
                    latency,
                    &tx,
                )
                .await;

                (index, result)
            });
        }

        // Collect results with cancellation support
        let mut indexed_results: Vec<(usize, HostScanResult)> = Vec::with_capacity(num_targets);
        let mut hosts_completed: usize = 0;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    join_set.abort_all();
                    // Drain any results that completed before the abort
                    while let Some(result) = join_set.join_next().await {
                        if let Ok((idx, host_result)) = result {
                            indexed_results.push((idx, host_result));
                        }
                    }
                    let _ = tx.send(ScanEvent::Error("scan cancelled".into())).await;
                    break;
                }
                result = join_set.join_next() => {
                    match result {
                        Some(Ok((index, host_result))) => {
                            hosts_completed += 1;
                            // Emit a non-fatal error event if the port scanner failed
                            if let Some(ref err) = host_result.scan_error {
                                let _ = tx.send(ScanEvent::Error(
                                    format!("scan error on {}: {}", host_result.host.ip, err)
                                )).await;
                            }
                            let _ = tx
                                .send(ScanEvent::HostResult {
                                    index,
                                    result: Box::new(host_result.clone()),
                                    hosts_completed,
                                    hosts_total,
                                })
                                .await;
                            indexed_results.push((index, host_result));
                        }
                        Some(Err(e)) => {
                            hosts_completed += 1;
                            warn!("host scan task error: {}", e);
                            let _ = tx.send(ScanEvent::Error(
                                format!("host scan task panicked: {e}")
                            )).await;
                        }
                        None => break,
                    }
                }
            }
        }

        // Sort by original target index to maintain order
        indexed_results.sort_by_key(|(idx, _)| *idx);
        let host_results: Vec<HostScanResult> = indexed_results
            .into_iter()
            .map(|(_, result)| result)
            .collect();

        let scan_result = ScanResult {
            hosts: host_results,
            total_duration: overall_start.elapsed(),
            scan_type: config.scan_type,
            start_time: None,
            command_args: None,
            num_services: config.ports.len(),
            pre_script_results: vec![],
            post_script_results: vec![],
        };
        let _ = tx.send(ScanEvent::Complete(Box::new(scan_result))).await;

        Ok(())
    }
}

/// Scan a single host with optional per-host timeout.
///
/// Wraps the inner scan function with `tokio::time::timeout` if a host
/// timeout is configured. On timeout, returns a partial result with empty ports.
#[allow(clippy::too_many_arguments)]
async fn scan_single_host(
    target: &Host,
    config: &ScanConfig,
    scanner: &dyn Scanner,
    service_detector: &ServiceDetector,
    os_detector: &OsDetector,
    status: HostStatus,
    latency: Option<Duration>,
    tx: &mpsc::Sender<ScanEvent>,
) -> HostScanResult {
    let host_timeout = config.host_timeout;

    if host_timeout.is_zero() {
        scan_single_host_inner(
            target,
            config,
            scanner,
            service_detector,
            os_detector,
            status,
            latency,
            tx,
        )
        .await
    } else {
        match tokio::time::timeout(
            host_timeout,
            scan_single_host_inner(
                target,
                config,
                scanner,
                service_detector,
                os_detector,
                status,
                latency,
                tx,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                info!(
                    target = %target.ip,
                    timeout_ms = host_timeout.as_millis(),
                    "host timed out"
                );
                HostScanResult {
                    host: target.clone(),
                    ports: vec![],
                    scan_duration: host_timeout,
                    host_status: status,
                    discovery_latency: latency,
                    os_fingerprint: None,
                    traceroute: None,
                    timing_snapshot: None,
                    host_script_results: vec![],
                    scan_error: None,
                    uptime_estimate: None,
                    risk_score: None,
                    mtu: None,
                }
            }
        }
    }
}

/// Inner single-host scanning: port scan → service enrichment → service detection → OS detection.
#[allow(clippy::too_many_arguments)]
async fn scan_single_host_inner(
    target: &Host,
    config: &ScanConfig,
    scanner: &dyn Scanner,
    service_detector: &ServiceDetector,
    os_detector: &OsDetector,
    status: HostStatus,
    latency: Option<Duration>,
    tx: &mpsc::Sender<ScanEvent>,
) -> HostScanResult {
    let host_label = target
        .hostname
        .as_deref()
        .map(|h| format!("{} ({})", target.ip, h))
        .unwrap_or_else(|| target.ip.to_string());

    info!("scanning host: {}", target.ip);

    // Phase 1: Port scan
    let _ = tx
        .send(ScanEvent::Log(format!(
            "Scanning {} ports on {host_label}...",
            config.ports.len()
        )))
        .await;
    let mut result = match scanner.scan_host(target, config).await {
        Ok(r) => r,
        Err(e) => {
            warn!("scan error on {}: {}", target.ip, e);
            return HostScanResult {
                host: target.clone(),
                ports: vec![],
                scan_duration: Duration::ZERO,
                host_status: status,
                discovery_latency: latency,
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: Some(e.to_string()),
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            };
        }
    };
    result.host_status = status;
    result.discovery_latency = latency;

    let open = result
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .count();
    let filtered = result
        .ports
        .iter()
        .filter(|p| p.state == PortState::Filtered)
        .count();
    let _ = tx
        .send(ScanEvent::Log(format!(
            "Port scan complete on {host_label}: {open} open, {filtered} filtered"
        )))
        .await;

    // Phase 1.5: MTU discovery (--mtu-discovery, IPv4 only)
    if config.mtu_discovery && target.ip.is_ipv4() {
        let _ = tx
            .send(ScanEvent::Log(format!(
                "Running MTU discovery on {host_label}..."
            )))
            .await;
        info!(target = %target.ip, "running path MTU discovery");
        result.mtu = rustmap_scan::discovery::discover_mtu(target, config.timeout).await;
    }

    // Phase 2: Service name enrichment (port-to-service map, always runs)
    service_detector.enrich_ports(&mut result.ports);

    // Phase 3: Active service/version detection (-sV)
    if config.service_detection.enabled {
        let open_count = result
            .ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .count();
        let _ = tx
            .send(ScanEvent::Log(format!(
                "Detecting services on {host_label} ({open_count} open ports)..."
            )))
            .await;
        info!("detecting services on {}", target.ip);
        if let Err(e) = service_detector
            .detect_services(
                target.ip,
                target.hostname.as_deref(),
                &mut result.ports,
                &config.service_detection,
                config.concurrency,
                config.proxy.clone(),
            )
            .await
        {
            info!("service detection error on {}: {}", target.ip, e);
        }

        // QUIC probing is now handled inside ServiceDetector::detect_services()
    }

    // Phase 4: OS detection (-O)
    if config.os_detection.enabled {
        let _ = tx
            .send(ScanEvent::Log(format!(
                "Running OS fingerprint on {host_label}..."
            )))
            .await;
        let open_port = find_open_port(&result.ports);
        let closed_port = find_closed_port(&result.ports);

        let mut probe_results = match open_port {
            Some(open) => {
                info!(
                    target = %target.ip,
                    open_port = open,
                    closed_port,
                    "running OS detection probes"
                );
                run_os_probes(target.ip, open, closed_port)
                    .await
                    .unwrap_or_default()
            }
            None => {
                info!(
                    target = %target.ip,
                    "no open port found, skipping active OS probes"
                );
                OsProbeResults::default()
            }
        };

        // TLS fingerprinting — reuse from service detection if available
        let existing_tls = result
            .ports
            .iter()
            .find_map(|p| p.tls_info.as_ref())
            .cloned();
        if let Some(tls_fp) = existing_tls {
            probe_results.tls = Some(tls_fp);
        } else {
            let tls_port = result
                .ports
                .iter()
                .find(|p| p.state == PortState::Open && is_tls_port(p.number))
                .map(|p| p.number);
            if let Some(port) = tls_port {
                info!(
                    target = %target.ip,
                    port,
                    "probing TLS server for OS fingerprinting"
                );
                match probe_tls_server(
                    target.ip,
                    port,
                    target.hostname.as_deref(),
                    config.proxy.as_ref(),
                )
                .await
                {
                    Ok(Some(tls_fp)) => {
                        probe_results.tls = Some(tls_fp);
                    }
                    Ok(None) => {
                        info!(
                            target = %target.ip,
                            port,
                            "TLS probe returned no fingerprint"
                        );
                    }
                    Err(e) => {
                        info!(
                            target = %target.ip,
                            port,
                            error = %e,
                            "TLS probe failed"
                        );
                    }
                }
            }
        }

        let os_fp = os_detector.detect(&probe_results);

        // Fallback: if raw probes produced no match, infer from service banners
        if os_fp.os_family.is_none() {
            if let Some(inferred) = infer_os_from_services(&result.ports) {
                info!(
                    target = %target.ip,
                    os = ?inferred.os_family,
                    "OS inferred from service banners (probe-based detection had no match)"
                );
                result.os_fingerprint = Some(inferred);
            } else {
                result.os_fingerprint = Some(os_fp);
            }
        } else {
            let mut enriched = os_fp;
            rustmap_detect::enrich_os_from_services(&mut enriched, &result.ports);
            result.os_fingerprint = Some(enriched);
        }
    }

    // Uptime estimation from TCP timestamps
    if let Some(ref os_fp) = result.os_fingerprint {
        result.uptime_estimate = rustmap_detect::estimate_uptime(os_fp);
    }

    // Phase 5: Traceroute (--traceroute)
    if config.traceroute {
        let _ = tx
            .send(ScanEvent::Log(format!(
                "Running traceroute to {host_label}..."
            )))
            .await;
        let open_port = result
            .ports
            .iter()
            .find(|p| p.state == PortState::Open)
            .map(|p| p.number);

        info!(target = %target.ip, open_port, "running traceroute");
        match rustmap_scan::trace_route(target, open_port, None).await {
            Ok(tr) => result.traceroute = Some(tr),
            Err(e) => warn!(target = %target.ip, error = %e, "traceroute failed"),
        }
    }

    result
}

/// Run host discovery based on configuration.
async fn run_discovery(config: &ScanConfig) -> Result<Vec<DiscoveryResult>, EngineError> {
    match &config.discovery.mode {
        DiscoveryMode::Skip => {
            // -Pn: treat all hosts as up (Unknown status = skipped discovery)
            Ok(config
                .targets
                .iter()
                .map(|h| DiscoveryResult {
                    ip: h.ip,
                    status: HostStatus::Unknown,
                    latency: None,
                })
                .collect())
        }
        _ => {
            let privileged = check_privileges().has_raw_socket_access();
            let results = HostDiscovery::discover(
                &config.targets,
                &config.discovery,
                config.timing_template,
                privileged,
            )
            .await?;
            Ok(results)
        }
    }
}

/// Build HostScanResult entries for ping-only mode (no port scan).
fn build_discovery_only_results(
    config: &ScanConfig,
    discovery: &[DiscoveryResult],
) -> Vec<HostScanResult> {
    // Build a HashMap for O(1) discovery lookup
    let discovery_map: std::collections::HashMap<std::net::IpAddr, &DiscoveryResult> =
        discovery.iter().map(|d| (d.ip, d)).collect();

    config
        .targets
        .iter()
        .map(|target| {
            let disc = discovery_map.get(&target.ip).copied();
            let is_pre_resolved = config.pre_resolved_up.contains(&target.ip);
            let (status, latency) = match disc {
                Some(d) if d.status == HostStatus::Down && is_pre_resolved => {
                    (HostStatus::Up, None)
                }
                Some(d) => (d.status, d.latency),
                None if is_pre_resolved => (HostStatus::Up, None),
                None => (HostStatus::Unknown, None),
            };
            HostScanResult {
                host: target.clone(),
                ports: vec![],
                scan_duration: Duration::ZERO,
                host_status: status,
                discovery_latency: latency,
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{DiscoveryConfig, Host, ServiceDetectionConfig, TimingTemplate};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_host(ip: [u8; 4]) -> Host {
        Host {
            ip: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            hostname: None,
            geo_info: None,
        }
    }

    fn make_config(targets: Vec<Host>, mode: DiscoveryMode) -> ScanConfig {
        ScanConfig {
            targets,
            ports: vec![80, 443],
            scan_type: ScanType::TcpConnect,
            timeout: Duration::from_secs(3),
            concurrency: 10,
            timing_template: TimingTemplate::Normal,
            verbose: false,
            discovery: DiscoveryConfig {
                mode,
                ..DiscoveryConfig::default()
            },
            service_detection: ServiceDetectionConfig::default(),
            os_detection: rustmap_types::OsDetectionConfig::default(),
            min_hostgroup: 1,
            max_hostgroup: 256,
            host_timeout: Duration::ZERO,
            min_rate: None,
            max_rate: None,
            randomize_ports: false,
            source_port: None,
            decoys: Vec::new(),
            fragment_packets: false,
            custom_payload: None,
            traceroute: false,
            scan_delay: None,
            max_scan_delay: None,
            learned_initial_rto_us: None,
            learned_initial_cwnd: None,
            learned_ssthresh: None,
            learned_max_retries: None,
            pre_resolved_up: vec![],
            proxy: None,
            mtu_discovery: false,
            ip_ttl: None,
            badsum: false,
            spoof_mac: None,
        }
    }

    #[tokio::test]
    async fn run_discovery_skip_mode() {
        let hosts = vec![make_host([10, 0, 0, 1]), make_host([10, 0, 0, 2])];
        let config = make_config(hosts, DiscoveryMode::Skip);
        let results = run_discovery(&config).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.status == HostStatus::Unknown));
        assert!(results.iter().all(|r| r.latency.is_none()));
    }

    #[test]
    fn build_discovery_only_results_maps_correctly() {
        let hosts = vec![
            make_host([10, 0, 0, 1]),
            make_host([10, 0, 0, 2]),
            make_host([10, 0, 0, 3]),
        ];
        let config = make_config(hosts, DiscoveryMode::PingOnly);

        let discovery = vec![
            DiscoveryResult {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                status: HostStatus::Up,
                latency: Some(Duration::from_millis(5)),
            },
            DiscoveryResult {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                status: HostStatus::Down,
                latency: None,
            },
            DiscoveryResult {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                status: HostStatus::Up,
                latency: Some(Duration::from_millis(12)),
            },
        ];

        let results = build_discovery_only_results(&config, &discovery);
        assert_eq!(results.len(), 3);

        assert_eq!(results[0].host_status, HostStatus::Up);
        assert!(results[0].discovery_latency.is_some());
        assert!(results[0].ports.is_empty());

        assert_eq!(results[1].host_status, HostStatus::Down);
        assert!(results[1].discovery_latency.is_none());

        assert_eq!(results[2].host_status, HostStatus::Up);
    }

    #[tokio::test]
    async fn engine_no_targets_error() {
        let config = make_config(vec![], DiscoveryMode::Skip);
        let result = ScanEngine::run(&config).await;
        assert!(matches!(result, Err(EngineError::NoTargets)));
    }

    #[tokio::test]
    async fn engine_no_ports_error() {
        let hosts = vec![make_host([10, 0, 0, 1])];
        let mut config = make_config(hosts, DiscoveryMode::Skip);
        config.ports = vec![];
        let result = ScanEngine::run(&config).await;
        assert!(matches!(result, Err(EngineError::NoPorts)));
    }

    #[tokio::test]
    async fn engine_ping_only_no_ports_ok() {
        let hosts = vec![make_host([10, 0, 0, 1])];
        let mut config = make_config(hosts, DiscoveryMode::PingOnly);
        config.ports = vec![];
        let disc = vec![DiscoveryResult {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            status: HostStatus::Up,
            latency: Some(Duration::from_millis(3)),
        }];
        let results = build_discovery_only_results(&config, &disc);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].host_status, HostStatus::Up);
        assert!(results[0].ports.is_empty());
    }

    #[test]
    fn scan_config_default_hostgroup_values() {
        let config = ScanConfig::default();
        assert_eq!(config.min_hostgroup, 1);
        assert_eq!(config.max_hostgroup, 256);
        assert_eq!(config.host_timeout, Duration::ZERO);
        assert!(config.min_rate.is_none());
        assert!(config.max_rate.is_none());
    }

    #[test]
    fn pre_resolved_up_overrides_down() {
        let hosts = vec![make_host([10, 0, 0, 1]), make_host([10, 0, 0, 2])];
        let mut config = make_config(hosts, DiscoveryMode::PingOnly);
        // Pre-resolve host 2 as Up
        config.pre_resolved_up = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))];

        let discovery = vec![
            DiscoveryResult {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                status: HostStatus::Up,
                latency: Some(Duration::from_millis(5)),
            },
            DiscoveryResult {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                status: HostStatus::Down,
                latency: None,
            },
        ];

        let results = build_discovery_only_results(&config, &discovery);
        assert_eq!(results.len(), 2);
        // Host 1: Up from discovery
        assert_eq!(results[0].host_status, HostStatus::Up);
        // Host 2: Down from discovery, but pre-resolved overrides to Up
        assert_eq!(results[1].host_status, HostStatus::Up);
    }

    #[test]
    fn pre_resolved_up_no_discovery_result() {
        let hosts = vec![make_host([10, 0, 0, 1])];
        let mut config = make_config(hosts, DiscoveryMode::PingOnly);
        config.pre_resolved_up = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];

        // No discovery result for this host
        let discovery = vec![];

        let results = build_discovery_only_results(&config, &discovery);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].host_status, HostStatus::Up);
    }

    #[test]
    fn no_discovery_no_pre_resolved_is_unknown() {
        let hosts = vec![make_host([10, 0, 0, 1])];
        let config = make_config(hosts, DiscoveryMode::PingOnly);

        // No discovery result and not pre-resolved
        let discovery = vec![];

        let results = build_discovery_only_results(&config, &discovery);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].host_status, HostStatus::Unknown);
    }

    #[test]
    fn hostgroup_size_clamping() {
        // With 3 targets and max_hostgroup=256, effective = min(256, 3).max(1) = 3
        assert_eq!(256_usize.min(3).max(1), 3);
        // With 1000 targets and max_hostgroup=256, effective = min(256, 1000).max(1) = 256
        assert_eq!(256_usize.min(1000).max(1), 256);
        // With 3 targets and min_hostgroup=10, effective = min(256, 3).max(10) = 10
        assert_eq!(256_usize.min(3).max(10), 10);
    }
}
