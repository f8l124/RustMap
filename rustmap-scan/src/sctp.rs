use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use rustmap_packet::{
    CaptureConfig, CapturedResponse, PacketReceiver, PacketSender, ResponseType, create_capture,
    create_sender,
};
use rustmap_timing::{TimingController, TimingParams};
use rustmap_types::{Host, HostScanResult, Port, PortState, ScanConfig, TimingSnapshot};

use crate::probe::{ProbeKey, ProbeTracker};
use crate::raw_tcp::get_sender_src_ip;
use crate::source_port::SourcePortAllocator;
use crate::traits::{ScanError, Scanner};

/// SCTP INIT port scanner (`-sZ`).
///
/// Sends SCTP INIT chunks to target ports and interprets responses:
/// - **INIT-ACK** → Open
/// - **ABORT** → Closed
/// - **ICMP unreachable** → Filtered
/// - **No response** → Open|Filtered
///
/// Uses the same 3-task concurrent architecture as `RawTcpScanner`:
/// send loop, response processor, and timeout checker.
pub struct SctpInitScanner;

impl Default for SctpInitScanner {
    fn default() -> Self {
        Self
    }
}

impl SctpInitScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for SctpInitScanner {
    async fn scan_host(
        &self,
        host: &Host,
        config: &ScanConfig,
    ) -> Result<HostScanResult, ScanError> {
        let start = Instant::now();
        let target_ip = host.ip;

        info!(target = %target_ip, ports = config.ports.len(), "starting SCTP INIT scan");

        // Create timing controller from template
        let mut params = TimingParams::from_template(config.timing_template);
        params.apply_learned(
            config.learned_initial_rto_us,
            config.learned_initial_cwnd,
            config.learned_ssthresh,
            config.learned_max_retries,
        );
        if let Some(min_rate) = config.min_rate {
            params.min_rate = Some(min_rate);
        }
        if let Some(max_rate) = config.max_rate {
            params.max_rate = Some(max_rate);
        }
        if let Some(delay) = config.scan_delay {
            params.scan_delay = delay;
        }
        if let Some(max_delay) = config.max_scan_delay {
            params.max_scan_delay = max_delay;
        }
        let timing = Arc::new(TimingController::new(params));

        // Create packet sender and capture
        let sender: Arc<dyn PacketSender> = Arc::from(create_sender(target_ip)?);

        // BPF filter: capture SCTP (IP proto 132) and ICMP from target
        let bpf_filter = sctp_bpf_filter(target_ip, config.source_port);
        let mut capture = create_capture(CaptureConfig {
            interface: sender.interface_name().map(String::from),
            bpf_filter,
            ..CaptureConfig::default()
        })?;

        // Get our source IP
        let src_ip = get_sender_src_ip(target_ip);

        // Shared state
        let tracker = Arc::new(ProbeTracker::new());
        let port_alloc = Arc::new(match config.source_port {
            Some(port) => SourcePortAllocator::new_fixed(port),
            None => SourcePortAllocator::new(),
        });
        let done_notify = Arc::new(Notify::new());

        let ports = config.ports.clone();
        let max_retries = timing.max_retries();

        // Spawn the three concurrent tasks
        let send_handle = {
            let sender = sender.clone();
            let timing = timing.clone();
            let tracker = tracker.clone();
            let port_alloc = port_alloc.clone();
            let done_notify = done_notify.clone();

            tokio::spawn(async move {
                send_loop(
                    &*sender,
                    src_ip,
                    target_ip,
                    &ports,
                    &timing,
                    &tracker,
                    &port_alloc,
                    max_retries,
                )
                .await;
                debug!("SCTP send loop finished");
                done_notify.notify_one();
            })
        };

        let recv_handle = {
            let timing = timing.clone();
            let tracker = tracker.clone();
            let done_notify = done_notify.clone();

            tokio::spawn(async move {
                response_processor(&mut capture, &timing, &tracker, &done_notify).await;
                debug!("SCTP response processor finished");
            })
        };

        let timeout_handle = {
            let sender = sender.clone();
            let timing = timing.clone();
            let tracker = tracker.clone();
            let port_alloc = port_alloc.clone();
            let done_notify = done_notify.clone();

            tokio::spawn(async move {
                timeout_checker(
                    &*sender,
                    src_ip,
                    target_ip,
                    &timing,
                    &tracker,
                    &port_alloc,
                    &done_notify,
                )
                .await;
                debug!("SCTP timeout checker finished");
            })
        };

        // Wait for send loop to complete
        let _ = send_handle.await;

        // Grace period for remaining responses
        let grace_period = timing.current_rto() * 2;
        let grace_deadline = Instant::now() + grace_period.max(Duration::from_secs(2));

        while !tracker.is_complete() && Instant::now() < grace_deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Signal all tasks to stop
        done_notify.notify_waiters();

        let _ = tokio::time::timeout(Duration::from_millis(500), recv_handle).await;
        let _ = tokio::time::timeout(Duration::from_millis(500), timeout_handle).await;

        // Collect results — SCTP ports use Protocol::Sctp
        let raw_results = tracker.collect_results();
        let mut ports: Vec<Port> = raw_results
            .into_iter()
            .map(|(port_num, state)| Port {
                number: port_num,
                state,
                protocol: rustmap_types::Protocol::Sctp,
                service: None,
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            })
            .collect();
        ports.sort_by_key(|p| p.number);

        let stats = timing.stats();
        info!(
            target = %target_ip,
            ports_scanned = ports.len(),
            probes_sent = stats.probes_sent,
            probes_completed = stats.probes_completed,
            srtt_ms = stats.srtt.map(|d| d.as_millis()),
            duration_ms = start.elapsed().as_millis(),
            "SCTP INIT scan complete"
        );

        let timing_snapshot = TimingSnapshot {
            srtt_us: stats.srtt.map(|d| d.as_micros() as u64),
            rto_us: stats.rto.as_micros() as u64,
            rttvar_us: stats.rttvar.map(|d| d.as_micros() as u64),
            cwnd: stats.cwnd,
            probes_sent: stats.probes_sent,
            probes_responded: stats.probes_responded,
            probes_timed_out: stats.probes_timed_out,
            loss_rate: if stats.probes_sent > 0 {
                1.0 - (stats.probes_responded as f64 / stats.probes_sent as f64)
            } else {
                0.0
            },
        };

        Ok(HostScanResult {
            host: host.clone(),
            ports,
            scan_duration: start.elapsed(),
            host_status: rustmap_types::HostStatus::Up,
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: None,
            timing_snapshot: Some(timing_snapshot),
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        })
    }
}

/// Build a BPF filter for SCTP scanning.
/// Captures SCTP (IP protocol 132) and ICMP from the target.
fn sctp_bpf_filter(target_ip: IpAddr, source_port: Option<u16>) -> String {
    match target_ip {
        IpAddr::V4(ip) => {
            let base = format!("(ip proto 132 and src host {ip}) or (icmp and src host {ip})");
            if let Some(port) = source_port {
                // With fixed source port, also filter on SCTP dst port
                format!(
                    "((ip proto 132 and src host {ip} and dst port {port}) or (icmp and src host {ip}))"
                )
            } else {
                base
            }
        }
        IpAddr::V6(ip) => {
            if let Some(port) = source_port {
                format!(
                    "((ip6 proto 132 and src host {ip} and dst port {port}) or (icmp6 and src host {ip}))"
                )
            } else {
                format!("(ip6 proto 132 and src host {ip}) or (icmp6 and src host {ip})")
            }
        }
    }
}

/// Send loop: iterates ports, sends SCTP INIT probes.
#[allow(clippy::too_many_arguments)]
async fn send_loop(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    ports: &[u16],
    timing: &TimingController,
    tracker: &ProbeTracker,
    port_alloc: &SourcePortAllocator,
    max_retries: u8,
) {
    for &dst_port in ports {
        // Wait for a send slot (respects cwnd + rate limit)
        timing.wait_for_slot().await;

        let src_port = port_alloc.next_port();
        let rto = timing.current_rto();

        // Register the probe before sending
        tracker.register_probe(dst_ip, dst_port, src_port, rto, max_retries);

        let send_result = sender
            .send_sctp_init(src_ip, src_port, dst_ip, dst_port)
            .await;

        match send_result {
            Ok(()) => {
                timing.on_probe_sent();
            }
            Err(e) => {
                warn!(port = dst_port, error = %e, "failed to send SCTP INIT");
                tracker.mark_no_response(
                    &ProbeKey {
                        dst_ip,
                        dst_port,
                        src_port,
                    },
                    PortState::OpenFiltered,
                );
                timing.on_drop();
            }
        }

        // Inter-probe delay with optional jitter
        let delay = timing.scan_delay_jittered();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// Response processor: captures packets, interprets SCTP scan responses.
async fn response_processor(
    capture: &mut dyn PacketReceiver,
    timing: &TimingController,
    tracker: &ProbeTracker,
    done: &Notify,
) {
    loop {
        tokio::select! {
            result = capture.recv() => {
                match result {
                    Ok(response) => {
                        handle_response(&response, timing, tracker);
                    }
                    Err(_) => {
                        debug!("capture ended");
                        break;
                    }
                }
            }
            _ = done.notified() => {
                capture.stop();
                break;
            }
        }
    }
}

/// Process a single captured response for SCTP INIT scanning.
fn handle_response(response: &CapturedResponse, timing: &TimingController, tracker: &ProbeTracker) {
    let port_state = match response.response_type {
        // SCTP INIT-ACK → port is open
        ResponseType::SctpInitAck => PortState::Open,
        // SCTP ABORT → port is closed
        ResponseType::SctpAbort => PortState::Closed,
        // ICMP unreachable → port is filtered
        ResponseType::IcmpUnreachable => PortState::Filtered,
        // All other response types are irrelevant during SCTP scan
        _ => return,
    };

    if let Some(rtt) = tracker.on_response(
        response.src_ip,
        response.src_port,
        response.dst_port,
        port_state,
    ) {
        timing.on_response(rtt);
        debug!(
            port = response.src_port,
            state = ?port_state,
            rtt_ms = rtt.as_millis(),
            "SCTP probe response"
        );
    }
}

/// Timeout checker: periodically checks for timed-out SCTP probes.
#[allow(clippy::too_many_arguments)]
async fn timeout_checker(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timing: &TimingController,
    tracker: &ProbeTracker,
    port_alloc: &SourcePortAllocator,
    done: &Notify,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                check_timeouts(sender, src_ip, dst_ip, timing, tracker, port_alloc).await;
            }
            _ = done.notified() => {
                break;
            }
        }
    }
}

/// Check for timed-out SCTP probes and retry or mark as open|filtered.
async fn check_timeouts(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timing: &TimingController,
    tracker: &ProbeTracker,
    port_alloc: &SourcePortAllocator,
) {
    let (retryable, expired) = tracker.collect_timed_out();

    for key in &retryable {
        if let Some((dst_port, retries)) = tracker.prepare_retry(key) {
            timing.on_timeout();

            tracker.remove(key);

            let new_src_port = port_alloc.next_port();
            let new_rto = timing.current_rto();

            tracker.register_probe(dst_ip, dst_port, new_src_port, new_rto, retries);

            let send_result = sender
                .send_sctp_init(src_ip, new_src_port, dst_ip, dst_port)
                .await;

            match send_result {
                Ok(()) => {
                    timing.on_probe_sent();
                }
                Err(e) => {
                    warn!(port = dst_port, error = %e, "SCTP retry send failed");
                    tracker.mark_no_response(
                        &ProbeKey {
                            dst_ip,
                            dst_port,
                            src_port: new_src_port,
                        },
                        PortState::OpenFiltered,
                    );
                    timing.on_drop();
                }
            }
        }
    }

    for key in &expired {
        tracker.mark_no_response(key, PortState::OpenFiltered);
        timing.on_timeout();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn sctp_scanner_creates() {
        let _scanner = SctpInitScanner::new();
    }

    #[test]
    fn sctp_bpf_filter_ipv4() {
        let filter = sctp_bpf_filter(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None);
        assert!(filter.contains("ip proto 132"));
        assert!(filter.contains("src host 10.0.0.1"));
        assert!(filter.contains("icmp"));
    }

    #[test]
    fn sctp_bpf_filter_ipv4_fixed_port() {
        let filter = sctp_bpf_filter(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), Some(40000));
        assert!(filter.contains("dst port 40000"));
    }

    #[test]
    fn handle_response_sctp_init_ack_open() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 3868, 40001, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 3868,
            dst_port: 40001,
            response_type: ResponseType::SctpInitAck,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, &timing, &tracker);

        let results = tracker.collect_results();
        assert_eq!(results.len(), 1);
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 3868 && *s == PortState::Open)
        );
    }

    #[test]
    fn handle_response_sctp_abort_closed() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 2905, 40002, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 2905,
            dst_port: 40002,
            response_type: ResponseType::SctpAbort,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, &timing, &tracker);

        let results = tracker.collect_results();
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 2905 && *s == PortState::Closed)
        );
    }

    #[test]
    fn handle_response_icmp_unreachable_filtered() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 5060, 40003, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 5060,
            dst_port: 40003,
            response_type: ResponseType::IcmpUnreachable,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, &timing, &tracker);

        let results = tracker.collect_results();
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 5060 && *s == PortState::Filtered)
        );
    }

    #[test]
    fn handle_response_irrelevant_types_ignored() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 80, 40004, Duration::from_secs(1), 3);

        // SYN/ACK should be ignored during SCTP scan
        let response = CapturedResponse {
            src_ip: ip,
            src_port: 80,
            dst_port: 40004,
            response_type: ResponseType::SynAck,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, &timing, &tracker);

        let results = tracker.collect_results();
        assert!(results.is_empty());
    }

    #[test]
    fn sctp_results_use_sctp_protocol() {
        let port = Port {
            number: 3868,
            state: PortState::Open,
            protocol: rustmap_types::Protocol::Sctp,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        };
        assert_eq!(port.protocol, rustmap_types::Protocol::Sctp);
    }
}
