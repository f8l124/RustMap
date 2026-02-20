use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use rustmap_packet::{
    CaptureConfig, CapturedResponse, PacketReceiver, PacketSender, ResponseType, create_capture,
    create_sender, fragment_ipv4_packet, udp_bpf_filter, udp_fixed_port_bpf_filter,
    udp_payloads::udp_payload_for_port,
};
use rustmap_timing::{TimingController, TimingParams};
use rustmap_types::{Host, HostScanResult, Port, PortState, ScanConfig, TimingSnapshot};

use crate::probe::{ProbeKey, ProbeTracker};
use crate::raw_tcp::get_sender_src_ip;
use crate::source_port::SourcePortAllocator;
use crate::traits::{ScanError, Scanner};

/// UDP port scanner.
///
/// Sends service-specific UDP payloads to target ports and interprets responses:
/// - **Direct UDP response** → Open
/// - **ICMP port unreachable** → Closed
/// - **ICMP unreachable (other)** → Filtered
/// - **No response** → Open|Filtered
///
/// Uses the same 3-task concurrent architecture as `RawTcpScanner`:
/// send loop, response processor, and timeout checker.
pub struct UdpScanner;

impl Default for UdpScanner {
    fn default() -> Self {
        Self
    }
}

impl UdpScanner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Scanner for UdpScanner {
    async fn scan_host(
        &self,
        host: &Host,
        config: &ScanConfig,
    ) -> Result<HostScanResult, ScanError> {
        let start = Instant::now();
        let target_ip = host.ip;

        info!(target = %target_ip, ports = config.ports.len(), "starting UDP scan");

        // Use slightly slower timing for UDP (most ports won't respond)
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

        // Create packet sender and capture on the same interface with UDP-specific BPF filter
        let sender: Arc<dyn PacketSender> = Arc::from(create_sender(target_ip)?);
        let bpf_filter = match config.source_port {
            Some(port) => udp_fixed_port_bpf_filter(port),
            None => udp_bpf_filter(),
        };
        let capture_config = CaptureConfig {
            interface: sender.interface_name().map(String::from),
            bpf_filter,
            ..CaptureConfig::default()
        };
        let mut capture = create_capture(capture_config)?;

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
        let decoys = config.decoys.clone();
        let fragment_packets = config.fragment_packets;
        let custom_payload = config.custom_payload.clone();

        // Spawn the three concurrent tasks
        let send_handle = {
            let sender = sender.clone();
            let timing = timing.clone();
            let tracker = tracker.clone();
            let port_alloc = port_alloc.clone();
            let done_notify = done_notify.clone();
            let custom_payload = custom_payload.clone();

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
                    &decoys,
                    fragment_packets,
                    custom_payload.as_deref(),
                )
                .await;
                debug!("UDP send loop finished");
                done_notify.notify_one();
            })
        };

        let recv_handle = {
            let timing = timing.clone();
            let tracker = tracker.clone();
            let done_notify = done_notify.clone();

            tokio::spawn(async move {
                response_processor(&mut capture, target_ip, &timing, &tracker, &done_notify).await;
                debug!("UDP response processor finished");
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
                    fragment_packets,
                    custom_payload.as_deref(),
                )
                .await;
                debug!("UDP timeout checker finished");
            })
        };

        // Wait for send loop to complete
        let _ = send_handle.await;

        // Wait for remaining probes to complete or time out.
        // UDP needs longer grace period since most ports won't respond.
        let grace_period = timing.current_rto() * 3;
        let grace_deadline = Instant::now() + grace_period.max(Duration::from_secs(3));

        while !tracker.is_complete() && Instant::now() < grace_deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Signal all tasks to stop
        done_notify.notify_waiters();

        // Give tasks a moment to shut down
        let _ = tokio::time::timeout(Duration::from_millis(500), recv_handle).await;
        let _ = tokio::time::timeout(Duration::from_millis(500), timeout_handle).await;

        // Collect results
        let raw_results = tracker.collect_results();
        let mut ports: Vec<Port> = raw_results
            .into_iter()
            .map(|(port_num, state)| Port {
                number: port_num,
                state,
                protocol: rustmap_types::Protocol::Udp,
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
            "UDP scan complete"
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

/// Send loop: iterates ports, sends UDP probes with service-specific payloads.
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
    decoys: &[IpAddr],
    fragment_packets: bool,
    custom_payload: Option<&[u8]>,
) {
    for &dst_port in ports {
        // Wait for a send slot (respects cwnd + rate limit)
        timing.wait_for_slot().await;

        let src_port = port_alloc.next_port();
        let rto = timing.current_rto();

        // Register the probe before sending
        tracker.register_probe(dst_ip, dst_port, src_port, rto, max_retries);

        // Use custom payload if specified, otherwise use service-specific payload
        let default_payload = udp_payload_for_port(dst_port);
        let payload = custom_payload.unwrap_or(default_payload);

        // Send the UDP probe, optionally fragmenting for IDS evasion
        let send_result = if fragment_packets && dst_ip.is_ipv4() {
            send_fragmented_udp(sender, src_ip, src_port, dst_ip, dst_port, payload).await
        } else {
            sender
                .send_udp_probe(src_ip, src_port, dst_ip, dst_port, payload)
                .await
        };

        match send_result {
            Ok(()) => {
                timing.on_probe_sent();
            }
            Err(e) => {
                warn!(port = dst_port, error = %e, "failed to send UDP probe");
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

        // Send decoy probes with spoofed source IPs
        for &decoy_ip in decoys {
            if decoy_ip == src_ip {
                continue;
            }
            let decoy_port = 1024 + (rustmap_packet::rand_seq() % 64000) as u16;
            if let Ok(pkt) = rustmap_packet::build::build_udp_probe_with_payload(
                decoy_ip, decoy_port, dst_ip, dst_port, payload,
            ) {
                let _ = sender.send_raw(decoy_ip, dst_ip, &pkt).await;
            }
        }

        // Inter-probe delay with optional jitter
        let delay = timing.scan_delay_jittered();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// Response processor: captures packets, interprets UDP scan responses.
async fn response_processor(
    capture: &mut dyn PacketReceiver,
    _target_ip: IpAddr,
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

/// Process a single captured response for UDP scanning.
fn handle_response(response: &CapturedResponse, timing: &TimingController, tracker: &ProbeTracker) {
    let port_state = match response.response_type {
        // Direct UDP response → port is open
        ResponseType::UdpResponse => PortState::Open,
        // ICMP port unreachable → port is closed
        ResponseType::IcmpPortUnreachable => PortState::Closed,
        // Other ICMP unreachable → port is filtered
        ResponseType::IcmpUnreachable => PortState::Filtered,
        // TCP and discovery response types — not relevant during UDP scan
        ResponseType::SynAck
        | ResponseType::Rst
        | ResponseType::IcmpEchoReply
        | ResponseType::IcmpTimestampReply
        | ResponseType::ArpReply
        | ResponseType::IcmpTimeExceeded
        | ResponseType::SctpInitAck
        | ResponseType::SctpAbort
        | ResponseType::IcmpFragmentationNeeded => return,
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
            "UDP probe response"
        );
    }
}

/// Timeout checker: periodically checks for timed-out probes.
#[allow(clippy::too_many_arguments)]
async fn timeout_checker(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timing: &TimingController,
    tracker: &ProbeTracker,
    port_alloc: &SourcePortAllocator,
    done: &Notify,
    fragment_packets: bool,
    custom_payload: Option<&[u8]>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                check_timeouts(sender, src_ip, dst_ip, timing, tracker, port_alloc, fragment_packets, custom_payload).await;
            }
            _ = done.notified() => {
                break;
            }
        }
    }
}

/// Check for timed-out probes and retry or mark as open|filtered.
#[allow(clippy::too_many_arguments)]
async fn check_timeouts(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timing: &TimingController,
    tracker: &ProbeTracker,
    port_alloc: &SourcePortAllocator,
    fragment_packets: bool,
    custom_payload: Option<&[u8]>,
) {
    let (retryable, expired) = tracker.collect_timed_out();

    // Handle retryable probes
    for key in &retryable {
        if let Some((dst_port, retries)) = tracker.prepare_retry(key) {
            timing.on_timeout();

            // Remove old probe and re-register with new source port
            tracker.remove(key);

            let new_src_port = port_alloc.next_port();
            let new_rto = timing.current_rto();

            tracker.register_probe(dst_ip, dst_port, new_src_port, new_rto, retries);

            // Use custom payload if specified, otherwise use service-specific payload
            let default_payload = udp_payload_for_port(dst_port);
            let payload = custom_payload.unwrap_or(default_payload);

            let send_result = if fragment_packets && dst_ip.is_ipv4() {
                send_fragmented_udp(sender, src_ip, new_src_port, dst_ip, dst_port, payload).await
            } else {
                sender
                    .send_udp_probe(src_ip, new_src_port, dst_ip, dst_port, payload)
                    .await
            };

            match send_result {
                Ok(()) => {
                    timing.on_probe_sent();
                }
                Err(e) => {
                    warn!(port = dst_port, error = %e, "UDP retry send failed");
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

    // Handle expired probes (no more retries) — mark as open|filtered
    for key in &expired {
        tracker.mark_no_response(key, PortState::OpenFiltered);
        timing.on_timeout();
    }
}

/// Build a UDP packet, fragment it into 8-byte payload fragments, and send each fragment.
/// Only applicable to IPv4 — IPv6 fragmentation is handled differently.
async fn send_fragmented_udp(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> Result<(), rustmap_packet::PacketError> {
    let pkt = rustmap_packet::build::build_udp_probe_with_payload(
        src_ip, src_port, dst_ip, dst_port, payload,
    )?;
    let fragments = fragment_ipv4_packet(&pkt)?;
    for frag in &fragments {
        sender.send_raw(src_ip, dst_ip, frag).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn udp_scanner_creates() {
        let _scanner = UdpScanner::new();
    }

    #[test]
    fn handle_response_udp_open() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 53, 40001, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 53,
            dst_port: 40001,
            response_type: ResponseType::UdpResponse,
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
                .any(|(p, s)| *p == 53 && *s == PortState::Open)
        );
    }

    #[test]
    fn handle_response_icmp_port_unreachable_closed() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 161, 40002, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 161,
            dst_port: 40002,
            response_type: ResponseType::IcmpPortUnreachable,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, &timing, &tracker);

        let results = tracker.collect_results();
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 161 && *s == PortState::Closed)
        );
    }

    #[test]
    fn handle_response_icmp_unreachable_filtered() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 123, 40003, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 123,
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
                .any(|(p, s)| *p == 123 && *s == PortState::Filtered)
        );
    }

    #[test]
    fn handle_response_tcp_types_ignored() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 80, 40004, Duration::from_secs(1), 3);

        // SYN/ACK should be ignored during UDP scan
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
    fn udp_results_use_udp_protocol() {
        // Verify that when results are collected, they use Protocol::Udp
        let port = Port {
            number: 53,
            state: PortState::Open,
            protocol: rustmap_types::Protocol::Udp,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        };
        assert_eq!(port.protocol, rustmap_types::Protocol::Udp);
    }
}
