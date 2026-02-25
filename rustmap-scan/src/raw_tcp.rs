use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use rustmap_packet::{
    CaptureConfig, CapturedResponse, PacketReceiver, PacketSender, ResponseType, TcpFlags,
    create_capture, fixed_port_bpf_filter, fragment_ipv4_packet, rand_seq,
};
use rustmap_timing::{TimingController, TimingParams};
use rustmap_types::{Host, HostScanResult, Port, PortState, ScanConfig, TimingSnapshot};

use crate::probe::{ProbeKey, ProbeTracker};
use crate::response_policy::ResponsePolicy;
use crate::source_port::SourcePortAllocator;
use crate::traits::{ScanError, Scanner};

/// Generic raw TCP scanner parameterized by TCP flags and response policy.
///
/// Supports all raw TCP scan types: SYN, FIN, NULL, Xmas, ACK, Window, Maimon.
/// The only differences between scan types are the outgoing TCP flags and how
/// responses map to `PortState` (captured by `ResponsePolicy`).
///
/// Runs three concurrent tasks:
/// 1. **Send loop**: iterates ports, respects cwnd/rate limits, sends probes
/// 2. **Response processor**: captures packets, correlates to probes, updates timing
/// 3. **Timeout checker**: periodically checks for timed-out probes, retries or marks no-response
pub struct RawTcpScanner {
    flags: TcpFlags,
    policy: ResponsePolicy,
    scan_name: &'static str,
}

impl RawTcpScanner {
    /// Create a SYN scanner (SYN flag only).
    pub fn syn() -> Self {
        Self {
            flags: TcpFlags::SYN,
            policy: ResponsePolicy::syn_scan(),
            scan_name: "SYN",
        }
    }

    /// Create a FIN scanner (FIN flag only).
    pub fn fin() -> Self {
        Self {
            flags: TcpFlags::FIN,
            policy: ResponsePolicy::fin_scan(),
            scan_name: "FIN",
        }
    }

    /// Create a NULL scanner (no flags).
    pub fn null() -> Self {
        Self {
            flags: TcpFlags::NONE,
            policy: ResponsePolicy::null_scan(),
            scan_name: "NULL",
        }
    }

    /// Create a Xmas scanner (FIN+PSH+URG).
    pub fn xmas() -> Self {
        Self {
            flags: TcpFlags::XMAS,
            policy: ResponsePolicy::xmas_scan(),
            scan_name: "Xmas",
        }
    }

    /// Create an ACK scanner (ACK flag only).
    pub fn ack() -> Self {
        Self {
            flags: TcpFlags::ACK,
            policy: ResponsePolicy::ack_scan(),
            scan_name: "ACK",
        }
    }

    /// Create a Window scanner (ACK flag, examines RST window size).
    pub fn window() -> Self {
        Self {
            flags: TcpFlags::ACK,
            policy: ResponsePolicy::window_scan(),
            scan_name: "Window",
        }
    }

    /// Create a Maimon scanner (FIN+ACK).
    pub fn maimon() -> Self {
        Self {
            flags: TcpFlags::MAIMON,
            policy: ResponsePolicy::maimon_scan(),
            scan_name: "Maimon",
        }
    }
}

#[async_trait]
impl Scanner for RawTcpScanner {
    async fn scan_host(
        &self,
        host: &Host,
        config: &ScanConfig,
    ) -> Result<HostScanResult, ScanError> {
        let start = Instant::now();
        let target_ip = host.ip;
        let scan_name = self.scan_name;

        info!(target = %target_ip, ports = config.ports.len(), scan = scan_name, "starting raw TCP scan");

        // Create timing controller from template, applying learned + CLI overrides
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

        // Create packet sender and capture on the same interface
        let sender: Arc<dyn PacketSender> = Arc::from(rustmap_packet::create_sender_with_options(
            target_ip,
            config.spoof_mac,
        )?);

        // Use fixed-port BPF filter when source port is specified
        let bpf_filter = match config.source_port {
            Some(port) => fixed_port_bpf_filter(port),
            None => rustmap_packet::capture::default_bpf_filter(),
        };
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
        let flags = self.flags;
        let no_response_state = self.policy.on_no_response;
        let decoys = config.decoys.clone();
        let fragment_packets = config.fragment_packets;
        let ip_ttl = config.ip_ttl;
        let badsum = config.badsum;

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
                    flags,
                    no_response_state,
                    &decoys,
                    fragment_packets,
                    ip_ttl,
                    badsum,
                )
                .await;
                debug!(scan = scan_name, "send loop finished");
                done_notify.notify_one();
            })
        };

        let recv_handle = {
            let timing = timing.clone();
            let tracker = tracker.clone();
            let done_notify = done_notify.clone();
            let policy = self.policy.clone();

            tokio::spawn(async move {
                response_processor(
                    &mut capture,
                    target_ip,
                    &timing,
                    &tracker,
                    &done_notify,
                    &policy,
                )
                .await;
                debug!(scan = scan_name, "response processor finished");
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
                    flags,
                    no_response_state,
                    fragment_packets,
                    ip_ttl,
                    badsum,
                )
                .await;
                debug!(scan = scan_name, "timeout checker finished");
            })
        };

        // Wait for send loop to complete
        let _ = send_handle.await;

        // Wait for remaining probes to complete or time out.
        // Give a grace period of 2x the current RTO.
        let grace_period = timing.current_rto() * 2;
        let grace_deadline = Instant::now() + grace_period.max(Duration::from_secs(2));

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
                protocol: rustmap_types::Protocol::Tcp,
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
            scan = scan_name,
            ports_scanned = ports.len(),
            probes_sent = stats.probes_sent,
            probes_completed = stats.probes_completed,
            srtt_ms = stats.srtt.map(|d| d.as_millis()),
            duration_ms = start.elapsed().as_millis(),
            "raw TCP scan complete"
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

/// Send loop: iterates ports, sends TCP probes with configured flags.
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
    flags: TcpFlags,
    no_response_state: PortState,
    decoys: &[IpAddr],
    fragment_packets: bool,
    ip_ttl: Option<u8>,
    badsum: bool,
) {
    for &dst_port in ports {
        // Wait for a send slot (respects cwnd + rate limit)
        timing.wait_for_slot().await;

        let src_port = port_alloc.next_port();
        let rto = timing.current_rto();

        // Register the probe before sending
        tracker.register_probe(dst_ip, dst_port, src_port, rto, max_retries);

        // Send the TCP packet, optionally with TTL/badsum overrides and fragmentation
        let send_result = if ip_ttl.is_some() || badsum {
            // Build packet manually to apply evasion overrides
            match rustmap_packet::build::build_tcp_packet(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                rand_seq(),
                flags,
            ) {
                Ok(mut pkt) => {
                    if let Some(ttl) = ip_ttl {
                        rustmap_packet::build::patch_ip_ttl(&mut pkt, ttl);
                    }
                    if badsum {
                        rustmap_packet::build::corrupt_checksum(&mut pkt);
                    }
                    if fragment_packets && dst_ip.is_ipv4() {
                        send_fragmented_raw(sender, &pkt, dst_ip).await
                    } else {
                        sender.send_raw(src_ip, dst_ip, &pkt).await
                    }
                }
                Err(e) => Err(e),
            }
        } else if fragment_packets && dst_ip.is_ipv4() {
            send_fragmented_tcp(sender, src_ip, src_port, dst_ip, dst_port, flags).await
        } else {
            sender
                .send_tcp_flags(src_ip, src_port, dst_ip, dst_port, flags)
                .await
        };

        match send_result {
            Ok(()) => {
                timing.on_probe_sent();
            }
            Err(e) => {
                warn!(port = dst_port, error = %e, "failed to send probe");
                tracker.mark_no_response(
                    &ProbeKey {
                        dst_ip,
                        dst_port,
                        src_port,
                    },
                    no_response_state,
                );
                timing.on_drop();
            }
        }

        // Send decoy probes with spoofed source IPs
        for &decoy_ip in decoys {
            if decoy_ip == src_ip {
                continue; // Skip our own IP
            }
            let decoy_port = 1024 + (rand_seq() % 64000) as u16;
            if let Ok(pkt) = rustmap_packet::build::build_tcp_packet(
                decoy_ip,
                decoy_port,
                dst_ip,
                dst_port,
                rand_seq(),
                flags,
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

/// Response processor: captures packets, correlates to probes using the response policy.
async fn response_processor(
    capture: &mut dyn PacketReceiver,
    target_ip: IpAddr,
    timing: &TimingController,
    tracker: &ProbeTracker,
    done: &Notify,
    policy: &ResponsePolicy,
) {
    loop {
        tokio::select! {
            result = capture.recv() => {
                match result {
                    Ok(response) => {
                        handle_response(&response, target_ip, timing, tracker, policy);
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

/// Process a single captured response using the response policy.
fn handle_response(
    response: &CapturedResponse,
    _target_ip: IpAddr,
    timing: &TimingController,
    tracker: &ProbeTracker,
    policy: &ResponsePolicy,
) {
    let port_state = match response.response_type {
        ResponseType::SynAck => {
            match policy.on_syn_ack {
                Some(state) => state,
                None => return, // This scan type ignores SYN/ACK
            }
        }
        ResponseType::Rst => {
            if policy.check_rst_window {
                // Window scan: examine the TCP window size in the RST response
                let window_size = response
                    .tcp_fingerprint
                    .as_ref()
                    .map(|fp| fp.window_size)
                    .unwrap_or(0);
                if window_size > 0 {
                    PortState::Open
                } else {
                    PortState::Closed
                }
            } else {
                match policy.on_rst {
                    Some(state) => state,
                    None => return, // Shouldn't happen if not check_rst_window, but be safe
                }
            }
        }
        ResponseType::IcmpUnreachable => policy.on_icmp_unreachable,
        // UDP and discovery-only response types — not relevant during TCP scan
        ResponseType::IcmpPortUnreachable
        | ResponseType::UdpResponse
        | ResponseType::IcmpEchoReply
        | ResponseType::IcmpTimestampReply
        | ResponseType::ArpReply
        | ResponseType::IcmpTimeExceeded
        | ResponseType::SctpInitAck
        | ResponseType::SctpAbort
        | ResponseType::IcmpFragmentationNeeded => return,
    };

    // dst_port in the response is our source port (for correlation)
    // src_port in the response is the target's port
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
            "probe response"
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
    flags: TcpFlags,
    no_response_state: PortState,
    fragment_packets: bool,
    ip_ttl: Option<u8>,
    badsum: bool,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                check_timeouts(sender, src_ip, dst_ip, timing, tracker, port_alloc, flags, no_response_state, fragment_packets, ip_ttl, badsum).await;
            }
            _ = done.notified() => {
                break;
            }
        }
    }
}

/// Check for timed-out probes and retry or mark with appropriate no-response state.
#[allow(clippy::too_many_arguments)]
async fn check_timeouts(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timing: &TimingController,
    tracker: &ProbeTracker,
    port_alloc: &SourcePortAllocator,
    flags: TcpFlags,
    no_response_state: PortState,
    fragment_packets: bool,
    ip_ttl: Option<u8>,
    badsum: bool,
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

            let send_result = if ip_ttl.is_some() || badsum {
                match rustmap_packet::build::build_tcp_packet(
                    src_ip,
                    new_src_port,
                    dst_ip,
                    dst_port,
                    rand_seq(),
                    flags,
                ) {
                    Ok(mut pkt) => {
                        if let Some(ttl) = ip_ttl {
                            rustmap_packet::build::patch_ip_ttl(&mut pkt, ttl);
                        }
                        if badsum {
                            rustmap_packet::build::corrupt_checksum(&mut pkt);
                        }
                        if fragment_packets && dst_ip.is_ipv4() {
                            send_fragmented_raw(sender, &pkt, dst_ip).await
                        } else {
                            sender.send_raw(src_ip, dst_ip, &pkt).await
                        }
                    }
                    Err(e) => Err(e),
                }
            } else if fragment_packets && dst_ip.is_ipv4() {
                send_fragmented_tcp(sender, src_ip, new_src_port, dst_ip, dst_port, flags).await
            } else {
                sender
                    .send_tcp_flags(src_ip, new_src_port, dst_ip, dst_port, flags)
                    .await
            };

            match send_result {
                Ok(()) => {
                    timing.on_probe_sent();
                }
                Err(e) => {
                    warn!(port = dst_port, error = %e, "retry send failed");
                    tracker.mark_no_response(
                        &ProbeKey {
                            dst_ip,
                            dst_port,
                            src_port: new_src_port,
                        },
                        no_response_state,
                    );
                    timing.on_drop();
                }
            }
        }
    }

    // Handle expired probes (no more retries)
    for key in &expired {
        tracker.mark_no_response(key, no_response_state);
        timing.on_timeout();
    }
}

/// Build a TCP packet, fragment it into 8-byte payload fragments, and send each fragment.
/// Only applicable to IPv4 — IPv6 fragmentation is handled differently.
async fn send_fragmented_tcp(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    flags: TcpFlags,
) -> Result<(), rustmap_packet::PacketError> {
    let pkt = rustmap_packet::build::build_tcp_packet(
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        rand_seq(),
        flags,
    )?;
    let fragments = fragment_ipv4_packet(&pkt)?;
    for frag in &fragments {
        sender.send_raw(src_ip, dst_ip, frag).await?;
    }
    Ok(())
}

/// Fragment and send a pre-built IP packet (used when TTL/badsum overrides are active).
async fn send_fragmented_raw(
    sender: &dyn PacketSender,
    packet: &[u8],
    dst_ip: IpAddr,
) -> Result<(), rustmap_packet::PacketError> {
    let src_ip = if packet.len() >= 20 {
        IpAddr::V4(std::net::Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))
    } else {
        dst_ip
    };
    let fragments = fragment_ipv4_packet(packet)?;
    for frag in &fragments {
        sender.send_raw(src_ip, dst_ip, frag).await?;
    }
    Ok(())
}

/// Get the source IP for reaching a target via UDP connect trick.
/// Falls back to the unspecified address (0.0.0.0 or ::) rather than the
/// target IP, which would produce src==dst packets.
pub(crate) fn get_sender_src_ip(target_ip: IpAddr) -> IpAddr {
    let bind_addr = match target_ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    if let Ok(socket) = std::net::UdpSocket::bind(bind_addr) {
        let addr = std::net::SocketAddr::new(target_ip, 80);
        if socket.connect(addr).is_ok()
            && let Ok(local) = socket.local_addr()
        {
            return local.ip();
        }
    }
    match target_ip {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn syn_scanner_creates() {
        let scanner = RawTcpScanner::syn();
        assert_eq!(scanner.flags, TcpFlags::SYN);
        assert_eq!(scanner.scan_name, "SYN");
    }

    #[test]
    fn fin_scanner_creates() {
        let scanner = RawTcpScanner::fin();
        assert_eq!(scanner.flags, TcpFlags::FIN);
        assert_eq!(scanner.scan_name, "FIN");
    }

    #[test]
    fn null_scanner_creates() {
        let scanner = RawTcpScanner::null();
        assert_eq!(scanner.flags, TcpFlags::NONE);
        assert_eq!(scanner.scan_name, "NULL");
    }

    #[test]
    fn xmas_scanner_creates() {
        let scanner = RawTcpScanner::xmas();
        assert_eq!(scanner.flags, TcpFlags::XMAS);
        assert_eq!(scanner.scan_name, "Xmas");
    }

    #[test]
    fn ack_scanner_creates() {
        let scanner = RawTcpScanner::ack();
        assert_eq!(scanner.flags, TcpFlags::ACK);
        assert_eq!(scanner.scan_name, "ACK");
    }

    #[test]
    fn window_scanner_creates() {
        let scanner = RawTcpScanner::window();
        assert_eq!(scanner.flags, TcpFlags::ACK); // Same flags as ACK
        assert!(scanner.policy.check_rst_window);
        assert_eq!(scanner.scan_name, "Window");
    }

    #[test]
    fn maimon_scanner_creates() {
        let scanner = RawTcpScanner::maimon();
        assert_eq!(scanner.flags, TcpFlags::MAIMON);
        assert_eq!(scanner.scan_name, "Maimon");
    }

    #[test]
    fn handle_response_syn_ack_with_syn_policy() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();
        let policy = ResponsePolicy::syn_scan();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        tracker.register_probe(ip, 80, 40001, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 80,
            dst_port: 40001,
            response_type: ResponseType::SynAck,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, ip, &timing, &tracker, &policy);

        let results = tracker.collect_results();
        assert_eq!(results.len(), 1);
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 80 && *s == PortState::Open)
        );
    }

    #[test]
    fn handle_response_rst_with_fin_policy() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();
        let policy = ResponsePolicy::fin_scan();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 443, 40002, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 443,
            dst_port: 40002,
            response_type: ResponseType::Rst,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, ip, &timing, &tracker, &policy);

        let results = tracker.collect_results();
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 443 && *s == PortState::Closed)
        );
    }

    #[test]
    fn handle_response_rst_with_ack_policy() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();
        let policy = ResponsePolicy::ack_scan();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 22, 40003, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 22,
            dst_port: 40003,
            response_type: ResponseType::Rst,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, ip, &timing, &tracker, &policy);

        let results = tracker.collect_results();
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 22 && *s == PortState::Unfiltered)
        );
    }

    #[test]
    fn handle_response_rst_window_scan_open() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();
        let policy = ResponsePolicy::window_scan();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 80, 40004, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 80,
            dst_port: 40004,
            response_type: ResponseType::Rst,
            timestamp: Instant::now(),
            tcp_fingerprint: Some(rustmap_types::TcpFingerprint {
                initial_ttl: 64,
                window_size: 1024, // Non-zero → open
                tcp_options: vec![],
                df_bit: true,
                mss: None,
            }),
            next_hop_mtu: None,
        };

        handle_response(&response, ip, &timing, &tracker, &policy);

        let results = tracker.collect_results();
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 80 && *s == PortState::Open)
        );
    }

    #[test]
    fn handle_response_rst_window_scan_closed() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();
        let policy = ResponsePolicy::window_scan();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 443, 40005, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 443,
            dst_port: 40005,
            response_type: ResponseType::Rst,
            timestamp: Instant::now(),
            tcp_fingerprint: Some(rustmap_types::TcpFingerprint {
                initial_ttl: 128,
                window_size: 0, // Zero → closed
                tcp_options: vec![],
                df_bit: false,
                mss: None,
            }),
            next_hop_mtu: None,
        };

        handle_response(&response, ip, &timing, &tracker, &policy);

        let results = tracker.collect_results();
        assert!(
            results
                .iter()
                .any(|(p, s)| *p == 443 && *s == PortState::Closed)
        );
    }

    #[test]
    fn handle_response_syn_ack_ignored_by_fin_policy() {
        let timing = TimingController::new(TimingParams::from_template(
            rustmap_types::TimingTemplate::Normal,
        ));
        let tracker = ProbeTracker::new();
        let policy = ResponsePolicy::fin_scan();

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.register_probe(ip, 80, 40006, Duration::from_secs(1), 3);

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 80,
            dst_port: 40006,
            response_type: ResponseType::SynAck,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_response(&response, ip, &timing, &tracker, &policy);

        // SYN/ACK is ignored by FIN scan policy, so no results recorded
        let results = tracker.collect_results();
        assert!(results.is_empty());
    }
}
