use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tracing::{debug, info, warn};

use rustmap_packet::{
    CaptureConfig, CapturedResponse, PacketReceiver, PacketSender, ResponseType, create_capture,
    create_sender,
};
use rustmap_timing::{TimingController, TimingParams};
use rustmap_types::{
    DiscoveryConfig, DiscoveryMethod, DiscoveryMode, Host, HostStatus, TimingTemplate,
};

use crate::discovery_tracker::{DiscoveryResult, DiscoveryTracker};
use crate::source_port::SourcePortAllocator;
use crate::traits::ScanError;

/// Host discovery engine.
///
/// Determines which target hosts are alive before port scanning.
/// Sends various probe types (ICMP echo, TCP SYN/ACK, UDP, etc.)
/// and listens for responses. Any response marks a host as "up".
pub struct HostDiscovery;

impl HostDiscovery {
    /// Discover which hosts are alive.
    pub async fn discover(
        targets: &[Host],
        config: &DiscoveryConfig,
        timing_template: TimingTemplate,
        privileged: bool,
    ) -> Result<Vec<DiscoveryResult>, ScanError> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        let target_ips: Vec<IpAddr> = targets.iter().map(|h| h.ip).collect();

        // Determine which methods to use
        let methods = resolve_methods(config, privileged);

        if methods.is_empty() {
            // No discovery methods available — treat all as up
            info!("no discovery methods available, treating all hosts as up");
            return Ok(target_ips
                .iter()
                .map(|&ip| DiscoveryResult {
                    ip,
                    status: HostStatus::Up,
                    latency: None,
                })
                .collect());
        }

        // Partition methods into raw-packet vs HTTP-based
        let raw_methods: Vec<DiscoveryMethod> = methods
            .iter()
            .filter(|m| !matches!(m, DiscoveryMethod::HttpPing | DiscoveryMethod::HttpsPing))
            .copied()
            .collect();
        let http_methods: Vec<DiscoveryMethod> = methods
            .iter()
            .filter(|m| matches!(m, DiscoveryMethod::HttpPing | DiscoveryMethod::HttpsPing))
            .copied()
            .collect();

        let mut results = Vec::new();

        // Run raw-packet discovery if privileged and methods exist.
        // Errors are logged but don't abort — HTTP discovery can still run.
        // Hard cap prevents hanging on external hosts where raw probes are filtered.
        if privileged && !raw_methods.is_empty() {
            let raw_timeout = Duration::from_secs(5);
            match tokio::time::timeout(
                raw_timeout,
                discover_privileged(&target_ips, &raw_methods, config, timing_template),
            )
            .await
            {
                Ok(Ok(r)) => results = r,
                Ok(Err(e)) => {
                    warn!(error = %e, "raw packet discovery failed, continuing with other methods");
                }
                Err(_) => {
                    warn!("raw packet discovery timed out after 5s, falling back to TCP connect");
                }
            }
        }

        // Run HTTP-based discovery if methods exist
        if !http_methods.is_empty() {
            let http_results = discover_http(&target_ips, &http_methods, config).await?;
            if results.is_empty() {
                results = http_results;
            } else {
                // Merge: any host Up in HTTP results upgrades existing entries,
                // and IPs only found via HTTP are appended.
                for hr in http_results {
                    if let Some(existing) = results.iter_mut().find(|r| r.ip == hr.ip) {
                        if hr.status == HostStatus::Up {
                            existing.status = HostStatus::Up;
                            if existing.latency.is_none() {
                                existing.latency = hr.latency;
                            }
                        }
                    } else {
                        // IP was not in raw results — add it
                        results.push(hr);
                    }
                }
            }
        }

        // TCP connect fallback: used when unprivileged, when raw discovery found
        // zero live hosts, or when raw discovery timed out (empty results while
        // privileged). Common on Windows with Npcap for external hosts.
        let any_up = results.iter().any(|r| r.status == HostStatus::Up);
        if results.is_empty() {
            info!("no raw discovery results — using TCP connect ping");
            results = discover_unprivileged(&target_ips, config).await?;
        } else if !any_up {
            warn!("raw discovery found no live hosts — falling back to TCP connect discovery");
            let connect_results = discover_unprivileged(&target_ips, config).await?;
            for cr in connect_results {
                if cr.status == HostStatus::Up
                    && let Some(existing) = results.iter_mut().find(|r| r.ip == cr.ip)
                {
                    existing.status = HostStatus::Up;
                    if existing.latency.is_none() {
                        existing.latency = cr.latency;
                    }
                }
            }
        }

        // If still no results at all (edge case), treat as unknown — not down.
        // Unknown hosts proceed to port scanning which makes the final determination.
        if results.is_empty() {
            results = target_ips
                .iter()
                .map(|&ip| DiscoveryResult {
                    ip,
                    status: HostStatus::Unknown,
                    latency: None,
                })
                .collect();
        }

        Ok(results)
    }
}

/// Resolve which discovery methods to use based on config and privileges.
fn resolve_methods(config: &DiscoveryConfig, privileged: bool) -> Vec<DiscoveryMethod> {
    match &config.mode {
        DiscoveryMode::Skip => vec![], // -Pn: no discovery
        DiscoveryMode::Custom(methods) => methods.clone(),
        DiscoveryMode::Default | DiscoveryMode::PingOnly => {
            if privileged {
                // Default privileged: ARP (same-subnet) + ICMP echo + TCP SYN 443 +
                // TCP ACK 80 + ICMP timestamp. ARP is first because it's the most
                // reliable for local subnet targets.
                vec![
                    DiscoveryMethod::ArpPing,
                    DiscoveryMethod::IcmpEcho,
                    DiscoveryMethod::TcpSyn,
                    DiscoveryMethod::TcpAck,
                    DiscoveryMethod::IcmpTimestamp,
                ]
            } else {
                // Default unprivileged: TCP connect ping (handled separately)
                vec![]
            }
        }
    }
}

/// Privileged discovery using raw packets.
async fn discover_privileged(
    targets: &[IpAddr],
    methods: &[DiscoveryMethod],
    config: &DiscoveryConfig,
    timing_template: TimingTemplate,
) -> Result<Vec<DiscoveryResult>, ScanError> {
    let params = TimingParams::from_template(timing_template);
    let timing = Arc::new(TimingController::new(params));

    // Pick a representative target for sender/interface selection
    let representative_ip = targets[0];
    let sender: Arc<dyn PacketSender> = Arc::from(create_sender(representative_ip)?);
    let mut capture = create_capture(CaptureConfig {
        interface: sender.interface_name().map(String::from),
        bpf_filter: discovery_bpf_filter(),
        ..CaptureConfig::default()
    })?;

    let src_ip = get_src_ip(representative_ip);

    let tracker = Arc::new(DiscoveryTracker::new(targets));
    let port_alloc = Arc::new(SourcePortAllocator::new());
    let done_notify = Arc::new(Notify::new());

    let total = targets.len();
    let icmp_id = std::process::id() as u16;

    info!(
        targets = total,
        methods = methods.len(),
        "starting host discovery"
    );

    // Clone data for tasks
    let targets_owned: Vec<IpAddr> = targets.to_vec();
    let methods_owned: Vec<DiscoveryMethod> = methods.to_vec();
    let tcp_syn_ports = config.tcp_syn_ports.clone();
    let tcp_ack_ports = config.tcp_ack_ports.clone();
    let udp_ports = config.udp_ports.clone();

    // Task 1: Send probes
    let send_handle = {
        let sender = sender.clone();
        let timing = timing.clone();
        let tracker = tracker.clone();
        let port_alloc = port_alloc.clone();
        let done_notify = done_notify.clone();

        tokio::spawn(async move {
            discovery_send_loop(
                &*sender,
                src_ip,
                &targets_owned,
                &methods_owned,
                &tcp_syn_ports,
                &tcp_ack_ports,
                &udp_ports,
                icmp_id,
                &timing,
                &tracker,
                &port_alloc,
            )
            .await;
            debug!("discovery send loop finished");
            done_notify.notify_one();
        })
    };

    // Task 2: Response processor
    let recv_handle = {
        let timing = timing.clone();
        let tracker = tracker.clone();
        let done_notify = done_notify.clone();

        tokio::spawn(async move {
            discovery_response_processor(&mut capture, &timing, &tracker, &done_notify).await;
            debug!("discovery response processor finished");
        })
    };

    // Wait for send loop to complete
    let _ = send_handle.await;

    // Grace period: wait for remaining responses
    let grace = timing.current_rto() * 2;
    let grace_deadline = Instant::now() + grace.max(Duration::from_secs(2));

    while !tracker.all_resolved() && Instant::now() < grace_deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Stop
    done_notify.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_millis(500), recv_handle).await;

    let results = tracker.collect_results();
    let up = results
        .iter()
        .filter(|r| r.status == HostStatus::Up)
        .count();

    info!(
        total = total,
        up = up,
        down = total - up,
        "host discovery complete"
    );

    Ok(results)
}

/// Send discovery probes for all targets.
#[allow(clippy::too_many_arguments)]
async fn discovery_send_loop(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    targets: &[IpAddr],
    methods: &[DiscoveryMethod],
    tcp_syn_ports: &[u16],
    tcp_ack_ports: &[u16],
    udp_ports: &[u16],
    icmp_id: u16,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
    port_alloc: &SourcePortAllocator,
) {
    for (seq, &target_ip) in targets.iter().enumerate() {
        // Use both id and seq fields to encode the full index, avoiding
        // truncation when there are more than 65535 targets.
        let icmp_id_override = (seq >> 16) as u16;
        let seq = (seq & 0xFFFF) as u16;

        for method in methods {
            // Skip if host already discovered
            if tracker.is_host_up(&target_ip) {
                break;
            }

            match method {
                DiscoveryMethod::IcmpEcho => {
                    send_icmp_echo(
                        sender,
                        src_ip,
                        target_ip,
                        icmp_id ^ icmp_id_override,
                        seq,
                        timing,
                        tracker,
                    )
                    .await;
                }
                DiscoveryMethod::TcpSyn => {
                    for &port in tcp_syn_ports {
                        send_tcp_syn_ping(
                            sender, src_ip, target_ip, port, timing, tracker, port_alloc,
                        )
                        .await;
                    }
                }
                DiscoveryMethod::TcpAck => {
                    for &port in tcp_ack_ports {
                        send_tcp_ack_ping(
                            sender, src_ip, target_ip, port, timing, tracker, port_alloc,
                        )
                        .await;
                    }
                }
                DiscoveryMethod::IcmpTimestamp => {
                    send_icmp_timestamp(
                        sender,
                        src_ip,
                        target_ip,
                        icmp_id ^ icmp_id_override,
                        seq,
                        timing,
                        tracker,
                    )
                    .await;
                }
                DiscoveryMethod::UdpPing => {
                    for &port in udp_ports {
                        send_udp_ping(sender, src_ip, target_ip, port, timing, tracker, port_alloc)
                            .await;
                    }
                }
                DiscoveryMethod::ArpPing => {
                    send_arp_ping(sender, src_ip, target_ip, timing, tracker).await;
                }
                DiscoveryMethod::HttpPing | DiscoveryMethod::HttpsPing => {
                    // Handled separately via discover_http(), not raw packets
                }
            }
        }
    }
}

async fn send_icmp_echo(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    id: u16,
    seq: u16,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
) {
    timing.wait_for_slot().await;
    tracker.on_probe_sent(dst_ip);

    let pkt = match rustmap_packet::build::build_icmp_echo_packet(src_ip, dst_ip, id, seq) {
        Ok(p) => p,
        Err(e) => {
            warn!(target_ip = %dst_ip, error = %e, "failed to build ICMP echo packet");
            timing.on_drop();
            return;
        }
    };
    match sender.send_raw(src_ip, dst_ip, &pkt).await {
        Ok(()) => timing.on_probe_sent(),
        Err(e) => {
            warn!(target_ip = %dst_ip, error = %e, "failed to send ICMP echo");
            timing.on_drop();
        }
    }
}

async fn send_tcp_syn_ping(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
    port_alloc: &SourcePortAllocator,
) {
    timing.wait_for_slot().await;
    let src_port = port_alloc.next_port();
    tracker.on_probe_sent(dst_ip);

    match sender
        .send_tcp_syn(src_ip, src_port, dst_ip, dst_port)
        .await
    {
        Ok(()) => timing.on_probe_sent(),
        Err(e) => {
            warn!(target_ip = %dst_ip, port = dst_port, error = %e, "failed to send TCP SYN ping");
            timing.on_drop();
        }
    }
}

async fn send_tcp_ack_ping(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
    port_alloc: &SourcePortAllocator,
) {
    timing.wait_for_slot().await;
    let src_port = port_alloc.next_port();
    tracker.on_probe_sent(dst_ip);

    let pkt = match rustmap_packet::build::build_tcp_ack_packet(
        src_ip, src_port, dst_ip, dst_port, 0,
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!(target_ip = %dst_ip, port = dst_port, error = %e, "failed to build TCP ACK ping packet");
            timing.on_drop();
            return;
        }
    };
    match sender.send_raw(src_ip, dst_ip, &pkt).await {
        Ok(()) => timing.on_probe_sent(),
        Err(e) => {
            warn!(target_ip = %dst_ip, port = dst_port, error = %e, "failed to send TCP ACK ping");
            timing.on_drop();
        }
    }
}

async fn send_icmp_timestamp(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    id: u16,
    seq: u16,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
) {
    timing.wait_for_slot().await;
    tracker.on_probe_sent(dst_ip);

    let pkt = match rustmap_packet::build::build_icmp_timestamp_packet(src_ip, dst_ip, id, seq) {
        Ok(p) => p,
        Err(e) => {
            warn!(target_ip = %dst_ip, error = %e, "failed to build ICMP timestamp packet");
            timing.on_drop();
            return;
        }
    };
    match sender.send_raw(src_ip, dst_ip, &pkt).await {
        Ok(()) => timing.on_probe_sent(),
        Err(e) => {
            warn!(target_ip = %dst_ip, error = %e, "failed to send ICMP timestamp");
            timing.on_drop();
        }
    }
}

async fn send_udp_ping(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
    port_alloc: &SourcePortAllocator,
) {
    timing.wait_for_slot().await;
    let src_port = port_alloc.next_port();
    tracker.on_probe_sent(dst_ip);

    let pkt = match rustmap_packet::build::build_udp_probe_packet(
        src_ip, src_port, dst_ip, dst_port,
    ) {
        Ok(p) => p,
        Err(e) => {
            warn!(target_ip = %dst_ip, port = dst_port, error = %e, "failed to build UDP ping packet");
            timing.on_drop();
            return;
        }
    };
    match sender.send_raw(src_ip, dst_ip, &pkt).await {
        Ok(()) => timing.on_probe_sent(),
        Err(e) => {
            warn!(target_ip = %dst_ip, port = dst_port, error = %e, "failed to send UDP ping");
            timing.on_drop();
        }
    }
}

async fn send_arp_ping(
    sender: &dyn PacketSender,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
) {
    // ARP requires layer 2 access and a known local MAC
    let src_mac = match sender.local_mac() {
        Some(mac) => mac,
        None => {
            debug!(target_ip = %dst_ip, "ARP ping skipped: local MAC unavailable");
            return;
        }
    };

    // ARP only works with IPv4
    let (src_v4, dst_v4) = match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        _ => {
            debug!("ARP ping skipped: IPv6 not supported for ARP");
            return;
        }
    };

    timing.wait_for_slot().await;
    tracker.on_probe_sent(dst_ip);

    let frame = rustmap_packet::build::build_arp_request(src_mac, src_v4, dst_v4);
    match sender.send_ethernet_frame(&frame).await {
        Ok(()) => timing.on_probe_sent(),
        Err(e) => {
            warn!(target_ip = %dst_ip, error = %e, "failed to send ARP ping");
            timing.on_drop();
        }
    }
}

/// Response processor for discovery.
async fn discovery_response_processor(
    capture: &mut dyn PacketReceiver,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
    done: &Notify,
) {
    loop {
        tokio::select! {
            result = capture.recv() => {
                match result {
                    Ok(response) => {
                        handle_discovery_response(&response, timing, tracker);
                    }
                    Err(_) => {
                        debug!("discovery capture ended");
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

/// Process a single captured response for discovery.
fn handle_discovery_response(
    response: &CapturedResponse,
    timing: &TimingController,
    tracker: &DiscoveryTracker,
) {
    // For ICMP unreachable, the src_ip is the host that sent the unreachable
    // (which IS the target — it responded, so it's alive)
    let resp_ip = response.src_ip;

    // Check if this IP is one of our targets
    if !tracker.is_target(&resp_ip) {
        return;
    }

    // Any response type from a target = host is up
    match response.response_type {
        ResponseType::SynAck
        | ResponseType::Rst
        | ResponseType::IcmpEchoReply
        | ResponseType::IcmpTimestampReply
        | ResponseType::IcmpUnreachable
        | ResponseType::IcmpPortUnreachable
        | ResponseType::UdpResponse
        | ResponseType::ArpReply
        | ResponseType::IcmpTimeExceeded
        | ResponseType::SctpInitAck
        | ResponseType::SctpAbort
        | ResponseType::IcmpFragmentationNeeded => {
            if tracker.on_response(resp_ip) {
                let rtt = response.timestamp.elapsed();
                timing.on_response(rtt);
                debug!(
                    ip = %resp_ip,
                    response = ?response.response_type,
                    "host is up"
                );
            }
        }
    }
}

/// BPF filter for discovery capture.
fn discovery_bpf_filter() -> String {
    "icmp[icmptype] = icmp-echoreply \
     or icmp[icmptype] = icmp-tstampreply \
     or icmp[icmptype] = icmp-unreach \
     or (tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack) and dst portrange 40000-59999) \
     or (tcp[tcpflags] & tcp-rst != 0 and dst portrange 40000-59999) \
     or (udp and dst portrange 40000-59999) \
     or arp \
     or icmp6"
        .to_string()
}

/// Unprivileged discovery fallback using TCP connect.
async fn discover_unprivileged(
    targets: &[IpAddr],
    config: &DiscoveryConfig,
) -> Result<Vec<DiscoveryResult>, ScanError> {
    use tokio::net::TcpStream;
    use tokio::sync::Semaphore;

    let ports: Vec<u16> = if config.tcp_syn_ports.is_empty() && config.tcp_ack_ports.is_empty() {
        vec![80, 443]
    } else {
        let mut p = config.tcp_syn_ports.clone();
        p.extend_from_slice(&config.tcp_ack_ports);
        p.sort_unstable();
        p.dedup();
        p
    };

    let semaphore = Arc::new(Semaphore::new(100));
    let tracker = Arc::new(DiscoveryTracker::new(targets));
    let timeout = Duration::from_secs(3);

    let mut handles = Vec::new();

    for &ip in targets {
        for &port in &ports {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let tracker = tracker.clone();

            let handle = tokio::spawn(async move {
                let addr = std::net::SocketAddr::new(ip, port);
                let result = tokio::time::timeout(timeout, TcpStream::connect(addr)).await;
                match result {
                    Ok(Ok(_)) => {
                        // Connection succeeded — host is up
                        tracker.on_response(ip);
                    }
                    Ok(Err(e)) => {
                        // Connection refused (RST) — host is up.
                        // Use ErrorKind for reliable cross-locale detection.
                        if e.kind() == std::io::ErrorKind::ConnectionRefused
                            || e.kind() == std::io::ErrorKind::ConnectionReset
                        {
                            tracker.on_response(ip);
                        }
                    }
                    Err(_) => {
                        // Timeout — no response
                    }
                }
                drop(permit);
            });
            handles.push(handle);
        }
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(tracker.collect_results())
}

/// HTTP/HTTPS-based discovery using TCP connect.
///
/// For `HttpPing`: connects to HTTP ports and sends a minimal HEAD request.
/// For `HttpsPing`: TCP connect only (proves liveness without full TLS handshake).
/// Any successful connect or connection-refused counts as host up.
async fn discover_http(
    targets: &[IpAddr],
    methods: &[DiscoveryMethod],
    config: &DiscoveryConfig,
) -> Result<Vec<DiscoveryResult>, ScanError> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::sync::Semaphore;

    let tracker = Arc::new(DiscoveryTracker::new(targets));
    let semaphore = Arc::new(Semaphore::new(100));
    let timeout = Duration::from_secs(3);

    let mut handles = Vec::new();

    for &ip in targets {
        for method in methods {
            let ports: &[u16] = match method {
                DiscoveryMethod::HttpPing => &config.http_ports,
                DiscoveryMethod::HttpsPing => &config.https_ports,
                _ => continue,
            };
            let is_http = matches!(method, DiscoveryMethod::HttpPing);

            for &port in ports {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                let tracker = tracker.clone();

                let handle = tokio::spawn(async move {
                    let addr = std::net::SocketAddr::new(ip, port);
                    let result = tokio::time::timeout(timeout, TcpStream::connect(addr)).await;
                    match result {
                        Ok(Ok(mut stream)) => {
                            // Connection succeeded — host is up
                            if is_http {
                                // Send minimal HEAD request (best effort).
                                // IPv6 addresses must be bracketed in the Host header (RFC 2732).
                                let host = if ip.is_ipv6() {
                                    format!("[{ip}]")
                                } else {
                                    format!("{ip}")
                                };
                                let _ = stream
                                    .write_all(
                                        format!("HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n")
                                            .as_bytes(),
                                    )
                                    .await;
                            }
                            tracker.on_response(ip);
                        }
                        Ok(Err(e)) => {
                            // Connection refused = host is up.
                            // Use ErrorKind for reliable cross-locale detection.
                            if e.kind() == std::io::ErrorKind::ConnectionRefused
                                || e.kind() == std::io::ErrorKind::ConnectionReset
                            {
                                tracker.on_response(ip);
                            }
                        }
                        Err(_) => {
                            // Timeout — no response
                        }
                    }
                    drop(permit);
                });
                handles.push(handle);
            }
        }
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(tracker.collect_results())
}

/// Get source IP for reaching a target via UDP connect trick.
/// Falls back to the unspecified address rather than target_ip to avoid src==dst packets.
fn get_src_ip(target_ip: IpAddr) -> IpAddr {
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

/// Discover the path MTU to a host using binary search with DF-bit ICMP echo.
///
/// Sends ICMP echo requests with the Don't Fragment bit set at decreasing sizes.
/// If a router can't forward the packet, it returns ICMP Fragmentation Needed
/// (type 3, code 4) with the next-hop MTU. Binary search converges on the path MTU.
///
/// IPv4 only. Returns `None` if the host doesn't respond to ICMP or the target is IPv6.
pub async fn discover_mtu(host: &Host, timeout: Duration) -> Option<u16> {
    let dst_ip = match host.ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            debug!(target = %host.ip, "MTU discovery is IPv4 only, skipping IPv6");
            return None;
        }
    };

    let sender: Arc<dyn PacketSender> = match create_sender(host.ip) {
        Ok(s) => Arc::from(s),
        Err(e) => {
            warn!(target = %host.ip, error = %e, "failed to create sender for MTU discovery");
            return None;
        }
    };

    // Capture ICMP destined for us from any source: echo replies come from
    // the target, but Fragmentation Needed (type 3 code 4) comes from
    // intermediate routers whose IPs we don't know in advance.
    let local_ip = match crate::raw_tcp::get_sender_src_ip(host.ip) {
        IpAddr::V4(v4) => v4,
        _ => return None,
    };
    let bpf_filter = format!("icmp and dst host {local_ip}");
    let mut capture = match create_capture(CaptureConfig {
        interface: sender.interface_name().map(String::from),
        bpf_filter,
        ..CaptureConfig::default()
    }) {
        Ok(c) => c,
        Err(e) => {
            warn!(target = %host.ip, error = %e, "failed to create capture for MTU discovery");
            return None;
        }
    };

    let src_ip = match crate::raw_tcp::get_sender_src_ip(host.ip) {
        IpAddr::V4(v4) => v4,
        _ => return None,
    };

    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        & 0xFFFF) as u16;

    let mut low: u16 = 68; // IPv4 minimum MTU
    let mut high: u16 = 1500; // Standard ethernet MTU (use as practical upper bound)
    let mut seq: u16 = 1;
    let probe_timeout = timeout.min(Duration::from_millis(500));

    // First check: can we reach the host at all with a small ICMP echo?
    let small_pkt = match rustmap_packet::build::build_icmp_echo_df_packet(src_ip, dst_ip, id, 0, 0)
    {
        Ok(p) => p,
        Err(_) => return None,
    };
    if sender.send_raw(host.ip, host.ip, &small_pkt).await.is_err() {
        return None;
    }

    let host_reachable = tokio::time::timeout(probe_timeout, async {
        loop {
            match capture.recv().await {
                Ok(r) if r.response_type == ResponseType::IcmpEchoReply => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);

    if !host_reachable {
        debug!(target = %host.ip, "host not responding to ICMP, skipping MTU discovery");
        return None;
    }

    // Binary search for path MTU
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        // payload_size = total_size - 20 (IP header) - 8 (ICMP header)
        let payload_size = (mid as usize).saturating_sub(28);

        let pkt = match rustmap_packet::build::build_icmp_echo_df_packet(
            src_ip,
            dst_ip,
            id,
            seq,
            payload_size,
        ) {
            Ok(p) => p,
            Err(_) => {
                high = mid;
                seq = seq.wrapping_add(1);
                continue;
            }
        };

        seq = seq.wrapping_add(1);

        if sender.send_raw(host.ip, host.ip, &pkt).await.is_err() {
            high = mid;
            continue;
        }

        match tokio::time::timeout(probe_timeout, async {
            loop {
                match capture.recv().await {
                    Ok(r) => match r.response_type {
                        ResponseType::IcmpEchoReply => return MtuProbeResult::Fits,
                        ResponseType::IcmpFragmentationNeeded => {
                            return MtuProbeResult::TooBig(r.next_hop_mtu);
                        }
                        _ => continue,
                    },
                    Err(_) => return MtuProbeResult::Timeout,
                }
            }
        })
        .await
        {
            Ok(MtuProbeResult::Fits) => {
                low = mid;
            }
            Ok(MtuProbeResult::TooBig(Some(next_hop))) if next_hop > 0 => {
                // Use the next-hop MTU hint for faster convergence
                high = next_hop;
            }
            Ok(MtuProbeResult::TooBig(_)) | Ok(MtuProbeResult::Timeout) | Err(_) => {
                high = mid;
            }
        }
    }

    info!(target = %host.ip, mtu = low, "MTU discovery complete");
    Some(low)
}

enum MtuProbeResult {
    Fits,
    TooBig(Option<u16>),
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn resolve_methods_default_privileged() {
        let config = DiscoveryConfig::default();
        let methods = resolve_methods(&config, true);
        assert_eq!(methods.len(), 5);
        assert!(methods.contains(&DiscoveryMethod::ArpPing));
        assert!(methods.contains(&DiscoveryMethod::IcmpEcho));
        assert!(methods.contains(&DiscoveryMethod::TcpSyn));
        assert!(methods.contains(&DiscoveryMethod::TcpAck));
        assert!(methods.contains(&DiscoveryMethod::IcmpTimestamp));
    }

    #[test]
    fn resolve_methods_default_unprivileged() {
        let config = DiscoveryConfig::default();
        let methods = resolve_methods(&config, false);
        assert!(methods.is_empty());
    }

    #[test]
    fn resolve_methods_skip() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Skip,
            ..DiscoveryConfig::default()
        };
        let methods = resolve_methods(&config, true);
        assert!(methods.is_empty());
    }

    #[test]
    fn resolve_methods_custom() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Custom(vec![DiscoveryMethod::IcmpEcho]),
            ..DiscoveryConfig::default()
        };
        let methods = resolve_methods(&config, true);
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0], DiscoveryMethod::IcmpEcho);
    }

    #[test]
    fn handle_discovery_response_marks_up() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let tracker = DiscoveryTracker::new(&[ip]);
        let timing = TimingController::new(TimingParams::from_template(TimingTemplate::Normal));

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 0,
            dst_port: 0,
            response_type: ResponseType::IcmpEchoReply,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_discovery_response(&response, &timing, &tracker);
        assert!(tracker.is_host_up(&ip));
    }

    #[test]
    fn handle_discovery_response_ignores_unknown_ip() {
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let unknown = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let tracker = DiscoveryTracker::new(&[target]);
        let timing = TimingController::new(TimingParams::from_template(TimingTemplate::Normal));

        let response = CapturedResponse {
            src_ip: unknown,
            src_port: 0,
            dst_port: 0,
            response_type: ResponseType::IcmpEchoReply,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_discovery_response(&response, &timing, &tracker);
        assert!(!tracker.is_host_up(&target));
    }

    #[test]
    fn resolve_methods_with_http_ping() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Custom(vec![DiscoveryMethod::HttpPing]),
            ..DiscoveryConfig::default()
        };
        let methods = resolve_methods(&config, false);
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0], DiscoveryMethod::HttpPing);
    }

    #[test]
    fn resolve_methods_with_https_ping() {
        let config = DiscoveryConfig {
            mode: DiscoveryMode::Custom(vec![DiscoveryMethod::HttpsPing]),
            ..DiscoveryConfig::default()
        };
        let methods = resolve_methods(&config, false);
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0], DiscoveryMethod::HttpsPing);
    }

    #[test]
    fn discovery_config_http_defaults() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.http_ports, vec![80]);
        assert_eq!(config.https_ports, vec![443]);
    }

    #[test]
    fn handle_discovery_response_rst_marks_up() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let tracker = DiscoveryTracker::new(&[ip]);
        let timing = TimingController::new(TimingParams::from_template(TimingTemplate::Normal));

        let response = CapturedResponse {
            src_ip: ip,
            src_port: 80,
            dst_port: 40001,
            response_type: ResponseType::Rst,
            timestamp: Instant::now(),
            tcp_fingerprint: None,
            next_hop_mtu: None,
        };

        handle_discovery_response(&response, &timing, &tracker);
        assert!(tracker.is_host_up(&ip));
    }
}
