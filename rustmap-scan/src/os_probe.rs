use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tracing::{debug, info, warn};

use rustmap_packet::{
    CaptureConfig, PacketReceiver, PacketSender, ResponseType, create_capture, create_sender,
    os_probes,
};
use rustmap_types::{OsProbeResults, Port, PortState, TcpFingerprint};

use crate::source_port::SourcePortAllocator;
use crate::traits::ScanError;

/// Default closed port to probe when no closed port was found during scanning.
/// This is a high port unlikely to be open (same as nmap's traceroute default).
const DEFAULT_CLOSED_PORT: u16 = 33434;

/// Timeout for waiting for a single probe response.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Delay between sending successive probes.
const INTER_PROBE_DELAY: Duration = Duration::from_millis(100);

/// Run OS fingerprinting probes against a target host.
///
/// Sends three probes using the existing raw packet infrastructure:
/// 1. SYN with custom options to an open port (expects SYN/ACK)
/// 2. SYN with custom options to a closed port (expects RST)
/// 3. ACK with custom options to an open port (expects RST)
///
/// Returns `OsProbeResults` with fingerprints extracted from each response.
pub async fn run_os_probes(
    target_ip: IpAddr,
    open_port: u16,
    closed_port: u16,
) -> Result<OsProbeResults, ScanError> {
    info!(
        target = %target_ip,
        open_port,
        closed_port,
        "starting OS fingerprinting probes"
    );

    let sender: Arc<dyn PacketSender> = Arc::from(create_sender(target_ip)?);
    let mut capture = create_capture(CaptureConfig {
        interface: sender.interface_name().map(String::from),
        ..CaptureConfig::default()
    })?;
    let src_ip = get_src_ip(target_ip);
    let port_alloc = SourcePortAllocator::new();

    let done = Arc::new(Notify::new());
    let mut results = OsProbeResults::default();

    // Probe 1: SYN to open port
    let src_port1 = port_alloc.next_port();
    results.syn_open =
        send_and_capture_syn(&sender, &mut capture, src_ip, src_port1, target_ip, open_port, &done)
            .await;

    tokio::time::sleep(INTER_PROBE_DELAY).await;

    // Probe 2: SYN to closed port
    let src_port2 = port_alloc.next_port();
    results.syn_closed = send_and_capture_syn(
        &sender,
        &mut capture,
        src_ip,
        src_port2,
        target_ip,
        closed_port,
        &done,
    )
    .await;

    tokio::time::sleep(INTER_PROBE_DELAY).await;

    // Probe 3: ACK to open port
    let src_port3 = port_alloc.next_port();
    results.ack_open =
        send_and_capture_ack(&sender, &mut capture, src_ip, src_port3, target_ip, open_port, &done)
            .await;

    capture.stop();

    info!(
        target = %target_ip,
        syn_open = results.syn_open.is_some(),
        syn_closed = results.syn_closed.is_some(),
        ack_open = results.ack_open.is_some(),
        "OS probes complete"
    );

    Ok(results)
}

/// Send a SYN OS probe and capture the response fingerprint.
async fn send_and_capture_syn(
    sender: &Arc<dyn PacketSender>,
    capture: &mut dyn PacketReceiver,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    done: &Notify,
) -> Option<TcpFingerprint> {
    let seq_num = rand_seq();

    // Build the IP-level probe packet. send_raw() handles Ethernet framing on Windows.
    let packet = match os_probes::build_os_syn_probe(src_ip, src_port, dst_ip, dst_port, seq_num) {
        Ok(p) => p,
        Err(e) => {
            warn!(port = dst_port, error = %e, "failed to build OS SYN probe");
            return None;
        }
    };

    if let Err(e) = sender.send_raw(src_ip, dst_ip, &packet).await {
        warn!(port = dst_port, error = %e, "failed to send OS SYN probe");
        return None;
    }

    debug!(port = dst_port, src_port, "sent OS SYN probe");
    wait_for_response(capture, dst_ip, dst_port, src_port, done).await
}

/// Send an ACK OS probe and capture the response fingerprint.
async fn send_and_capture_ack(
    sender: &Arc<dyn PacketSender>,
    capture: &mut dyn PacketReceiver,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    done: &Notify,
) -> Option<TcpFingerprint> {
    let seq_num = rand_seq();

    // Build the IP-level probe packet. send_raw() handles Ethernet framing on Windows.
    let packet = match os_probes::build_os_ack_probe(src_ip, src_port, dst_ip, dst_port, seq_num) {
        Ok(p) => p,
        Err(e) => {
            warn!(port = dst_port, error = %e, "failed to build OS ACK probe");
            return None;
        }
    };

    if let Err(e) = sender.send_raw(src_ip, dst_ip, &packet).await {
        warn!(port = dst_port, error = %e, "failed to send OS ACK probe");
        return None;
    }

    debug!(port = dst_port, src_port, "sent OS ACK probe");
    wait_for_response(capture, dst_ip, dst_port, src_port, done).await
}

/// Wait for a TCP response matching our probe and extract the fingerprint.
async fn wait_for_response(
    capture: &mut dyn PacketReceiver,
    target_ip: IpAddr,
    target_port: u16,
    our_src_port: u16,
    done: &Notify,
) -> Option<TcpFingerprint> {
    let deadline = Instant::now() + PROBE_TIMEOUT;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            debug!(port = target_port, "OS probe timed out");
            return None;
        }

        tokio::select! {
            result = capture.recv() => {
                match result {
                    Ok(response) => {
                        // Check if this response matches our probe
                        if response.src_ip == target_ip
                            && response.src_port == target_port
                            && response.dst_port == our_src_port
                            && matches!(response.response_type, ResponseType::SynAck | ResponseType::Rst)
                        {
                            return response.tcp_fingerprint;
                        }
                        // Not our response — continue listening
                    }
                    Err(_) => return None,
                }
            }
            _ = tokio::time::sleep(remaining) => {
                debug!(port = target_port, "OS probe timed out");
                return None;
            }
            _ = done.notified() => {
                return None;
            }
        }
    }
}

/// Find an open port from scan results for OS probing.
pub fn find_open_port(ports: &[Port]) -> Option<u16> {
    ports
        .iter()
        .find(|p| p.state == PortState::Open)
        .map(|p| p.number)
}

/// Find a closed port from scan results for OS probing.
/// Falls back to `DEFAULT_CLOSED_PORT` if no closed port was found.
pub fn find_closed_port(ports: &[Port]) -> u16 {
    ports
        .iter()
        .find(|p| p.state == PortState::Closed)
        .map(|p| p.number)
        .unwrap_or(DEFAULT_CLOSED_PORT)
}

/// Get a random TCP sequence number for probe construction.
fn rand_seq() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    h.finish() as u32
}

/// Get our source IP for reaching the target.
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::Protocol;

    #[test]
    fn find_open_port_returns_first_open() {
        let ports = vec![
            Port {
                number: 22,
                protocol: Protocol::Tcp,
                state: PortState::Closed,
                service: None,
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            },
            Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: None,
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            },
            Port {
                number: 443,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: None,
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            },
        ];
        assert_eq!(find_open_port(&ports), Some(80));
    }

    #[test]
    fn find_open_port_returns_none_when_no_open() {
        let ports = vec![Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Closed,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        assert_eq!(find_open_port(&ports), None);
    }

    #[test]
    fn find_open_port_empty_list() {
        assert_eq!(find_open_port(&[]), None);
    }

    #[test]
    fn find_closed_port_returns_first_closed() {
        let ports = vec![
            Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: None,
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            },
            Port {
                number: 443,
                protocol: Protocol::Tcp,
                state: PortState::Closed,
                service: None,
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            },
        ];
        assert_eq!(find_closed_port(&ports), 443);
    }

    #[test]
    fn find_closed_port_falls_back_to_default() {
        let ports = vec![Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        assert_eq!(find_closed_port(&ports), DEFAULT_CLOSED_PORT);
    }

    #[test]
    fn find_closed_port_empty_list() {
        assert_eq!(find_closed_port(&[]), DEFAULT_CLOSED_PORT);
    }
}
