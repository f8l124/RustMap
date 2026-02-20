use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use pcap::{Capture, Device};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::parse::parse_response_from_ethernet;
use crate::privilege::PacketError;
use crate::traits::{CapturedResponse, PacketReceiver};

/// Configuration for the packet capture.
pub struct CaptureConfig {
    /// Interface name to capture on (or auto-detect if None).
    pub interface: Option<String>,
    /// BPF filter string.
    pub bpf_filter: String,
    /// Channel buffer size.
    pub channel_size: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            bpf_filter: default_bpf_filter(),
            channel_size: 4096,
        }
    }
}

/// Build the default BPF filter for SYN scan responses.
/// Captures: TCP SYN/ACK or RST destined to our source port range,
/// plus ICMP/ICMPv6 destination unreachable.
pub fn default_bpf_filter() -> String {
    // Capture TCP packets with SYN+ACK or RST flags destined to our
    // ephemeral source port range (40000-59999), plus ICMP unreachable.
    // The tcp[tcpflags] filter works for both IPv4 and IPv6 TCP in libpcap.
    // We add `icmp6` to capture all ICMPv6 (unreachable, echo reply, etc.)
    // and let the Rust parser discriminate.
    "(tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack) and dst portrange 40000-59999) \
     or (tcp[tcpflags] & tcp-rst != 0 and dst portrange 40000-59999) \
     or icmp[icmptype] = icmp-unreach \
     or icmp[icmptype] = icmp-timxceed \
     or icmp6"
        .to_string()
}

/// Build a BPF filter for when a fixed source port is used (`-g`/`--source-port`).
/// Captures TCP SYN/ACK or RST destined to the specific port, plus ICMP/ICMPv6 unreachable.
pub fn fixed_port_bpf_filter(port: u16) -> String {
    format!(
        "(tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack) and dst port {port}) \
         or (tcp[tcpflags] & tcp-rst != 0 and dst port {port}) \
         or icmp[icmptype] = icmp-unreach \
         or icmp[icmptype] = icmp-timxceed \
         or icmp6"
    )
}

/// Build a BPF filter for UDP scanning with a fixed source port.
pub fn udp_fixed_port_bpf_filter(port: u16) -> String {
    format!(
        "(udp and dst port {port}) \
         or icmp[icmptype] = icmp-unreach \
         or icmp[icmptype] = icmp-timxceed \
         or icmp6"
    )
}

/// Build the BPF filter for UDP scan responses.
/// Captures: UDP packets destined to our source port range,
/// plus ICMP/ICMPv6 destination unreachable (for closed/filtered ports).
pub fn udp_bpf_filter() -> String {
    "(udp and dst portrange 40000-59999) \
     or icmp[icmptype] = icmp-unreach \
     or icmp[icmptype] = icmp-timxceed \
     or icmp6"
        .to_string()
}

/// Async packet capture using a background OS thread with pcap.
///
/// The blocking pcap capture loop runs in a dedicated `std::thread`,
/// parsed responses are sent over a tokio mpsc channel.
pub struct AsyncCapture {
    rx: mpsc::Receiver<CapturedResponse>,
    stop_flag: Arc<AtomicBool>,
}

impl AsyncCapture {
    /// Start the capture. Spawns a background thread.
    pub fn start(config: CaptureConfig) -> Result<Self, PacketError> {
        let device = match &config.interface {
            Some(name) => find_device_by_name(name)?,
            None => Device::lookup()
                .map_err(|e| PacketError::PcapNotAvailable(e.to_string()))?
                .ok_or(PacketError::NoInterface)?,
        };

        debug!(device = %device.name, "starting packet capture");

        let mut cap = Capture::from_device(device)
            .map_err(|e| PacketError::CaptureSetup(e.to_string()))?
            .promisc(false)
            .snaplen(256) // Enough for Ethernet(14) + max IPv4/IPv6(60) + max TCP(60) + ICMP embedded headers
            .timeout(100) // 100ms read timeout for responsiveness
            .immediate_mode(true)
            .open()
            .map_err(|e| PacketError::CaptureSetup(e.to_string()))?;

        cap.filter(&config.bpf_filter, true)
            .map_err(|e| PacketError::CaptureSetup(format!("BPF filter error: {e}")))?;

        let (tx, rx) = mpsc::channel(config.channel_size);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = stop_flag.clone();

        // Spawn a blocking OS thread for the capture loop
        std::thread::Builder::new()
            .name("pcap-capture".into())
            .spawn(move || {
                capture_loop(cap, tx, stop_clone);
            })
            .map_err(|e| PacketError::CaptureSetup(format!("failed to spawn thread: {e}")))?;

        Ok(Self { rx, stop_flag })
    }
}

fn capture_loop(
    mut cap: Capture<pcap::Active>,
    tx: mpsc::Sender<CapturedResponse>,
    stop: Arc<AtomicBool>,
) {
    debug!("capture thread started");
    while !stop.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                let ts = Instant::now();
                if let Some(response) = parse_response_from_ethernet(packet.data, ts)
                    && tx.blocking_send(response).is_err()
                {
                    // Receiver dropped — exit
                    debug!("capture channel closed, stopping");
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Normal — no packet within read timeout, loop and check stop
                continue;
            }
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                warn!(error = %e, "pcap capture error");
                // Avoid busy-spinning on persistent errors (e.g., device removed)
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
    debug!("capture thread stopped");
}

#[async_trait]
impl PacketReceiver for AsyncCapture {
    async fn recv(&mut self) -> Result<CapturedResponse, PacketError> {
        self.rx.recv().await.ok_or(PacketError::CaptureStopped)
    }

    fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

impl Drop for AsyncCapture {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }
}

/// Find a pcap device by name.
fn find_device_by_name(name: &str) -> Result<Device, PacketError> {
    let devices = Device::list().map_err(|e| PacketError::PcapNotAvailable(e.to_string()))?;
    devices
        .into_iter()
        .find(|d| d.name == name)
        .ok_or(PacketError::NoInterface)
}

/// List available network interfaces (for diagnostics/auto-detection).
pub fn list_interfaces() -> Result<Vec<String>, PacketError> {
    let devices = Device::list().map_err(|e| PacketError::PcapNotAvailable(e.to_string()))?;
    Ok(devices.into_iter().map(|d| d.name).collect())
}

/// Detect the best interface for reaching a target IP.
///
/// Uses the OS routing table (via UDP connect trick) to determine which local
/// IP would be used to reach the target, then finds the pcap device with that
/// address. This handles multi-NIC systems correctly.
pub fn detect_interface(target_ip: std::net::IpAddr) -> Result<Device, PacketError> {
    let devices = Device::list().map_err(|e| PacketError::PcapNotAvailable(e.to_string()))?;

    // Use the OS routing table to find which local IP reaches the target.
    // Connect a UDP socket (no actual traffic) — the kernel picks the outbound interface.
    if let Ok(routed_ip) = get_routed_src_ip(target_ip) {
        for device in &devices {
            for addr in &device.addresses {
                if addr.addr == routed_ip {
                    debug!(device = %device.name, addr = %routed_ip, "selected interface via routing table");
                    return Ok(device.clone());
                }
            }
        }
        warn!(routed_ip = %routed_ip, "routing table returned IP not found in pcap devices");
    }

    // Fallback: first non-loopback device with a matching address family
    for device in &devices {
        for addr in &device.addresses {
            match (target_ip, addr.addr) {
                (std::net::IpAddr::V4(_), std::net::IpAddr::V4(dev_addr))
                    if !dev_addr.is_loopback() =>
                {
                    debug!(device = %device.name, addr = %dev_addr, "selected interface (fallback)");
                    return Ok(device.clone());
                }
                (std::net::IpAddr::V6(_), std::net::IpAddr::V6(dev_addr))
                    if !dev_addr.is_loopback() =>
                {
                    debug!(device = %device.name, addr = %dev_addr, "selected interface (fallback v6)");
                    return Ok(device.clone());
                }
                _ => continue,
            }
        }
    }

    // Last resort: pcap default
    Device::lookup()
        .map_err(|e| PacketError::PcapNotAvailable(e.to_string()))?
        .ok_or(PacketError::NoInterface)
}

/// Determine the local source IP for reaching a target via the OS routing table.
/// Connects a UDP socket (no actual traffic) — the kernel selects the outbound interface.
fn get_routed_src_ip(target: std::net::IpAddr) -> Result<std::net::IpAddr, PacketError> {
    let bind_addr = match target {
        std::net::IpAddr::V4(_) => "0.0.0.0:0",
        std::net::IpAddr::V6(_) => "[::]:0",
    };
    let socket = std::net::UdpSocket::bind(bind_addr).map_err(|_| PacketError::NoInterface)?;
    let dst = std::net::SocketAddr::new(target, 80);
    socket.connect(dst).map_err(|_| PacketError::NoInterface)?;
    let local = socket.local_addr().map_err(|_| PacketError::NoInterface)?;
    Ok(local.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bpf_filter_contains_port_range() {
        let filter = default_bpf_filter();
        assert!(filter.contains("40000-59999"));
        assert!(filter.contains("tcp-syn"));
        assert!(filter.contains("icmp-unreach"));
        assert!(filter.contains("icmp6"));
    }

    #[test]
    fn fixed_port_bpf_filter_contains_port() {
        let filter = fixed_port_bpf_filter(53);
        assert!(filter.contains("dst port 53"));
        assert!(filter.contains("tcp-syn"));
        assert!(filter.contains("icmp-unreach"));
        assert!(filter.contains("icmp6"));
        // Should NOT contain the default port range
        assert!(!filter.contains("40000-59999"));
    }

    #[test]
    fn udp_fixed_port_bpf_filter_contains_port() {
        let filter = udp_fixed_port_bpf_filter(20);
        assert!(filter.contains("dst port 20"));
        assert!(filter.contains("udp"));
        assert!(filter.contains("icmp-unreach"));
        assert!(filter.contains("icmp6"));
    }

    #[test]
    fn udp_bpf_filter_contains_port_range() {
        let filter = udp_bpf_filter();
        assert!(filter.contains("40000-59999"));
        assert!(filter.contains("udp"));
        assert!(filter.contains("icmp6"));
    }
}
