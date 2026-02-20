use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use pcap::{Capture, Device};
use tracing::{debug, warn};

use crate::build::build_syn_packet_ethernet;
use crate::capture::detect_interface;
use crate::net_windows::{get_adapter_info, resolve_dst_mac};
use crate::privilege::PacketError;
use crate::traits::PacketSender;

/// Packet sender using Npcap's packet injection (Windows).
///
/// On Windows, raw TCP sockets are blocked. Instead, we use Npcap's
/// `sendpacket()` to inject Ethernet frames directly. This requires
/// Npcap to be installed and the process to run as Administrator.
pub struct NpcapSender {
    /// pcap handle opened in send mode.
    cap: Mutex<Capture<pcap::Active>>,
    /// Our local MAC address (source for Ethernet frame).
    src_mac: [u8; 6],
    /// Gateway/destination MAC address (next-hop for Ethernet frame).
    dst_mac: [u8; 6],
    /// Our local IP address (source for IP header).
    src_ip: IpAddr,
    /// Name of the network interface this sender is bound to.
    interface_name: String,
}

impl NpcapSender {
    /// Create a sender for the given target, auto-detecting interface.
    pub fn new(target_ip: IpAddr) -> Result<Self, PacketError> {
        let device = detect_interface(target_ip)?;
        Self::with_device(device, target_ip)
    }

    /// Create a sender using a specific device.
    pub fn with_device(device: Device, target_ip: IpAddr) -> Result<Self, PacketError> {
        // Pick an address matching the target's address family
        let src_ip = match target_ip {
            IpAddr::V6(_) => device
                .addresses
                .iter()
                .find_map(|a| match a.addr {
                    IpAddr::V6(v6) if !v6.is_loopback() => Some(IpAddr::V6(v6)),
                    _ => None,
                })
                .or_else(|| {
                    // Fall back to IPv4 if no IPv6 address available
                    device.addresses.iter().find_map(|a| match a.addr {
                        IpAddr::V4(v4) if !v4.is_loopback() => Some(IpAddr::V4(v4)),
                        _ => None,
                    })
                })
                .ok_or(PacketError::NoInterface)?,
            IpAddr::V4(_) => device
                .addresses
                .iter()
                .find_map(|a| match a.addr {
                    IpAddr::V4(v4) if !v4.is_loopback() => Some(IpAddr::V4(v4)),
                    _ => None,
                })
                .ok_or(PacketError::NoInterface)?,
        };

        // Save the device name before consuming the device into the capture handle
        let interface_name = device.name.clone();

        debug!(device = %device.name, src_ip = %src_ip, "opening Npcap sender");

        let cap = Capture::from_device(device)
            .map_err(|e| PacketError::CaptureSetup(e.to_string()))?
            .promisc(false)
            .snaplen(0) // We're only sending
            .immediate_mode(true)
            .open()
            .map_err(|e| PacketError::CaptureSetup(e.to_string()))?;

        // Resolve real MAC addresses using Windows networking APIs
        let (src_mac, dst_mac) = resolve_macs(src_ip, target_ip);

        Ok(Self {
            cap: Mutex::new(cap),
            src_mac,
            dst_mac,
            src_ip,
            interface_name,
        })
    }

    /// Get the local IP address being used.
    pub fn src_ip(&self) -> IpAddr {
        self.src_ip
    }
}

/// Resolve source and destination MAC addresses for packet construction.
///
/// Uses the Windows IP Helper API:
/// - `GetAdaptersAddresses` → local adapter MAC, gateway IP, subnet info
/// - `SendARP` → gateway MAC resolution (for cross-subnet targets)
///
/// Fallback: zeros src MAC (Npcap may auto-fill) + broadcast dst MAC.
fn resolve_macs(src_ip: IpAddr, target_ip: IpAddr) -> ([u8; 6], [u8; 6]) {
    let broadcast = [0xFF; 6];
    let zero_mac = [0x00; 6];

    let src_v4 = match src_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            warn!("IPv6 MAC resolution not yet supported");
            return (zero_mac, broadcast);
        }
    };

    let adapter = match get_adapter_info(src_v4) {
        Some(info) => info,
        None => {
            warn!(%src_v4, "could not resolve adapter info — using fallback MACs");
            return (zero_mac, broadcast);
        }
    };

    let src_mac = adapter.mac;

    let dst_mac = match target_ip {
        IpAddr::V4(dst_v4) => resolve_dst_mac(src_v4, dst_v4, &adapter),
        IpAddr::V6(_) => broadcast,
    };

    debug!(
        src_mac = ?src_mac,
        dst_mac = ?dst_mac,
        "MAC addresses resolved"
    );

    (src_mac, dst_mac)
}

#[async_trait]
impl PacketSender for NpcapSender {
    async fn send_tcp_syn(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Result<(), PacketError> {
        let packet = build_syn_packet_ethernet(
            self.src_mac,
            self.dst_mac,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            rand_seq(),
        )?;

        let mut cap = self.cap.lock().unwrap_or_else(|e| e.into_inner());
        cap.sendpacket(packet)
            .map_err(|e| PacketError::SendFailed(e.to_string()))?;
        Ok(())
    }

    async fn send_raw(
        &self,
        _src_ip: IpAddr,
        dst_ip: IpAddr,
        packet: &[u8],
    ) -> Result<(), PacketError> {
        // Wrap the IP-level packet in an Ethernet frame for Npcap injection
        let ether_type = match dst_ip {
            IpAddr::V4(_) => [0x08, 0x00], // EtherType: IPv4
            IpAddr::V6(_) => [0x86, 0xDD], // EtherType: IPv6
        };
        let mut frame = Vec::with_capacity(14 + packet.len());
        frame.extend_from_slice(&self.dst_mac); // destination MAC
        frame.extend_from_slice(&self.src_mac); // source MAC
        frame.extend_from_slice(&ether_type);
        frame.extend_from_slice(packet);

        let mut cap = self.cap.lock().unwrap_or_else(|e| e.into_inner());
        cap.sendpacket(frame)
            .map_err(|e| PacketError::SendFailed(e.to_string()))?;
        Ok(())
    }

    async fn send_ethernet_frame(&self, frame: &[u8]) -> Result<(), PacketError> {
        let mut cap = self.cap.lock().unwrap_or_else(|e| e.into_inner());
        cap.sendpacket(frame)
            .map_err(|e| PacketError::SendFailed(e.to_string()))?;
        Ok(())
    }

    fn local_mac(&self) -> Option<[u8; 6]> {
        // Return None if the MAC is the placeholder (all zeros)
        if self.src_mac == [0x00; 6] {
            None
        } else {
            Some(self.src_mac)
        }
    }

    fn interface_name(&self) -> Option<&str> {
        Some(&self.interface_name)
    }
}

/// Generate a random TCP sequence number.
fn rand_seq() -> u32 {
    crate::traits::rand_seq()
}
