use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Instant;

use crate::privilege::PacketError;
use crate::tcp_flags::TcpFlags;

/// Type of response extracted from a captured packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    /// TCP SYN+ACK — port is open.
    SynAck,
    /// TCP RST — port is closed.
    Rst,
    /// ICMP destination unreachable — port is filtered.
    IcmpUnreachable,
    /// ICMP port unreachable (type 3, code 3) — for UDP scanning, port is closed.
    IcmpPortUnreachable,
    /// Direct UDP response data — for UDP scanning, port is open.
    UdpResponse,
    /// ICMP echo reply — host is up (discovery).
    IcmpEchoReply,
    /// ICMP timestamp reply — host is up (discovery).
    IcmpTimestampReply,
    /// ARP reply — host is up (discovery, local subnet).
    ArpReply,
    /// ICMP Time Exceeded (type 11) — intermediate hop in traceroute.
    IcmpTimeExceeded,
    /// SCTP INIT-ACK — port is open.
    SctpInitAck,
    /// SCTP ABORT — port is closed.
    SctpAbort,
    /// ICMP Fragmentation Needed (type 3, code 4) — for MTU discovery.
    IcmpFragmentationNeeded,
}

/// A parsed response from a captured packet, ready for probe correlation.
#[derive(Debug, Clone)]
pub struct CapturedResponse {
    /// Source IP of the responder (the target host).
    pub src_ip: IpAddr,
    /// Source port of the responder (the target port we probed).
    pub src_port: u16,
    /// Destination port on our side (the source port we used, for correlation).
    pub dst_port: u16,
    /// What kind of response this is.
    pub response_type: ResponseType,
    /// When we captured this packet.
    pub timestamp: Instant,
    /// TCP fingerprint data extracted from the response (for OS detection).
    /// Only populated for TCP responses (SynAck, Rst).
    pub tcp_fingerprint: Option<rustmap_types::TcpFingerprint>,
    /// Next-hop MTU from ICMP Fragmentation Needed (type 3, code 4).
    pub next_hop_mtu: Option<u16>,
}

/// Trait for sending raw packets.
#[async_trait]
pub trait PacketSender: Send + Sync {
    /// Send a TCP SYN packet.
    async fn send_tcp_syn(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Result<(), PacketError>;

    /// Send a pre-built raw packet (IP-level, no Ethernet header on Linux;
    /// Ethernet-framed on Windows).
    async fn send_raw(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        packet: &[u8],
    ) -> Result<(), PacketError>;

    /// Send a pre-built Ethernet frame as-is. Required for ARP and other L2 protocols.
    /// Default: returns unsupported error. Implemented on Windows (Npcap).
    async fn send_ethernet_frame(&self, _frame: &[u8]) -> Result<(), PacketError> {
        Err(PacketError::SendFailed(
            "send_ethernet_frame not supported on this platform".into(),
        ))
    }

    /// Send a TCP packet with arbitrary flags.
    ///
    /// Default implementation builds the packet and sends via `send_raw()`.
    /// Works cross-platform because `send_raw()` handles Ethernet framing on Windows.
    async fn send_tcp_flags(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        flags: TcpFlags,
    ) -> Result<(), PacketError> {
        let packet = crate::build::build_tcp_packet(
            src_ip, src_port, dst_ip, dst_port, rand_seq(), flags,
        )?;
        self.send_raw(src_ip, dst_ip, &packet).await
    }

    /// Send a UDP probe with a service-specific payload.
    ///
    /// Default implementation builds the packet and sends via `send_raw()`.
    async fn send_udp_probe(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), PacketError> {
        let packet = crate::build::build_udp_probe_with_payload(
            src_ip, src_port, dst_ip, dst_port, payload,
        )?;
        self.send_raw(src_ip, dst_ip, &packet).await
    }

    /// Send an SCTP INIT packet for SCTP port scanning.
    ///
    /// Default implementation builds the raw SCTP INIT and sends via `send_raw()`.
    async fn send_sctp_init(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Result<(), PacketError> {
        let packet = crate::build::build_sctp_init_packet(src_ip, src_port, dst_ip, dst_port)?;
        self.send_raw(src_ip, dst_ip, &packet).await
    }

    /// Get the local MAC address for this sender, if available.
    /// Needed for ARP request construction.
    fn local_mac(&self) -> Option<[u8; 6]> {
        None
    }

    /// Get the network interface name this sender is bound to.
    /// Used to ensure the capture listens on the same interface as the sender.
    fn interface_name(&self) -> Option<&str> {
        None
    }
}

/// Generate a random TCP sequence number.
pub fn rand_seq() -> u32 {
    use rand::Rng;
    rand::thread_rng().r#gen()
}

/// Trait for receiving captured packets asynchronously.
#[async_trait]
pub trait PacketReceiver: Send + Sync {
    /// Wait for and return the next captured response.
    async fn recv(&mut self) -> Result<CapturedResponse, PacketError>;

    /// Signal the capture loop to stop.
    fn stop(&self);
}
