use std::net::IpAddr;

use async_trait::async_trait;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::debug;

use crate::build::build_syn_packet;
use crate::privilege::PacketError;
use crate::traits::PacketSender;

/// Raw socket sender for Linux.
///
/// Uses `socket2` to create a raw TCP socket with IP_HDRINCL.
/// Sends complete IP+TCP packets. Requires CAP_NET_RAW or root.
pub struct RawSocketSender {
    socket: Socket,
    src_ip: IpAddr,
}

impl RawSocketSender {
    /// Create a raw socket sender.
    pub fn new(src_ip: IpAddr) -> Result<Self, PacketError> {
        let domain = match src_ip {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        let socket = Socket::new(domain, Type::RAW, Some(Protocol::TCP))
            .map_err(|e| PacketError::SendFailed(format!("raw socket creation failed: {e}")))?;

        if src_ip.is_ipv4() {
            // IP_HDRINCL: we construct the full IP header ourselves
            socket
                .set_header_included(true)
                .map_err(|e| PacketError::SendFailed(format!("IP_HDRINCL failed: {e}")))?;
        }
        // For IPv6 raw sockets, IPV6_HDRINCL is not standard on Linux.
        // Instead, the kernel constructs the IPv6 header. Our build functions
        // produce IPv6+transport packets, so we need to skip the 40-byte
        // IPv6 header and only send the transport payload.
        // This is handled in send_raw() below.

        debug!(src_ip = %src_ip, "raw socket sender created");

        Ok(Self { socket, src_ip })
    }

    /// Get the local IP address being used.
    pub fn src_ip(&self) -> IpAddr {
        self.src_ip
    }

    /// For IPv6 raw sockets on Linux, the kernel constructs the IPv6 header.
    /// Our build functions produce full IPv6+transport packets, so we strip
    /// the 40-byte IPv6 header and return only the transport payload.
    /// For IPv4, returns the packet unchanged (IP_HDRINCL handles it).
    /// For IPv6 raw sockets on Linux, strip the 40-byte base IPv6 header.
    ///
    /// Assumes no IPv6 extension headers are present between the base header
    /// and the transport payload. This is valid for our generated probe packets
    /// which never include extension headers.
    fn ipv6_strip_header<'a>(&self, packet: &'a [u8], dst_ip: IpAddr) -> &'a [u8] {
        if dst_ip.is_ipv6() && packet.len() > 40 {
            debug_assert!(packet.len() >= 40, "IPv6 packet shorter than minimum header");
            &packet[40..]
        } else {
            packet
        }
    }
}

#[async_trait]
impl PacketSender for RawSocketSender {
    async fn send_tcp_syn(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Result<(), PacketError> {
        let packet = build_syn_packet(src_ip, src_port, dst_ip, dst_port, rand_seq())?;

        // sendto() destination — kernel uses the IP header for routing,
        // but needs a destination address for the raw socket API.
        let dst_addr = match dst_ip {
            IpAddr::V4(v4) => SockAddr::from(std::net::SocketAddrV4::new(v4, dst_port)),
            IpAddr::V6(v6) => SockAddr::from(std::net::SocketAddrV6::new(v6, dst_port, 0, 0)),
        };

        let data = self.ipv6_strip_header(&packet, dst_ip);
        self.socket
            .send_to(data, &dst_addr)
            .map_err(|e| PacketError::SendFailed(e.to_string()))?;

        Ok(())
    }

    async fn send_raw(
        &self,
        _src_ip: IpAddr,
        dst_ip: IpAddr,
        packet: &[u8],
    ) -> Result<(), PacketError> {
        // With IP_HDRINCL, the kernel uses the protocol field from the IP header
        // we provide, regardless of the socket's protocol parameter.
        let dst_addr = match dst_ip {
            IpAddr::V4(v4) => SockAddr::from(std::net::SocketAddrV4::new(v4, 0)),
            IpAddr::V6(v6) => SockAddr::from(std::net::SocketAddrV6::new(v6, 0, 0, 0)),
        };

        let data = self.ipv6_strip_header(packet, dst_ip);
        self.socket
            .send_to(data, &dst_addr)
            .map_err(|e| PacketError::SendFailed(e.to_string()))?;

        Ok(())
    }
}

fn rand_seq() -> u32 {
    crate::traits::rand_seq()
}
