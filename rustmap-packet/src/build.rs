use std::net::IpAddr;

use etherparse::PacketBuilder;

use crate::privilege::PacketError;
use crate::tcp_flags::TcpFlags;

pub const DEFAULT_WINDOW_SIZE: u16 = 1024;
pub const DEFAULT_TTL: u8 = 64;

fn mixed_addr_err() -> PacketError {
    PacketError::BuildFailed("cannot mix IPv4 and IPv6 addresses".into())
}

/// Helper macro to build a packet from a PacketBuilder and write it to a Vec.
macro_rules! build_packet {
    ($builder:expr) => {{
        let builder = $builder;
        let mut buf = Vec::with_capacity(builder.size(0));
        builder
            .write(&mut buf, &[])
            .map_err(|e| PacketError::BuildFailed(e.to_string()))?;
        Ok(buf)
    }};
    ($builder:expr, $payload:expr) => {{
        let builder = $builder;
        let payload: &[u8] = $payload;
        let mut buf = Vec::with_capacity(builder.size(payload.len()));
        builder
            .write(&mut buf, payload)
            .map_err(|e| PacketError::BuildFailed(e.to_string()))?;
        Ok(buf)
    }};
}

/// Build a raw TCP SYN packet (IP + TCP headers, no Ethernet).
/// Suitable for raw socket sending on Linux (IP_HDRINCL).
pub fn build_syn_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .syn();
            build_packet!(builder)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .syn();
            build_packet!(builder)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a TCP SYN packet with Ethernet frame header.
/// Needed for Windows/Npcap packet injection which operates at layer 2.
pub fn build_syn_packet_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .syn();
            build_packet!(builder)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .syn();
            build_packet!(builder)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a raw TCP packet with arbitrary flags (IP + TCP headers, no Ethernet).
///
/// This is the generalized version of `build_syn_packet` and `build_tcp_ack_packet`,
/// used by the generic `RawTcpScanner` for FIN, NULL, Xmas, ACK, Window, and Maimon scans.
pub fn build_tcp_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
    flags: TcpFlags,
) -> Result<Vec<u8>, PacketError> {
    macro_rules! apply_flags {
        ($builder:expr, $flags:expr) => {{
            let mut b = $builder;
            if $flags.syn {
                b = b.syn();
            }
            if $flags.fin {
                b = b.fin();
            }
            if $flags.psh {
                b = b.psh();
            }
            if $flags.urg {
                b = b.urg(0);
            }
            if $flags.ack {
                b = b.ack(0);
            }
            if $flags.rst {
                b = b.rst();
            }
            b
        }};
    }

    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), DEFAULT_TTL).tcp(
                src_port,
                dst_port,
                seq_num,
                DEFAULT_WINDOW_SIZE,
            );
            build_packet!(apply_flags!(builder, flags))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), DEFAULT_TTL).tcp(
                src_port,
                dst_port,
                seq_num,
                DEFAULT_WINDOW_SIZE,
            );
            build_packet!(apply_flags!(builder, flags))
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a raw ICMP echo request packet (IP + ICMP headers, no Ethernet).
pub fn build_icmp_echo_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    id: u16,
    seq: u16,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .icmpv4_echo_request(id, seq);
            build_packet!(builder)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .icmpv6_echo_request(id, seq);
            build_packet!(builder)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build an ICMP echo request with Ethernet frame header.
pub fn build_icmp_echo_packet_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    id: u16,
    seq: u16,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .icmpv4_echo_request(id, seq);
            build_packet!(builder)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .icmpv6_echo_request(id, seq);
            build_packet!(builder)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a raw TCP ACK packet (IP + TCP headers, no Ethernet).
/// Used for TCP ACK ping discovery — expects RST back if host is up.
pub fn build_tcp_ack_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .ack(0);
            build_packet!(builder)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .ack(0);
            build_packet!(builder)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a TCP ACK packet with Ethernet frame header.
pub fn build_tcp_ack_packet_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .ack(0);
            build_packet!(builder)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .ack(0);
            build_packet!(builder)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a raw UDP probe packet (IP + UDP headers, no Ethernet).
/// Empty payload — provokes ICMP port unreachable if host is up.
pub fn build_udp_probe_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .udp(src_port, dst_port);
            build_packet!(builder)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .udp(src_port, dst_port);
            build_packet!(builder)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a raw UDP probe packet with a service-specific payload (IP + UDP headers, no Ethernet).
/// Used for UDP port scanning — service-specific payloads increase response rates.
pub fn build_udp_probe_with_payload(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .udp(src_port, dst_port);
            build_packet!(builder, payload)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .udp(src_port, dst_port);
            build_packet!(builder, payload)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a UDP probe packet with Ethernet frame header.
pub fn build_udp_probe_packet_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .udp(src_port, dst_port);
            build_packet!(builder)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv6(src.octets(), dst.octets(), DEFAULT_TTL)
                .udp(src_port, dst_port);
            build_packet!(builder)
        }
        _ => Err(mixed_addr_err()),
    }
}

/// Build a raw ICMP timestamp request packet (IP + ICMP headers, no Ethernet).
/// ICMP type 13, code 0. Payload: 12 bytes (originate/receive/transmit timestamps).
pub fn build_icmp_timestamp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    id: u16,
    seq: u16,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            // ICMP timestamp request: type 13, code 0
            // bytes5to8 = [id_hi, id_lo, seq_hi, seq_lo]
            let bytes5to8 = [
                (id >> 8) as u8,
                (id & 0xff) as u8,
                (seq >> 8) as u8,
                (seq & 0xff) as u8,
            ];
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .icmpv4_raw(13, 0, bytes5to8);

            // 12 bytes of timestamp payload (originate, receive, transmit — all zero)
            let payload = [0u8; 12];
            let mut buf = Vec::with_capacity(builder.size(payload.len()));
            builder
                .write(&mut buf, &payload)
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;
            Ok(buf)
        }
        _ => Err(PacketError::BuildFailed(
            "IPv6 ICMP timestamp not yet supported".into(),
        )),
    }
}

/// Build an ICMP timestamp request with Ethernet frame header.
pub fn build_icmp_timestamp_packet_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    id: u16,
    seq: u16,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let bytes5to8 = [
                (id >> 8) as u8,
                (id & 0xff) as u8,
                (seq >> 8) as u8,
                (seq & 0xff) as u8,
            ];
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv4(src.octets(), dst.octets(), DEFAULT_TTL)
                .icmpv4_raw(13, 0, bytes5to8);

            let payload = [0u8; 12];
            let mut buf = Vec::with_capacity(builder.size(payload.len()));
            builder
                .write(&mut buf, &payload)
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;
            Ok(buf)
        }
        _ => Err(PacketError::BuildFailed(
            "IPv6 ICMP timestamp not yet supported".into(),
        )),
    }
}

/// Build a raw ARP request (who-has) Ethernet frame.
/// ARP operates at layer 2 — the returned buffer is a complete Ethernet frame.
/// There is no IP-only variant since ARP is inherently an Ethernet protocol.
pub fn build_arp_request(
    src_mac: [u8; 6],
    src_ip: std::net::Ipv4Addr,
    dst_ip: std::net::Ipv4Addr,
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(42); // 14 Ethernet + 28 ARP

    // Ethernet header
    pkt.extend_from_slice(&[0xff; 6]); // dst MAC: broadcast
    pkt.extend_from_slice(&src_mac); // src MAC
    pkt.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP

    // ARP header
    pkt.extend_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
    pkt.extend_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
    pkt.push(6); // Hardware address length
    pkt.push(4); // Protocol address length
    pkt.extend_from_slice(&[0x00, 0x01]); // Operation: request (1)
    pkt.extend_from_slice(&src_mac); // Sender hardware address
    pkt.extend_from_slice(&src_ip.octets()); // Sender protocol address
    pkt.extend_from_slice(&[0x00; 6]); // Target hardware address (unknown)
    pkt.extend_from_slice(&dst_ip.octets()); // Target protocol address

    pkt
}

/// Build a TCP SYN packet with explicit TTL (for traceroute).
pub fn build_syn_packet_with_ttl(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
    ttl: u8,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_packet!(
            PacketBuilder::ipv4(src.octets(), dst.octets(), ttl)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .syn()
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_packet!(
            PacketBuilder::ipv6(src.octets(), dst.octets(), ttl)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .syn()
        ),
        _ => Err(mixed_addr_err()),
    }
}

/// Build a TCP SYN packet with explicit TTL + Ethernet framing (for Windows traceroute).
#[allow(clippy::too_many_arguments)]
pub fn build_syn_packet_with_ttl_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
    ttl: u8,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_packet!(
            PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv4(src.octets(), dst.octets(), ttl)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .syn()
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_packet!(
            PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv6(src.octets(), dst.octets(), ttl)
                .tcp(src_port, dst_port, seq_num, DEFAULT_WINDOW_SIZE)
                .syn()
        ),
        _ => Err(mixed_addr_err()),
    }
}

/// Build a UDP probe packet with explicit TTL (for traceroute).
pub fn build_udp_probe_with_ttl(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    ttl: u8,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_packet!(
            PacketBuilder::ipv4(src.octets(), dst.octets(), ttl).udp(src_port, dst_port),
            &[]
        ),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_packet!(
            PacketBuilder::ipv6(src.octets(), dst.octets(), ttl).udp(src_port, dst_port),
            &[]
        ),
        _ => Err(mixed_addr_err()),
    }
}

/// Build a raw SCTP INIT packet (IP + SCTP common header + INIT chunk).
///
/// SCTP common header (12 bytes): src_port, dst_port, verification_tag=0, checksum (CRC-32c).
/// INIT chunk (20 bytes): type=1, flags=0, length=20, initiate_tag, a_rwnd=65535,
/// num_outbound=1, num_inbound=1, initial_tsn.
///
/// etherparse does not support SCTP, so we build the entire packet manually.
pub fn build_sctp_init_packet(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => build_sctp_init_ipv4(src, dst, src_port, dst_port),
        (IpAddr::V6(src), IpAddr::V6(dst)) => build_sctp_init_ipv6(src, dst, src_port, dst_port),
        _ => Err(mixed_addr_err()),
    }
}

fn build_sctp_init_ipv4(
    src_ip: std::net::Ipv4Addr,
    dst_ip: std::net::Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>, PacketError> {
    use rand::Rng;

    let sctp_len: u16 = 32; // 12 common header + 20 INIT chunk
    let total_len: u16 = 20 + sctp_len; // 20 IPv4 header + SCTP

    let mut pkt = Vec::with_capacity(total_len as usize);

    // --- IPv4 header (20 bytes) ---
    pkt.push(0x45); // version=4, IHL=5 (20 bytes)
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&total_len.to_be_bytes()); // total length
    let id: u16 = rand::thread_rng().r#gen();
    pkt.extend_from_slice(&id.to_be_bytes()); // identification
    pkt.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment offset=0
    pkt.push(DEFAULT_TTL); // TTL
    pkt.push(132); // protocol = SCTP
    pkt.extend_from_slice(&[0x00, 0x00]); // header checksum (placeholder)
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());

    // Calculate IPv4 header checksum
    let ip_checksum = ipv4_checksum(&pkt[..20]);
    pkt[10] = (ip_checksum >> 8) as u8;
    pkt[11] = (ip_checksum & 0xff) as u8;

    // --- SCTP common header (12 bytes) ---
    let sctp_start = pkt.len();
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]); // verification tag = 0 for INIT
    pkt.extend_from_slice(&[0x00; 4]); // checksum placeholder (zeroed for CRC calculation)

    // --- INIT chunk (20 bytes) ---
    pkt.push(1); // chunk type = INIT
    pkt.push(0); // chunk flags
    pkt.extend_from_slice(&20u16.to_be_bytes()); // chunk length
    let initiate_tag: u32 = rand::thread_rng().r#gen::<u32>() | 1; // must be non-zero
    pkt.extend_from_slice(&initiate_tag.to_be_bytes());
    pkt.extend_from_slice(&65535u32.to_be_bytes()); // a-rwnd
    pkt.extend_from_slice(&1u16.to_be_bytes()); // num outbound streams
    pkt.extend_from_slice(&1u16.to_be_bytes()); // num inbound streams
    let initial_tsn: u32 = rand::thread_rng().r#gen();
    pkt.extend_from_slice(&initial_tsn.to_be_bytes());

    // CRC-32c over SCTP portion (checksum field is already zeroed)
    let crc = crc32c::crc32c(&pkt[sctp_start..]);
    pkt[sctp_start + 8..sctp_start + 12].copy_from_slice(&crc.to_le_bytes());

    Ok(pkt)
}

fn build_sctp_init_ipv6(
    src_ip: std::net::Ipv6Addr,
    dst_ip: std::net::Ipv6Addr,
    src_port: u16,
    dst_port: u16,
) -> Result<Vec<u8>, PacketError> {
    use rand::Rng;

    let sctp_len: u16 = 32; // 12 common header + 20 INIT chunk
    let mut pkt = Vec::with_capacity(40 + sctp_len as usize);

    // --- IPv6 header (40 bytes) ---
    pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // version=6, traffic class, flow label
    pkt.extend_from_slice(&sctp_len.to_be_bytes()); // payload length
    pkt.push(132); // next header = SCTP
    pkt.push(DEFAULT_TTL); // hop limit
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());

    // --- SCTP common header (12 bytes) ---
    let sctp_start = pkt.len();
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]); // verification tag = 0 for INIT
    pkt.extend_from_slice(&[0x00; 4]); // checksum placeholder

    // --- INIT chunk (20 bytes) ---
    pkt.push(1);
    pkt.push(0);
    pkt.extend_from_slice(&20u16.to_be_bytes());
    let initiate_tag: u32 = rand::thread_rng().r#gen::<u32>() | 1;
    pkt.extend_from_slice(&initiate_tag.to_be_bytes());
    pkt.extend_from_slice(&65535u32.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    let initial_tsn: u32 = rand::thread_rng().r#gen();
    pkt.extend_from_slice(&initial_tsn.to_be_bytes());

    // CRC-32c over SCTP portion
    let crc = crc32c::crc32c(&pkt[sctp_start..]);
    pkt[sctp_start + 8..sctp_start + 12].copy_from_slice(&crc.to_le_bytes());

    Ok(pkt)
}

/// Build an ICMP echo request with the Don't Fragment (DF) bit set and configurable payload size.
/// Used for path MTU discovery. IPv4 only.
pub fn build_icmp_echo_df_packet(
    src_ip: std::net::Ipv4Addr,
    dst_ip: std::net::Ipv4Addr,
    id: u16,
    seq: u16,
    payload_size: usize,
) -> Result<Vec<u8>, PacketError> {
    let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), DEFAULT_TTL)
        .icmpv4_echo_request(id, seq);

    let payload = vec![0xABu8; payload_size];
    let mut buf = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut buf, &payload)
        .map_err(|e| PacketError::BuildFailed(e.to_string()))?;

    // Set DF bit: byte 6 of IP header, set bit 0x40
    if buf.len() >= 7 {
        buf[6] |= 0x40;
        // Recompute IP header checksum since we modified flags
        buf[10] = 0;
        buf[11] = 0;
        let cksum = ipv4_checksum(&buf[..20]);
        buf[10] = (cksum >> 8) as u8;
        buf[11] = (cksum & 0xff) as u8;
    }

    Ok(buf)
}

/// Compute IPv4 header checksum (RFC 1071).
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            (chunk[0] as u32) << 8 | (chunk[1] as u32)
        } else {
            (chunk[0] as u32) << 8
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn build_syn_produces_valid_packet() {
        let pkt = build_syn_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
            0x12345678,
        )
        .unwrap();

        // IP header (20) + TCP header (20 base + 4 MSS option from etherparse) = ~44
        assert!(pkt.len() >= 40);

        // Parse it back
        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        let tcp = parsed.transport.unwrap();
        match tcp {
            etherparse::TransportSlice::Tcp(tcp_hdr) => {
                assert_eq!(tcp_hdr.source_port(), 12345);
                assert_eq!(tcp_hdr.destination_port(), 80);
                assert!(tcp_hdr.syn());
                assert!(!tcp_hdr.ack());
                assert_eq!(tcp_hdr.sequence_number(), 0x12345678);
            }
            _ => panic!("expected TCP transport"),
        }
    }

    #[test]
    fn build_syn_ethernet_adds_frame_header() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pkt = build_syn_packet_ethernet(
            src_mac,
            dst_mac,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            1,
        )
        .unwrap();

        // Ethernet (14) + IP (20) + TCP (20+) = at least 54
        assert!(pkt.len() >= 54);

        // Verify Ethernet header
        assert_eq!(&pkt[0..6], &dst_mac);
        assert_eq!(&pkt[6..12], &src_mac);
        // EtherType 0x0800 = IPv4
        assert_eq!(&pkt[12..14], &[0x08, 0x00]);
    }

    #[test]
    fn build_syn_ipv6_produces_valid_packet() {
        let src = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        let pkt = build_syn_packet(src, 12345, dst, 80, 0xABCD).unwrap();

        // IPv6 header (40) + TCP header (20+) = at least 60
        assert!(pkt.len() >= 60);

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.syn());
                assert_eq!(tcp.source_port(), 12345);
                assert_eq!(tcp.destination_port(), 80);
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_ipv6_mixed_addresses_error() {
        let result = build_syn_packet(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12345,
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            80,
            1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_icmp_echo_produces_valid_packet() {
        let pkt = build_icmp_echo_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            0x1234,
            1,
        )
        .unwrap();

        // IP header (20) + ICMP header (8) = 28 minimum
        assert!(pkt.len() >= 28);

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Icmpv4(icmp) => match icmp.header().icmp_type {
                etherparse::Icmpv4Type::EchoRequest(echo) => {
                    assert_eq!(echo.id, 0x1234);
                    assert_eq!(echo.seq, 1);
                }
                other => panic!("expected EchoRequest, got {:?}", other),
            },
            _ => panic!("expected ICMPv4 transport"),
        }
    }

    #[test]
    fn build_tcp_ack_has_ack_flag() {
        let pkt = build_tcp_ack_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            0xDEADBEEF,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.ack());
                assert!(!tcp.syn());
                assert!(!tcp.rst());
                assert_eq!(tcp.source_port(), 40001);
                assert_eq!(tcp.destination_port(), 80);
            }
            _ => panic!("expected TCP transport"),
        }
    }

    #[test]
    fn build_udp_probe_produces_valid_packet() {
        let pkt = build_udp_probe_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            40125,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Udp(udp) => {
                assert_eq!(udp.source_port(), 40001);
                assert_eq!(udp.destination_port(), 40125);
            }
            _ => panic!("expected UDP transport"),
        }
    }

    #[test]
    fn build_icmp_timestamp_produces_valid_packet() {
        let pkt = build_icmp_timestamp_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            0x5678,
            2,
        )
        .unwrap();

        // IP (20) + ICMP header (8) + timestamp payload (12) = 40
        assert!(pkt.len() >= 40);

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Icmpv4(icmp) => {
                let header = icmp.header();
                match header.icmp_type {
                    etherparse::Icmpv4Type::TimestampRequest(ref msg) => {
                        assert_eq!(msg.id, 0x5678);
                        assert_eq!(msg.seq, 2);
                        assert_eq!(msg.originate_timestamp, 0);
                    }
                    other => panic!("expected TimestampRequest, got {:?}", other),
                }
            }
            _ => panic!("expected ICMPv4 transport"),
        }
    }

    #[test]
    fn build_arp_request_produces_valid_frame() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 1);

        let frame = build_arp_request(src_mac, src_ip, dst_ip);

        // Should be exactly 42 bytes: 14 Ethernet + 28 ARP
        assert_eq!(frame.len(), 42);

        // Ethernet: dst MAC = broadcast
        assert_eq!(&frame[0..6], &[0xff; 6]);
        // Ethernet: src MAC
        assert_eq!(&frame[6..12], &src_mac);
        // Ethernet: EtherType = ARP (0x0806)
        assert_eq!(&frame[12..14], &[0x08, 0x06]);

        // ARP: hardware type = Ethernet (1)
        assert_eq!(&frame[14..16], &[0x00, 0x01]);
        // ARP: protocol type = IPv4 (0x0800)
        assert_eq!(&frame[16..18], &[0x08, 0x00]);
        // ARP: operation = request (1)
        assert_eq!(&frame[20..22], &[0x00, 0x01]);
        // ARP: sender MAC
        assert_eq!(&frame[22..28], &src_mac);
        // ARP: sender IP
        assert_eq!(&frame[28..32], &src_ip.octets());
        // ARP: target MAC = unknown (zeros)
        assert_eq!(&frame[32..38], &[0x00; 6]);
        // ARP: target IP
        assert_eq!(&frame[38..42], &dst_ip.octets());
    }

    #[test]
    fn roundtrip_preserves_fields() {
        let src = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2));
        let pkt = build_syn_packet(src, 50000, dst, 8080, 0xDEADBEEF).unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();

        // Check IP addresses
        match parsed.net.unwrap() {
            etherparse::NetSlice::Ipv4(ipv4) => {
                assert_eq!(ipv4.header().source(), [172, 16, 0, 1]);
                assert_eq!(ipv4.header().destination(), [172, 16, 0, 2]);
            }
            _ => panic!("expected IPv4"),
        }

        // Check TCP fields
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert_eq!(tcp.source_port(), 50000);
                assert_eq!(tcp.destination_port(), 8080);
                assert_eq!(tcp.sequence_number(), 0xDEADBEEF);
                assert!(tcp.syn());
                assert!(!tcp.ack());
                assert!(!tcp.rst());
                assert_eq!(tcp.window_size(), DEFAULT_WINDOW_SIZE);
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_tcp_packet_syn_flags() {
        let pkt = build_tcp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            1,
            TcpFlags::SYN,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.syn());
                assert!(!tcp.ack());
                assert!(!tcp.fin());
                assert!(!tcp.rst());
                assert!(!tcp.psh());
                assert!(!tcp.urg());
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_tcp_packet_fin_flags() {
        let pkt = build_tcp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            1,
            TcpFlags::FIN,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.fin());
                assert!(!tcp.syn());
                assert!(!tcp.ack());
                assert!(!tcp.rst());
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_tcp_packet_null_no_flags() {
        let pkt = build_tcp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            1,
            TcpFlags::NONE,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(!tcp.syn());
                assert!(!tcp.ack());
                assert!(!tcp.fin());
                assert!(!tcp.rst());
                assert!(!tcp.psh());
                assert!(!tcp.urg());
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_tcp_packet_xmas_flags() {
        let pkt = build_tcp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            1,
            TcpFlags::XMAS,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.fin());
                assert!(tcp.psh());
                assert!(tcp.urg());
                assert!(!tcp.syn());
                assert!(!tcp.ack());
                assert!(!tcp.rst());
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_tcp_packet_ack_flags() {
        let pkt = build_tcp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            1,
            TcpFlags::ACK,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.ack());
                assert!(!tcp.syn());
                assert!(!tcp.fin());
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_tcp_packet_maimon_flags() {
        let pkt = build_tcp_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            1,
            TcpFlags::MAIMON,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.fin());
                assert!(tcp.ack());
                assert!(!tcp.syn());
                assert!(!tcp.rst());
                assert!(!tcp.psh());
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_udp_probe_with_payload_roundtrip() {
        let payload = b"\x00\x00\x00\x00\x00\x01\x00\x00"; // Fake DNS header fragment
        let pkt = build_udp_probe_with_payload(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            53,
            payload,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Udp(udp) => {
                assert_eq!(udp.source_port(), 40001);
                assert_eq!(udp.destination_port(), 53);
            }
            _ => panic!("expected UDP transport"),
        }
        // Verify the packet is larger than one without payload
        // IP (20) + UDP (8) + payload (8) = 36
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
    }

    #[test]
    fn build_udp_probe_with_empty_payload() {
        let pkt = build_udp_probe_with_payload(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            161,
            &[],
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Udp(udp) => {
                assert_eq!(udp.destination_port(), 161);
            }
            _ => panic!("expected UDP transport"),
        }
        // Empty payload: IP (20) + UDP (8) = 28
        assert_eq!(pkt.len(), 28);
    }

    #[test]
    fn build_tcp_packet_ipv6_with_flags() {
        let src = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        let pkt = build_tcp_packet(src, 40001, dst, 443, 1, TcpFlags::XMAS).unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.fin());
                assert!(tcp.psh());
                assert!(tcp.urg());
                assert!(!tcp.syn());
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn build_ipv6_udp_probe() {
        let src = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        let pkt = build_udp_probe_packet(src, 40001, dst, 53).unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Udp(udp) => {
                assert_eq!(udp.source_port(), 40001);
                assert_eq!(udp.destination_port(), 53);
            }
            _ => panic!("expected UDP"),
        }
    }

    #[test]
    fn build_ipv6_icmpv6_echo() {
        let src = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        let pkt = build_icmp_echo_packet(src, dst, 0x1234, 1).unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Icmpv6(icmpv6) => match icmpv6.header().icmp_type {
                etherparse::Icmpv6Type::EchoRequest(echo) => {
                    assert_eq!(echo.id, 0x1234);
                    assert_eq!(echo.seq, 1);
                }
                other => panic!("expected EchoRequest, got {:?}", other),
            },
            _ => panic!("expected ICMPv6"),
        }
    }

    #[test]
    fn build_sctp_init_packet_length() {
        let pkt = build_sctp_init_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            3868,
        )
        .unwrap();
        // 20 IP + 12 SCTP header + 20 INIT chunk = 52
        assert_eq!(pkt.len(), 52);
    }

    #[test]
    fn build_sctp_init_packet_protocol() {
        let pkt = build_sctp_init_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            3868,
        )
        .unwrap();
        // IP protocol field is at byte 9
        assert_eq!(pkt[9], 132, "IP protocol should be SCTP (132)");
    }

    #[test]
    fn build_sctp_init_packet_crc32c() {
        let pkt = build_sctp_init_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            3868,
        )
        .unwrap();
        // SCTP portion starts at byte 20
        let sctp_data = &pkt[20..];
        // Read the stored checksum (bytes 8-11 of SCTP, little-endian)
        let stored_crc =
            u32::from_le_bytes([sctp_data[8], sctp_data[9], sctp_data[10], sctp_data[11]]);
        // Zero the checksum field and recompute
        let mut verify = sctp_data.to_vec();
        verify[8..12].copy_from_slice(&[0x00; 4]);
        let computed_crc = crc32c::crc32c(&verify);
        assert_eq!(
            stored_crc, computed_crc,
            "SCTP CRC-32c checksum should be valid"
        );
    }

    #[test]
    fn build_sctp_init_packet_init_chunk() {
        let pkt = build_sctp_init_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            3868,
        )
        .unwrap();
        // INIT chunk starts at byte 32 (20 IP + 12 SCTP header)
        assert_eq!(pkt[32], 1, "chunk type should be INIT (1)");
        assert_eq!(pkt[33], 0, "chunk flags should be 0");
        let chunk_len = u16::from_be_bytes([pkt[34], pkt[35]]);
        assert_eq!(chunk_len, 20, "INIT chunk length should be 20");
        // Verification tag in SCTP header should be 0 for INIT
        let vtag = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);
        assert_eq!(vtag, 0, "verification tag should be 0 for INIT");
    }

    #[test]
    fn build_sctp_init_ipv6_packet_length() {
        let src = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        let dst = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        let pkt = build_sctp_init_packet(src, 40001, dst, 3868).unwrap();
        // 40 IPv6 + 12 SCTP header + 20 INIT chunk = 72
        assert_eq!(pkt.len(), 72);
    }

    #[test]
    fn build_icmp_echo_df_has_df_bit() {
        let pkt = build_icmp_echo_df_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            0x1234,
            1,
            100,
        )
        .unwrap();
        // DF bit is in byte 6, bit 0x40
        assert_eq!(pkt[6] & 0x40, 0x40, "DF bit should be set");
    }

    #[test]
    fn build_icmp_echo_df_correct_size() {
        let payload_size = 100;
        let pkt = build_icmp_echo_df_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            0x1234,
            1,
            payload_size,
        )
        .unwrap();
        // 20 IP + 8 ICMP header + payload
        assert_eq!(pkt.len(), 20 + 8 + payload_size);
    }
}
