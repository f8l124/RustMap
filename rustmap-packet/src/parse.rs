use std::net::IpAddr;
use std::time::Instant;

use etherparse::SlicedPacket;
use rustmap_types::{TcpFingerprint, TcpOption, estimate_initial_ttl};

use crate::traits::{CapturedResponse, ResponseType};

/// Parse a raw captured packet (starting from IP header) into a CapturedResponse.
/// Returns None if the packet is not relevant (not TCP SYN/ACK, RST, or ICMP unreachable).
// TODO: Add cargo-fuzz targets for parse_response_from_ip
pub fn parse_response_from_ip(data: &[u8], timestamp: Instant) -> Option<CapturedResponse> {
    let packet = SlicedPacket::from_ip(data).ok()?;
    parse_sliced_packet(&packet, timestamp)
}

/// Parse a raw captured packet (starting from Ethernet header) into a CapturedResponse.
/// Returns None if the packet is not relevant.
pub fn parse_response_from_ethernet(data: &[u8], timestamp: Instant) -> Option<CapturedResponse> {
    // Try ARP first (EtherType 0x0806) — SlicedPacket won't parse these
    if let Some(resp) = try_parse_arp(data, timestamp) {
        return Some(resp);
    }

    let packet = SlicedPacket::from_ethernet(data).ok()?;
    parse_sliced_packet(&packet, timestamp)
}

fn parse_sliced_packet(packet: &SlicedPacket<'_>, timestamp: Instant) -> Option<CapturedResponse> {
    // Try TCP response first
    if let Some(resp) = try_parse_tcp(packet, timestamp) {
        return Some(resp);
    }
    // Try direct UDP response
    if let Some(resp) = try_parse_udp(packet, timestamp) {
        return Some(resp);
    }
    // Try SCTP response (etherparse doesn't parse SCTP, so we check the raw payload)
    if let Some(resp) = try_parse_sctp(packet, timestamp) {
        return Some(resp);
    }
    // Try ICMP unreachable (contains embedded TCP or UDP header)
    try_parse_icmp(packet, timestamp)
}

fn extract_src_ip(net: &etherparse::NetSlice<'_>) -> Option<IpAddr> {
    match net {
        etherparse::NetSlice::Ipv4(ipv4) => {
            Some(IpAddr::V4(ipv4.header().source_addr()))
        }
        etherparse::NetSlice::Ipv6(ipv6) => {
            Some(IpAddr::V6(ipv6.header().source_addr()))
        }
    }
}

fn try_parse_tcp(packet: &SlicedPacket<'_>, timestamp: Instant) -> Option<CapturedResponse> {
    let net = packet.net.as_ref()?;
    let src_ip = extract_src_ip(net)?;

    let transport = packet.transport.as_ref()?;
    match transport {
        etherparse::TransportSlice::Tcp(tcp) => {
            let response_type = if tcp.syn() && tcp.ack() {
                ResponseType::SynAck
            } else if tcp.rst() {
                ResponseType::Rst
            } else {
                return None; // Not a response we care about
            };

            let tcp_fingerprint = extract_tcp_fingerprint(net, tcp);

            Some(CapturedResponse {
                src_ip,
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                response_type,
                timestamp,
                tcp_fingerprint,
                next_hop_mtu: None,
            })
        }
        _ => None,
    }
}

/// Parse a direct UDP response — indicates the port is open and responding.
fn try_parse_udp(packet: &SlicedPacket<'_>, timestamp: Instant) -> Option<CapturedResponse> {
    let net = packet.net.as_ref()?;
    let src_ip = extract_src_ip(net)?;

    let transport = packet.transport.as_ref()?;
    match transport {
        etherparse::TransportSlice::Udp(udp) => {
            Some(CapturedResponse {
                src_ip,
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                response_type: ResponseType::UdpResponse,
                timestamp,
                tcp_fingerprint: None,
                next_hop_mtu: None,
            })
        }
        _ => None,
    }
}

/// Parse an SCTP response (INIT-ACK or ABORT) from raw packet payload.
/// etherparse doesn't support SCTP, so we check the IP protocol number
/// and parse the SCTP header manually from the payload bytes.
fn try_parse_sctp(packet: &SlicedPacket<'_>, timestamp: Instant) -> Option<CapturedResponse> {
    let net = packet.net.as_ref()?;
    let src_ip = extract_src_ip(net)?;

    // Check IP protocol number for SCTP (132)
    let ip_protocol = match net {
        etherparse::NetSlice::Ipv4(ipv4) => ipv4.header().protocol().0,
        etherparse::NetSlice::Ipv6(ipv6) => ipv6.header().next_header().0,
    };

    if ip_protocol != 132 {
        return None;
    }

    // When etherparse sees an unknown protocol, transport is None.
    // The SCTP data is in the IP payload (transport is None for SCTP).
    let payload = match net {
        etherparse::NetSlice::Ipv4(ipv4) => ipv4.payload().payload,
        etherparse::NetSlice::Ipv6(ipv6) => ipv6.payload().payload,
    };
    // Need at least 12 bytes common header + 4 bytes chunk header = 16 bytes
    if payload.len() < 16 {
        return None;
    }

    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    // First chunk starts at byte 12 (after 12-byte common header)
    let chunk_type = payload[12];

    let response_type = match chunk_type {
        2 => ResponseType::SctpInitAck,
        6 => ResponseType::SctpAbort,
        _ => return None,
    };

    Some(CapturedResponse {
        src_ip,
        src_port,
        dst_port,
        response_type,
        timestamp,
        tcp_fingerprint: None,
        next_hop_mtu: None,
    })
}

/// Extract OS fingerprinting data from a TCP response packet.
fn extract_tcp_fingerprint(
    net: &etherparse::NetSlice<'_>,
    tcp: &etherparse::TcpSlice<'_>,
) -> Option<TcpFingerprint> {
    // Extract TTL and DF bit from IP header
    let (observed_ttl, df_bit) = match net {
        etherparse::NetSlice::Ipv4(ipv4) => {
            let hdr = ipv4.header();
            (hdr.ttl(), !hdr.is_fragmenting_payload())
        }
        etherparse::NetSlice::Ipv6(ipv6) => {
            // IPv6 uses hop_limit instead of TTL; DF is always implicitly set
            // (fragmentation is handled by extension headers, not the base header)
            (ipv6.header().hop_limit(), true)
        }
    };

    let window_size = tcp.window_size();

    // Parse TCP options into our TcpOption type
    let mut tcp_options = Vec::new();
    let mut mss = None;

    for opt_result in tcp.options_iterator() {
        match opt_result {
            Ok(opt) => {
                use etherparse::TcpOptionElement;
                match opt {
                    TcpOptionElement::Noop => tcp_options.push(TcpOption::Nop),
                    TcpOptionElement::MaximumSegmentSize(val) => {
                        mss = Some(val);
                        tcp_options.push(TcpOption::Mss(val));
                    }
                    TcpOptionElement::WindowScale(val) => {
                        tcp_options.push(TcpOption::WindowScale(val));
                    }
                    TcpOptionElement::SelectiveAcknowledgementPermitted => {
                        tcp_options.push(TcpOption::SackPermitted);
                    }
                    TcpOptionElement::Timestamp(ts_val, ts_ecr) => {
                        tcp_options.push(TcpOption::Timestamp(ts_val, ts_ecr));
                    }
                    TcpOptionElement::SelectiveAcknowledgement(_, _) => {
                        // SACK data — not used for fingerprinting, skip
                    }
                }
            }
            Err(_) => break,
        }
    }

    Some(TcpFingerprint {
        initial_ttl: estimate_initial_ttl(observed_ttl),
        window_size,
        tcp_options,
        df_bit,
        mss,
    })
}

fn try_parse_icmp(packet: &SlicedPacket<'_>, timestamp: Instant) -> Option<CapturedResponse> {
    let net = packet.net.as_ref()?;
    let src_ip = extract_src_ip(net)?;

    let transport = packet.transport.as_ref()?;
    match transport {
        etherparse::TransportSlice::Icmpv4(icmp) => {
            let header = icmp.header();
            match header.icmp_type {
                etherparse::Icmpv4Type::DestinationUnreachable(ref dest_header) => {
                    // Check for Fragmentation Needed (code 4) — used for MTU discovery
                    if let etherparse::icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu } = dest_header {
                        return Some(CapturedResponse {
                            src_ip,
                            src_port: 0,
                            dst_port: 0,
                            response_type: ResponseType::IcmpFragmentationNeeded,
                            timestamp,
                            tcp_fingerprint: None,
                            next_hop_mtu: Some(*next_hop_mtu),
                        });
                    }
                    let payload = icmp.payload();
                    // Determine if this is specifically port unreachable (code 3)
                    let is_port_unreachable = matches!(
                        dest_header,
                        etherparse::icmpv4::DestUnreachableHeader::Port
                    );
                    parse_icmp_embedded(payload, timestamp, is_port_unreachable)
                }
                etherparse::Icmpv4Type::EchoReply(_) => {
                    Some(CapturedResponse {
                        src_ip,
                        src_port: 0,
                        dst_port: 0,
                        response_type: ResponseType::IcmpEchoReply,
                        timestamp,
                        tcp_fingerprint: None,
                        next_hop_mtu: None,
                    })
                }
                etherparse::Icmpv4Type::TimestampReply(_) => {
                    Some(CapturedResponse {
                        src_ip,
                        src_port: 0,
                        dst_port: 0,
                        response_type: ResponseType::IcmpTimestampReply,
                        timestamp,
                        tcp_fingerprint: None,
                        next_hop_mtu: None,
                    })
                }
                etherparse::Icmpv4Type::TimeExceeded(_) => {
                    // TTL expired — intermediate router in traceroute
                    Some(CapturedResponse {
                        src_ip,
                        src_port: 0,
                        dst_port: 0,
                        response_type: ResponseType::IcmpTimeExceeded,
                        timestamp,
                        tcp_fingerprint: None,
                        next_hop_mtu: None,
                    })
                }
                _ => None,
            }
        }
        etherparse::TransportSlice::Icmpv6(icmpv6) => {
            let header = icmpv6.header();
            match header.icmp_type {
                etherparse::Icmpv6Type::DestinationUnreachable(ref code) => {
                    let payload = icmpv6.payload();
                    let is_port_unreachable = matches!(
                        code,
                        etherparse::icmpv6::DestUnreachableCode::Port
                    );
                    parse_icmpv6_embedded(payload, timestamp, is_port_unreachable)
                }
                etherparse::Icmpv6Type::EchoReply(_) => {
                    Some(CapturedResponse {
                        src_ip,
                        src_port: 0,
                        dst_port: 0,
                        response_type: ResponseType::IcmpEchoReply,
                        timestamp,
                        tcp_fingerprint: None,
                        next_hop_mtu: None,
                    })
                }
                etherparse::Icmpv6Type::TimeExceeded(_) => {
                    // Hop limit expired — intermediate router in traceroute
                    Some(CapturedResponse {
                        src_ip,
                        src_port: 0,
                        dst_port: 0,
                        response_type: ResponseType::IcmpTimeExceeded,
                        timestamp,
                        tcp_fingerprint: None,
                        next_hop_mtu: None,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Parse an ARP reply from a raw Ethernet frame.
/// ARP replies have EtherType 0x0806 and operation code 2.
fn try_parse_arp(data: &[u8], timestamp: Instant) -> Option<CapturedResponse> {
    // Minimum ARP frame: 14 Ethernet + 28 ARP = 42 bytes
    if data.len() < 42 {
        return None;
    }
    // Check EtherType: ARP (0x0806)
    if data[12..14] != [0x08, 0x06] {
        return None;
    }
    // Check ARP operation: reply (2)
    if data[20..22] != [0x00, 0x02] {
        return None;
    }
    // Sender IP is at bytes 28-31
    let sender_ip = std::net::Ipv4Addr::new(data[28], data[29], data[30], data[31]);
    Some(CapturedResponse {
        src_ip: IpAddr::V4(sender_ip),
        src_port: 0,
        dst_port: 0,
        response_type: ResponseType::ArpReply,
        timestamp,
        tcp_fingerprint: None,
        next_hop_mtu: None,
    })
}

/// Parse the embedded IPv6+transport header from an ICMPv6 destination unreachable payload.
/// ICMPv6 errors include "As much of invoking packet as possible without the ICMPv6 packet
/// exceeding the minimum IPv6 MTU" (RFC 4443). At minimum: IPv6 header (40 bytes) + 8 bytes.
fn parse_icmpv6_embedded(
    payload: &[u8],
    timestamp: Instant,
    is_port_unreachable: bool,
) -> Option<CapturedResponse> {
    // Need at least IPv6 header (40 bytes) + 8 bytes of transport
    if payload.len() < 48 {
        return None;
    }

    let embedded = SlicedPacket::from_ip(payload).ok()?;

    let net = embedded.net.as_ref()?;
    let target_ip = match net {
        etherparse::NetSlice::Ipv6(ipv6) => IpAddr::V6(ipv6.header().destination_addr()),
        _ => return None,
    };

    // Try TCP/UDP via etherparse first
    if let Some(transport) = embedded.transport.as_ref() {
        return match transport {
            etherparse::TransportSlice::Tcp(tcp) => {
                Some(CapturedResponse {
                    src_ip: target_ip,
                    src_port: tcp.destination_port(),
                    dst_port: tcp.source_port(),
                    response_type: ResponseType::IcmpUnreachable,
                    timestamp,
                    tcp_fingerprint: None,
                    next_hop_mtu: None,
                })
            }
            etherparse::TransportSlice::Udp(udp) => {
                let response_type = if is_port_unreachable {
                    ResponseType::IcmpPortUnreachable
                } else {
                    ResponseType::IcmpUnreachable
                };
                Some(CapturedResponse {
                    src_ip: target_ip,
                    src_port: udp.destination_port(),
                    dst_port: udp.source_port(),
                    response_type,
                    timestamp,
                    tcp_fingerprint: None,
                    next_hop_mtu: None,
                })
            }
            _ => None,
        };
    }

    // etherparse doesn't parse SCTP, so transport is None for next_header 132.
    // Manually extract SCTP ports from the embedded IPv6 payload.
    let (ip_proto, embedded_payload) = match net {
        etherparse::NetSlice::Ipv6(ipv6) => (ipv6.header().next_header().0, ipv6.payload().payload),
        _ => return None,
    };
    if ip_proto == 132 && embedded_payload.len() >= 4 {
        let sctp_src_port = u16::from_be_bytes([embedded_payload[0], embedded_payload[1]]);
        let sctp_dst_port = u16::from_be_bytes([embedded_payload[2], embedded_payload[3]]);
        return Some(CapturedResponse {
            src_ip: target_ip,
            src_port: sctp_dst_port,
            dst_port: sctp_src_port,
            response_type: ResponseType::IcmpUnreachable,
            timestamp,
            tcp_fingerprint: None,
            next_hop_mtu: None,
        });
    }

    None
}

/// Parse the embedded IP+transport header from an ICMP destination unreachable payload.
/// ICMP unreachable includes the original IP header + first 8 bytes of the
/// original datagram (enough for TCP/UDP src/dst ports).
///
/// When `is_port_unreachable` is true (ICMP code 3) and the embedded transport is UDP,
/// emits `IcmpPortUnreachable`. Otherwise emits `IcmpUnreachable`.
fn parse_icmp_embedded(
    payload: &[u8],
    timestamp: Instant,
    is_port_unreachable: bool,
) -> Option<CapturedResponse> {
    // The embedded packet starts with the original IP header.
    // We need at least IP header (20 bytes) + 8 bytes of transport
    if payload.len() < 28 {
        return None;
    }

    let embedded = SlicedPacket::from_ip(payload).ok()?;

    // The destination in the embedded packet is the original target (the responder).
    let net = embedded.net.as_ref()?;
    let target_ip = match net {
        etherparse::NetSlice::Ipv4(ipv4) => IpAddr::V4(ipv4.header().destination_addr()),
        _ => return None,
    };

    // Try TCP/UDP via etherparse first
    if let Some(transport) = embedded.transport.as_ref() {
        return match transport {
            etherparse::TransportSlice::Tcp(tcp) => {
                Some(CapturedResponse {
                    src_ip: target_ip,
                    // The embedded packet's src_port is OUR source port
                    // The embedded packet's dst_port is the TARGET's port
                    src_port: tcp.destination_port(),
                    dst_port: tcp.source_port(),
                    response_type: ResponseType::IcmpUnreachable,
                    timestamp,
                    tcp_fingerprint: None,
                    next_hop_mtu: None,
                })
            }
            etherparse::TransportSlice::Udp(udp) => {
                let response_type = if is_port_unreachable {
                    ResponseType::IcmpPortUnreachable
                } else {
                    ResponseType::IcmpUnreachable
                };
                Some(CapturedResponse {
                    src_ip: target_ip,
                    src_port: udp.destination_port(),
                    dst_port: udp.source_port(),
                    response_type,
                    timestamp,
                    tcp_fingerprint: None,
                    next_hop_mtu: None,
                })
            }
            _ => None,
        };
    }

    // etherparse doesn't parse SCTP, so transport is None for IP protocol 132.
    // Manually extract SCTP ports from the embedded IP payload.
    let (ip_proto, embedded_payload) = match net {
        etherparse::NetSlice::Ipv4(ipv4) => (ipv4.header().protocol().0, ipv4.payload().payload),
        _ => return None,
    };
    if ip_proto == 132 && embedded_payload.len() >= 4 {
        let sctp_src_port = u16::from_be_bytes([embedded_payload[0], embedded_payload[1]]);
        let sctp_dst_port = u16::from_be_bytes([embedded_payload[2], embedded_payload[3]]);
        return Some(CapturedResponse {
            src_ip: target_ip,
            src_port: sctp_dst_port, // target's port
            dst_port: sctp_src_port, // our source port
            response_type: ResponseType::IcmpUnreachable,
            timestamp,
            tcp_fingerprint: None,
            next_hop_mtu: None,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_syn_ack() {
        // Build a SYN+ACK response packet
        let builder = etherparse::PacketBuilder::ipv4(
            [192, 168, 1, 1],  // source (target responding)
            [192, 168, 1, 100], // dest (our machine)
            64,
        )
        .tcp(80, 40001, 1000, 65535) // src_port=80, dst_port=40001
        .syn()
        .ack(0x12345679);

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(resp.src_port, 80);
        assert_eq!(resp.dst_port, 40001);
        assert_eq!(resp.response_type, ResponseType::SynAck);
    }

    #[test]
    fn parse_rst() {
        let builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 100],
            64,
        )
        .tcp(443, 40002, 0, 0)
        .rst();

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_port, 443);
        assert_eq!(resp.dst_port, 40002);
        assert_eq!(resp.response_type, ResponseType::Rst);
    }

    #[test]
    fn ignores_non_syn_ack_non_rst() {
        // Build a plain ACK (no SYN, no RST)
        let builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 100],
            64,
        )
        .tcp(80, 40003, 100, 65535)
        .ack(200);

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();

        let ts = Instant::now();
        assert!(parse_response_from_ip(&buf, ts).is_none());
    }

    #[test]
    fn parse_ethernet_frame() {
        let builder = etherparse::PacketBuilder::ethernet2(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        )
        .ipv4([172, 16, 0, 1], [172, 16, 0, 100], 64)
        .tcp(22, 40010, 500, 32768)
        .syn()
        .ack(1);

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ethernet(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
        assert_eq!(resp.src_port, 22);
        assert_eq!(resp.dst_port, 40010);
        assert_eq!(resp.response_type, ResponseType::SynAck);
    }

    #[test]
    fn parse_icmp_echo_reply() {
        // Build an ICMP echo reply packet
        let builder = etherparse::PacketBuilder::ipv4(
            [192, 168, 1, 1],   // source (target responding)
            [192, 168, 1, 100], // dest (our machine)
            64,
        )
        .icmpv4_echo_reply(0x1234, 1);

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(resp.src_port, 0);
        assert_eq!(resp.dst_port, 0);
        assert_eq!(resp.response_type, ResponseType::IcmpEchoReply);
    }

    #[test]
    fn parse_icmp_timestamp_reply() {
        // Build an ICMP timestamp reply (type 14, code 0)
        let bytes5to8 = [0x12u8, 0x34, 0x00, 0x01]; // id=0x1234, seq=1
        let builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 100],
            64,
        )
        .icmpv4_raw(14, 0, bytes5to8);

        // 12-byte timestamp payload
        let payload = [0u8; 12];
        let mut buf = Vec::new();
        builder.write(&mut buf, &payload).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(resp.response_type, ResponseType::IcmpTimestampReply);
    }

    #[test]
    fn parse_arp_reply() {
        // Build a fake ARP reply frame manually
        let mut frame = vec![0u8; 42];
        // Ethernet header
        frame[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst MAC
        frame[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src MAC
        frame[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType: ARP
        // ARP header
        frame[14..16].copy_from_slice(&[0x00, 0x01]); // Hardware type: Ethernet
        frame[16..18].copy_from_slice(&[0x08, 0x00]); // Protocol type: IPv4
        frame[18] = 6; // Hardware addr len
        frame[19] = 4; // Protocol addr len
        frame[20..22].copy_from_slice(&[0x00, 0x02]); // Operation: reply (2)
        frame[22..28].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Sender MAC
        frame[28..32].copy_from_slice(&[192, 168, 1, 1]); // Sender IP
        frame[32..38].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // Target MAC
        frame[38..42].copy_from_slice(&[192, 168, 1, 100]); // Target IP

        let ts = Instant::now();
        let resp = parse_response_from_ethernet(&frame, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(resp.src_port, 0);
        assert_eq!(resp.dst_port, 0);
        assert_eq!(resp.response_type, ResponseType::ArpReply);
    }

    #[test]
    fn parse_arp_request_ignored() {
        // ARP request (operation 1) should not be parsed as a response
        let mut frame = vec![0u8; 42];
        frame[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType: ARP
        frame[20..22].copy_from_slice(&[0x00, 0x01]); // Operation: request (1)
        frame[28..32].copy_from_slice(&[192, 168, 1, 1]); // Sender IP

        let ts = Instant::now();
        assert!(parse_response_from_ethernet(&frame, ts).is_none());
    }

    #[test]
    fn parse_udp_response() {
        // Build a direct UDP response packet
        let builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 1],   // source (target responding)
            [10, 0, 0, 100], // dest (our machine)
            64,
        )
        .udp(53, 40001); // src_port=53 (DNS), dst_port=40001 (our port)

        let payload = b"\x00\x00\x81\x80"; // DNS response fragment
        let mut buf = Vec::new();
        builder.write(&mut buf, payload).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(resp.src_port, 53);
        assert_eq!(resp.dst_port, 40001);
        assert_eq!(resp.response_type, ResponseType::UdpResponse);
    }

    #[test]
    fn parse_icmp_port_unreachable_with_udp() {
        // Build the original UDP probe that we "sent"
        let udp_builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 100], // our IP (the sender)
            [10, 0, 0, 1],   // target IP
            64,
        )
        .udp(40001, 161); // our_port=40001, target_port=161

        let mut embedded_pkt = Vec::new();
        udp_builder.write(&mut embedded_pkt, &[]).unwrap();

        // Build ICMP port unreachable wrapping the embedded UDP
        // ICMP type 3, code 3 = port unreachable
        // DestUnreachableHeader::Port maps to code 3
        let icmp_builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 1],   // responder (the target)
            [10, 0, 0, 100], // our machine
            64,
        )
        .icmpv4_raw(3, 3, [0u8; 4]); // type 3, code 3, unused bytes

        let mut buf = Vec::new();
        icmp_builder.write(&mut buf, &embedded_pkt).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(resp.src_port, 161);
        assert_eq!(resp.dst_port, 40001);
        assert_eq!(resp.response_type, ResponseType::IcmpPortUnreachable);
    }

    #[test]
    fn parse_icmp_admin_prohibited_with_udp() {
        // Build the original UDP probe
        let udp_builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 100],
            [10, 0, 0, 1],
            64,
        )
        .udp(40002, 53);

        let mut embedded_pkt = Vec::new();
        udp_builder.write(&mut embedded_pkt, &[]).unwrap();

        // ICMP type 3, code 13 = communication administratively prohibited
        let icmp_builder = etherparse::PacketBuilder::ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 100],
            64,
        )
        .icmpv4_raw(3, 13, [0u8; 4]);

        let mut buf = Vec::new();
        icmp_builder.write(&mut buf, &embedded_pkt).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_port, 53);
        assert_eq!(resp.dst_port, 40002);
        // Code 13 is NOT port unreachable → should be IcmpUnreachable (filtered)
        assert_eq!(resp.response_type, ResponseType::IcmpUnreachable);
    }

    #[test]
    fn empty_data_returns_none() {
        assert!(parse_response_from_ip(&[], Instant::now()).is_none());
        assert!(parse_response_from_ethernet(&[], Instant::now()).is_none());
    }

    #[test]
    fn parse_ipv6_syn_ack() {
        use std::net::Ipv6Addr;
        let builder = etherparse::PacketBuilder::ipv6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 100).octets(),
            64,
        )
        .tcp(80, 40001, 1000, 65535)
        .syn()
        .ack(0x12345679);

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(resp.src_port, 80);
        assert_eq!(resp.dst_port, 40001);
        assert_eq!(resp.response_type, ResponseType::SynAck);
        // IPv6 fingerprint should be extracted
        let fp = resp.tcp_fingerprint.unwrap();
        assert_eq!(fp.initial_ttl, 64);
        assert!(fp.df_bit); // IPv6 always DF
    }

    #[test]
    fn parse_ipv6_rst() {
        use std::net::Ipv6Addr;
        let builder = etherparse::PacketBuilder::ipv6(
            Ipv6Addr::LOCALHOST.octets(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2).octets(),
            64,
        )
        .tcp(443, 40002, 0, 0)
        .rst();

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_port, 443);
        assert_eq!(resp.dst_port, 40002);
        assert_eq!(resp.response_type, ResponseType::Rst);
    }

    #[test]
    fn parse_ipv6_icmpv6_echo_reply() {
        use std::net::Ipv6Addr;
        let builder = etherparse::PacketBuilder::ipv6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 100).octets(),
            64,
        )
        .icmpv6_echo_reply(0x1234, 1);

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(resp.response_type, ResponseType::IcmpEchoReply);
    }

    #[test]
    fn parse_ipv6_icmpv6_port_unreachable() {
        use std::net::Ipv6Addr;
        // Build the original UDP probe that we "sent"
        let udp_builder = etherparse::PacketBuilder::ipv6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 100).octets(), // our IP
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets(),   // target
            64,
        )
        .udp(40001, 161); // our_port=40001, target_port=161

        let mut embedded_pkt = Vec::new();
        udp_builder.write(&mut embedded_pkt, &[]).unwrap();

        // Build ICMPv6 destination unreachable (port) wrapping the embedded UDP
        // ICMPv6 type 1 (dest unreachable), code 4 (port unreachable)
        let icmpv6_builder = etherparse::PacketBuilder::ipv6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets(),   // responder
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 100).octets(), // our machine
            64,
        )
        .icmpv6_raw(1, 4, [0u8; 4]); // type 1 = dest unreachable, code 4 = port

        let mut buf = Vec::new();
        icmpv6_builder.write(&mut buf, &embedded_pkt).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(resp.src_port, 161);
        assert_eq!(resp.dst_port, 40001);
        assert_eq!(resp.response_type, ResponseType::IcmpPortUnreachable);
    }

    #[test]
    fn parse_ipv6_udp_response() {
        use std::net::Ipv6Addr;
        let builder = etherparse::PacketBuilder::ipv6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 100).octets(),
            64,
        )
        .udp(53, 40001);

        let payload = b"\x00\x00\x81\x80";
        let mut buf = Vec::new();
        builder.write(&mut buf, payload).unwrap();

        let ts = Instant::now();
        let resp = parse_response_from_ip(&buf, ts).unwrap();
        assert_eq!(resp.src_ip, IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(resp.src_port, 53);
        assert_eq!(resp.dst_port, 40001);
        assert_eq!(resp.response_type, ResponseType::UdpResponse);
    }
}
