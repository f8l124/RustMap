use std::net::IpAddr;

use etherparse::{PacketBuilder, TcpOptionElement};

use crate::privilege::PacketError;

/// TTL for OS fingerprinting probes — use 64 to mimic Linux/macOS.
const OS_PROBE_TTL: u8 = 64;
/// Large window size to elicit full option responses from target.
const OS_PROBE_WINDOW: u16 = 65535;

/// Get the standard TCP options used for OS fingerprinting probes.
/// Order: MSS(1460), SACK_PERM, Timestamp, NOP, WindowScale(7)
/// This mimics a typical Linux SYN and elicits a full options response.
fn os_probe_options() -> [TcpOptionElement; 5] {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    [
        TcpOptionElement::MaximumSegmentSize(1460),
        TcpOptionElement::SelectiveAcknowledgementPermitted,
        TcpOptionElement::Timestamp(ts, 0),
        TcpOptionElement::Noop,
        TcpOptionElement::WindowScale(7),
    ]
}

/// Build a TCP SYN probe with specific TCP options for OS fingerprinting.
/// Sent to both open ports (expects SYN/ACK) and closed ports (expects RST).
pub fn build_os_syn_probe(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let options = os_probe_options();
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), OS_PROBE_TTL)
                .tcp(src_port, dst_port, seq_num, OS_PROBE_WINDOW)
                .syn()
                .options(&options)
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;

            let mut buf = Vec::with_capacity(builder.size(0));
            builder
                .write(&mut buf, &[])
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;
            Ok(buf)
        }
        _ => Err(PacketError::BuildFailed(
            "IPv6 OS probes not yet supported".into(),
        )),
    }
}

/// Build a TCP SYN probe with Ethernet frame header (Windows/Npcap).
pub fn build_os_syn_probe_ethernet(
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
            let options = os_probe_options();
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv4(src.octets(), dst.octets(), OS_PROBE_TTL)
                .tcp(src_port, dst_port, seq_num, OS_PROBE_WINDOW)
                .syn()
                .options(&options)
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;

            let mut buf = Vec::with_capacity(builder.size(0));
            builder
                .write(&mut buf, &[])
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;
            Ok(buf)
        }
        _ => Err(PacketError::BuildFailed(
            "IPv6 OS probes not yet supported".into(),
        )),
    }
}

/// Build a TCP ACK probe with specific TCP options for OS fingerprinting.
/// Sent to open ports — expects RST response with OS-specific characteristics.
pub fn build_os_ack_probe(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq_num: u32,
) -> Result<Vec<u8>, PacketError> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let options = os_probe_options();
            let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), OS_PROBE_TTL)
                .tcp(src_port, dst_port, seq_num, OS_PROBE_WINDOW)
                .ack(0)
                .options(&options)
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;

            let mut buf = Vec::with_capacity(builder.size(0));
            builder
                .write(&mut buf, &[])
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;
            Ok(buf)
        }
        _ => Err(PacketError::BuildFailed(
            "IPv6 OS probes not yet supported".into(),
        )),
    }
}

/// Build a TCP ACK probe with Ethernet frame header (Windows/Npcap).
pub fn build_os_ack_probe_ethernet(
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
            let options = os_probe_options();
            let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
                .ipv4(src.octets(), dst.octets(), OS_PROBE_TTL)
                .tcp(src_port, dst_port, seq_num, OS_PROBE_WINDOW)
                .ack(0)
                .options(&options)
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;

            let mut buf = Vec::with_capacity(builder.size(0));
            builder
                .write(&mut buf, &[])
                .map_err(|e| PacketError::BuildFailed(e.to_string()))?;
            Ok(buf)
        }
        _ => Err(PacketError::BuildFailed(
            "IPv6 OS probes not yet supported".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn syn_probe_has_custom_options() {
        let pkt = build_os_syn_probe(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            0x12345678,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();

        // Check IP header
        match parsed.net.as_ref().unwrap() {
            etherparse::NetSlice::Ipv4(ipv4) => {
                assert_eq!(ipv4.header().ttl(), OS_PROBE_TTL);
                // DF bit should be set (etherparse default for non-fragmenting)
                assert!(!ipv4.header().is_fragmenting_payload());
            }
            _ => panic!("expected IPv4"),
        }

        // Check TCP header
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.syn());
                assert!(!tcp.ack());
                assert_eq!(tcp.source_port(), 40001);
                assert_eq!(tcp.destination_port(), 80);
                assert_eq!(tcp.window_size(), OS_PROBE_WINDOW);
                assert_eq!(tcp.sequence_number(), 0x12345678);

                // Verify TCP options are present
                let mut found_mss = false;
                let mut found_sack = false;
                let mut found_ts = false;
                let mut found_ws = false;
                for opt in tcp.options_iterator() {
                    match opt.unwrap() {
                        etherparse::TcpOptionElement::MaximumSegmentSize(1460) => {
                            found_mss = true;
                        }
                        etherparse::TcpOptionElement::SelectiveAcknowledgementPermitted => {
                            found_sack = true;
                        }
                        etherparse::TcpOptionElement::Timestamp(_, _) => found_ts = true,
                        etherparse::TcpOptionElement::WindowScale(7) => found_ws = true,
                        _ => {}
                    }
                }
                assert!(found_mss, "MSS option missing");
                assert!(found_sack, "SACK_PERM option missing");
                assert!(found_ts, "Timestamp option missing");
                assert!(found_ws, "WindowScale option missing");
            }
            _ => panic!("expected TCP transport"),
        }
    }

    #[test]
    fn ack_probe_has_ack_flag_and_options() {
        let pkt = build_os_ack_probe(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40002,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            0xDEADBEEF,
        )
        .unwrap();

        let parsed = etherparse::SlicedPacket::from_ip(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.ack());
                assert!(!tcp.syn());
                assert!(!tcp.rst());
                assert_eq!(tcp.source_port(), 40002);
                assert_eq!(tcp.destination_port(), 443);
                assert_eq!(tcp.window_size(), OS_PROBE_WINDOW);

                // Verify options are present
                let mut has_mss = false;
                for opt in tcp.options_iterator() {
                    if let Ok(etherparse::TcpOptionElement::MaximumSegmentSize(1460)) = opt {
                        has_mss = true;
                    }
                }
                assert!(has_mss, "ACK probe should have MSS option");
            }
            _ => panic!("expected TCP transport"),
        }
    }

    #[test]
    fn syn_probe_ethernet_has_frame_header() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pkt = build_os_syn_probe_ethernet(
            src_mac,
            dst_mac,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40003,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            22,
            1,
        )
        .unwrap();

        // Ethernet (14) + IP (20) + TCP (20 base + options) = at least 54
        assert!(pkt.len() >= 54);
        assert_eq!(&pkt[0..6], &dst_mac);
        assert_eq!(&pkt[6..12], &src_mac);
        assert_eq!(&pkt[12..14], &[0x08, 0x00]); // IPv4

        // Parse and verify SYN + options
        let parsed = etherparse::SlicedPacket::from_ethernet(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.syn());
                assert_eq!(tcp.window_size(), OS_PROBE_WINDOW);
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn ack_probe_ethernet_has_frame_header() {
        let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let dst_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let pkt = build_os_ack_probe_ethernet(
            src_mac,
            dst_mac,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40004,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            42,
        )
        .unwrap();

        assert!(pkt.len() >= 54);
        let parsed = etherparse::SlicedPacket::from_ethernet(&pkt).unwrap();
        match parsed.transport.unwrap() {
            etherparse::TransportSlice::Tcp(tcp) => {
                assert!(tcp.ack());
                assert!(!tcp.syn());
            }
            _ => panic!("expected TCP"),
        }
    }

    #[test]
    fn ipv6_probes_not_supported() {
        let v6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert!(build_os_syn_probe(v6, 1, v6, 80, 0).is_err());
        assert!(build_os_ack_probe(v6, 1, v6, 80, 0).is_err());
    }

    #[test]
    fn syn_probe_larger_than_basic_syn() {
        // OS probe should be larger than a basic SYN due to TCP options
        let os_pkt = build_os_syn_probe(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            1,
        )
        .unwrap();

        let basic_pkt = crate::build::build_syn_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            80,
            1,
        )
        .unwrap();

        assert!(
            os_pkt.len() > basic_pkt.len(),
            "OS probe ({}) should be larger than basic SYN ({}) due to options",
            os_pkt.len(),
            basic_pkt.len()
        );
    }
}
