use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::debug;

use crate::proxy::connect_tcp;
use crate::tls_fingerprint::probe_tls_server;
use crate::DetectionError;
use rustmap_types::{DetectionMethod, ProxyConfig, ServiceInfo, TlsServerFingerprint};

/// Probe a port with a TLS handshake and derive service information from the result.
///
/// Returns both a `ServiceInfo` (for the service detection pipeline) and the raw
/// `TlsServerFingerprint` (stored on `Port.tls_info`).
pub async fn probe_tls_for_service(
    ip: IpAddr,
    port: u16,
    hostname: Option<&str>,
    proxy: Option<&ProxyConfig>,
) -> Result<Option<(ServiceInfo, TlsServerFingerprint)>, DetectionError> {
    let fp = match probe_tls_server(ip, port, hostname, proxy).await? {
        Some(fp) => fp,
        None => return Ok(None),
    };

    let tls_ver_str = match fp.tls_version {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        _ => "TLS",
    };

    let alpn_str = fp.alpn.as_deref().unwrap_or("");

    // Derive service name and info based on ALPN and port
    let (service_name, info_str) = if port == 853 {
        ("domain", format!("DNS over TLS; {tls_ver_str}"))
    } else if alpn_str == "h2" {
        ("https", format!("HTTP/2 over TLS; {tls_ver_str}"))
    } else if alpn_str == "http/1.1" {
        ("https", format!("HTTP/1.1 over TLS; {tls_ver_str}"))
    } else if !alpn_str.is_empty() {
        ("ssl", format!("{alpn_str}; {tls_ver_str}"))
    } else {
        ("ssl", tls_ver_str.to_string())
    };

    let info = ServiceInfo {
        name: service_name.to_string(),
        product: None,
        version: None,
        info: Some(info_str),
        method: DetectionMethod::TlsProbe,
    };

    Ok(Some((info, fp)))
}

/// HTTP/2 connection preface bytes.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Empty HTTP/2 SETTINGS frame (type=0x04, flags=0, stream=0, length=0).
const H2_SETTINGS: &[u8] = &[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];

/// Send an HTTP/2 connection preface to detect cleartext h2c support.
///
/// Returns `true` if the server responds with an HTTP/2 SETTINGS frame.
pub async fn probe_http2_cleartext(
    ip: IpAddr,
    port: u16,
    proxy: Option<&ProxyConfig>,
    timeout: Duration,
) -> Result<bool, DetectionError> {
    let addr = std::net::SocketAddr::new(ip, port);
    let stream = match connect_tcp(addr, proxy, timeout).await {
        Ok(s) => s,
        Err(e) => {
            debug!(port, error = %e, "h2c probe: connection failed");
            return Ok(false);
        }
    };

    let (mut reader, mut writer) = stream.into_split();

    // Send preface + SETTINGS
    let mut payload = Vec::with_capacity(H2_PREFACE.len() + H2_SETTINGS.len());
    payload.extend_from_slice(H2_PREFACE);
    payload.extend_from_slice(H2_SETTINGS);

    match tokio::time::timeout(timeout, writer.write_all(&payload)).await {
        Ok(Ok(())) => {}
        _ => return Ok(false),
    }

    // Read response — look for SETTINGS frame (type byte = 0x04 at offset 3)
    let mut buf = vec![0u8; 128];
    match tokio::time::timeout(timeout, reader.read(&mut buf)).await {
        Ok(Ok(n)) if n >= 9 => {
            // HTTP/2 frame: length(3) + type(1) + flags(1) + stream_id(4)
            // SETTINGS frame type = 0x04
            Ok(buf[3] == 0x04)
        }
        _ => Ok(false),
    }
}

/// Build a minimal QUIC v1 Initial packet for probing.
///
/// The packet is padded to 1200 bytes (QUIC minimum for Initial packets).
pub fn build_quic_initial() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(1200);

    // Long header byte: form(1)=1 | fixed(1)=1 | type(2)=00 (Initial) | reserved(2)=00 | pn_len(2)=00
    // pn_len bits 00 encodes a 1-byte packet number (actual_len = encoded_value + 1)
    pkt.push(0xC0); // 1100_0000

    // Version: QUIC v1
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    // DCID length + DCID (8 bytes of pseudorandom)
    pkt.push(0x08);
    let dcid: [u8; 8] = {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        ts.to_le_bytes()
    };
    pkt.extend_from_slice(&dcid);

    // SCID length = 0
    pkt.push(0x00);

    // Token length = 0 (varint)
    pkt.push(0x00);

    // Length: remaining bytes as a 2-byte varint (with 0x40 prefix for 2-byte form)
    // We need to fill to 1200 total. Current header = 1+4+1+8+1+1 = 16 bytes
    // Plus 2 for this length field = 18 bytes
    // Remaining = 1200 - 18 = 1182 bytes for packet number + payload
    let remaining = 1200u16 - 18;
    pkt.push(0x40 | ((remaining >> 8) as u8));
    pkt.push((remaining & 0xFF) as u8);

    // Packet number (1 byte since pn_len=0 → 1 byte)
    pkt.push(0x00);

    // Pad rest with zeros
    pkt.resize(1200, 0x00);

    pkt
}

/// Result of a QUIC probe with version negotiation details.
#[derive(Debug, Clone)]
pub struct QuicProbeResult {
    /// Server supports QUIC.
    pub supported: bool,
    /// Detected QUIC versions from Version Negotiation or response header.
    pub versions: Vec<u32>,
    /// Whether the server appears to support HTTP/3 (QUIC v1).
    pub http3: bool,
}

/// Send a QUIC Initial packet to detect HTTP/3 / QUIC support.
///
/// Returns `true` if the server responds with any UDP data (indicating QUIC support).
pub async fn probe_quic(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<bool, DetectionError> {
    let result = probe_quic_detailed(ip, port, timeout).await?;
    Ok(result.supported)
}

/// Send a QUIC Initial packet and parse the response for version information.
///
/// Parses Version Negotiation packets to extract supported QUIC versions,
/// and detects HTTP/3 when QUIC v1 (0x00000001) is present.
pub async fn probe_quic_detailed(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<QuicProbeResult, DetectionError> {
    let bind_addr = if ip.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    let target = std::net::SocketAddr::new(ip, port);
    let packet = build_quic_initial();

    match tokio::time::timeout(timeout, socket.send_to(&packet, target)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            debug!(port, error = %e, "QUIC probe: send failed");
            return Ok(QuicProbeResult {
                supported: false,
                versions: vec![],
                http3: false,
            });
        }
        Err(_) => {
            return Ok(QuicProbeResult {
                supported: false,
                versions: vec![],
                http3: false,
            });
        }
    }

    // Wait for response
    let mut buf = vec![0u8; 1500];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) if n > 0 => Ok(parse_quic_response(&buf[..n])),
        _ => Ok(QuicProbeResult {
            supported: false,
            versions: vec![],
            http3: false,
        }),
    }
}

/// Parse a QUIC UDP response to extract version information.
fn parse_quic_response(data: &[u8]) -> QuicProbeResult {
    if data.is_empty() {
        return QuicProbeResult {
            supported: false,
            versions: vec![],
            http3: false,
        };
    }

    let form_bit = data[0] & 0x80 != 0;

    if !form_bit {
        // Short header — server speaks QUIC (established connection)
        return QuicProbeResult {
            supported: true,
            versions: vec![],
            http3: false,
        };
    }

    // Long header — extract version field (bytes 1-4)
    if data.len() < 5 {
        return QuicProbeResult {
            supported: true,
            versions: vec![],
            http3: false,
        };
    }

    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

    if version == 0x0000_0000 {
        // Version Negotiation packet: parse supported versions from payload
        let versions = parse_version_negotiation(data);
        let http3 = versions.contains(&0x0000_0001);
        return QuicProbeResult {
            supported: true,
            versions,
            http3,
        };
    }

    if version == 0x0000_0001 {
        // QUIC v1 response (Initial/Retry) — HTTP/3 supported
        return QuicProbeResult {
            supported: true,
            versions: vec![0x0000_0001],
            http3: true,
        };
    }

    // Some other QUIC version
    QuicProbeResult {
        supported: true,
        versions: vec![version],
        http3: false,
    }
}

/// Parse a QUIC Version Negotiation packet to extract the list of supported versions.
///
/// Format after the long header byte (1) + version (4):
///   DCID Len (1) + DCID + SCID Len (1) + SCID + Supported Versions (4 each)
pub fn parse_version_negotiation(data: &[u8]) -> Vec<u32> {
    let mut versions = Vec::new();
    if data.len() < 7 {
        return versions;
    }

    // Skip: form byte (1) + version (4) = 5 bytes
    let mut offset = 5;

    // DCID length
    if offset >= data.len() {
        return versions;
    }
    let dcid_len = data[offset] as usize;
    offset += 1 + dcid_len;

    // SCID length
    if offset >= data.len() {
        return versions;
    }
    let scid_len = data[offset] as usize;
    offset += 1 + scid_len;

    // Remaining bytes are 4-byte version entries
    while offset + 4 <= data.len() {
        let ver = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        versions.push(ver);
        offset += 4;
    }

    versions
}

/// Detect gRPC by sending an HTTP/2 preface with gRPC-style content-type.
///
/// This is a simplified probe: if h2 is confirmed and the server responds to
/// a gRPC-like request, it's likely a gRPC server.
pub async fn probe_grpc_cleartext(
    ip: IpAddr,
    port: u16,
    proxy: Option<&ProxyConfig>,
    timeout: Duration,
) -> Result<bool, DetectionError> {
    let addr = std::net::SocketAddr::new(ip, port);
    let stream = match connect_tcp(addr, proxy, timeout).await {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    let (mut reader, mut writer) = stream.into_split();

    // Send H2 preface + SETTINGS + a minimal HEADERS frame with gRPC content-type
    let mut payload = Vec::new();
    payload.extend_from_slice(H2_PREFACE);
    payload.extend_from_slice(H2_SETTINGS);

    // Minimal HEADERS frame on stream 1 with gRPC markers
    // This is a simplified approach — real gRPC would use HPACK encoding
    // We just check if the server speaks h2 and doesn't reject immediately
    let headers_payload = b":method: POST\r\ncontent-type: application/grpc\r\n";
    let frame_len = headers_payload.len() as u32;
    // Frame header: length(3) + type(1)=0x01 (HEADERS) + flags(1)=0x04 (END_HEADERS) + stream(4)=1
    payload.push((frame_len >> 16) as u8);
    payload.push((frame_len >> 8) as u8);
    payload.push(frame_len as u8);
    payload.push(0x01); // HEADERS frame
    payload.push(0x04); // END_HEADERS flag
    payload.extend_from_slice(&1u32.to_be_bytes()); // stream ID 1
    payload.extend_from_slice(headers_payload);

    match tokio::time::timeout(timeout, writer.write_all(&payload)).await {
        Ok(Ok(())) => {}
        _ => return Ok(false),
    }

    // Read response — look for any valid h2 response that mentions grpc
    let mut buf = vec![0u8; 512];
    match tokio::time::timeout(timeout, reader.read(&mut buf)).await {
        Ok(Ok(n)) if n >= 9 => {
            // If we get a SETTINGS frame back, the server speaks h2
            // Check if response contains "grpc" anywhere (simplified)
            let response = String::from_utf8_lossy(&buf[..n]);
            Ok(response.contains("grpc"))
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_initial_packet_size() {
        let pkt = build_quic_initial();
        assert_eq!(pkt.len(), 1200, "QUIC Initial must be >= 1200 bytes");
    }

    #[test]
    fn quic_initial_packet_header() {
        let pkt = build_quic_initial();
        // Long header bit set
        assert_eq!(pkt[0] & 0x80, 0x80);
        // Version = QUIC v1
        assert_eq!(&pkt[1..5], &[0x00, 0x00, 0x00, 0x01]);
        // DCID length = 8
        assert_eq!(pkt[5], 0x08);
        // SCID length = 0
        assert_eq!(pkt[14], 0x00);
    }

    #[test]
    fn http2_preface_format() {
        assert!(H2_PREFACE.starts_with(b"PRI * HTTP/2.0"));
        assert_eq!(H2_SETTINGS.len(), 9);
        assert_eq!(H2_SETTINGS[3], 0x04); // SETTINGS frame type
    }

    #[test]
    fn quic_initial_packet_dcid_unique() {
        let pkt1 = build_quic_initial();
        // Introduce a small delay so nanos timestamp differs
        std::thread::sleep(std::time::Duration::from_millis(1));
        let pkt2 = build_quic_initial();
        // DCID is bytes 6..14
        assert_ne!(&pkt1[6..14], &pkt2[6..14], "DCIDs should differ between calls");
    }

    #[test]
    fn parse_quic_version_negotiation_extracts_versions() {
        // Build a mock Version Negotiation packet:
        // form byte (0x80) + version 0x00000000 + DCID len(8) + DCID + SCID len(0) + versions
        let mut pkt = Vec::new();
        pkt.push(0x80); // long header
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // version = 0 (VN)
        pkt.push(0x08); // DCID len
        pkt.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // DCID
        pkt.push(0x00); // SCID len
        // Supported versions
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
        pkt.extend_from_slice(&[0xff, 0x00, 0x00, 0x1d]); // draft-29

        let versions = parse_version_negotiation(&pkt);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0], 0x0000_0001); // QUIC v1
        assert_eq!(versions[1], 0xff00_001d); // draft-29

        // Also test via parse_quic_response
        let result = parse_quic_response(&pkt);
        assert!(result.supported);
        assert!(result.http3); // contains QUIC v1
        assert_eq!(result.versions.len(), 2);
    }

    #[test]
    fn parse_quic_response_quic_v1() {
        // A QUIC v1 Initial response
        let mut pkt = vec![0xC0]; // long header
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version = QUIC v1
        pkt.resize(20, 0x00); // pad

        let result = parse_quic_response(&pkt);
        assert!(result.supported);
        assert!(result.http3);
        assert_eq!(result.versions, vec![0x0000_0001]);
    }

    #[test]
    fn parse_quic_response_empty() {
        let result = parse_quic_response(&[]);
        assert!(!result.supported);
    }
}
