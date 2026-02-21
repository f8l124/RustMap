use serde::{Deserialize, Serialize};

/// A TCP option type observed in a packet, used for OS fingerprinting.
/// The ordering of these options in a SYN/ACK is a strong OS differentiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpOption {
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    Timestamp(u32, u32),
    Nop,
    Eol,
}

/// A simplified "kind" for comparing option ordering without values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpOptionKind {
    Mss,
    WindowScale,
    SackPermitted,
    Timestamp,
    Nop,
    Eol,
}

impl TcpOption {
    /// Extract the kind (type without value) for ordering comparison.
    pub fn kind(&self) -> TcpOptionKind {
        match self {
            TcpOption::Mss(_) => TcpOptionKind::Mss,
            TcpOption::WindowScale(_) => TcpOptionKind::WindowScale,
            TcpOption::SackPermitted => TcpOptionKind::SackPermitted,
            TcpOption::Timestamp(_, _) => TcpOptionKind::Timestamp,
            TcpOption::Nop => TcpOptionKind::Nop,
            TcpOption::Eol => TcpOptionKind::Eol,
        }
    }
}

/// TCP/IP fingerprint extracted from a single packet response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprint {
    /// Estimated initial TTL (rounded up to 64/128/255).
    pub initial_ttl: u8,
    /// TCP window size from the response.
    pub window_size: u16,
    /// TCP options in the order they appeared in the packet.
    pub tcp_options: Vec<TcpOption>,
    /// Whether the Don't Fragment bit was set in the IP header.
    pub df_bit: bool,
    /// MSS value if present in TCP options.
    pub mss: Option<u16>,
}

/// X.509 certificate information extracted from a TLS handshake.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Common Name from the certificate Subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_cn: Option<String>,
    /// Full Subject Distinguished Name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_dn: Option<String>,
    /// Common Name from the certificate Issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    /// Full Issuer Distinguished Name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_dn: Option<String>,
    /// Certificate serial number (hex string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Validity start (RFC 2822 string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Validity end / expiration (RFC 2822 string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Subject Alternative Names (DNS entries only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub san_dns: Vec<String>,
    /// Signature algorithm (e.g., "sha256WithRSAEncryption").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    /// Public key info (e.g., "RSA 2048", "EC P-256").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_info: Option<String>,
    /// SHA-256 fingerprint of the DER-encoded certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_fingerprint: Option<String>,
    /// Whether the certificate is self-signed (subject == issuer).
    #[serde(default)]
    pub self_signed: bool,
    /// Position in the certificate chain (0 = leaf, 1 = intermediate, etc.).
    #[serde(default)]
    pub chain_position: u8,
}

/// TLS ServerHello fingerprint extracted from a TLS handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsServerFingerprint {
    /// Negotiated TLS version (e.g., 0x0303 = TLS 1.2, 0x0304 = TLS 1.3).
    pub tls_version: u16,
    /// Cipher suite selected by the server.
    pub cipher_suite: u16,
    /// Extension types present in the ServerHello, in order.
    pub extensions: Vec<u16>,
    /// Compression method selected by the server.
    pub compression_method: u8,
    /// ALPN protocol negotiated by the server (e.g., "h2", "http/1.1").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// JA4S fingerprint string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4s: Option<String>,
    /// SNI hostname that was sent in the ClientHello.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// X.509 certificate chain extracted from the TLS handshake (TLS 1.2 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<CertificateInfo>>,
}

/// Results from all OS detection probes for a single host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsProbeResults {
    /// Fingerprint from SYN probe to an open port (SYN/ACK response).
    pub syn_open: Option<TcpFingerprint>,
    /// Fingerprint from SYN probe to a closed port (RST response).
    pub syn_closed: Option<TcpFingerprint>,
    /// Fingerprint from ACK probe to an open port (RST response).
    pub ack_open: Option<TcpFingerprint>,
    /// Fingerprint passively extracted from port scan SYN/ACK responses.
    pub passive: Option<TcpFingerprint>,
    /// TLS ServerHello fingerprint from a TLS-enabled port.
    pub tls: Option<TlsServerFingerprint>,
}

/// Configuration for OS detection (-O flag).
#[derive(Debug, Clone, Default)]
pub struct OsDetectionConfig {
    /// Whether OS detection is enabled.
    pub enabled: bool,
}

/// Final OS fingerprint result for a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    /// Detected OS family (e.g., "Linux", "Windows", "macOS", "FreeBSD").
    pub os_family: Option<String>,
    /// OS generation/version (e.g., "4.x-5.x", "10/11", "12-15").
    pub os_generation: Option<String>,
    /// Distribution-level detail (e.g., "Ubuntu 24.04", "Debian 12").
    /// Populated from service banner analysis (SSH version → distro mapping).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_detail: Option<String>,
    /// Confidence percentage (0-100).
    pub accuracy: Option<u8>,
    /// Raw probe results used for the detection.
    pub probe_results: OsProbeResults,
}

/// Estimate the initial TTL based on the observed (decremented) TTL.
/// Standard initial TTL values: 64 (Linux/macOS/FreeBSD), 128 (Windows), 255 (Solaris/Cisco).
pub fn estimate_initial_ttl(observed: u8) -> u8 {
    if observed <= 64 {
        64
    } else if observed <= 128 {
        128
    } else {
        255
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_ttl_linux_macos() {
        assert_eq!(estimate_initial_ttl(64), 64);
        assert_eq!(estimate_initial_ttl(63), 64);
        assert_eq!(estimate_initial_ttl(55), 64);
        assert_eq!(estimate_initial_ttl(1), 64);
    }

    #[test]
    fn estimate_ttl_windows() {
        assert_eq!(estimate_initial_ttl(128), 128);
        assert_eq!(estimate_initial_ttl(127), 128);
        assert_eq!(estimate_initial_ttl(120), 128);
        assert_eq!(estimate_initial_ttl(65), 128);
    }

    #[test]
    fn estimate_ttl_solaris_cisco() {
        assert_eq!(estimate_initial_ttl(255), 255);
        assert_eq!(estimate_initial_ttl(254), 255);
        assert_eq!(estimate_initial_ttl(200), 255);
        assert_eq!(estimate_initial_ttl(129), 255);
    }

    #[test]
    fn tcp_option_kind_extraction() {
        assert_eq!(TcpOption::Mss(1460).kind(), TcpOptionKind::Mss);
        assert_eq!(TcpOption::WindowScale(7).kind(), TcpOptionKind::WindowScale);
        assert_eq!(
            TcpOption::SackPermitted.kind(),
            TcpOptionKind::SackPermitted
        );
        assert_eq!(TcpOption::Timestamp(0, 0).kind(), TcpOptionKind::Timestamp);
        assert_eq!(TcpOption::Nop.kind(), TcpOptionKind::Nop);
        assert_eq!(TcpOption::Eol.kind(), TcpOptionKind::Eol);
    }

    #[test]
    fn os_probe_results_default_is_empty() {
        let results = OsProbeResults::default();
        assert!(results.syn_open.is_none());
        assert!(results.syn_closed.is_none());
        assert!(results.ack_open.is_none());
        assert!(results.passive.is_none());
    }

    #[test]
    fn os_detection_config_default_disabled() {
        let config = OsDetectionConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn tls_fingerprint_serde_new_fields() {
        let fp = TlsServerFingerprint {
            tls_version: 0x0304,
            cipher_suite: 0x1301,
            extensions: vec![0x002B],
            compression_method: 0,
            alpn: Some("h2".into()),
            ja4s: Some("t1302_1301_abcdef012345".into()),
            sni: Some("example.com".into()),
            certificate_chain: None,
        };
        let json = serde_json::to_string(&fp).unwrap();
        assert!(json.contains("\"alpn\":\"h2\""));
        assert!(json.contains("\"ja4s\":\"t1302_1301_abcdef012345\""));
        assert!(json.contains("\"sni\":\"example.com\""));
        let parsed: TlsServerFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.alpn.as_deref(), Some("h2"));
        assert_eq!(parsed.ja4s.as_deref(), Some("t1302_1301_abcdef012345"));
        assert_eq!(parsed.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn tls_fingerprint_backward_compat() {
        // Old JSON without new fields should deserialize to None
        let json = r#"{"tls_version":771,"cipher_suite":49199,"extensions":[65281],"compression_method":0}"#;
        let fp: TlsServerFingerprint = serde_json::from_str(json).unwrap();
        assert!(fp.alpn.is_none());
        assert!(fp.ja4s.is_none());
        assert!(fp.sni.is_none());
    }

    #[test]
    fn tls_fingerprint_none_fields_skipped() {
        let fp = TlsServerFingerprint {
            tls_version: 0x0303,
            cipher_suite: 0xC02F,
            extensions: vec![],
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };
        let json = serde_json::to_string(&fp).unwrap();
        assert!(!json.contains("alpn"));
        assert!(!json.contains("ja4s"));
        assert!(!json.contains("sni"));
    }
}
