use crate::os::TlsServerFingerprint;
use crate::script::ScriptResult;
use crate::service::ServiceInfo;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The state of a scanned port, following nmap conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::Unfiltered => write!(f, "unfiltered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
            PortState::ClosedFiltered => write!(f, "closed|filtered"),
        }
    }
}

/// A single port result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<String>,
    /// Detailed service/version info (populated by -sV detection).
    pub service_info: Option<ServiceInfo>,
    /// Reason for the port state (e.g., "syn-ack", "rst", "conn-refused").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Results from scripts run against this port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub script_results: Vec<ScriptResult>,
    /// TLS handshake metadata (populated when service detection probes TLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_info: Option<TlsServerFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Sctp => write!(f, "sctp"),
        }
    }
}

/// User-specified port specification, parsed from -p argument.
#[derive(Debug, Clone)]
pub enum PortSpec {
    Single(u16),
    Range(u16, u16),
}

/// A list of port specs that can be expanded into concrete port numbers.
#[derive(Debug, Clone)]
pub struct PortRange {
    specs: Vec<PortSpec>,
}

impl PortRange {
    /// Parse an nmap-style port string like "80,443,1000-2000"
    pub fn parse(input: &str) -> Result<Self, PortParseError> {
        let mut specs = Vec::new();
        for part in input.split(',') {
            let part = part.trim();
            if let Some((start, end)) = part.split_once('-') {
                let start: u16 = start
                    .trim()
                    .parse()
                    .map_err(|_| PortParseError::InvalidPort(start.to_string()))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .map_err(|_| PortParseError::InvalidPort(end.to_string()))?;
                if start == 0 {
                    return Err(PortParseError::InvalidPort(
                        "0 (ports must be 1-65535)".to_string(),
                    ));
                }
                if start > end {
                    return Err(PortParseError::InvalidRange(start, end));
                }
                specs.push(PortSpec::Range(start, end));
            } else {
                let port: u16 = part
                    .parse()
                    .map_err(|_| PortParseError::InvalidPort(part.to_string()))?;
                if port == 0 {
                    return Err(PortParseError::InvalidPort(
                        "0 (ports must be 1-65535)".to_string(),
                    ));
                }
                specs.push(PortSpec::Single(port));
            }
        }
        if specs.is_empty() {
            return Err(PortParseError::Empty);
        }
        Ok(Self { specs })
    }

    /// Expand all specs into a sorted, deduplicated list of port numbers.
    /// Uses a BTreeSet internally to cap memory at ~400 KB regardless of input
    /// (u16 has at most 65,536 distinct values).
    pub fn expand(&self) -> Vec<u16> {
        let mut set = std::collections::BTreeSet::new();
        for spec in &self.specs {
            match spec {
                PortSpec::Single(p) => {
                    set.insert(*p);
                }
                PortSpec::Range(start, end) => {
                    for p in *start..=*end {
                        set.insert(p);
                    }
                }
            }
        }
        set.into_iter().collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PortParseError {
    #[error("invalid port: {0}")]
    InvalidPort(String),
    #[error("invalid range: {0}-{1} (start > end)")]
    InvalidRange(u16, u16),
    #[error("empty port specification")]
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_port() {
        let range = PortRange::parse("80").unwrap();
        assert_eq!(range.expand(), vec![80]);
    }

    #[test]
    fn parse_comma_separated() {
        let range = PortRange::parse("80,443,8080").unwrap();
        assert_eq!(range.expand(), vec![80, 443, 8080]);
    }

    #[test]
    fn parse_range() {
        let range = PortRange::parse("1-5").unwrap();
        assert_eq!(range.expand(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn parse_mixed() {
        let range = PortRange::parse("22,80,100-102,443").unwrap();
        assert_eq!(range.expand(), vec![22, 80, 100, 101, 102, 443]);
    }

    #[test]
    fn parse_deduplicates() {
        let range = PortRange::parse("80,80,80").unwrap();
        assert_eq!(range.expand(), vec![80]);
    }

    #[test]
    fn parse_invalid_port() {
        assert!(PortRange::parse("abc").is_err());
    }

    #[test]
    fn parse_invalid_range() {
        assert!(PortRange::parse("100-50").is_err());
    }

    #[test]
    fn parse_empty() {
        assert!(PortRange::parse("").is_err());
    }

    #[test]
    fn port_tls_info_serde() {
        use crate::os::TlsServerFingerprint;
        let port = Port {
            number: 443,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("https".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: Some(TlsServerFingerprint {
                tls_version: 0x0304,
                cipher_suite: 0x1301,
                extensions: vec![0x002B],
                compression_method: 0,
                alpn: Some("h2".into()),
                ja4s: Some("t1302_1301_abcdef012345".into()),
                sni: None,
                certificate_chain: None,
            }),
        };
        let json = serde_json::to_string(&port).unwrap();
        assert!(json.contains("\"tls_info\""));
        assert!(json.contains("\"alpn\":\"h2\""));
        let parsed: Port = serde_json::from_str(&json).unwrap();
        assert!(parsed.tls_info.is_some());
        assert_eq!(parsed.tls_info.unwrap().alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn port_tls_info_none_skipped() {
        let port = Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        };
        let json = serde_json::to_string(&port).unwrap();
        assert!(!json.contains("tls_info"), "tls_info should be skipped when None");
    }
}
