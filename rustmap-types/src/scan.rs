use crate::host::Host;
use crate::os::{OsDetectionConfig, OsFingerprint};
use crate::port::Port;
use crate::script::ScriptResult;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

/// Which type of scan to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    TcpConnect,
    TcpSyn,
    TcpFin,
    TcpNull,
    TcpXmas,
    TcpAck,
    TcpWindow,
    TcpMaimon,
    Udp,
    SctpInit,
    Ping,
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TcpConnect => write!(f, "connect"),
            Self::TcpSyn => write!(f, "syn"),
            Self::TcpFin => write!(f, "fin"),
            Self::TcpNull => write!(f, "null"),
            Self::TcpXmas => write!(f, "xmas"),
            Self::TcpAck => write!(f, "ack"),
            Self::TcpWindow => write!(f, "window"),
            Self::TcpMaimon => write!(f, "maimon"),
            Self::Udp => write!(f, "udp"),
            Self::SctpInit => write!(f, "sctp-init"),
            Self::Ping => write!(f, "ping"),
        }
    }
}

/// Timing template, roughly matching nmap's -T0 through -T5.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingTemplate {
    Paranoid = 0,
    Sneaky = 1,
    Polite = 2,
    #[default]
    Normal = 3,
    Aggressive = 4,
    Insane = 5,
}

impl TryFrom<u8> for TimingTemplate {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Paranoid),
            1 => Ok(Self::Sneaky),
            2 => Ok(Self::Polite),
            3 => Ok(Self::Normal),
            4 => Ok(Self::Aggressive),
            5 => Ok(Self::Insane),
            _ => Err(format!("invalid timing template: {} (must be 0-5)", value)),
        }
    }
}

impl fmt::Display for TimingTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Paranoid => write!(f, "T0 (paranoid)"),
            Self::Sneaky => write!(f, "T1 (sneaky)"),
            Self::Polite => write!(f, "T2 (polite)"),
            Self::Normal => write!(f, "T3 (normal)"),
            Self::Aggressive => write!(f, "T4 (aggressive)"),
            Self::Insane => write!(f, "T5 (insane)"),
        }
    }
}

/// Which discovery probes to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// ICMP echo request (-PE).
    IcmpEcho,
    /// TCP SYN to specified ports (-PS).
    TcpSyn,
    /// TCP ACK to specified ports (-PA).
    TcpAck,
    /// ICMP timestamp request (-PP).
    IcmpTimestamp,
    /// UDP to specified ports (-PU).
    UdpPing,
    /// ARP on local network (-PR).
    ArpPing,
    /// HTTP HEAD request discovery (--PH). Works without raw sockets.
    HttpPing,
    /// TLS handshake discovery (--PHT). Works without raw sockets.
    HttpsPing,
}

impl fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IcmpEcho => write!(f, "icmp-echo"),
            Self::TcpSyn => write!(f, "tcp-syn"),
            Self::TcpAck => write!(f, "tcp-ack"),
            Self::IcmpTimestamp => write!(f, "icmp-timestamp"),
            Self::UdpPing => write!(f, "udp"),
            Self::ArpPing => write!(f, "arp"),
            Self::HttpPing => write!(f, "http"),
            Self::HttpsPing => write!(f, "https"),
        }
    }
}

/// How to handle host discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMode {
    /// Auto-select probes based on privileges.
    Default,
    /// Skip discovery, treat all hosts as up (-Pn).
    Skip,
    /// Discovery only, no port scan (-sn).
    PingOnly,
    /// Custom probe selection.
    Custom(Vec<DiscoveryMethod>),
}

/// Configuration for host discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub mode: DiscoveryMode,
    /// Ports for TCP SYN ping (default: [443]).
    pub tcp_syn_ports: Vec<u16>,
    /// Ports for TCP ACK ping (default: [80]).
    pub tcp_ack_ports: Vec<u16>,
    /// Ports for UDP ping (default: [40125]).
    pub udp_ports: Vec<u16>,
    /// Ports for HTTP ping (default: [80]).
    pub http_ports: Vec<u16>,
    /// Ports for HTTPS ping (default: [443]).
    pub https_ports: Vec<u16>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            mode: DiscoveryMode::Default,
            tcp_syn_ports: vec![443],
            tcp_ack_ports: vec![80],
            udp_ports: vec![40125],
            http_ports: vec![80],
            https_ports: vec![443],
        }
    }
}

/// Result of host discovery for a single host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    Up,
    Down,
    /// Skipped (when using -Pn).
    Unknown,
}

impl fmt::Display for HostStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Up => write!(f, "up"),
            Self::Down => write!(f, "down"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Configuration for service/version detection (-sV).
#[derive(Debug, Clone)]
pub struct ServiceDetectionConfig {
    /// Enable service/version detection.
    pub enabled: bool,
    /// Version detection intensity (0-9, default 7).
    pub intensity: u8,
    /// Per-probe timeout.
    pub probe_timeout: Duration,
    /// Probe open UDP ports for QUIC/HTTP3 support.
    pub quic_probing: bool,
    /// Ports to probe for QUIC when running TCP scans (probe corresponding UDP ports).
    pub quic_ports: Vec<u16>,
}

impl Default for ServiceDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            intensity: 7,
            probe_timeout: Duration::from_secs(5),
            quic_probing: true,
            quic_ports: vec![443, 8443, 8080, 4433],
        }
    }
}

/// SOCKS5 proxy configuration for routing TCP connections.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    /// Parse a SOCKS5 proxy URL: `socks5://[user:pass@]host:port`
    pub fn parse(url: &str) -> Result<Self, String> {
        let stripped = url
            .strip_prefix("socks5://")
            .ok_or_else(|| "proxy URL must start with socks5://".to_string())?;

        // Split optional user:pass@ from host:port
        let (auth, host_port) = if let Some(at_pos) = stripped.rfind('@') {
            let auth_part = &stripped[..at_pos];
            let hp = &stripped[at_pos + 1..];
            let (user, pass) = auth_part
                .split_once(':')
                .ok_or_else(|| "auth must be user:pass".to_string())?;
            (Some((user.to_string(), pass.to_string())), hp)
        } else {
            (None, stripped)
        };

        // Parse host:port — handle IPv6 [addr]:port
        let (host, port) = if host_port.starts_with('[') {
            // IPv6: [::1]:1080
            let bracket_end = host_port
                .find(']')
                .ok_or_else(|| "missing closing ] for IPv6 address".to_string())?;
            let h = &host_port[1..bracket_end];
            let rest = &host_port[bracket_end + 1..];
            let p = rest
                .strip_prefix(':')
                .ok_or_else(|| "missing :port after IPv6 address".to_string())?;
            (h.to_string(), p)
        } else {
            let colon = host_port
                .rfind(':')
                .ok_or_else(|| "missing :port in proxy URL".to_string())?;
            (host_port[..colon].to_string(), &host_port[colon + 1..])
        };

        let port: u16 = port.parse().map_err(|_| format!("invalid port: {port}"))?;

        if host.is_empty() {
            return Err("proxy host cannot be empty".to_string());
        }

        Ok(Self {
            host,
            port,
            username: auth.as_ref().map(|(u, _)| u.clone()),
            password: auth.map(|(_, p)| p),
        })
    }

    /// Returns `(host, port)` tuple for use with tokio-socks.
    pub fn addr(&self) -> (&str, u16) {
        (&self.host, self.port)
    }
}

/// Configuration for DNS resolution.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Custom DNS server IP addresses. Empty = use system resolver.
    pub servers: Vec<String>,
    /// DNS query timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            timeout_ms: 5000,
        }
    }
}

/// Configuration for a scan run.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<Host>,
    pub ports: Vec<u16>,
    pub scan_type: ScanType,
    pub timeout: Duration,
    pub concurrency: usize,
    pub verbose: bool,
    pub timing_template: TimingTemplate,
    pub discovery: DiscoveryConfig,
    pub service_detection: ServiceDetectionConfig,
    pub os_detection: OsDetectionConfig,
    /// Minimum number of hosts to scan in parallel.
    pub min_hostgroup: usize,
    /// Maximum number of hosts to scan in parallel.
    pub max_hostgroup: usize,
    /// Per-host timeout. `Duration::ZERO` means no timeout.
    pub host_timeout: Duration,
    /// CLI override for minimum packet rate (packets/sec).
    pub min_rate: Option<f64>,
    /// CLI override for maximum packet rate (packets/sec).
    pub max_rate: Option<f64>,
    /// CLI override for inter-probe delay.
    pub scan_delay: Option<Duration>,
    /// CLI override for maximum inter-probe delay (enables jitter when > scan_delay).
    pub max_scan_delay: Option<Duration>,
    /// Randomize port scan order (LCG-based pseudo-random permutation).
    pub randomize_ports: bool,
    /// Fixed source port for all probes (None = random per-probe).
    /// Useful for firewall evasion (e.g., port 53 or 20).
    pub source_port: Option<u16>,
    /// Decoy source IPs to send alongside real probes.
    pub decoys: Vec<std::net::IpAddr>,
    /// Fragment IP packets for IDS evasion.
    pub fragment_packets: bool,
    /// Custom payload bytes to append to outgoing probes.
    /// Set via --data-hex, --data-string, or --data-length.
    pub custom_payload: Option<Vec<u8>>,
    /// Perform traceroute after port scan.
    pub traceroute: bool,
    /// Learned initial RTO from historical data (microseconds).
    pub learned_initial_rto_us: Option<u64>,
    /// Learned initial congestion window from historical data.
    pub learned_initial_cwnd: Option<f64>,
    /// Learned slow-start threshold from historical data.
    pub learned_ssthresh: Option<f64>,
    /// Learned max retries from historical data.
    pub learned_max_retries: Option<u8>,
    /// Hosts pre-resolved as Up (skip discovery probes for these).
    pub pre_resolved_up: Vec<IpAddr>,
    /// SOCKS5 proxy for TCP connections (e.g., socks5://127.0.0.1:9050).
    pub proxy: Option<ProxyConfig>,
    /// Perform path MTU discovery (IPv4 only).
    pub mtu_discovery: bool,
    /// Override IP TTL/hop-limit on outgoing probes (None = default 64).
    pub ip_ttl: Option<u8>,
    /// Intentionally corrupt TCP/UDP checksums (firewall rule testing).
    pub badsum: bool,
    /// Spoof Ethernet source MAC address (None = real adapter MAC).
    pub spoof_mac: Option<[u8; 6]>,
}

impl ScanConfig {
    /// Validate that the configuration is internally consistent.
    /// Returns a list of error messages for any contradictory or invalid field values.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.concurrency == 0 {
            errors.push("concurrency must be >= 1".into());
        }
        if self.min_hostgroup == 0 {
            errors.push("min_hostgroup must be >= 1".into());
        }
        if self.min_hostgroup > self.max_hostgroup {
            errors.push(format!(
                "min_hostgroup ({}) cannot exceed max_hostgroup ({})",
                self.min_hostgroup, self.max_hostgroup
            ));
        }
        if let (Some(min), Some(max)) = (self.min_rate, self.max_rate)
            && min > max
        {
            errors.push(format!("min_rate ({min}) cannot exceed max_rate ({max})"));
        }
        if let (Some(delay), Some(max_delay)) = (self.scan_delay, self.max_scan_delay)
            && delay > max_delay
        {
            errors.push(format!(
                "scan_delay ({delay:?}) cannot exceed max_scan_delay ({max_delay:?})"
            ));
        }
        if self.service_detection.intensity > 9 {
            errors.push(format!(
                "service detection intensity must be 0-9, got {}",
                self.service_detection.intensity
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            ports: Vec::new(),
            scan_type: ScanType::TcpConnect,
            timeout: Duration::from_secs(3),
            concurrency: 100,
            verbose: false,
            timing_template: TimingTemplate::Normal,
            discovery: DiscoveryConfig::default(),
            service_detection: ServiceDetectionConfig::default(),
            os_detection: OsDetectionConfig::default(),
            min_hostgroup: 1,
            max_hostgroup: 256,
            host_timeout: Duration::ZERO,
            min_rate: None,
            max_rate: None,
            scan_delay: None,
            max_scan_delay: None,
            randomize_ports: false,
            source_port: None,
            decoys: Vec::new(),
            fragment_packets: false,
            custom_payload: None,
            traceroute: false,
            learned_initial_rto_us: None,
            learned_initial_cwnd: None,
            learned_ssthresh: None,
            learned_max_retries: None,
            pre_resolved_up: Vec::new(),
            proxy: None,
            mtu_discovery: false,
            ip_ttl: None,
            badsum: false,
            spoof_mac: None,
        }
    }
}

/// A single hop in a traceroute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub rtt: Option<Duration>,
}

/// Traceroute result for a single target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteResult {
    pub target: Host,
    pub hops: Vec<TracerouteHop>,
    /// Port and protocol used for the traceroute probes.
    pub port: u16,
    pub protocol: String,
}

/// Timing telemetry captured at end of a host scan.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimingSnapshot {
    /// Smoothed RTT in microseconds.
    pub srtt_us: Option<u64>,
    /// Final retransmission timeout in microseconds.
    pub rto_us: u64,
    /// RTT variance in microseconds (for jitter estimation).
    pub rttvar_us: Option<u64>,
    /// Final congestion window size.
    pub cwnd: usize,
    /// Total probes sent.
    pub probes_sent: u64,
    /// Probes that received a response.
    pub probes_responded: u64,
    /// Probes that timed out.
    pub probes_timed_out: u64,
    /// Packet loss rate: 1.0 - (responded / sent).
    pub loss_rate: f64,
}

/// Result for a single host scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostScanResult {
    pub host: Host,
    pub ports: Vec<Port>,
    pub scan_duration: Duration,
    pub host_status: HostStatus,
    pub discovery_latency: Option<Duration>,
    pub os_fingerprint: Option<OsFingerprint>,
    /// Traceroute result (when --traceroute is enabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceroute: Option<TracerouteResult>,
    /// Timing telemetry from the scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing_snapshot: Option<TimingSnapshot>,
    /// Results from host-level scripts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_script_results: Vec<ScriptResult>,
    /// Error message if the port scan failed (e.g. Npcap unavailable for SYN scan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_error: Option<String>,
    /// Estimated host uptime from TCP timestamp analysis (requires -O).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_estimate: Option<Duration>,
    /// Per-host risk score from vulnerability correlation (0.0-10.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    /// Discovered path MTU (IPv4 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
}

/// Top-level result for an entire scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub hosts: Vec<HostScanResult>,
    pub total_duration: Duration,
    pub scan_type: ScanType,
    /// Timestamp when the scan started (for XML/Grepable output).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<std::time::SystemTime>,
    /// Command-line arguments used (for XML/Grepable headers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_args: Option<String>,
    /// Number of services (ports) scanned.
    #[serde(default)]
    pub num_services: usize,
    /// Results from prerule scripts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pre_script_results: Vec<ScriptResult>,
    /// Results from postrule scripts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_script_results: Vec<ScriptResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_snapshot_serde_roundtrip() {
        let snap = TimingSnapshot {
            srtt_us: Some(5000),
            rto_us: 15000,
            rttvar_us: Some(2000),
            cwnd: 8,
            probes_sent: 100,
            probes_responded: 95,
            probes_timed_out: 5,
            loss_rate: 0.05,
        };

        let json = serde_json::to_string(&snap).unwrap();
        let deserialized: TimingSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.srtt_us, Some(5000));
        assert_eq!(deserialized.rto_us, 15000);
        assert_eq!(deserialized.rttvar_us, Some(2000));
        assert_eq!(deserialized.cwnd, 8);
        assert_eq!(deserialized.probes_sent, 100);
        assert_eq!(deserialized.probes_responded, 95);
        assert_eq!(deserialized.probes_timed_out, 5);
        assert!((deserialized.loss_rate - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn timing_snapshot_default_is_zeroed() {
        let snap = TimingSnapshot::default();
        assert_eq!(snap.srtt_us, None);
        assert_eq!(snap.rto_us, 0);
        assert_eq!(snap.rttvar_us, None);
        assert_eq!(snap.cwnd, 0);
        assert_eq!(snap.probes_sent, 0);
        assert_eq!(snap.probes_responded, 0);
        assert_eq!(snap.probes_timed_out, 0);
        assert_eq!(snap.loss_rate, 0.0);
    }

    #[test]
    fn proxy_config_parse_basic() {
        let p = ProxyConfig::parse("socks5://127.0.0.1:9050").unwrap();
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 9050);
        assert!(p.username.is_none());
        assert!(p.password.is_none());
    }

    #[test]
    fn proxy_config_parse_with_auth() {
        let p = ProxyConfig::parse("socks5://admin:secret@proxy.example.com:1080").unwrap();
        assert_eq!(p.host, "proxy.example.com");
        assert_eq!(p.port, 1080);
        assert_eq!(p.username.as_deref(), Some("admin"));
        assert_eq!(p.password.as_deref(), Some("secret"));
    }

    #[test]
    fn proxy_config_parse_ipv6() {
        let p = ProxyConfig::parse("socks5://[::1]:9050").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 9050);
    }

    #[test]
    fn proxy_config_parse_invalid() {
        assert!(ProxyConfig::parse("http://127.0.0.1:9050").is_err());
        assert!(ProxyConfig::parse("socks5://").is_err());
        assert!(ProxyConfig::parse("socks5://host").is_err());
        assert!(ProxyConfig::parse("socks5://:9050").is_err());
        assert!(ProxyConfig::parse("socks5://host:notaport").is_err());
    }

    #[test]
    fn proxy_field_on_scan_config() {
        let config = ScanConfig::default();
        assert!(config.proxy.is_none());

        let mut config = ScanConfig::default();
        config.proxy = Some(ProxyConfig::parse("socks5://127.0.0.1:9050").unwrap());
        assert_eq!(config.proxy.as_ref().unwrap().port, 9050);
    }

    #[test]
    fn host_scan_result_timing_snapshot_optional_serde() {
        // Deserialize HostScanResult JSON without timing_snapshot field
        // (backward compat via #[serde(default)])
        let json = r#"{
            "host": {"ip": "192.168.1.1", "hostname": null},
            "ports": [],
            "scan_duration": {"secs": 1, "nanos": 0},
            "host_status": "Up",
            "discovery_latency": null,
            "os_fingerprint": null,
            "traceroute": null
        }"#;
        let result: HostScanResult = serde_json::from_str(json).unwrap();
        assert!(result.timing_snapshot.is_none());
    }
}
