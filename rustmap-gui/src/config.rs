use std::time::Duration;

use rustmap_core::parse_target;
use rustmap_timing::TimingParams;
use rustmap_types::{
    DiscoveryConfig, DiscoveryMethod, DiscoveryMode, OsDetectionConfig, PortRange, ProxyConfig,
    ScanConfig, ScanType, ServiceDetectionConfig, TimingTemplate, top_tcp_ports,
};
use serde::{Deserialize, Serialize};

/// GUI-facing scan configuration DTO.
///
/// Uses only JSON-serializable primitive types for the Tauri IPC boundary.
/// Convert to [`ScanConfig`] via [`into_scan_config()`](Self::into_scan_config).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiScanConfig {
    pub targets: Vec<String>,
    pub ports: Option<String>,
    pub scan_type: String,
    pub timing: u8,
    pub service_detection: bool,
    pub os_detection: bool,
    pub discovery_mode: String,
    pub discovery_methods: Vec<String>,
    pub tcp_syn_ports: Option<String>,
    pub tcp_ack_ports: Option<String>,
    pub udp_ping_ports: Option<String>,
    pub http_ports: Option<String>,
    pub https_ports: Option<String>,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub max_hostgroup: usize,
    pub host_timeout_ms: u64,
    pub min_rate: Option<f64>,
    pub max_rate: Option<f64>,
    pub randomize_ports: bool,
    pub source_port: Option<u16>,
    pub fragment_packets: bool,
    pub traceroute: bool,
    pub version_intensity: u8,
    pub scan_delay_ms: u64,
    pub mtu_discovery: bool,
    pub verbose: bool,
    pub min_hostgroup: usize,
    pub max_scan_delay_ms: u64,
    pub probe_timeout_ms: u64,
    pub quic_probing: bool,
    pub proxy_url: Option<String>,
    pub decoys: Option<String>,
    pub pre_resolved_up: Option<String>,
    pub payload_type: String,
    pub payload_value: Option<String>,
}

fn parse_port_list_opt(s: &Option<String>) -> Result<Option<Vec<u16>>, String> {
    match s {
        Some(s) if !s.trim().is_empty() => {
            let ports: Vec<u16> = s
                .split(',')
                .map(|p| {
                    p.trim()
                        .parse::<u16>()
                        .map_err(|_| format!("invalid port '{}'", p.trim()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(ports))
        }
        _ => Ok(None),
    }
}

impl GuiScanConfig {
    pub fn into_scan_config(self) -> Result<ScanConfig, String> {
        // Parse targets
        let mut hosts = Vec::new();
        for target in &self.targets {
            match parse_target(target) {
                Ok(parsed) => hosts.extend(parsed),
                Err(e) => return Err(format!("invalid target '{}': {}", target, e)),
            }
        }

        if hosts.is_empty() {
            return Err("no valid targets specified".into());
        }

        // Parse ports
        let ports = if let Some(ref port_spec) = self.ports {
            PortRange::parse(port_spec)
                .map_err(|e| format!("invalid port specification: {e}"))?
                .expand()
        } else {
            top_tcp_ports(1000)
        };

        // Map scan type string to enum
        let scan_type = match self.scan_type.as_str() {
            "T" => ScanType::TcpConnect,
            "S" => ScanType::TcpSyn,
            "U" => ScanType::Udp,
            "F" => ScanType::TcpFin,
            "N" => ScanType::TcpNull,
            "X" => ScanType::TcpXmas,
            "A" => ScanType::TcpAck,
            "W" => ScanType::TcpWindow,
            "M" => ScanType::TcpMaimon,
            "Z" => ScanType::SctpInit,
            other => return Err(format!("unknown scan type: {other}")),
        };

        // Map timing template
        let timing_template = match self.timing {
            0 => TimingTemplate::Paranoid,
            1 => TimingTemplate::Sneaky,
            2 => TimingTemplate::Polite,
            3 => TimingTemplate::Normal,
            4 => TimingTemplate::Aggressive,
            5 => TimingTemplate::Insane,
            n => return Err(format!("invalid timing template: {n}")),
        };

        // Resolve timing-aware defaults: 0 means "auto from template"
        let timing_params = TimingParams::from_template(timing_template);
        let concurrency = if self.concurrency == 0 {
            timing_params.connect_concurrency
        } else {
            self.concurrency
        };
        let timeout = if self.timeout_ms == 0 {
            timing_params.connect_timeout
        } else {
            Duration::from_millis(self.timeout_ms)
        };

        // Discovery config
        let discovery = match self.discovery_mode.as_str() {
            "skip" => DiscoveryConfig {
                mode: DiscoveryMode::Skip,
                ..DiscoveryConfig::default()
            },
            "ping_only" => DiscoveryConfig {
                mode: DiscoveryMode::PingOnly,
                ..DiscoveryConfig::default()
            },
            "custom" => {
                let methods: Vec<DiscoveryMethod> = self
                    .discovery_methods
                    .iter()
                    .map(|m| match m.as_str() {
                        "icmp_echo" => Ok(DiscoveryMethod::IcmpEcho),
                        "tcp_syn" => Ok(DiscoveryMethod::TcpSyn),
                        "tcp_ack" => Ok(DiscoveryMethod::TcpAck),
                        "icmp_timestamp" => Ok(DiscoveryMethod::IcmpTimestamp),
                        "udp_ping" => Ok(DiscoveryMethod::UdpPing),
                        "arp_ping" => Ok(DiscoveryMethod::ArpPing),
                        "http_ping" => Ok(DiscoveryMethod::HttpPing),
                        "https_ping" => Ok(DiscoveryMethod::HttpsPing),
                        other => Err(format!("unknown discovery method: {other}")),
                    })
                    .collect::<Result<_, _>>()?;
                let defaults = DiscoveryConfig::default();
                DiscoveryConfig {
                    mode: DiscoveryMode::Custom(methods),
                    tcp_syn_ports: parse_port_list_opt(&self.tcp_syn_ports)?
                        .unwrap_or(defaults.tcp_syn_ports),
                    tcp_ack_ports: parse_port_list_opt(&self.tcp_ack_ports)?
                        .unwrap_or(defaults.tcp_ack_ports),
                    udp_ports: parse_port_list_opt(&self.udp_ping_ports)?
                        .unwrap_or(defaults.udp_ports),
                    http_ports: parse_port_list_opt(&self.http_ports)?
                        .unwrap_or(defaults.http_ports),
                    https_ports: parse_port_list_opt(&self.https_ports)?
                        .unwrap_or(defaults.https_ports),
                }
            }
            _ => DiscoveryConfig::default(),
        };

        Ok(ScanConfig {
            targets: hosts,
            ports,
            scan_type,
            timeout,
            concurrency,
            verbose: self.verbose,
            timing_template,
            discovery,
            service_detection: ServiceDetectionConfig {
                enabled: self.service_detection,
                intensity: self.version_intensity,
                probe_timeout: if self.probe_timeout_ms > 0 {
                    Duration::from_millis(self.probe_timeout_ms)
                } else {
                    ServiceDetectionConfig::default().probe_timeout
                },
                quic_probing: self.quic_probing,
                ..ServiceDetectionConfig::default()
            },
            os_detection: OsDetectionConfig {
                enabled: self.os_detection,
            },
            min_hostgroup: self.min_hostgroup,
            max_hostgroup: self.max_hostgroup,
            host_timeout: Duration::from_millis(self.host_timeout_ms),
            min_rate: self.min_rate,
            max_rate: self.max_rate,
            randomize_ports: self.randomize_ports,
            source_port: self.source_port,
            decoys: if let Some(ref decoy_str) = self.decoys {
                decoy_str
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse().map_err(|e| format!("invalid decoy IP '{}': {}", s, e)))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            },
            fragment_packets: self.fragment_packets,
            custom_payload: match self.payload_type.as_str() {
                "hex" => {
                    let s = self.payload_value.as_deref().unwrap_or("");
                    let hex = s.strip_prefix("0x").unwrap_or(s);
                    if hex.is_empty() {
                        None
                    } else {
                        if hex.len() % 2 != 0 {
                            return Err(
                                "hex payload must have even number of characters".into()
                            );
                        }
                        let bytes: Vec<u8> = (0..hex.len())
                            .step_by(2)
                            .map(|i| {
                                u8::from_str_radix(&hex[i..i + 2], 16)
                                    .map_err(|_| format!("invalid hex at position {i}"))
                            })
                            .collect::<Result<_, _>>()?;
                        Some(bytes)
                    }
                }
                "string" => {
                    let s = self.payload_value.as_deref().unwrap_or("");
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.as_bytes().to_vec())
                    }
                }
                "length" => {
                    let s = self.payload_value.as_deref().unwrap_or("0");
                    let n: usize = s
                        .parse()
                        .map_err(|_| format!("invalid payload length: {s}"))?;
                    if n == 0 {
                        None
                    } else if n > 65400 {
                        return Err("payload length must be <= 65400".into());
                    } else {
                        let mut buf = vec![0u8; n];
                        use rand::RngCore;
                        rand::thread_rng().fill_bytes(&mut buf);
                        Some(buf)
                    }
                }
                _ => None,
            },
            traceroute: self.traceroute,
            scan_delay: if self.scan_delay_ms > 0 {
                Some(Duration::from_millis(self.scan_delay_ms))
            } else {
                None
            },
            max_scan_delay: if self.max_scan_delay_ms > 0 {
                Some(Duration::from_millis(self.max_scan_delay_ms))
            } else {
                None
            },
            learned_initial_rto_us: None,
            learned_initial_cwnd: None,
            learned_ssthresh: None,
            learned_max_retries: None,
            pre_resolved_up: if let Some(ref up_str) = self.pre_resolved_up {
                up_str
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        s.parse()
                            .map_err(|e| format!("invalid pre-resolved IP '{}': {}", s, e))
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                vec![]
            },
            proxy: if let Some(ref url) = self.proxy_url {
                Some(ProxyConfig::parse(url).map_err(|e| format!("invalid proxy: {e}"))?)
            } else {
                None
            },
            mtu_discovery: self.mtu_discovery,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_gui_config() -> GuiScanConfig {
        GuiScanConfig {
            targets: vec!["127.0.0.1".into()],
            ports: None,
            scan_type: "T".into(),
            timing: 3,
            service_detection: false,
            os_detection: false,
            discovery_mode: "default".into(),
            discovery_methods: vec![],
            tcp_syn_ports: None,
            tcp_ack_ports: None,
            udp_ping_ports: None,
            http_ports: None,
            https_ports: None,
            timeout_ms: 0,
            concurrency: 0,
            max_hostgroup: 256,
            host_timeout_ms: 0,
            min_rate: None,
            max_rate: None,
            randomize_ports: false,
            source_port: None,
            fragment_packets: false,
            traceroute: false,
            version_intensity: 7,
            scan_delay_ms: 0,
            mtu_discovery: false,
            verbose: false,
            min_hostgroup: 1,
            max_scan_delay_ms: 0,
            probe_timeout_ms: 0,
            quic_probing: true,
            proxy_url: None,
            decoys: None,
            pre_resolved_up: None,
            payload_type: "none".into(),
            payload_value: None,
        }
    }

    // --- Scan type mapping ---

    #[test]
    fn scan_type_t_tcp_connect() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::TcpConnect);
    }

    #[test]
    fn scan_type_s_tcp_syn() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "S".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::TcpSyn);
    }

    #[test]
    fn scan_type_u_udp() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "U".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::Udp);
    }

    #[test]
    fn scan_type_f_tcp_fin() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "F".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::TcpFin);
    }

    #[test]
    fn scan_type_n_tcp_null() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "N".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::TcpNull);
    }

    #[test]
    fn scan_type_x_tcp_xmas() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "X".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::TcpXmas);
    }

    #[test]
    fn scan_type_a_tcp_ack() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "A".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::TcpAck);
    }

    #[test]
    fn scan_type_w_tcp_window() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "W".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::TcpWindow);
    }

    #[test]
    fn scan_type_m_tcp_maimon() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "M".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::TcpMaimon);
    }

    #[test]
    fn scan_type_z_sctp_init() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "Z".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_type, ScanType::SctpInit);
    }

    #[test]
    fn scan_type_invalid_returns_error() {
        let mut cfg = default_gui_config();
        cfg.scan_type = "Q".into();
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("unknown scan type"), "got: {err}");
    }

    // --- Timing templates ---

    #[test]
    fn timing_all_valid_templates() {
        let expected = [
            (0, TimingTemplate::Paranoid),
            (1, TimingTemplate::Sneaky),
            (2, TimingTemplate::Polite),
            (3, TimingTemplate::Normal),
            (4, TimingTemplate::Aggressive),
            (5, TimingTemplate::Insane),
        ];
        for (value, expected_template) in expected {
            let mut cfg = default_gui_config();
            cfg.timing = value;
            let result = cfg.into_scan_config().unwrap();
            assert_eq!(result.timing_template, expected_template, "timing {value}");
        }
    }

    #[test]
    fn timing_invalid_returns_error() {
        let mut cfg = default_gui_config();
        cfg.timing = 6;
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("invalid timing template"), "got: {err}");
    }

    // --- Port parsing ---

    #[test]
    fn ports_none_uses_top_1000() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.ports.len(), 1000);
    }

    #[test]
    fn ports_custom_parsed() {
        let mut cfg = default_gui_config();
        cfg.ports = Some("80,443".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.ports.len(), 2);
        assert!(result.ports.contains(&80));
        assert!(result.ports.contains(&443));
    }

    #[test]
    fn ports_range_parsed() {
        let mut cfg = default_gui_config();
        cfg.ports = Some("20-25".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.ports.len(), 6);
        for port in 20..=25 {
            assert!(result.ports.contains(&port), "missing port {port}");
        }
    }

    #[test]
    fn ports_invalid_returns_error() {
        let mut cfg = default_gui_config();
        cfg.ports = Some("abc".into());
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("invalid port"), "got: {err}");
    }

    // --- Target parsing ---

    #[test]
    fn target_single_ip() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.targets.len(), 1);
        assert_eq!(result.targets[0].ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn target_cidr() {
        let mut cfg = default_gui_config();
        cfg.targets = vec!["192.168.1.0/30".into()];
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.targets.len(), 4);
    }

    #[test]
    fn target_multiple() {
        let mut cfg = default_gui_config();
        cfg.targets = vec!["10.0.0.1".into(), "10.0.0.2".into()];
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.targets.len(), 2);
    }

    #[test]
    fn target_empty_returns_error() {
        let mut cfg = default_gui_config();
        cfg.targets = vec![];
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("no valid targets"), "got: {err}");
    }

    #[test]
    fn target_invalid_returns_error() {
        let mut cfg = default_gui_config();
        cfg.targets = vec!["not-a-valid-!!!-target".into()];
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("invalid target"), "got: {err}");
    }

    // --- Flag propagation ---

    #[test]
    fn discovery_mode_default() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.discovery.mode, DiscoveryMode::Default);
    }

    #[test]
    fn discovery_mode_skip() {
        let mut cfg = default_gui_config();
        cfg.discovery_mode = "skip".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.discovery.mode, DiscoveryMode::Skip);
    }

    #[test]
    fn discovery_mode_ping_only() {
        let mut cfg = default_gui_config();
        cfg.discovery_mode = "ping_only".into();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.discovery.mode, DiscoveryMode::PingOnly);
    }

    #[test]
    fn discovery_mode_custom_methods() {
        let mut cfg = default_gui_config();
        cfg.discovery_mode = "custom".into();
        cfg.discovery_methods = vec!["icmp_echo".into(), "tcp_syn".into()];
        let result = cfg.into_scan_config().unwrap();
        match result.discovery.mode {
            DiscoveryMode::Custom(methods) => {
                assert_eq!(methods.len(), 2);
                assert_eq!(methods[0], DiscoveryMethod::IcmpEcho);
                assert_eq!(methods[1], DiscoveryMethod::TcpSyn);
            }
            other => panic!("expected Custom, got {:?}", other),
        }
    }

    #[test]
    fn discovery_custom_ports_override() {
        let mut cfg = default_gui_config();
        cfg.discovery_mode = "custom".into();
        cfg.discovery_methods = vec!["tcp_syn".into()];
        cfg.tcp_syn_ports = Some("80,8080".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.discovery.tcp_syn_ports, vec![80, 8080]);
    }

    #[test]
    fn discovery_invalid_method_errors() {
        let mut cfg = default_gui_config();
        cfg.discovery_mode = "custom".into();
        cfg.discovery_methods = vec!["bogus".into()];
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("unknown discovery method"), "got: {err}");
    }

    #[test]
    fn feature_flags_propagate() {
        let mut cfg = default_gui_config();
        cfg.service_detection = true;
        cfg.os_detection = true;
        cfg.timeout_ms = 5000; // explicit override, not 0
        cfg.concurrency = 200; // explicit override, not 0
        cfg.max_hostgroup = 512;
        cfg.host_timeout_ms = 10000;
        cfg.min_rate = Some(100.0);
        cfg.max_rate = Some(500.0);

        let result = cfg.into_scan_config().unwrap();
        assert!(result.service_detection.enabled);
        assert!(result.os_detection.enabled);
        assert_eq!(result.timeout, Duration::from_millis(5000));
        assert_eq!(result.concurrency, 200);
        assert_eq!(result.max_hostgroup, 512);
        assert_eq!(result.host_timeout, Duration::from_millis(10000));
        assert_eq!(result.min_rate, Some(100.0));
        assert_eq!(result.max_rate, Some(500.0));
    }

    #[test]
    fn features_disabled_by_default() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert!(!result.service_detection.enabled);
        assert!(!result.os_detection.enabled);
        assert!(!result.verbose);
    }

    // --- Timing-aware defaults ---

    #[test]
    fn concurrency_zero_uses_template_default() {
        let mut cfg = default_gui_config();
        cfg.concurrency = 0;
        cfg.timing = 3;
        let result = cfg.into_scan_config().unwrap();
        let expected = TimingParams::from_template(TimingTemplate::Normal);
        assert_eq!(result.concurrency, expected.connect_concurrency);
    }

    #[test]
    fn timeout_zero_uses_template_default() {
        let mut cfg = default_gui_config();
        cfg.timeout_ms = 0;
        cfg.timing = 4;
        let result = cfg.into_scan_config().unwrap();
        let expected = TimingParams::from_template(TimingTemplate::Aggressive);
        assert_eq!(result.timeout, expected.connect_timeout);
    }

    #[test]
    fn timing_template_affects_auto_defaults() {
        let mut cfg_slow = default_gui_config();
        cfg_slow.concurrency = 0;
        cfg_slow.timeout_ms = 0;
        cfg_slow.timing = 0;
        let slow = cfg_slow.into_scan_config().unwrap();

        let mut cfg_fast = default_gui_config();
        cfg_fast.concurrency = 0;
        cfg_fast.timeout_ms = 0;
        cfg_fast.timing = 5;
        let fast = cfg_fast.into_scan_config().unwrap();

        assert!(fast.concurrency > slow.concurrency);
        assert!(fast.timeout < slow.timeout);
    }

    #[test]
    fn randomize_ports_propagates() {
        let mut cfg = default_gui_config();
        cfg.randomize_ports = true;
        let result = cfg.into_scan_config().unwrap();
        assert!(result.randomize_ports);
    }

    #[test]
    fn version_intensity_propagates() {
        let mut cfg = default_gui_config();
        cfg.service_detection = true;
        cfg.version_intensity = 3;
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.service_detection.intensity, 3);
    }

    #[test]
    fn scan_delay_propagates() {
        let mut cfg = default_gui_config();
        cfg.scan_delay_ms = 500;
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_delay, Some(Duration::from_millis(500)));
    }

    #[test]
    fn scan_delay_zero_is_none() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.scan_delay, None);
    }

    #[test]
    fn mtu_discovery_propagates() {
        let mut cfg = default_gui_config();
        cfg.mtu_discovery = true;
        let result = cfg.into_scan_config().unwrap();
        assert!(result.mtu_discovery);
    }

    #[test]
    fn verbose_propagates() {
        let mut cfg = default_gui_config();
        cfg.verbose = true;
        let result = cfg.into_scan_config().unwrap();
        assert!(result.verbose);
    }

    #[test]
    fn min_hostgroup_propagates() {
        let mut cfg = default_gui_config();
        cfg.min_hostgroup = 16;
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.min_hostgroup, 16);
    }

    #[test]
    fn max_scan_delay_propagates() {
        let mut cfg = default_gui_config();
        cfg.max_scan_delay_ms = 1000;
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.max_scan_delay, Some(Duration::from_millis(1000)));
    }

    #[test]
    fn max_scan_delay_zero_is_none() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.max_scan_delay, None);
    }

    #[test]
    fn probe_timeout_propagates() {
        let mut cfg = default_gui_config();
        cfg.probe_timeout_ms = 3000;
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(
            result.service_detection.probe_timeout,
            Duration::from_millis(3000)
        );
    }

    #[test]
    fn probe_timeout_zero_uses_default() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(
            result.service_detection.probe_timeout,
            ServiceDetectionConfig::default().probe_timeout
        );
    }

    #[test]
    fn quic_probing_propagates() {
        let mut cfg = default_gui_config();
        cfg.quic_probing = false;
        let result = cfg.into_scan_config().unwrap();
        assert!(!result.service_detection.quic_probing);
    }

    #[test]
    fn proxy_url_propagates() {
        let mut cfg = default_gui_config();
        cfg.proxy_url = Some("socks5://127.0.0.1:1080".into());
        let result = cfg.into_scan_config().unwrap();
        let proxy = result.proxy.unwrap();
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 1080);
    }

    #[test]
    fn proxy_url_none_is_none() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert!(result.proxy.is_none());
    }

    #[test]
    fn proxy_url_invalid_returns_error() {
        let mut cfg = default_gui_config();
        cfg.proxy_url = Some("http://not-socks".into());
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("proxy"), "got: {err}");
    }

    #[test]
    fn decoys_propagate() {
        let mut cfg = default_gui_config();
        cfg.decoys = Some("10.0.0.1, 10.0.0.2".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.decoys.len(), 2);
        assert_eq!(result.decoys[0].to_string(), "10.0.0.1");
        assert_eq!(result.decoys[1].to_string(), "10.0.0.2");
    }

    #[test]
    fn decoys_invalid_returns_error() {
        let mut cfg = default_gui_config();
        cfg.decoys = Some("not-an-ip".into());
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("decoy"), "got: {err}");
    }

    #[test]
    fn pre_resolved_up_propagates() {
        let mut cfg = default_gui_config();
        cfg.pre_resolved_up = Some("192.168.1.1, 192.168.1.2".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.pre_resolved_up.len(), 2);
    }

    #[test]
    fn pre_resolved_up_invalid_returns_error() {
        let mut cfg = default_gui_config();
        cfg.pre_resolved_up = Some("bad-ip".into());
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("pre-resolved"), "got: {err}");
    }

    // --- Custom payload ---

    #[test]
    fn payload_none_is_none() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert!(result.custom_payload.is_none());
    }

    #[test]
    fn payload_hex_propagates() {
        let mut cfg = default_gui_config();
        cfg.payload_type = "hex".into();
        cfg.payload_value = Some("deadbeef".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(
            result.custom_payload.unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn payload_hex_with_prefix() {
        let mut cfg = default_gui_config();
        cfg.payload_type = "hex".into();
        cfg.payload_value = Some("0xCAFE".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.custom_payload.unwrap(), vec![0xca, 0xfe]);
    }

    #[test]
    fn payload_hex_invalid_returns_error() {
        let mut cfg = default_gui_config();
        cfg.payload_type = "hex".into();
        cfg.payload_value = Some("abc".into()); // odd length
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("even number"), "got: {err}");
    }

    #[test]
    fn payload_string_propagates() {
        let mut cfg = default_gui_config();
        cfg.payload_type = "string".into();
        cfg.payload_value = Some("HELLO".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.custom_payload.unwrap(), b"HELLO");
    }

    #[test]
    fn payload_length_propagates() {
        let mut cfg = default_gui_config();
        cfg.payload_type = "length".into();
        cfg.payload_value = Some("32".into());
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.custom_payload.unwrap().len(), 32);
    }

    #[test]
    fn payload_length_too_large_returns_error() {
        let mut cfg = default_gui_config();
        cfg.payload_type = "length".into();
        cfg.payload_value = Some("99999".into());
        let err = cfg.into_scan_config().unwrap_err();
        assert!(err.contains("65400"), "got: {err}");
    }
}
