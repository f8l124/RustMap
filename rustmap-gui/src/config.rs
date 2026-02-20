use std::time::Duration;

use rustmap_core::parse_target;
use rustmap_timing::TimingParams;
use rustmap_types::{
    DiscoveryConfig, DiscoveryMode, OsDetectionConfig, PortRange, ScanConfig, ScanType,
    ServiceDetectionConfig, TimingTemplate, top_tcp_ports,
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
    pub skip_discovery: bool,
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
        let discovery = if self.skip_discovery {
            DiscoveryConfig {
                mode: DiscoveryMode::Skip,
                ..DiscoveryConfig::default()
            }
        } else {
            DiscoveryConfig::default()
        };

        Ok(ScanConfig {
            targets: hosts,
            ports,
            scan_type,
            timeout,
            concurrency,
            verbose: false,
            timing_template,
            discovery,
            service_detection: ServiceDetectionConfig {
                enabled: self.service_detection,
                ..ServiceDetectionConfig::default()
            },
            os_detection: OsDetectionConfig {
                enabled: self.os_detection,
            },
            min_hostgroup: 1,
            max_hostgroup: self.max_hostgroup,
            host_timeout: Duration::from_millis(self.host_timeout_ms),
            min_rate: self.min_rate,
            max_rate: self.max_rate,
            randomize_ports: self.randomize_ports,
            source_port: self.source_port,
            decoys: Vec::new(), // Decoys configured via CLI only
            fragment_packets: self.fragment_packets,
            custom_payload: None,
            traceroute: self.traceroute,
            scan_delay: None,
            max_scan_delay: None,
            learned_initial_rto_us: None,
            learned_initial_cwnd: None,
            learned_ssthresh: None,
            learned_max_retries: None,
            pre_resolved_up: vec![],
            proxy: None,
            mtu_discovery: false,
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
            skip_discovery: false,
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
    fn skip_discovery_sets_mode() {
        let mut cfg = default_gui_config();
        cfg.skip_discovery = true;
        let result = cfg.into_scan_config().unwrap();
        assert_eq!(result.discovery.mode, DiscoveryMode::Skip);
    }

    #[test]
    fn discovery_default_mode() {
        let cfg = default_gui_config();
        let result = cfg.into_scan_config().unwrap();
        assert_ne!(result.discovery.mode, DiscoveryMode::Skip);
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
}
