// ---------------------------------------------------------------------------
// API scan configuration DTO
// ---------------------------------------------------------------------------
//
// Mirrors GuiScanConfig from rustmap-gui/src/config.rs for JSON API input.

use std::time::Duration;

use rustmap_core::parse_target;
use rustmap_timing::TimingParams;
use rustmap_types::{
    DiscoveryConfig, DiscoveryMode, OsDetectionConfig, PortRange, ScanConfig, ScanType,
    ServiceDetectionConfig, TimingTemplate, top_tcp_ports,
};
use serde::{Deserialize, Serialize};

/// JSON-serializable scan configuration for the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiScanConfig {
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

impl ApiScanConfig {
    /// Convert to a `ScanConfig` suitable for the scan engine.
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

        // Resolve timing-aware defaults and clamp to safe upper bounds
        let timing_params = TimingParams::from_template(timing_template);
        let concurrency = if self.concurrency == 0 {
            timing_params.connect_concurrency
        } else {
            self.concurrency.min(10_000)
        };
        let timeout = if self.timeout_ms == 0 {
            timing_params.connect_timeout
        } else {
            Duration::from_millis(self.timeout_ms.clamp(1, 3_600_000))
        };

        // Clamp host timeout (0 means no per-host timeout — leave it)
        let host_timeout_ms = if self.host_timeout_ms == 0 {
            self.host_timeout_ms
        } else {
            self.host_timeout_ms.clamp(1, 3_600_000)
        };

        // Clamp max_hostgroup
        let max_hostgroup = self.max_hostgroup.min(65_536);

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
            max_hostgroup,
            host_timeout: Duration::from_millis(host_timeout_ms),
            min_rate: self.min_rate,
            max_rate: self.max_rate,
            randomize_ports: self.randomize_ports,
            source_port: self.source_port,
            decoys: Vec::new(),
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

impl Default for ApiScanConfig {
    fn default() -> Self {
        Self {
            targets: vec![],
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
}
