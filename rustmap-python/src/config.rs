use pyo3::prelude::*;
use std::time::Duration;

use rustmap_core::parse_target;
use rustmap_timing::TimingParams;
use rustmap_types::{
    DiscoveryConfig, DiscoveryMode, OsDetectionConfig, PortRange, ProxyConfig, ScanConfig,
    ServiceDetectionConfig, top_tcp_ports,
};

use crate::enums::{scan_type_from_str, timing_from_value};
use crate::error::RustmapError;

#[pyclass(name = "ScanConfig")]
pub struct PyScanConfig {
    #[pyo3(get, set)]
    pub targets: Vec<String>,
    #[pyo3(get, set)]
    pub ports: Option<String>,
    #[pyo3(get, set)]
    pub scan_type: String,
    #[pyo3(get, set)]
    pub timing: u8,
    #[pyo3(get, set)]
    pub timeout_secs: f64,
    #[pyo3(get, set)]
    pub concurrency: usize,
    #[pyo3(get, set)]
    pub service_detection: bool,
    #[pyo3(get, set)]
    pub version_intensity: u8,
    #[pyo3(get, set)]
    pub os_detection: bool,
    #[pyo3(get, set)]
    pub skip_discovery: bool,
    #[pyo3(get, set)]
    pub verbose: bool,
    #[pyo3(get, set)]
    pub max_hostgroup: usize,
    #[pyo3(get, set)]
    pub min_hostgroup: usize,
    #[pyo3(get, set)]
    pub host_timeout_secs: f64,
    #[pyo3(get, set)]
    pub min_rate: Option<f64>,
    #[pyo3(get, set)]
    pub max_rate: Option<f64>,
    #[pyo3(get, set)]
    pub randomize_ports: bool,
    #[pyo3(get, set)]
    pub source_port: Option<u16>,
    #[pyo3(get, set)]
    pub fragment_packets: bool,
    #[pyo3(get, set)]
    pub traceroute: bool,
    #[pyo3(get, set)]
    pub proxy: Option<String>,
}

#[pymethods]
impl PyScanConfig {
    #[new]
    fn new() -> Self {
        Self {
            targets: vec![],
            ports: None,
            scan_type: "connect".into(),
            timing: 3,
            timeout_secs: 0.0,
            concurrency: 0,
            service_detection: false,
            version_intensity: 7,
            os_detection: false,
            skip_discovery: false,
            verbose: false,
            max_hostgroup: 256,
            min_hostgroup: 1,
            host_timeout_secs: 0.0,
            min_rate: None,
            max_rate: None,
            randomize_ports: false,
            source_port: None,
            fragment_packets: false,
            traceroute: false,
            proxy: None,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ScanConfig(targets={:?}, ports={:?}, scan_type='{}')",
            self.targets, self.ports, self.scan_type
        )
    }
}

impl PyScanConfig {
    /// Create a new config with default values (Rust-side constructor).
    pub fn create() -> Self {
        Self {
            targets: vec![],
            ports: None,
            scan_type: "connect".into(),
            timing: 3,
            timeout_secs: 0.0,
            concurrency: 0,
            service_detection: false,
            version_intensity: 7,
            os_detection: false,
            skip_discovery: false,
            verbose: false,
            max_hostgroup: 256,
            min_hostgroup: 1,
            host_timeout_secs: 0.0,
            min_rate: None,
            max_rate: None,
            randomize_ports: false,
            source_port: None,
            fragment_packets: false,
            traceroute: false,
            proxy: None,
        }
    }

    /// Convert to the internal `ScanConfig` for the scan engine.
    /// Follows the same pattern as `ApiScanConfig::to_scan_config()`.
    pub fn to_scan_config(&self) -> PyResult<ScanConfig> {
        // Parse targets
        let mut hosts = Vec::new();
        for target in &self.targets {
            match parse_target(target) {
                Ok(parsed) => hosts.extend(parsed),
                Err(e) => {
                    return Err(RustmapError::new_err(format!(
                        "invalid target '{}': {}",
                        target, e
                    )));
                }
            }
        }
        if hosts.is_empty() {
            return Err(RustmapError::new_err("no valid targets specified"));
        }

        // Parse ports
        let ports = if let Some(ref port_spec) = self.ports {
            PortRange::parse(port_spec)
                .map_err(|e| RustmapError::new_err(format!("invalid port specification: {e}")))?
                .expand()
        } else {
            top_tcp_ports(1000)
        };

        let scan_type = scan_type_from_str(&self.scan_type).map_err(RustmapError::new_err)?;
        let timing_template = timing_from_value(self.timing).map_err(RustmapError::new_err)?;

        let timing_params = TimingParams::from_template(timing_template);

        let concurrency = if self.concurrency == 0 {
            timing_params.connect_concurrency
        } else {
            self.concurrency
        };

        let timeout = if self.timeout_secs <= 0.0 {
            timing_params.connect_timeout
        } else if self.timeout_secs.is_nan() || self.timeout_secs.is_infinite() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "timeout must be a positive finite number",
            ));
        } else {
            Duration::from_secs_f64(self.timeout_secs)
        };

        let host_timeout = if self.host_timeout_secs <= 0.0 {
            Duration::ZERO
        } else if self.host_timeout_secs.is_nan() || self.host_timeout_secs.is_infinite() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "host_timeout must be a positive finite number",
            ));
        } else {
            Duration::from_secs_f64(self.host_timeout_secs)
        };

        let discovery = if self.skip_discovery {
            DiscoveryConfig {
                mode: DiscoveryMode::Skip,
                ..DiscoveryConfig::default()
            }
        } else {
            DiscoveryConfig::default()
        };

        let proxy = if let Some(ref url) = self.proxy {
            Some(ProxyConfig::parse(url).map_err(RustmapError::new_err)?)
        } else {
            None
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
                ..ServiceDetectionConfig::default()
            },
            os_detection: OsDetectionConfig {
                enabled: self.os_detection,
            },
            min_hostgroup: self.min_hostgroup,
            max_hostgroup: self.max_hostgroup,
            host_timeout,
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
            proxy,
            mtu_discovery: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_into_scan_config_defaults() {
        let mut cfg = PyScanConfig::create();
        cfg.targets = vec!["127.0.0.1".to_string()];
        let sc = cfg.to_scan_config().unwrap();
        assert_eq!(sc.targets.len(), 1);
        assert_eq!(sc.ports.len(), 1000); // top 1000
        assert_eq!(sc.scan_type, rustmap_types::ScanType::TcpConnect);
        assert!(!sc.service_detection.enabled);
        assert!(!sc.os_detection.enabled);
    }

    #[test]
    fn config_into_scan_config_custom() {
        let mut cfg = PyScanConfig::create();
        cfg.targets = vec!["10.0.0.1".to_string()];
        cfg.ports = Some("80,443".to_string());
        cfg.scan_type = "syn".to_string();
        cfg.timing = 4;
        cfg.service_detection = true;
        cfg.os_detection = true;
        cfg.traceroute = true;
        cfg.randomize_ports = true;
        let sc = cfg.to_scan_config().unwrap();
        assert_eq!(sc.ports, vec![80, 443]);
        assert_eq!(sc.scan_type, rustmap_types::ScanType::TcpSyn);
        assert!(sc.service_detection.enabled);
        assert!(sc.os_detection.enabled);
        assert!(sc.traceroute);
        assert!(sc.randomize_ports);
    }

    #[test]
    fn config_into_scan_config_invalid_target() {
        let cfg = PyScanConfig::create();
        // No targets — should fail
        let result = cfg.to_scan_config();
        assert!(result.is_err());
    }

    #[test]
    fn config_into_scan_config_invalid_ports() {
        let mut cfg = PyScanConfig::create();
        cfg.targets = vec!["127.0.0.1".to_string()];
        cfg.ports = Some("abc".to_string());
        let result = cfg.to_scan_config();
        assert!(result.is_err());
    }
}
