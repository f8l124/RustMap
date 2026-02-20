use std::fs;

use crate::cef::CefFormatter;
use crate::config::{OutputConfig, OutputFormat};
use crate::csv::CsvFormatter;
use crate::grepable::GrepableFormatter;
use crate::html::HtmlFormatter;
use crate::json::JsonFormatter;
use crate::leef::LeefFormatter;
use crate::stdout::StdoutFormatter;
use crate::traits::{OutputError, OutputFormatter};
use crate::xml::XmlFormatter;
use crate::yaml::YamlFormatter;
use rustmap_types::ScanResult;

fn validate_output_path(path: &std::path::Path) -> Result<(), OutputError> {
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(OutputError::FormatError(format!(
                "output path '{}' must not contain '..' components",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Coordinates output to stdout and/or multiple file destinations.
pub struct OutputManager {
    config: OutputConfig,
}

impl OutputManager {
    pub fn new(config: OutputConfig) -> Self {
        Self { config }
    }

    /// Format the scan result and write to all configured destinations.
    pub fn run(&self, result: &ScanResult) -> Result<(), OutputError> {
        let stdout_formatter = StdoutFormatter::new(self.config.show_reason, result.scan_type);

        // Always print to stdout if configured
        if self.config.stdout {
            let output = stdout_formatter.format(result)?;
            print!("{}", output);
        }

        // Write to each file output
        for spec in &self.config.outputs {
            validate_output_path(&spec.path)?;
            let formatter = self.formatter_for(spec.format, result);
            let output = formatter.format(result)?;
            fs::write(&spec.path, &output).map_err(|e| {
                OutputError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to write {}: {}", spec.path.display(), e),
                ))
            })?;
        }

        Ok(())
    }

    /// Get the appropriate formatter for a given output format.
    fn formatter_for(&self, format: OutputFormat, result: &ScanResult) -> Box<dyn OutputFormatter> {
        match format {
            OutputFormat::Normal => Box::new(StdoutFormatter::new(
                self.config.show_reason,
                result.scan_type,
            )),
            OutputFormat::Json => Box::new(JsonFormatter),
            OutputFormat::Xml => Box::new(XmlFormatter),
            OutputFormat::Grepable => Box::new(GrepableFormatter),
            OutputFormat::Yaml => Box::new(YamlFormatter),
            OutputFormat::Csv => Box::new(CsvFormatter),
            OutputFormat::Cef => Box::new(CefFormatter),
            OutputFormat::Leef => Box::new(LeefFormatter),
            OutputFormat::Html => Box::new(HtmlFormatter),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OutputConfig;
    use rustmap_types::{Host, HostScanResult, HostStatus, ScanType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_result() -> ScanResult {
        ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                ports: vec![],
                scan_duration: Duration::from_millis(500),
                host_status: HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(3)),
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn manager_stdout_only() {
        let config = OutputConfig {
            outputs: vec![],
            open_only: false,
            show_reason: false,
            stdout: true,
        };
        let manager = OutputManager::new(config);
        let result = make_result();
        // Should not error (prints to stdout)
        manager.run(&result).unwrap();
    }

    #[test]
    fn manager_file_output() {
        use crate::config::OutputSpec;

        let tmp = std::env::temp_dir().join("rustmap_test_output.nmap");
        let config = OutputConfig {
            outputs: vec![OutputSpec {
                format: OutputFormat::Normal,
                path: tmp.clone(),
            }],
            open_only: false,
            show_reason: false,
            stdout: false,
        };

        let manager = OutputManager::new(config);
        let result = make_result();
        manager.run(&result).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.contains("rustmap"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn manager_json_file_output() {
        use crate::config::OutputSpec;
        use rustmap_types::{Port, PortState, Protocol};

        let tmp = std::env::temp_dir().join("rustmap_test_output.json");
        let config = OutputConfig {
            outputs: vec![OutputSpec {
                format: OutputFormat::Json,
                path: tmp.clone(),
            }],
            open_only: false,
            show_reason: false,
            stdout: false,
        };

        let mut result = make_result();
        result.hosts[0].ports = vec![Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];

        let manager = OutputManager::new(config);
        manager.run(&result).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        // Should be valid JSON
        let parsed: ScanResult = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.hosts[0].ports[0].number, 80);
        assert_eq!(parsed.hosts[0].ports[0].service.as_deref(), Some("http"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn manager_xml_file_output() {
        use crate::config::OutputSpec;
        use rustmap_types::{Port, PortState, Protocol};

        let tmp = std::env::temp_dir().join("rustmap_test_output.xml");
        let config = OutputConfig {
            outputs: vec![OutputSpec {
                format: OutputFormat::Xml,
                path: tmp.clone(),
            }],
            open_only: false,
            show_reason: false,
            stdout: false,
        };

        let mut result = make_result();
        result.hosts[0].ports = vec![Port {
            number: 443,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("https".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];

        let manager = OutputManager::new(config);
        manager.run(&result).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.starts_with("<?xml"));
        assert!(content.contains("<nmaprun "));
        assert!(content.contains("portid=\"443\""));
        assert!(content.contains("</nmaprun>"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn manager_grepable_file_output() {
        use crate::config::OutputSpec;
        use rustmap_types::{Port, PortState, Protocol};

        let tmp = std::env::temp_dir().join("rustmap_test_output.gnmap");
        let config = OutputConfig {
            outputs: vec![OutputSpec {
                format: OutputFormat::Grepable,
                path: tmp.clone(),
            }],
            open_only: false,
            show_reason: false,
            stdout: false,
        };

        let mut result = make_result();
        result.hosts[0].ports = vec![Port {
            number: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("ssh".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];

        let manager = OutputManager::new(config);
        manager.run(&result).unwrap();

        let content = fs::read_to_string(&tmp).unwrap();
        assert!(content.starts_with("# rustmap"));
        assert!(content.contains("22/open/tcp//ssh///"));
        assert!(content.contains("# rustmap done"));
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn manager_all_formats_output() {
        use rustmap_types::{Port, PortState, Protocol};

        let tmp_dir = std::env::temp_dir();
        let basename = "rustmap_test_all_formats";
        let specs = OutputConfig::expand_all_formats(&tmp_dir.join(basename).to_string_lossy());

        let config = OutputConfig {
            outputs: specs,
            open_only: false,
            show_reason: false,
            stdout: false,
        };

        let mut result = make_result();
        result.hosts[0].ports = vec![Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];

        let manager = OutputManager::new(config);
        manager.run(&result).unwrap();

        // Verify all 6 files were created with correct content
        let nmap_path = tmp_dir.join(format!("{basename}.nmap"));
        let xml_path = tmp_dir.join(format!("{basename}.xml"));
        let gnmap_path = tmp_dir.join(format!("{basename}.gnmap"));
        let json_path = tmp_dir.join(format!("{basename}.json"));
        let yaml_path = tmp_dir.join(format!("{basename}.yaml"));
        let csv_path = tmp_dir.join(format!("{basename}.csv"));

        let nmap = fs::read_to_string(&nmap_path).unwrap();
        assert!(
            nmap.contains("rustmap"),
            "Normal output should contain 'rustmap'"
        );

        let xml = fs::read_to_string(&xml_path).unwrap();
        assert!(
            xml.starts_with("<?xml"),
            "XML should start with declaration"
        );
        assert!(xml.contains("portid=\"80\""));

        let gnmap = fs::read_to_string(&gnmap_path).unwrap();
        assert!(gnmap.contains("80/open/tcp//http///"));

        let json = fs::read_to_string(&json_path).unwrap();
        let parsed: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hosts[0].ports[0].number, 80);

        let yaml = fs::read_to_string(&yaml_path).unwrap();
        assert!(!yaml.is_empty(), "YAML output should not be empty");
        let _: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();

        let csv = fs::read_to_string(&csv_path).unwrap();
        assert!(
            csv.starts_with("ip,hostname,country,city,asn,as_org,port,"),
            "CSV should start with header"
        );
        assert!(csv.contains(",80,"), "CSV should contain port 80");

        let html_path = tmp_dir.join(format!("{basename}.html"));
        let html = fs::read_to_string(&html_path).unwrap();
        assert!(
            html.starts_with("<!DOCTYPE html>"),
            "HTML should start with doctype"
        );
        assert!(html.contains("192.168.1.1"), "HTML should contain host IP");

        // Cleanup
        let _ = fs::remove_file(&nmap_path);
        let _ = fs::remove_file(&xml_path);
        let _ = fs::remove_file(&gnmap_path);
        let _ = fs::remove_file(&json_path);
        let _ = fs::remove_file(&yaml_path);
        let _ = fs::remove_file(&csv_path);
        let _ = fs::remove_file(&html_path);
    }

    #[test]
    fn manager_cross_format_same_result() {
        use rustmap_types::{
            DetectionMethod, OsFingerprint, OsProbeResults, Port, PortState, Protocol, ServiceInfo,
        };

        // Build a rich result with ports, services, and OS info
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
                ports: vec![
                    Port {
                        number: 22,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service: Some("ssh".into()),
                        service_info: Some(ServiceInfo {
                            name: "ssh".into(),
                            product: Some("OpenSSH".into()),
                            version: Some("8.9p1".into()),
                            info: None,
                            method: DetectionMethod::Probe,
                        }),
                        reason: None,
                        script_results: vec![],
                        tls_info: None,
                    },
                    Port {
                        number: 80,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service: Some("http".into()),
                        service_info: None,
                        reason: None,
                        script_results: vec![],
                        tls_info: None,
                    },
                ],
                scan_duration: Duration::from_millis(1500),
                host_status: HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(5)),
                os_fingerprint: Some(OsFingerprint {
                    os_family: Some("Linux".into()),
                    os_generation: Some("5.x".into()),
                    accuracy: Some(92),
                    probe_results: OsProbeResults::default(),
                }),
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_millis(2000),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: Some("rustmap -sV -O 192.168.1.100".into()),
            num_services: 2,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        // All 4 formatters should succeed on the same result
        let normal = StdoutFormatter::default().format(&result).unwrap();
        let json = JsonFormatter.format(&result).unwrap();
        let xml = XmlFormatter.format(&result).unwrap();
        let grep = GrepableFormatter.format(&result).unwrap();

        // Normal contains key elements
        assert!(normal.contains("192.168.1.100"));
        assert!(normal.contains("22/tcp"));
        assert!(normal.contains("OS details: Linux 5.x"));

        // JSON round-trips
        let parsed: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hosts[0].ports.len(), 2);
        assert_eq!(parsed.hosts[0].ports[0].number, 22);

        // XML has structure
        assert!(xml.contains("<port protocol=\"tcp\" portid=\"22\">"));
        assert!(xml.contains("<osmatch name=\"Linux 5.x\""));

        // Grepable has correct format
        assert!(grep.contains("22/open/tcp//ssh//OpenSSH 8.9p1/"));
        assert!(grep.contains("\tOS: Linux 5.x"));
    }
}
