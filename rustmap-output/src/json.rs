use crate::traits::{OutputError, OutputFormatter};
use rustmap_types::ScanResult;

/// Formats scan results as pretty-printed JSON.
///
/// Since all types in `ScanResult` derive `Serialize`, this is near-trivial.
pub struct JsonFormatter;

impl OutputFormatter for JsonFormatter {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError> {
        serde_json::to_string_pretty(result)
            .map_err(|e| OutputError::FormatError(format!("JSON serialization error: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{
        DetectionMethod, Host, HostScanResult, HostStatus, OsFingerprint, OsProbeResults, Port,
        PortState, Protocol, ScanType, ServiceInfo,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_host(ip: [u8; 4]) -> Host {
        Host {
            ip: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            hostname: None,
            geo_info: None,
        }
    }

    fn make_scan_result() -> ScanResult {
        ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([192, 168, 1, 1]),
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
                            info: Some("Ubuntu Linux; protocol 2.0".into()),
                            method: DetectionMethod::Banner,
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
                    Port {
                        number: 443,
                        protocol: Protocol::Tcp,
                        state: PortState::Closed,
                        service: Some("https".into()),
                        service_info: None,
                        reason: None,
                        script_results: vec![],
                        tls_info: None,
                    },
                ],
                scan_duration: Duration::from_millis(2500),
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
            total_duration: Duration::from_millis(3000),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: Some("rustmap -p 22,80,443 192.168.1.1".into()),
            num_services: 3,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn json_output_is_valid_json() {
        let result = make_scan_result();
        let json = JsonFormatter.format(&result).unwrap();
        // Verify it parses back as valid JSON
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn json_round_trip() {
        let result = make_scan_result();
        let json = JsonFormatter.format(&result).unwrap();
        let parsed: ScanResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.hosts[0].ports.len(), 3);
        assert_eq!(parsed.scan_type, ScanType::TcpSyn);
        assert_eq!(parsed.num_services, 3);
        assert_eq!(
            parsed.command_args.as_deref(),
            Some("rustmap -p 22,80,443 192.168.1.1")
        );
    }

    #[test]
    fn json_round_trip_preserves_service_info() {
        let result = make_scan_result();
        let json = JsonFormatter.format(&result).unwrap();
        let parsed: ScanResult = serde_json::from_str(&json).unwrap();

        let port_22 = &parsed.hosts[0].ports[0];
        assert_eq!(port_22.number, 22);
        assert_eq!(port_22.service.as_deref(), Some("ssh"));

        let info = port_22.service_info.as_ref().unwrap();
        assert_eq!(info.name, "ssh");
        assert_eq!(info.product.as_deref(), Some("OpenSSH"));
        assert_eq!(info.version.as_deref(), Some("8.9p1"));
        assert_eq!(info.method, DetectionMethod::Banner);
    }

    #[test]
    fn json_round_trip_preserves_os_fingerprint() {
        let result = make_scan_result();
        let json = JsonFormatter.format(&result).unwrap();
        let parsed: ScanResult = serde_json::from_str(&json).unwrap();

        let os = parsed.hosts[0].os_fingerprint.as_ref().unwrap();
        assert_eq!(os.os_family.as_deref(), Some("Linux"));
        assert_eq!(os.os_generation.as_deref(), Some("5.x"));
        assert_eq!(os.accuracy, Some(92));
    }

    #[test]
    fn json_empty_hosts() {
        let result = ScanResult {
            hosts: vec![],
            total_duration: Duration::from_millis(100),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };
        let json = JsonFormatter.format(&result).unwrap();
        let parsed: ScanResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.hosts.is_empty());
    }

    #[test]
    fn json_contains_expected_fields() {
        let result = make_scan_result();
        let json = JsonFormatter.format(&result).unwrap();

        assert!(json.contains("\"hosts\""));
        assert!(json.contains("\"scan_type\""));
        assert!(json.contains("\"total_duration\""));
        assert!(json.contains("\"ports\""));
        assert!(json.contains("\"host_status\""));
        assert!(json.contains("\"os_fingerprint\""));
    }

    #[test]
    fn json_host_with_hostname() {
        let mut result = make_scan_result();
        result.hosts[0].host.hostname = Some("example.local".into());

        let json = JsonFormatter.format(&result).unwrap();
        assert!(json.contains("example.local"));

        let parsed: ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.hosts[0].host.hostname.as_deref(),
            Some("example.local")
        );
    }

    #[test]
    fn json_port_state_serialization() {
        let result = make_scan_result();
        let json = JsonFormatter.format(&result).unwrap();

        // PortState uses serde(rename_all = "lowercase")
        assert!(json.contains("\"open\""));
        assert!(json.contains("\"closed\""));
    }
}
