use crate::traits::{OutputError, OutputFormatter};
use rustmap_types::ScanResult;

pub struct YamlFormatter;

impl OutputFormatter for YamlFormatter {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError> {
        serde_yaml::to_string(result)
            .map_err(|e| OutputError::FormatError(format!("YAML serialization error: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::OutputFormatter;
    use rustmap_types::{
        Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanType, ServiceInfo,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_result() -> ScanResult {
        ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                ports: vec![Port {
                    number: 22,
                    state: PortState::Open,
                    protocol: Protocol::Tcp,
                    service: Some("ssh".into()),
                    service_info: Some(ServiceInfo {
                        name: "ssh".into(),
                        product: Some("OpenSSH".into()),
                        version: Some("8.9p1".into()),
                        info: None,
                        method: rustmap_types::DetectionMethod::Banner,
                    }),
                    reason: Some("syn-ack".into()),
                    script_results: vec![],
                    tls_info: None,
                }],
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
            total_duration: Duration::from_secs(1),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: Some("rustmap -p 22 192.168.1.1".into()),
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn yaml_output_valid() {
        let result = make_result();
        let output = YamlFormatter.format(&result).unwrap();
        // Must parse back as valid YAML
        let _: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
    }

    #[test]
    fn yaml_round_trip() {
        let result = make_result();
        let output = YamlFormatter.format(&result).unwrap();
        let deserialized: ScanResult = serde_yaml::from_str(&output).unwrap();
        assert_eq!(deserialized.hosts.len(), 1);
        assert_eq!(deserialized.hosts[0].ports.len(), 1);
        assert_eq!(deserialized.hosts[0].ports[0].number, 22);
        assert_eq!(deserialized.hosts[0].ports[0].state, PortState::Open);
    }

    #[test]
    fn yaml_empty_hosts() {
        let result = ScanResult {
            hosts: vec![],
            total_duration: Duration::from_secs(0),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };
        let output = YamlFormatter.format(&result).unwrap();
        let _: serde_yaml::Value = serde_yaml::from_str(&output).unwrap();
    }
}
