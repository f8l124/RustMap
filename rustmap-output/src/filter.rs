use rustmap_types::{PortState, ScanResult};

/// Filter a `ScanResult` to only include open ports (--open flag).
///
/// Returns a new `ScanResult` with non-open ports removed from each host.
/// Hosts with no open ports are still included (for host-up/down reporting).
pub fn filter_open_ports(result: &ScanResult) -> ScanResult {
    let mut filtered = result.clone();
    for host in &mut filtered.hosts {
        host.ports.retain(|p| p.state == PortState::Open);
    }
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_port(number: u16, state: PortState) -> Port {
        Port {
            number,
            protocol: Protocol::Tcp,
            state,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }
    }

    fn make_host_result(ports: Vec<Port>) -> HostScanResult {
        HostScanResult {
            host: Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            ports,
            scan_duration: Duration::from_millis(500),
            host_status: HostStatus::Up,
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: None,
            timing_snapshot: None,
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        }
    }

    #[test]
    fn filter_retains_only_open() {
        let result = ScanResult {
            hosts: vec![make_host_result(vec![
                make_port(22, PortState::Open),
                make_port(80, PortState::Closed),
                make_port(443, PortState::Open),
                make_port(8080, PortState::Filtered),
            ])],
            total_duration: Duration::from_millis(1000),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 4,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let filtered = filter_open_ports(&result);
        assert_eq!(filtered.hosts[0].ports.len(), 2);
        assert!(
            filtered.hosts[0]
                .ports
                .iter()
                .all(|p| p.state == PortState::Open)
        );
        assert_eq!(filtered.hosts[0].ports[0].number, 22);
        assert_eq!(filtered.hosts[0].ports[1].number, 443);
    }

    #[test]
    fn filter_preserves_hosts_with_no_open_ports() {
        let result = ScanResult {
            hosts: vec![make_host_result(vec![
                make_port(80, PortState::Closed),
                make_port(443, PortState::Filtered),
            ])],
            total_duration: Duration::from_millis(1000),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 2,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let filtered = filter_open_ports(&result);
        assert_eq!(filtered.hosts.len(), 1);
        assert!(filtered.hosts[0].ports.is_empty());
    }

    #[test]
    fn filter_preserves_metadata() {
        let result = ScanResult {
            hosts: vec![make_host_result(vec![make_port(80, PortState::Open)])],
            total_duration: Duration::from_millis(1234),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: Some("rustmap -p 80 --open 192.168.1.1".into()),
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let filtered = filter_open_ports(&result);
        assert_eq!(filtered.total_duration, Duration::from_millis(1234));
        assert_eq!(filtered.scan_type, ScanType::TcpSyn);
        assert_eq!(
            filtered.command_args.as_deref(),
            Some("rustmap -p 80 --open 192.168.1.1")
        );
    }

    #[test]
    fn filter_all_open_unchanged() {
        let result = ScanResult {
            hosts: vec![make_host_result(vec![
                make_port(22, PortState::Open),
                make_port(80, PortState::Open),
            ])],
            total_duration: Duration::from_millis(500),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 2,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let filtered = filter_open_ports(&result);
        assert_eq!(filtered.hosts[0].ports.len(), 2);
    }
}
