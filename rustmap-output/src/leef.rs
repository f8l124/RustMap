use std::fmt::Write;

use rustmap_types::{HostStatus, PortState, ScanResult};

use crate::traits::{OutputError, OutputFormatter};

/// LEEF (Log Event Extended Format) output formatter for IBM QRadar integration.
///
/// Emits one LEEF event per open port per host.
/// Format: `LEEF:2.0|Vendor|Product|Version|EventID\t<tab-separated extensions>`
pub struct LeefFormatter;

/// Escape LEEF special characters: tab (field separator), equals (key=value delimiter),
/// backslash (escape char), and newlines.
fn leef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('=', "\\=")
}

impl OutputFormatter for LeefFormatter {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError> {
        let mut output = String::new();
        for host in &result.hosts {
            if host.host_status != HostStatus::Up {
                continue;
            }
            for port in &host.ports {
                if port.state != PortState::Open {
                    continue;
                }
                let svc = port.service.as_deref().unwrap_or("unknown");

                // LEEF header (tab is field separator in extensions)
                write!(output, "LEEF:2.0|RustMap|rustmap|0.1.0|PORT_SCAN\t").unwrap();

                // Extensions (tab-separated key=value)
                write!(output, "dst={}", host.host.ip).unwrap();
                write!(output, "\tdstPort={}", port.number).unwrap();
                write!(output, "\tproto={}", port.protocol).unwrap();
                write!(output, "\tsvc={}", leef_escape(svc)).unwrap();

                if let Some(ref hn) = host.host.hostname {
                    write!(output, "\tdstName={}", leef_escape(hn)).unwrap();
                }
                if let Some(ref si) = port.service_info {
                    if let Some(ref p) = si.product {
                        write!(output, "\tproduct={}", leef_escape(p)).unwrap();
                    }
                    if let Some(ref v) = si.version {
                        write!(output, "\tversion={}", leef_escape(v)).unwrap();
                    }
                }
                if let Some(ref geo) = host.host.geo_info
                    && let Some(ref cc) = geo.country_code
                {
                    write!(output, "\tcountryCode={}", leef_escape(cc)).unwrap();
                }
                if let Some(risk) = host.risk_score {
                    write!(output, "\triskScore={risk:.1}").unwrap();
                }
                if let Some(ref os) = host.os_fingerprint
                    && let Some(ref fam) = os.os_family
                {
                    write!(output, "\tosFamily={}", leef_escape(fam)).unwrap();
                }
                if let Some(ref tls) = port.tls_info
                    && let Some(ref chain) = tls.certificate_chain
                    && let Some(leaf) = chain.first()
                {
                    if let Some(ref cn) = leaf.subject_cn {
                        write!(output, "\tcertSubject={}", leef_escape(cn)).unwrap();
                    }
                    if let Some(ref iss) = leaf.issuer_cn {
                        write!(output, "\tcertIssuer={}", leef_escape(iss)).unwrap();
                    }
                }

                writeln!(output).unwrap();
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn leef_basic_output() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                ports: vec![Port {
                    number: 443,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("https".into()),
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: None,
                }],
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
            }],
            total_duration: Duration::from_millis(1000),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = LeefFormatter.format(&result).unwrap();
        assert!(output.starts_with("LEEF:2.0|RustMap|rustmap|0.1.0|PORT_SCAN\t"));
        assert!(output.contains("dst=192.168.1.1"));
        assert!(output.contains("dstPort=443"));
        assert!(output.contains("proto=tcp"));
        assert!(output.contains("svc=https"));
    }

    #[test]
    fn leef_tab_separated() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("http".into()),
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: None,
                }],
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
            }],
            total_duration: Duration::from_millis(1000),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = LeefFormatter.format(&result).unwrap();
        let line = output.lines().next().unwrap();
        // After the header, extensions should be tab-separated
        let parts: Vec<&str> = line.split('\t').collect();
        // At least: header, dst=..., dstPort=..., proto=..., svc=...
        assert!(
            parts.len() >= 5,
            "expected >= 5 tab-separated parts, got {}",
            parts.len()
        );
        assert!(parts[1].starts_with("dst="));
        assert!(parts[2].starts_with("dstPort="));
    }
}
