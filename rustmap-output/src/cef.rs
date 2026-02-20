use std::fmt::Write;

use rustmap_types::{HostStatus, PortState, ScanResult};

use crate::traits::{OutputError, OutputFormatter};

/// CEF (Common Event Format) output formatter for ArcSight/Splunk integration.
///
/// Emits one CEF event per open port per host.
/// Format: `CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extensions`
pub struct CefFormatter;

impl OutputFormatter for CefFormatter {
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
                let severity = cef_severity(host.risk_score);
                let svc = port.service.as_deref().unwrap_or("unknown");
                let event_id =
                    cef_header_escape(&format!("port-{}-{}", port.protocol, port.number));
                let name =
                    cef_header_escape(&format!("{}/{} {} open", port.number, port.protocol, svc));

                // CEF header
                write!(
                    output,
                    "CEF:0|RustMap|rustmap|0.1.0|{event_id}|{name}|{severity}|"
                )
                .unwrap();

                // Extensions (key=value pairs, space-separated)
                write!(output, "dst={}", host.host.ip).unwrap();
                if let Some(ref hn) = host.host.hostname {
                    write!(output, " dhost={}", cef_escape(hn)).unwrap();
                }
                write!(output, " dpt={} proto={}", port.number, port.protocol).unwrap();
                write!(output, " act=open").unwrap();

                // Service info
                if let Some(ref si) = port.service_info {
                    if let Some(ref p) = si.product {
                        write!(output, " cs1={}", cef_escape(p)).unwrap();
                        write!(output, " cs1Label=product").unwrap();
                    }
                    if let Some(ref v) = si.version {
                        write!(output, " cs2={}", cef_escape(v)).unwrap();
                        write!(output, " cs2Label=version").unwrap();
                    }
                }

                // GeoIP
                if let Some(ref geo) = host.host.geo_info
                    && let Some(ref cc) = geo.country_code
                {
                    write!(output, " cs3={} cs3Label=countryCode", cef_escape(cc)).unwrap();
                }

                // Risk score
                if let Some(risk) = host.risk_score {
                    write!(output, " cn1={risk:.1} cn1Label=riskScore").unwrap();
                }

                // OS
                if let Some(ref os) = host.os_fingerprint
                    && let Some(ref fam) = os.os_family
                {
                    write!(output, " cs4={}", cef_escape(fam)).unwrap();
                    write!(output, " cs4Label=osFamily").unwrap();
                }

                // TLS certificate
                if let Some(ref tls) = port.tls_info
                    && let Some(ref chain) = tls.certificate_chain
                    && let Some(leaf) = chain.first()
                {
                    if let Some(ref cn) = leaf.subject_cn {
                        write!(output, " cs5={}", cef_escape(cn)).unwrap();
                        write!(output, " cs5Label=certSubject").unwrap();
                    }
                    if let Some(ref iss) = leaf.issuer_cn {
                        write!(output, " cs6={}", cef_escape(iss)).unwrap();
                        write!(output, " cs6Label=certIssuer").unwrap();
                    }
                }

                writeln!(output).unwrap();
            }
        }
        Ok(output)
    }
}

/// Map risk score to CEF severity (0-10 integer scale).
fn cef_severity(risk: Option<f64>) -> u8 {
    match risk {
        Some(r) => r.clamp(0.0, 10.0) as u8,
        None => 3, // default "Low" for no risk data
    }
}

/// Escape CEF header field special characters: pipe and backslash.
fn cef_header_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

/// Escape CEF special characters: \ = and newlines.
fn cef_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{
        DetectionMethod, Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanType,
        ServiceInfo,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn cef_basic_output() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
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

        let output = CefFormatter.format(&result).unwrap();
        assert!(output.starts_with("CEF:0|RustMap|rustmap|0.1.0|"));
        assert!(output.contains("dst=192.168.1.1"));
        assert!(output.contains("dpt=80"));
        assert!(output.contains("proto=tcp"));
        assert!(output.contains("act=open"));
    }

    #[test]
    fn cef_escape_special_chars() {
        assert_eq!(cef_escape("normal"), "normal");
        assert_eq!(cef_escape("a=b"), "a\\=b");
        assert_eq!(cef_escape("a\\b"), "a\\\\b");
        assert_eq!(cef_escape("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn cef_with_service_info() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                ports: vec![Port {
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
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = CefFormatter.format(&result).unwrap();
        assert!(output.contains("cs1=OpenSSH"));
        assert!(output.contains("cs1Label=product"));
        assert!(output.contains("cs2=8.9p1"));
        assert!(output.contains("cs2Label=version"));
    }
}
