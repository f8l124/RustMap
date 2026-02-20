use std::fmt::Write;

use crate::traits::{OutputError, OutputFormatter};
use rustmap_types::ScanResult;

pub struct CsvFormatter;

impl OutputFormatter for CsvFormatter {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError> {
        let mut out = String::new();

        // Header row
        writeln!(out, "ip,hostname,country,city,asn,as_org,port,protocol,state,service,version,reason,tls_version,alpn,ja4s,cert_subject,cert_issuer,cert_expiry")
            .map_err(|e| OutputError::FormatError(e.to_string()))?;

        // One row per port per host
        for host in &result.hosts {
            let ip = &host.host.ip;
            let hostname = host.host.hostname.as_deref().unwrap_or("");
            let (country, city, asn, as_org) = match &host.host.geo_info {
                Some(geo) => (
                    geo.country.as_deref().unwrap_or(""),
                    geo.city.as_deref().unwrap_or(""),
                    geo.asn.map(|n| n.to_string()).unwrap_or_default(),
                    geo.as_org.as_deref().unwrap_or(""),
                ),
                None => ("", "", String::new(), ""),
            };
            for port in &host.ports {
                let service = port.service.as_deref().unwrap_or("");
                let version = port
                    .service_info
                    .as_ref()
                    .and_then(|si| si.version_display())
                    .unwrap_or_default();
                let reason = port.reason.as_deref().unwrap_or("");
                let (tls_ver, tls_alpn, tls_ja4s) = match &port.tls_info {
                    Some(tls) => {
                        let ver = match tls.tls_version {
                            0x0304 => "1.3",
                            0x0303 => "1.2",
                            0x0302 => "1.1",
                            0x0301 => "1.0",
                            _ => "",
                        };
                        (
                            ver,
                            tls.alpn.as_deref().unwrap_or(""),
                            tls.ja4s.as_deref().unwrap_or(""),
                        )
                    }
                    None => ("", "", ""),
                };
                let (cert_subject, cert_issuer, cert_expiry) = match &port.tls_info {
                    Some(tls) => {
                        let leaf = tls.certificate_chain.as_ref().and_then(|c| c.first());
                        (
                            leaf.and_then(|l| l.subject_cn.as_deref()).unwrap_or(""),
                            leaf.and_then(|l| l.issuer_cn.as_deref()).unwrap_or(""),
                            leaf.and_then(|l| l.not_after.as_deref()).unwrap_or(""),
                        )
                    }
                    None => ("", "", ""),
                };
                writeln!(
                    out,
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    ip,
                    csv_escape(hostname),
                    csv_escape(country),
                    csv_escape(city),
                    csv_escape(&asn),
                    csv_escape(as_org),
                    port.number,
                    port.protocol,
                    port.state,
                    csv_escape(service),
                    csv_escape(&version),
                    csv_escape(reason),
                    csv_escape(tls_ver),
                    csv_escape(tls_alpn),
                    csv_escape(tls_ja4s),
                    csv_escape(cert_subject),
                    csv_escape(cert_issuer),
                    csv_escape(cert_expiry),
                )
                .map_err(|e| OutputError::FormatError(e.to_string()))?;
            }
        }
        Ok(out)
    }
}

fn csv_escape(s: &str) -> String {
    let needs_quoting = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    let has_formula_prefix = matches!(s.as_bytes().first(), Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r'));

    if has_formula_prefix {
        // Prepend single-quote to neutralize formula interpretation in spreadsheets
        format!("\"'{}\"", s.replace('"', "\"\""))
    } else if needs_quoting {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
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

    fn make_port(number: u16, service: &str, version: &str) -> Port {
        Port {
            number,
            state: PortState::Open,
            protocol: Protocol::Tcp,
            service: Some(service.into()),
            service_info: Some(ServiceInfo {
                name: service.into(),
                product: None,
                version: Some(version.into()),
                info: None,
                method: rustmap_types::DetectionMethod::Banner,
            }),
            reason: Some("syn-ack".into()),
            script_results: vec![],
            tls_info: None,
        }
    }

    fn make_host(ip: [u8; 4], ports: Vec<Port>) -> HostScanResult {
        HostScanResult {
            host: Host::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))),
            ports,
            scan_duration: Duration::from_millis(100),
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

    fn make_result(hosts: Vec<HostScanResult>) -> ScanResult {
        ScanResult {
            hosts,
            total_duration: Duration::from_secs(1),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn csv_header_includes_tls_columns() {
        let result = make_result(vec![]);
        let output = CsvFormatter.format(&result).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(
            lines[0],
            "ip,hostname,country,city,asn,as_org,port,protocol,state,service,version,reason,tls_version,alpn,ja4s,cert_subject,cert_issuer,cert_expiry"
        );
    }

    #[test]
    fn csv_one_host_one_port() {
        let result = make_result(vec![make_host(
            [192, 168, 1, 1],
            vec![make_port(22, "ssh", "8.9p1")],
        )]);
        let output = CsvFormatter.format(&result).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 row
        assert!(lines[1].starts_with("192.168.1.1,"));
        assert!(lines[1].contains(",22,"));
        assert!(lines[1].contains(",open,"));
        assert!(lines[1].contains(",ssh,"));
    }

    #[test]
    fn csv_multiple_hosts_ports() {
        let result = make_result(vec![
            make_host(
                [10, 0, 0, 1],
                vec![make_port(22, "ssh", "8.9"), make_port(80, "http", "1.24")],
            ),
            make_host([10, 0, 0, 2], vec![make_port(443, "https", "")]),
        ]);
        let output = CsvFormatter.format(&result).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 rows
    }

    #[test]
    fn csv_escape_comma() {
        let escaped = csv_escape("hello,world");
        assert_eq!(escaped, "\"hello,world\"");
    }

    #[test]
    fn csv_escape_quotes() {
        let escaped = csv_escape("say \"hello\"");
        assert_eq!(escaped, "\"say \"\"hello\"\"\"");
    }

    #[test]
    fn csv_empty_scan() {
        let result = make_result(vec![]);
        let output = CsvFormatter.format(&result).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1); // header only
    }

    #[test]
    fn csv_geo_columns_populated() {
        use rustmap_types::GeoInfo;
        let mut host = make_host([93, 184, 216, 34], vec![make_port(80, "http", "")]);
        host.host.geo_info = Some(GeoInfo {
            country_code: Some("US".into()),
            country: Some("United States".into()),
            city: Some("Seattle".into()),
            latitude: Some(47.6),
            longitude: Some(-122.3),
            timezone: None,
            asn: Some(13335),
            as_org: Some("Cloudflare, Inc.".into()),
        });
        let result = make_result(vec![host]);
        let output = CsvFormatter.format(&result).unwrap();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("United States"));
        assert!(lines[1].contains("Seattle"));
        assert!(lines[1].contains("13335"));
        assert!(lines[1].contains("Cloudflare"));
    }
}
