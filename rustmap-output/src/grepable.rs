use rustmap_types::{HostStatus, PortState, ScanResult};
use std::fmt::Write;

use crate::traits::{OutputError, OutputFormatter};

/// Grepable output formatter matching nmap's `-oG` format.
///
/// Each host produces a tab-separated line with fields like:
/// `Host: IP (hostname)`, `Status: Up`, `Ports: 22/open/tcp//ssh///`,
/// `Ignored State: closed (N)`, and `OS: Linux 5.x`.
pub struct GrepableFormatter;

impl OutputFormatter for GrepableFormatter {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError> {
        let mut out = String::new();

        // Header comment
        let args = result.command_args.as_deref().unwrap_or("rustmap")
            .replace(['\n', '\r'], " ");
        let datetime = format_start_datetime(result);
        writeln!(
            out,
            "# rustmap 0.1.0 scan initiated {} as: {}",
            datetime,
            args,
        )
        .unwrap();

        for host_result in &result.hosts {
            let ip = host_result.host.ip.to_string();
            let hostname = escape_grepable(
                host_result.host.hostname.as_deref().unwrap_or(""),
            );

            // Status line
            let status = match host_result.host_status {
                HostStatus::Up => "Up",
                HostStatus::Down => "Down",
                HostStatus::Unknown => "Up",
            };
            writeln!(out, "Host: {} ({})\tStatus: {}", ip, hostname, status).unwrap();

            // If host is down or has no ports, skip ports line
            if host_result.host_status == HostStatus::Down || host_result.ports.is_empty() {
                continue;
            }

            // Build ports field
            let port_entries: Vec<String> = host_result
                .ports
                .iter()
                .filter(|p| p.state != PortState::Closed || closed_count(&host_result.ports) <= 10)
                .map(|port| {
                    let state = port.state.to_string();
                    let protocol = port.protocol.to_string();
                    let service = port
                        .service
                        .as_deref()
                        .or_else(|| port.service_info.as_ref().map(|si| si.name.as_str()))
                        .unwrap_or("");
                    let version = port
                        .service_info
                        .as_ref()
                        .and_then(|si| si.version_display())
                        .unwrap_or_default();

                    // nmap grepable port format: port/state/protocol//service//version/
                    // Slashes in values are replaced with |
                    let mut entry = format!(
                        "{}/{}/{}//{}//{}/",
                        port.number,
                        escape_grepable(&state),
                        escape_grepable(&protocol),
                        escape_grepable(service),
                        escape_grepable(&version),
                    );

                    // Append TLS info when present
                    if let Some(ref tls) = port.tls_info {
                        let ver = match tls.tls_version {
                            0x0304 => "1.3",
                            0x0303 => "1.2",
                            0x0302 => "1.1",
                            0x0301 => "1.0",
                            _ => "?",
                        };
                        write!(entry, " TLS:{ver}").unwrap();
                        if let Some(ref alpn) = tls.alpn {
                            write!(entry, " ALPN:{}", escape_grepable(alpn)).unwrap();
                        }
                        if let Some(ref ja4s) = tls.ja4s {
                            write!(entry, " JA4S:{}", escape_grepable(ja4s)).unwrap();
                        }
                        if let Some(ref chain) = tls.certificate_chain
                            && let Some(leaf) = chain.first()
                            && let Some(ref cn) = leaf.subject_cn
                        {
                            write!(entry, " CERT:{}", escape_grepable(cn)).unwrap();
                        }
                    }

                    entry
                })
                .collect();

            // Build the host line with tab-separated fields
            let mut line = format!("Host: {} ({})", ip, hostname);

            // GeoIP field
            if let Some(ref geo) = host_result.host.geo_info {
                let mut parts = Vec::new();
                if let Some(ref cc) = geo.country_code {
                    parts.push(escape_grepable(cc));
                }
                if let Some(ref city) = geo.city {
                    parts.push(escape_grepable(city));
                }
                if let Some(asn) = geo.asn {
                    parts.push(format!("AS{asn}"));
                }
                if let Some(ref org) = geo.as_org {
                    parts.push(escape_grepable(org));
                }
                if !parts.is_empty() {
                    write!(line, "\tGeoIP: {}", parts.join("; ")).unwrap();
                }
            }

            if !port_entries.is_empty() {
                write!(line, "\tPorts: {}", port_entries.join(", ")).unwrap();
            }

            // Ignored state summary (closed ports when there are many)
            let closed = closed_count(&host_result.ports);
            if closed > 10 {
                write!(line, "\tIgnored State: closed ({})", closed).unwrap();
            }

            let filtered = host_result
                .ports
                .iter()
                .filter(|p| p.state == PortState::Filtered)
                .count();
            if filtered > 10 {
                write!(line, "\tIgnored State: filtered ({})", filtered).unwrap();
            }

            // OS info
            if let Some(ref os_fp) = host_result.os_fingerprint
                && let Some(ref family) = os_fp.os_family
            {
                let os_str = match &os_fp.os_generation {
                    Some(generation) => format!("{family} {generation}"),
                    None => family.clone(),
                };
                write!(line, "\tOS: {}", escape_grepable(&os_str)).unwrap();
            }

            // Script results
            let script_entries: Vec<String> = host_result
                .ports
                .iter()
                .flat_map(|p| {
                    p.script_results.iter().map(move |sr| {
                        format!(
                            "{}/{}: {}",
                            p.number,
                            escape_grepable(&sr.id),
                            escape_grepable(&sr.output.replace('\n', " ")),
                        )
                    })
                })
                .chain(host_result.host_script_results.iter().map(|sr| {
                    format!(
                        "{}: {}",
                        escape_grepable(&sr.id),
                        escape_grepable(&sr.output.replace('\n', " ")),
                    )
                }))
                .collect();
            if !script_entries.is_empty() {
                write!(line, "\tScript: {}", script_entries.join("; ")).unwrap();
            }

            // Traceroute
            if let Some(ref tr) = host_result.traceroute {
                let hops_str: Vec<String> = tr
                    .hops
                    .iter()
                    .map(|hop| {
                        let addr = hop
                            .ip
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "*".to_string());
                        let rtt = hop
                            .rtt
                            .map(|d| format!("{:.2}ms", d.as_secs_f64() * 1000.0))
                            .unwrap_or_else(|| "*".to_string());
                        format!("{} ({})", addr, rtt)
                    })
                    .collect();
                write!(line, "\tTraceroute: {}", hops_str.join(", ")).unwrap();
            }

            writeln!(out, "{}", line).unwrap();
        }

        // Footer comment
        let up_count = result
            .hosts
            .iter()
            .filter(|h| h.host_status != HostStatus::Down)
            .count();
        let total = result.hosts.len();
        let elapsed = result.total_duration.as_secs_f64();

        writeln!(
            out,
            "# rustmap done -- {} IP address{} ({} host{} up) scanned in {:.2} seconds",
            total,
            if total == 1 { "" } else { "es" },
            up_count,
            if up_count == 1 { "" } else { "s" },
            elapsed,
        )
        .unwrap();

        Ok(out)
    }
}

/// Escape characters that would break the grepable format: slashes (field delimiters),
/// tabs (field separators), and newlines (record terminators).
fn escape_grepable(s: &str) -> String {
    s.replace('/', "|")
        .replace(['\t', '\n', '\r'], " ")
}

/// Count closed ports in a port list.
fn closed_count(ports: &[rustmap_types::Port]) -> usize {
    ports.iter().filter(|p| p.state == PortState::Closed).count()
}

/// Format start time for the grepable header.
fn format_start_datetime(result: &ScanResult) -> String {
    if let Some(ref start) = result.start_time
        && let Ok(d) = start.duration_since(std::time::UNIX_EPOCH)
    {
        return format_unix_timestamp(d.as_secs());
    }
    "N/A".to_string()
}

/// Format a Unix timestamp into a human-readable UTC string.
fn format_unix_timestamp(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);

    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day_names = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let weekday = (days % 7) as usize;

    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {} UTC",
        day_names[weekday],
        month_names[(month - 1) as usize],
        day,
        hours,
        minutes,
        seconds,
        year,
    )
}

fn days_to_ymd(days: u64) -> (u64, u32, u32) {
    let mut remaining = days as i64;
    let mut year: u64 = 1970;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month: u32 = 1;
    for &days_in_month in &month_days {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }

    (year, month, remaining as u32 + 1)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{
        DetectionMethod, Host, HostScanResult, HostStatus, OsFingerprint, OsProbeResults, Port,
        PortState, Protocol, ScanType, ScriptResult, ServiceInfo,
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

    fn make_scan_result(hosts: Vec<HostScanResult>) -> ScanResult {
        ScanResult {
            hosts,
            total_duration: Duration::from_millis(2450),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn grepable_basic_format() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([192, 168, 1, 1]),
            ports: vec![
                Port {
                    number: 22,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("ssh".into()),
                    service_info: None,
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.starts_with("# rustmap 0.1.0 scan initiated"));
        assert!(output.contains("Host: 192.168.1.1 ()\tStatus: Up"));
        assert!(output.contains("22/open/tcp//ssh///"));
        assert!(output.contains("80/open/tcp//http///"));
        assert!(output.contains("\tPorts: "));
        assert!(output.contains("# rustmap done"));
    }

    #[test]
    fn grepable_tab_separated_fields() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        // The ports line should have tab-separated fields
        let ports_line = output.lines().find(|l| l.contains("Ports:")).unwrap();
        assert!(ports_line.contains('\t'));
        let fields: Vec<&str> = ports_line.split('\t').collect();
        assert!(fields[0].starts_with("Host:"));
        assert!(fields[1].starts_with("Ports:"));
    }

    #[test]
    fn grepable_port_format() {
        // Port format: port/state/protocol//service//version/
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("22/open/tcp//ssh//OpenSSH 8.9p1/"));
    }

    #[test]
    fn grepable_slash_escaping() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
            ports: vec![Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("http".into()),
                service_info: Some(ServiceInfo {
                    name: "http".into(),
                    product: Some("Apache/2.4".into()),
                    version: Some("2.4.52".into()),
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        // Slashes in "Apache/2.4" should be replaced with "|"
        assert!(output.contains("Apache|2.4 2.4.52"));
        assert!(!output.contains("Apache/2.4"));
    }

    #[test]
    fn grepable_host_down() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
            ports: vec![],
            scan_duration: Duration::ZERO,
            host_status: HostStatus::Down,
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: None,
            timing_snapshot: None,
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("Status: Down"));
        assert!(!output.contains("Ports:"));
    }

    #[test]
    fn grepable_os_info() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([192, 168, 1, 1]),
            ports: vec![make_port(22, PortState::Open)],
            scan_duration: Duration::from_millis(500),
            host_status: HostStatus::Up,
            discovery_latency: None,
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("\tOS: Linux 5.x"));
    }

    #[test]
    fn grepable_hostname() {
        let result = make_scan_result(vec![HostScanResult {
            host: Host {
                ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                hostname: Some("example.com".into()),
                geo_info: None,
            },
            ports: vec![make_port(80, PortState::Open)],
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("Host: 93.184.216.34 (example.com)"));
    }

    #[test]
    fn grepable_ignored_state() {
        // Create 15 closed ports + 1 open
        let mut ports: Vec<Port> = (1..=15)
            .map(|n| make_port(n, PortState::Closed))
            .collect();
        ports.push(Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        });

        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("Ignored State: closed (15)"));
        // Open port should still appear
        assert!(output.contains("80/open/tcp//http///"));
        // Closed ports should NOT appear as individual entries
        assert!(!output.contains("1/closed"));
    }

    #[test]
    fn grepable_footer_counts() {
        let result = make_scan_result(vec![
            HostScanResult {
                host: make_host([192, 168, 1, 1]),
                ports: vec![make_port(80, PortState::Open)],
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
            },
            HostScanResult {
                host: make_host([192, 168, 1, 2]),
                ports: vec![],
                scan_duration: Duration::ZERO,
                host_status: HostStatus::Down,
                discovery_latency: None,
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            },
        ]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("2 IP addresses (1 host up) scanned in 2.45 seconds"));
    }

    #[test]
    fn grepable_empty_scan() {
        let result = make_scan_result(vec![]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.starts_with("# rustmap"));
        assert!(output.contains("0 IP addresses (0 hosts up)"));
    }

    #[test]
    fn grepable_command_args() {
        let mut result = make_scan_result(vec![]);
        result.command_args = Some("rustmap -Pn -p 80,443 192.168.1.1".into());

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("as: rustmap -Pn -p 80,443 192.168.1.1"));
    }

    #[test]
    fn grepable_script_results() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([192, 168, 1, 1]),
            ports: vec![Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("http".into()),
                service_info: None,
                reason: None,
                script_results: vec![ScriptResult {
                    id: "http-title".into(),
                    output: "Title: Welcome".into(),
                    elements: None,
                }],
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("\tScript: 80/http-title: Title: Welcome"));
    }

    #[test]
    fn grepable_no_script_no_field() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
            ports: vec![make_port(80, PortState::Open)],
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(!output.contains("Script:"));
    }

    #[test]
    fn grepable_geoip_field() {
        use rustmap_types::GeoInfo;
        let result = make_scan_result(vec![HostScanResult {
            host: Host {
                ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                hostname: None,
                geo_info: Some(GeoInfo {
                    country_code: Some("US".into()),
                    country: None,
                    city: Some("Norwell".into()),
                    latitude: None,
                    longitude: None,
                    timezone: None,
                    asn: Some(15133),
                    as_org: Some("Edgecast Inc.".into()),
                }),
            },
            ports: vec![make_port(80, PortState::Open)],
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
        }]);

        let output = GrepableFormatter.format(&result).unwrap();
        assert!(output.contains("GeoIP: US; Norwell; AS15133; Edgecast Inc."));
    }
}
