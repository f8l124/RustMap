use std::time::Duration;

use rustmap_types::{HostStatus, PortState, ScanResult, ScanType, ScriptResult};

use crate::traits::{OutputError, OutputFormatter};

/// Strip terminal control characters from untrusted data to prevent escape injection.
fn sanitize_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

pub struct StdoutFormatter {
    show_reason: bool,
    scan_type: ScanType,
}

impl StdoutFormatter {
    pub fn new(show_reason: bool, scan_type: ScanType) -> Self {
        Self {
            show_reason,
            scan_type,
        }
    }
}

impl Default for StdoutFormatter {
    fn default() -> Self {
        Self {
            show_reason: false,
            scan_type: ScanType::TcpConnect,
        }
    }
}

impl OutputFormatter for StdoutFormatter {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError> {
        let mut output = String::new();

        output.push_str("Starting rustmap 0.1.0\n");

        // Pre-script results
        if !result.pre_script_results.is_empty() {
            output.push_str("\nPre-scan script results:\n");
            format_script_results(&result.pre_script_results, &mut output);
        }

        let is_ping_only = result.hosts.iter().all(|h| h.ports.is_empty());
        let total_hosts = result.hosts.len();
        let up_count = result
            .hosts
            .iter()
            .filter(|h| h.host_status == HostStatus::Up)
            .count();

        for host_result in &result.hosts {
            output.push_str(&format!(
                "\nrustmap scan report for {}\n",
                host_result.host.ip
            ));

            // Show host status
            match host_result.host_status {
                HostStatus::Up => {
                    if let Some(latency) = host_result.discovery_latency {
                        output.push_str(&format!(
                            "Host is up ({:.4}s latency).\n",
                            latency.as_secs_f64()
                        ));
                    } else {
                        output.push_str("Host is up.\n");
                    }
                }
                HostStatus::Down => {
                    output.push_str("Host seems down.\n");
                    continue;
                }
                HostStatus::Unknown => {
                    // Discovery was skipped (-Pn)
                }
            }

            // GeoIP information
            if let Some(ref geo) = host_result.host.geo_info {
                let mut parts = Vec::new();
                if let Some(ref city) = geo.city {
                    parts.push(sanitize_terminal(city));
                }
                if let Some(ref country) = geo.country {
                    parts.push(sanitize_terminal(country));
                }
                if let Some(asn) = geo.asn {
                    let asn_str = if let Some(ref org) = geo.as_org {
                        format!("AS{asn} ({})", sanitize_terminal(org))
                    } else {
                        format!("AS{asn}")
                    };
                    parts.push(asn_str);
                }
                if !parts.is_empty() {
                    output.push_str(&format!("GeoIP: {}\n", parts.join(", ")));
                }
            }

            // Skip port table for ping-only mode
            if host_result.ports.is_empty() {
                continue;
            }

            let closed_count = host_result
                .ports
                .iter()
                .filter(|p| p.state == PortState::Closed)
                .count();
            let filtered_count = host_result
                .ports
                .iter()
                .filter(|p| p.state == PortState::Filtered)
                .count();
            let open_filtered_count = host_result
                .ports
                .iter()
                .filter(|p| p.state == PortState::OpenFiltered)
                .count();
            let unfiltered_count = host_result
                .ports
                .iter()
                .filter(|p| p.state == PortState::Unfiltered)
                .count();
            let closed_filtered_count = host_result
                .ports
                .iter()
                .filter(|p| p.state == PortState::ClosedFiltered)
                .count();

            // Build "Not shown" summary for states with many ports
            let mut not_shown_parts = Vec::new();
            if closed_count > 10 {
                not_shown_parts.push(format!("{} closed", closed_count));
            }
            if filtered_count > 10 {
                not_shown_parts.push(format!("{} filtered", filtered_count));
            }
            if open_filtered_count > 10 {
                not_shown_parts.push(format!("{} open|filtered", open_filtered_count));
            }
            if unfiltered_count > 10 {
                not_shown_parts.push(format!("{} unfiltered", unfiltered_count));
            }
            if closed_filtered_count > 10 {
                not_shown_parts.push(format!("{} closed|filtered", closed_filtered_count));
            }
            if !not_shown_parts.is_empty() {
                output.push_str(&format!(
                    "Not shown: {} ports\n",
                    not_shown_parts.join(", ")
                ));
            }

            // Check if any port has version info (service_info)
            let has_version_info = host_result.ports.iter().any(|p| p.service_info.is_some());

            // Build header based on what columns we need
            let show_reason = self.show_reason;
            match (has_version_info, show_reason) {
                (true, true) => {
                    output.push_str("PORT      STATE    REASON       SERVICE    VERSION\n");
                }
                (true, false) => {
                    output.push_str("PORT      STATE    SERVICE    VERSION\n");
                }
                (false, true) => {
                    output.push_str("PORT      STATE    REASON       SERVICE\n");
                }
                (false, false) => {
                    output.push_str("PORT      STATE    SERVICE\n");
                }
            }

            for port in &host_result.ports {
                // If we're summarizing a port state, skip those ports in the table
                let should_hide = match port.state {
                    PortState::Closed => closed_count > 10,
                    PortState::Filtered => filtered_count > 10,
                    PortState::OpenFiltered => open_filtered_count > 10,
                    PortState::Unfiltered => unfiltered_count > 10,
                    PortState::ClosedFiltered => closed_filtered_count > 10,
                    _ => false,
                };
                if should_hide {
                    continue;
                }

                let port_str = format!("{}/{}", port.number, port.protocol);
                let service = sanitize_terminal(port.service.as_deref().unwrap_or("unknown"));
                let reason = if show_reason {
                    sanitize_terminal(
                        port.reason
                            .as_deref()
                            .unwrap_or_else(|| derive_reason(self.scan_type, port.state)),
                    )
                } else {
                    String::new()
                };

                match (has_version_info, show_reason) {
                    (true, true) => {
                        let version = sanitize_terminal(
                            &port
                                .service_info
                                .as_ref()
                                .and_then(|si| si.version_display())
                                .unwrap_or_default(),
                        );
                        output.push_str(&format!(
                            "{:<9} {:<8} {:<12} {:<10} {}\n",
                            port_str, port.state, reason, service, version
                        ));
                    }
                    (true, false) => {
                        let version = sanitize_terminal(
                            &port
                                .service_info
                                .as_ref()
                                .and_then(|si| si.version_display())
                                .unwrap_or_default(),
                        );
                        output.push_str(&format!(
                            "{:<9} {:<8} {:<10} {}\n",
                            port_str, port.state, service, version
                        ));
                    }
                    (false, true) => {
                        output.push_str(&format!(
                            "{:<9} {:<8} {:<12} {}\n",
                            port_str, port.state, reason, service
                        ));
                    }
                    (false, false) => {
                        output
                            .push_str(&format!("{:<9} {:<8} {}\n", port_str, port.state, service));
                    }
                }

                // TLS info line
                if let Some(ref tls) = port.tls_info {
                    let ver = match tls.tls_version {
                        0x0304 => "v1.3",
                        0x0303 => "v1.2",
                        0x0302 => "v1.1",
                        0x0301 => "v1.0",
                        _ => "unknown",
                    };
                    let mut tls_parts = vec![format!("TLS: {ver}")];
                    if let Some(ref alpn) = tls.alpn {
                        tls_parts.push(sanitize_terminal(alpn));
                    }
                    if let Some(ref ja4s) = tls.ja4s {
                        tls_parts.push(format!("JA4S:{}", sanitize_terminal(ja4s)));
                    }
                    output.push_str(&format!("              {}\n", tls_parts.join(" ")));
                    // Certificate chain info
                    if let Some(ref chain) = tls.certificate_chain {
                        if let Some(leaf) = chain.first() {
                            let subject =
                                sanitize_terminal(leaf.subject_cn.as_deref().unwrap_or("unknown"));
                            let issuer =
                                sanitize_terminal(leaf.issuer_cn.as_deref().unwrap_or("unknown"));
                            let expiry =
                                sanitize_terminal(leaf.not_after.as_deref().unwrap_or("unknown"));
                            output.push_str(&format!(
                                "              CERT: {subject} (issuer: {issuer}) expires: {expiry}\n"
                            ));
                            if !leaf.san_dns.is_empty() {
                                let sanitized_sans: Vec<String> =
                                    leaf.san_dns.iter().map(|s| sanitize_terminal(s)).collect();
                                output.push_str(&format!(
                                    "              SANs: {}\n",
                                    sanitized_sans.join(", ")
                                ));
                            }
                        }
                    } else if tls.tls_version >= 0x0304 {
                        output.push_str("              CERT: (TLS 1.3 - certs encrypted)\n");
                    }
                }

                // Port script results
                format_script_results(&port.script_results, &mut output);
            }

            // Host script results
            if !host_result.host_script_results.is_empty() {
                output.push_str("Host script results:\n");
                format_script_results(&host_result.host_script_results, &mut output);
            }

            // OS detection results
            if let Some(ref os_fp) = host_result.os_fingerprint
                && let Some(ref family) = os_fp.os_family
            {
                let family_safe = sanitize_terminal(family);
                let generation = os_fp
                    .os_generation
                    .as_deref()
                    .map(|g| format!(" {}", sanitize_terminal(g)))
                    .unwrap_or_default();
                let confidence = os_fp
                    .accuracy
                    .map(|a| format!(" ({a}% confidence)"))
                    .unwrap_or_default();
                output.push_str(&format!(
                    "OS details: {family_safe}{generation}{confidence}\n"
                ));
            }

            // Uptime estimate
            if let Some(ref uptime) = host_result.uptime_estimate {
                output.push_str(&format!("Uptime estimate: {}\n", format_uptime(uptime)));
            }

            // Path MTU
            if let Some(mtu) = host_result.mtu {
                output.push_str(&format!("Path MTU: {mtu}\n"));
            }

            // Risk score
            if let Some(risk) = host_result.risk_score {
                let sev = if risk >= 9.0 {
                    "CRITICAL"
                } else if risk >= 7.0 {
                    "HIGH"
                } else if risk >= 4.0 {
                    "MEDIUM"
                } else {
                    "LOW"
                };
                output.push_str(&format!("Risk Score: {risk:.1}/10.0 ({sev})\n"));
            }

            // Traceroute results
            if let Some(ref tr) = host_result.traceroute {
                output.push_str(&format!(
                    "\nTRACEROUTE (using port {}/{})\n",
                    tr.port, tr.protocol
                ));
                output.push_str("HOP  RTT       ADDRESS\n");
                for hop in &tr.hops {
                    let rtt = hop
                        .rtt
                        .map(|d| format!("{:.2} ms", d.as_secs_f64() * 1000.0))
                        .unwrap_or_else(|| "*".to_string());
                    let addr = hop
                        .ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "*".to_string());
                    output.push_str(&format!("{:<4} {:<9} {}\n", hop.ttl, rtt, addr));
                }
            }

            if host_result.scan_duration.as_nanos() > 0 {
                output.push_str(&format!(
                    "\nScan completed in {:.2}s\n",
                    host_result.scan_duration.as_secs_f64()
                ));
            }
        }

        // Service histogram (across all hosts)
        if !is_ping_only {
            let mut service_counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for host in &result.hosts {
                for port in &host.ports {
                    if port.state == PortState::Open {
                        let svc = port.service.as_deref().unwrap_or("unknown");
                        *service_counts.entry(svc).or_insert(0) += 1;
                    }
                }
            }
            if !service_counts.is_empty() {
                let mut sorted: Vec<_> = service_counts.into_iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(&a.1));

                output.push_str("\nService distribution:");
                for (svc, count) in sorted.iter().take(10) {
                    output.push_str(&format!(" {}({count})", sanitize_terminal(svc)));
                }
                if sorted.len() > 10 {
                    output.push_str(&format!(" ... +{} more", sorted.len() - 10));
                }
                output.push('\n');
            }
        }

        // Post-script results
        if !result.post_script_results.is_empty() {
            output.push_str("\nPost-scan script results:\n");
            format_script_results(&result.post_script_results, &mut output);
        }

        if is_ping_only {
            output.push_str(&format!(
                "\nrustmap done: {} host(s) up ({} total) in {:.2} seconds\n",
                up_count,
                total_hosts,
                result.total_duration.as_secs_f64()
            ));
        } else {
            output.push_str(&format!(
                "\nrustmap done: {} host(s) scanned in {:.2} seconds\n",
                total_hosts,
                result.total_duration.as_secs_f64()
            ));
        }

        Ok(output)
    }
}

/// Format a Duration as a human-readable uptime string (e.g., "42d 3h 15m" or "5m 30s").
///
/// Mirrors the canonical implementation in `rustmap_detect::uptime::format_uptime`.
fn format_uptime(d: &Duration) -> String {
    let total_secs = d.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m {seconds}s")
    }
}

/// Derive a reason string from scan type and port state when no explicit reason is set.
fn derive_reason(scan_type: ScanType, state: PortState) -> &'static str {
    match (scan_type, state) {
        (ScanType::TcpSyn, PortState::Open) => "syn-ack",
        (ScanType::TcpSyn, PortState::Closed) => "rst",
        (ScanType::TcpConnect, PortState::Open) => "syn-ack",
        (ScanType::TcpConnect, PortState::Closed) => "conn-refused",
        // FIN/NULL/Xmas/Maimon scans
        (
            ScanType::TcpFin | ScanType::TcpNull | ScanType::TcpXmas | ScanType::TcpMaimon,
            PortState::Closed,
        ) => "rst",
        (
            ScanType::TcpFin | ScanType::TcpNull | ScanType::TcpXmas | ScanType::TcpMaimon,
            PortState::OpenFiltered,
        ) => "no-response",
        // ACK scan
        (ScanType::TcpAck, PortState::Unfiltered) => "rst",
        // Window scan
        (ScanType::TcpWindow, PortState::Open) => "rst",
        (ScanType::TcpWindow, PortState::Closed) => "rst",
        (ScanType::TcpWindow, PortState::Unfiltered) => "rst",
        // UDP scan
        (ScanType::Udp, PortState::Open) => "udp-response",
        (ScanType::Udp, PortState::Closed) => "port-unreach",
        (ScanType::Udp, PortState::OpenFiltered) => "no-response",
        // SCTP scan
        (ScanType::SctpInit, PortState::Open) => "init-ack",
        (ScanType::SctpInit, PortState::Closed) => "abort",
        (ScanType::SctpInit, PortState::OpenFiltered) => "no-response",
        // Common across scan types
        (_, PortState::Filtered) => "no-response",
        _ => "unknown",
    }
}

/// Format script results with nmap-style `| ` prefix.
fn format_script_results(results: &[ScriptResult], output: &mut String) {
    for sr in results {
        let sanitized_output = sanitize_terminal(&sr.output);
        let lines: Vec<&str> = sanitized_output.lines().collect();
        if lines.len() <= 1 {
            output.push_str(&format!(
                "| {}: {}\n",
                sanitize_terminal(&sr.id),
                sanitized_output
            ));
        } else {
            output.push_str(&format!("| {}:\n", sanitize_terminal(&sr.id)));
            for line in lines {
                output.push_str(&format!("|   {}\n", line));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{
        Host, HostScanResult, OsFingerprint, OsProbeResults, Port, Protocol, ScanType, ScriptResult,
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

    #[test]
    fn format_host_up_with_latency() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([192, 168, 1, 1]),
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: None,
                }],
                scan_duration: Duration::from_millis(1230),
                host_status: HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(5)),
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_millis(2000),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("Host is up (0.0050s latency)."));
        assert!(output.contains("80/tcp"));
        assert!(output.contains("open"));
    }

    #[test]
    fn format_host_down() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
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
            }],
            total_duration: Duration::from_millis(3000),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("Host seems down."));
        assert!(!output.contains("PORT"));
    }

    #[test]
    fn format_ping_only() {
        let result = ScanResult {
            hosts: vec![
                HostScanResult {
                    host: make_host([192, 168, 1, 1]),
                    ports: vec![],
                    scan_duration: Duration::ZERO,
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
            ],
            total_duration: Duration::from_millis(2500),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("Host is up"));
        assert!(output.contains("Host seems down."));
        assert!(output.contains("1 host(s) up (2 total)"));
        assert!(!output.contains("PORT"));
    }

    #[test]
    fn format_skip_discovery() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![Port {
                    number: 443,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: None,
                }],
                scan_duration: Duration::from_millis(500),
                host_status: HostStatus::Unknown,
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
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        // Unknown status should not show "Host is up" or "Host seems down"
        assert!(!output.contains("Host is up"));
        assert!(!output.contains("Host seems down"));
        assert!(output.contains("443/tcp"));
    }

    #[test]
    fn format_os_fingerprint() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([192, 168, 1, 100]),
                ports: vec![Port {
                    number: 22,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("ssh".into()),
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: None,
                }],
                scan_duration: Duration::from_millis(2450),
                host_status: HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(3)),
                os_fingerprint: Some(OsFingerprint {
                    os_family: Some("Linux".into()),
                    os_generation: Some("5.x".into()),
                    os_detail: None,
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
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("OS details: Linux 5.x (92% confidence)"));
    }

    #[test]
    fn format_os_fingerprint_no_match() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: None,
                }],
                scan_duration: Duration::from_millis(500),
                host_status: HostStatus::Up,
                discovery_latency: None,
                os_fingerprint: Some(OsFingerprint {
                    os_family: None,
                    os_generation: None,
                    os_detail: None,
                    accuracy: None,
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
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(!output.contains("OS details"));
    }

    #[test]
    fn format_no_os_detection() {
        // When os_fingerprint is None (OS detection not enabled)
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
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
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(!output.contains("OS details"));
    }

    #[test]
    fn format_reason_column_syn_scan() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
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
                        state: PortState::Closed,
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
            }],
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 2,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let formatter = StdoutFormatter::new(true, ScanType::TcpSyn);
        let output = formatter.format(&result).unwrap();
        assert!(output.contains("REASON"));
        assert!(output.contains("syn-ack"));
        assert!(output.contains("rst"));
    }

    #[test]
    fn format_reason_column_connect_scan() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![
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
                    Port {
                        number: 8080,
                        protocol: Protocol::Tcp,
                        state: PortState::Filtered,
                        service: None,
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
            }],
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 3,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let formatter = StdoutFormatter::new(true, ScanType::TcpConnect);
        let output = formatter.format(&result).unwrap();
        assert!(output.contains("syn-ack"));
        assert!(output.contains("conn-refused"));
        assert!(output.contains("no-response"));
    }

    #[test]
    fn format_reason_column_not_shown_by_default() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
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
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(!output.contains("REASON"));
        assert!(!output.contains("syn-ack"));
    }

    #[test]
    fn format_explicit_reason_overrides_derived() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
                    service_info: None,
                    reason: Some("custom-reason".into()),
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
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let formatter = StdoutFormatter::new(true, ScanType::TcpConnect);
        let output = formatter.format(&result).unwrap();
        assert!(output.contains("custom-reason"));
        assert!(!output.contains("syn-ack"));
    }

    #[test]
    fn format_port_script_results() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
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
            }],
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("| http-title: Title: Welcome"));
    }

    #[test]
    fn format_multiline_script_output() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![Port {
                    number: 22,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("ssh".into()),
                    service_info: None,
                    reason: None,
                    script_results: vec![ScriptResult {
                        id: "ssh-hostkey".into(),
                        output: "RSA: abc123\nECDSA: def456".into(),
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
            }],
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("| ssh-hostkey:"));
        assert!(output.contains("|   RSA: abc123"));
        assert!(output.contains("|   ECDSA: def456"));
    }

    #[test]
    fn format_host_script_results() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([192, 168, 1, 1]),
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
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
                host_script_results: vec![ScriptResult {
                    id: "smb-os-discovery".into(),
                    output: "Windows 10".into(),
                    elements: None,
                }],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("Host script results:"));
        assert!(output.contains("| smb-os-discovery: Windows 10"));
    }

    #[test]
    fn format_pre_post_script_results() {
        let result = ScanResult {
            hosts: vec![],
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![ScriptResult {
                id: "broadcast-ping".into(),
                output: "Found 3 hosts".into(),
                elements: None,
            }],
            post_script_results: vec![ScriptResult {
                id: "summary".into(),
                output: "Scan complete".into(),
                elements: None,
            }],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("Pre-scan script results:"));
        assert!(output.contains("| broadcast-ping: Found 3 hosts"));
        assert!(output.contains("Post-scan script results:"));
        assert!(output.contains("| summary: Scan complete"));
    }

    #[test]
    fn format_no_scripts_no_output() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
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
            total_duration: Duration::from_millis(600),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(!output.contains("| "));
        assert!(!output.contains("Pre-scan script"));
        assert!(!output.contains("Post-scan script"));
        assert!(!output.contains("Host script"));
    }

    #[test]
    fn stdout_tls_info_line() {
        use rustmap_types::TlsServerFingerprint;
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([192, 168, 1, 1]),
                ports: vec![Port {
                    number: 443,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: Some("https".into()),
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: Some(TlsServerFingerprint {
                        tls_version: 0x0304,
                        cipher_suite: 0x1301,
                        extensions: vec![0x002B],
                        compression_method: 0,
                        alpn: Some("h2".into()),
                        ja4s: Some("t1302_1301_abcdef012345".into()),
                        sni: Some("example.com".into()),
                        certificate_chain: None,
                    }),
                }],
                scan_duration: Duration::from_millis(500),
                host_status: HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(5)),
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
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("TLS: v1.3 h2 JA4S:t1302_1301_abcdef012345"));
    }

    #[test]
    fn stdout_geoip_line() {
        use rustmap_types::GeoInfo;
        let mut host = make_host([93, 184, 216, 34]);
        host.geo_info = Some(GeoInfo {
            country_code: Some("US".into()),
            country: Some("United States".into()),
            city: Some("Seattle".into()),
            latitude: None,
            longitude: None,
            timezone: None,
            asn: Some(13335),
            as_org: Some("Cloudflare, Inc.".into()),
        });
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host,
                ports: vec![Port {
                    number: 80,
                    protocol: Protocol::Tcp,
                    state: PortState::Open,
                    service: None,
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: None,
                }],
                scan_duration: Duration::from_millis(100),
                host_status: HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(5)),
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_millis(200),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(output.contains("GeoIP: Seattle, United States, AS13335 (Cloudflare, Inc.)"));
    }

    #[test]
    fn service_histogram_displayed() {
        let result = ScanResult {
            hosts: vec![
                HostScanResult {
                    host: make_host([10, 0, 0, 1]),
                    ports: vec![
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
                            number: 22,
                            protocol: Protocol::Tcp,
                            state: PortState::Open,
                            service: Some("ssh".into()),
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
                },
                HostScanResult {
                    host: make_host([10, 0, 0, 2]),
                    ports: vec![
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
                            state: PortState::Open,
                            service: Some("https".into()),
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
                },
            ],
            total_duration: Duration::from_millis(1000),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 3,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(
            output.contains("Service distribution:"),
            "should have histogram header"
        );
        assert!(
            output.contains("http(2)"),
            "http should appear with count 2"
        );
        assert!(output.contains("ssh(1)"), "ssh should appear with count 1");
        assert!(
            output.contains("https(1)"),
            "https should appear with count 1"
        );
    }

    #[test]
    fn service_histogram_empty_for_ping_only() {
        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: make_host([10, 0, 0, 1]),
                ports: vec![],
                scan_duration: Duration::ZERO,
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
            total_duration: Duration::from_millis(200),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        let output = StdoutFormatter::default().format(&result).unwrap();
        assert!(
            !output.contains("Service distribution:"),
            "ping-only should not show histogram"
        );
    }
}
