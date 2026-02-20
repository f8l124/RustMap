use rustmap_types::{DetectionMethod, HostStatus, PortState, ScanResult, ScanType, ScriptResult, ScriptValue};
use std::fmt::Write;

use crate::traits::{OutputError, OutputFormatter};

pub struct XmlFormatter;

impl OutputFormatter for XmlFormatter {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError> {
        let mut out = String::new();

        // XML declaration
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

        // <nmaprun> root element
        let args = result
            .command_args
            .as_deref()
            .unwrap_or("rustmap");
        let (start_unix, start_str) = format_start_time(result);
        writeln!(
            out,
            "<nmaprun scanner=\"rustmap\" args=\"{}\" start=\"{}\" startstr=\"{}\" version=\"0.1.0\" xmloutputversion=\"1.05\">",
            xml_escape(args),
            start_unix,
            xml_escape(&start_str),
        )
        .unwrap();

        // <scaninfo> — emit one per protocol present in results
        let has_tcp = result.hosts.iter().any(|h| {
            h.ports
                .iter()
                .any(|p| p.protocol == rustmap_types::Protocol::Tcp)
        });
        let has_udp = result.hosts.iter().any(|h| {
            h.ports
                .iter()
                .any(|p| p.protocol == rustmap_types::Protocol::Udp)
        });

        if has_tcp || !has_udp {
            // Default to TCP scaninfo if no ports at all
            let scan_type_str = result.scan_type.to_string();
            let services_str = build_services_string(result);
            writeln!(
                out,
                "<scaninfo type=\"{}\" protocol=\"tcp\" numservices=\"{}\" services=\"{}\"/>",
                xml_escape(&scan_type_str),
                result.num_services,
                xml_escape(&services_str),
            )
            .unwrap();
        }
        if has_udp {
            let services_str = build_services_string(result);
            writeln!(
                out,
                "<scaninfo type=\"udp\" protocol=\"udp\" numservices=\"{}\" services=\"{}\"/>",
                result.num_services,
                xml_escape(&services_str),
            )
            .unwrap();
        }
        let has_sctp = result.hosts.iter().any(|h| {
            h.ports
                .iter()
                .any(|p| p.protocol == rustmap_types::Protocol::Sctp)
        });
        if has_sctp {
            let services_str = build_services_string(result);
            writeln!(
                out,
                "<scaninfo type=\"sctp-init\" protocol=\"sctp\" numservices=\"{}\" services=\"{}\"/>",
                result.num_services,
                xml_escape(&services_str),
            )
            .unwrap();
        }

        // Pre-script results
        if !result.pre_script_results.is_empty() {
            out.push_str("<prescript>\n");
            for sr in &result.pre_script_results {
                format_script_xml(&mut out, sr);
            }
            out.push_str("</prescript>\n");
        }

        // Hosts
        for host_result in &result.hosts {
            out.push_str("<host");
            if let Some(ref start) = result.start_time
                && let Ok(d) = start.duration_since(std::time::UNIX_EPOCH)
            {
                write!(out, " starttime=\"{}\"", d.as_secs()).unwrap();
                let end = d.as_secs() + host_result.scan_duration.as_secs();
                write!(out, " endtime=\"{}\"", end).unwrap();
            }
            out.push_str(">\n");

            // <status>
            let host_state = host_result.host_status.to_string();
            let host_reason = match host_result.host_status {
                HostStatus::Up => {
                    if host_result.discovery_latency.is_some() {
                        "syn-ack"
                    } else {
                        "user-set"
                    }
                }
                HostStatus::Down => "no-response",
                HostStatus::Unknown => "user-set",
            };
            writeln!(
                out,
                "<status state=\"{}\" reason=\"{}\"/>",
                xml_escape(&host_state),
                host_reason,
            )
            .unwrap();

            // <address>
            let addr = host_result.host.ip.to_string();
            let addrtype = if host_result.host.ip.is_ipv4() {
                "ipv4"
            } else {
                "ipv6"
            };
            writeln!(
                out,
                "<address addr=\"{}\" addrtype=\"{}\"/>",
                xml_escape(&addr),
                addrtype,
            )
            .unwrap();

            // <hostname> if available
            if let Some(ref hostname) = host_result.host.hostname {
                writeln!(
                    out,
                    "<hostnames><hostname name=\"{}\" type=\"user\"/></hostnames>",
                    xml_escape(hostname),
                )
                .unwrap();
            }

            // <geoip> if available
            if let Some(ref geo) = host_result.host.geo_info {
                let mut attrs = Vec::new();
                if let Some(ref cc) = geo.country_code {
                    attrs.push(format!("country_code=\"{}\"", xml_escape(cc)));
                }
                if let Some(ref country) = geo.country {
                    attrs.push(format!("country=\"{}\"", xml_escape(country)));
                }
                if let Some(ref city) = geo.city {
                    attrs.push(format!("city=\"{}\"", xml_escape(city)));
                }
                if let Some(lat) = geo.latitude {
                    attrs.push(format!("latitude=\"{lat}\""));
                }
                if let Some(lon) = geo.longitude {
                    attrs.push(format!("longitude=\"{lon}\""));
                }
                if let Some(asn) = geo.asn {
                    attrs.push(format!("asn=\"{asn}\""));
                }
                if let Some(ref org) = geo.as_org {
                    attrs.push(format!("as_org=\"{}\"", xml_escape(org)));
                }
                if !attrs.is_empty() {
                    writeln!(out, "<geoip {}/>", attrs.join(" ")).unwrap();
                }
            }

            // <ports>
            if !host_result.ports.is_empty() {
                out.push_str("<ports>\n");

                // <extraports> for closed/filtered ports when there are many
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

                if closed_count > 10 {
                    let reason = match result.scan_type {
                        ScanType::TcpSyn => "resets",
                        ScanType::TcpConnect => "conn-refused",
                        _ => "resets",
                    };
                    writeln!(
                        out,
                        "<extraports state=\"closed\" count=\"{}\">",
                        closed_count,
                    )
                    .unwrap();
                    writeln!(
                        out,
                        "<extrareasons reason=\"{}\" count=\"{}\"/>",
                        reason, closed_count,
                    )
                    .unwrap();
                    out.push_str("</extraports>\n");
                }

                if filtered_count > 10 {
                    writeln!(
                        out,
                        "<extraports state=\"filtered\" count=\"{}\">",
                        filtered_count,
                    )
                    .unwrap();
                    writeln!(
                        out,
                        "<extrareasons reason=\"no-response\" count=\"{}\"/>",
                        filtered_count,
                    )
                    .unwrap();
                    out.push_str("</extraports>\n");
                }

                // Individual port entries (skip closed if summarized)
                for port in &host_result.ports {
                    if closed_count > 10 && port.state == PortState::Closed {
                        continue;
                    }
                    if filtered_count > 10 && port.state == PortState::Filtered {
                        continue;
                    }

                    writeln!(
                        out,
                        "<port protocol=\"{}\" portid=\"{}\">",
                        port.protocol, port.number,
                    )
                    .unwrap();

                    let reason = port.reason.as_deref().unwrap_or_else(|| {
                        derive_reason(result.scan_type, port.state)
                    });
                    writeln!(
                        out,
                        "<state state=\"{}\" reason=\"{}\"/>",
                        port.state,
                        xml_escape(reason),
                    )
                    .unwrap();

                    // <service> element
                    if let Some(ref si) = port.service_info {
                        let conf = confidence_for_method(si.method);
                        let mut attrs = format!(
                            "name=\"{}\" method=\"{}\" conf=\"{}\"",
                            xml_escape(&si.name),
                            si.method,
                            conf,
                        );
                        if let Some(ref product) = si.product {
                            write!(attrs, " product=\"{}\"", xml_escape(product)).unwrap();
                        }
                        if let Some(ref version) = si.version {
                            write!(attrs, " version=\"{}\"", xml_escape(version)).unwrap();
                        }
                        if let Some(ref info) = si.info {
                            write!(attrs, " extrainfo=\"{}\"", xml_escape(info)).unwrap();
                        }
                        writeln!(out, "<service {attrs}/>").unwrap();
                    } else if let Some(ref name) = port.service {
                        writeln!(
                            out,
                            "<service name=\"{}\" method=\"table\" conf=\"3\"/>",
                            xml_escape(name),
                        )
                        .unwrap();
                    }

                    // TLS info
                    if let Some(ref tls) = port.tls_info {
                        let ver = match tls.tls_version {
                            0x0304 => "1.3",
                            0x0303 => "1.2",
                            0x0302 => "1.1",
                            0x0301 => "1.0",
                            _ => "unknown",
                        };
                        let mut attrs = format!(
                            "version=\"{}\" cipher=\"{:04x}\"",
                            ver, tls.cipher_suite,
                        );
                        if let Some(ref alpn) = tls.alpn {
                            write!(attrs, " alpn=\"{}\"", xml_escape(alpn)).unwrap();
                        }
                        if let Some(ref ja4s) = tls.ja4s {
                            write!(attrs, " ja4s=\"{}\"", xml_escape(ja4s)).unwrap();
                        }
                        if let Some(ref sni) = tls.sni {
                            write!(attrs, " sni=\"{}\"", xml_escape(sni)).unwrap();
                        }
                        if let Some(ref chain) = tls.certificate_chain {
                            writeln!(out, "<tls {attrs}>").unwrap();
                            for cert in chain {
                                let subj = cert.subject_cn.as_deref().unwrap_or("");
                                let iss = cert.issuer_cn.as_deref().unwrap_or("");
                                let exp = cert.not_after.as_deref().unwrap_or("");
                                let pos = cert.chain_position;
                                let ss = if cert.self_signed { " self-signed=\"true\"" } else { "" };
                                writeln!(
                                    out,
                                    "<certificate subject=\"{}\" issuer=\"{}\" expires=\"{}\" position=\"{}\"{ss}/>",
                                    xml_escape(subj),
                                    xml_escape(iss),
                                    xml_escape(exp),
                                    pos,
                                ).unwrap();
                            }
                            out.push_str("</tls>\n");
                        } else {
                            writeln!(out, "<tls {attrs}/>").unwrap();
                        }
                    }

                    // Script results for this port
                    for sr in &port.script_results {
                        format_script_xml(&mut out, sr);
                    }

                    out.push_str("</port>\n");
                }

                out.push_str("</ports>\n");
            }

            // Host script results
            if !host_result.host_script_results.is_empty() {
                out.push_str("<hostscript>\n");
                for sr in &host_result.host_script_results {
                    format_script_xml(&mut out, sr);
                }
                out.push_str("</hostscript>\n");
            }

            // <os> section
            if let Some(ref os_fp) = host_result.os_fingerprint
                && let Some(ref family) = os_fp.os_family
            {
                out.push_str("<os>\n");
                let accuracy = os_fp.accuracy.unwrap_or(0);
                let name = match &os_fp.os_generation {
                    Some(generation) => format!("{family} {generation}"),
                    None => family.clone(),
                };
                writeln!(
                    out,
                    "<osmatch name=\"{}\" accuracy=\"{}\">",
                    xml_escape(&name),
                    accuracy,
                )
                .unwrap();

                let osgen = os_fp
                    .os_generation
                    .as_deref()
                    .unwrap_or("");
                writeln!(
                    out,
                    "<osclass osfamily=\"{}\" osgen=\"{}\" accuracy=\"{}\"/>",
                    xml_escape(family),
                    xml_escape(osgen),
                    accuracy,
                )
                .unwrap();

                out.push_str("</osmatch>\n");
                out.push_str("</os>\n");
            }

            // Uptime estimate
            if let Some(ref uptime) = host_result.uptime_estimate {
                writeln!(out, "<uptime seconds=\"{}\"/>", uptime.as_secs()).unwrap();
            }

            // Path MTU
            if let Some(mtu) = host_result.mtu {
                writeln!(out, "<mtu value=\"{mtu}\"/>").unwrap();
            }

            // Risk score
            if let Some(risk) = host_result.risk_score {
                let sev = if risk >= 9.0 { "critical" } else if risk >= 7.0 { "high" } else if risk >= 4.0 { "medium" } else { "low" };
                writeln!(out, "<risk score=\"{risk:.1}\" severity=\"{sev}\"/>").unwrap();
            }

            // Traceroute
            if let Some(ref tr) = host_result.traceroute {
                writeln!(
                    out,
                    "<trace port=\"{}\" proto=\"{}\">",
                    tr.port, tr.protocol
                )
                .unwrap();
                for hop in &tr.hops {
                    if let Some(ip) = hop.ip {
                        let rtt = hop
                            .rtt
                            .map(|d| format!("{:.2}", d.as_secs_f64() * 1000.0))
                            .unwrap_or_default();
                        writeln!(
                            out,
                            "<hop ttl=\"{}\" rtt=\"{}\" ipaddr=\"{}\"/>",
                            hop.ttl, rtt, ip
                        )
                        .unwrap();
                    }
                    // Skip hops with no response (*)
                }
                out.push_str("</trace>\n");
            }

            out.push_str("</host>\n");
        }

        // Post-script results
        if !result.post_script_results.is_empty() {
            out.push_str("<postscript>\n");
            for sr in &result.post_script_results {
                format_script_xml(&mut out, sr);
            }
            out.push_str("</postscript>\n");
        }

        // <services> histogram
        {
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
                out.push_str("<services>\n");
                for (svc, count) in &sorted {
                    writeln!(out, "<service name=\"{}\" count=\"{}\"/>", xml_escape(svc), count)
                        .unwrap();
                }
                out.push_str("</services>\n");
            }
        }

        // <runstats>
        let up_count = result
            .hosts
            .iter()
            .filter(|h| h.host_status == HostStatus::Up)
            .count();
        let down_count = result
            .hosts
            .iter()
            .filter(|h| h.host_status == HostStatus::Down)
            .count();
        let total = result.hosts.len();
        let elapsed = result.total_duration.as_secs_f64();

        out.push_str("<runstats>\n");

        let finish_time = if let Some(ref start) = result.start_time {
            if let Ok(d) = start.duration_since(std::time::UNIX_EPOCH) {
                d.as_secs() + result.total_duration.as_secs()
            } else {
                0
            }
        } else {
            0
        };
        writeln!(
            out,
            "<finished time=\"{}\" elapsed=\"{:.2}\" exit=\"success\"/>",
            finish_time, elapsed,
        )
        .unwrap();
        writeln!(
            out,
            "<hosts up=\"{}\" down=\"{}\" total=\"{}\"/>",
            up_count, down_count, total,
        )
        .unwrap();
        out.push_str("</runstats>\n");

        out.push_str("</nmaprun>\n");

        Ok(out)
    }
}

/// Escape XML special characters.
fn xml_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {} // strip invalid XML controls
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Derive a reason string from scan type and port state.
fn derive_reason(scan_type: ScanType, state: PortState) -> &'static str {
    match (scan_type, state) {
        (ScanType::TcpSyn, PortState::Open) => "syn-ack",
        (ScanType::TcpSyn, PortState::Closed) => "rst",
        (ScanType::TcpConnect, PortState::Open) => "syn-ack",
        (ScanType::TcpConnect, PortState::Closed) => "conn-refused",
        // FIN/NULL/Xmas/Maimon scans
        (ScanType::TcpFin | ScanType::TcpNull | ScanType::TcpXmas | ScanType::TcpMaimon,
         PortState::Closed) => "rst",
        (ScanType::TcpFin | ScanType::TcpNull | ScanType::TcpXmas | ScanType::TcpMaimon,
         PortState::OpenFiltered) => "no-response",
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

/// Map detection method to nmap confidence level (0-10).
fn confidence_for_method(method: DetectionMethod) -> u8 {
    match method {
        DetectionMethod::Probe => 10,
        DetectionMethod::TlsProbe => 9,
        DetectionMethod::Banner => 8,
        DetectionMethod::PortBased => 3,
        DetectionMethod::None => 0,
    }
}

/// Format start time as (unix_timestamp, human-readable string).
fn format_start_time(result: &ScanResult) -> (u64, String) {
    if let Some(ref start) = result.start_time
        && let Ok(d) = start.duration_since(std::time::UNIX_EPOCH)
    {
        let secs = d.as_secs();
        return (secs, format_unix_timestamp(secs));
    }
    (0, "N/A".to_string())
}

/// Format a Unix timestamp into a human-readable UTC string.
/// Avoids adding a chrono dependency by doing manual calculation.
fn format_unix_timestamp(secs: u64) -> String {
    // Simple UTC date-time formatting without chrono
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year/month/day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days);

    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day_names = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]; // 1970-01-01 was Thursday
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

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u32, u32) {
    // Algorithm: iterate years and months
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

/// Build a comma-separated string of port numbers scanned.
fn build_services_string(result: &ScanResult) -> String {
    let mut ports: Vec<u16> = result
        .hosts
        .iter()
        .flat_map(|h| h.ports.iter().map(|p| p.number))
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Format a single script result as an XML element.
fn format_script_xml(out: &mut String, sr: &ScriptResult) {
    write!(
        out,
        "<script id=\"{}\" output=\"{}\"",
        xml_escape(&sr.id),
        xml_escape(&sr.output),
    )
    .unwrap();

    if let Some(ref elements) = sr.elements {
        out.push_str(">\n");
        format_script_value_xml(out, elements, None);
        out.push_str("</script>\n");
    } else {
        out.push_str("/>\n");
    }
}

/// Render a ScriptValue as XML elements.
fn format_script_value_xml(out: &mut String, value: &ScriptValue, key: Option<&str>) {
    match value {
        ScriptValue::String(s) => {
            if let Some(k) = key {
                writeln!(out, "<elem key=\"{}\">{}</elem>", xml_escape(k), xml_escape(s)).unwrap();
            } else {
                writeln!(out, "<elem>{}</elem>", xml_escape(s)).unwrap();
            }
        }
        ScriptValue::Number(n) => {
            let s = n.to_string();
            if let Some(k) = key {
                writeln!(out, "<elem key=\"{}\">{}</elem>", xml_escape(k), s).unwrap();
            } else {
                writeln!(out, "<elem>{}</elem>", s).unwrap();
            }
        }
        ScriptValue::Bool(b) => {
            let s = b.to_string();
            if let Some(k) = key {
                writeln!(out, "<elem key=\"{}\">{}</elem>", xml_escape(k), s).unwrap();
            } else {
                writeln!(out, "<elem>{}</elem>", s).unwrap();
            }
        }
        ScriptValue::List(items) => {
            if let Some(k) = key {
                writeln!(out, "<table key=\"{}\">", xml_escape(k)).unwrap();
            } else {
                out.push_str("<table>\n");
            }
            for item in items {
                format_script_value_xml(out, item, None);
            }
            out.push_str("</table>\n");
        }
        ScriptValue::Map(entries) => {
            if let Some(k) = key {
                writeln!(out, "<table key=\"{}\">", xml_escape(k)).unwrap();
                for (ek, ev) in entries {
                    format_script_value_xml(out, ev, Some(ek));
                }
                out.push_str("</table>\n");
            } else {
                for (ek, ev) in entries {
                    format_script_value_xml(out, ev, Some(ek));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{
        DetectionMethod, Host, HostScanResult, HostStatus, OsFingerprint, OsProbeResults, Port,
        PortState, Protocol, ScanType, ScriptResult, ScriptValue, ServiceInfo,
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
            total_duration: Duration::from_millis(1000),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn xml_well_formed_structure() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([192, 168, 1, 1]),
            ports: vec![make_port(80, PortState::Open)],
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
        }]);

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(output.contains("<nmaprun "));
        assert!(output.contains("</nmaprun>"));
        assert!(output.contains("<scaninfo "));
        assert!(output.contains("<host"));
        assert!(output.contains("</host>"));
        assert!(output.contains("<runstats>"));
        assert!(output.contains("</runstats>"));
    }

    #[test]
    fn xml_escape_special_chars() {
        assert_eq!(xml_escape("hello"), "hello");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(xml_escape("it's"), "it&apos;s");
        assert_eq!(
            xml_escape("a & b < c > d \"e\" f'g"),
            "a &amp; b &lt; c &gt; d &quot;e&quot; f&apos;g"
        );
    }

    #[test]
    fn xml_port_entries() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<port protocol=\"tcp\" portid=\"22\">"));
        assert!(output.contains("<port protocol=\"tcp\" portid=\"80\">"));
        assert!(output.contains("<state state=\"open\" reason=\"syn-ack\"/>"));
        assert!(output.contains("<service name=\"ssh\" method=\"table\" conf=\"3\"/>"));
        assert!(output.contains("<service name=\"http\" method=\"table\" conf=\"3\"/>"));
    }

    #[test]
    fn xml_service_info() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([192, 168, 1, 1]),
            ports: vec![Port {
                number: 22,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("ssh".into()),
                service_info: Some(ServiceInfo {
                    name: "ssh".into(),
                    product: Some("OpenSSH".into()),
                    version: Some("8.9p1".into()),
                    info: Some("Ubuntu Linux; protocol 2.0".into()),
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("name=\"ssh\""));
        assert!(output.contains("method=\"probe\""));
        assert!(output.contains("conf=\"10\""));
        assert!(output.contains("product=\"OpenSSH\""));
        assert!(output.contains("version=\"8.9p1\""));
        assert!(output.contains("extrainfo=\"Ubuntu Linux; protocol 2.0\""));
    }

    #[test]
    fn xml_os_detection() {
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<os>"));
        assert!(output.contains("</os>"));
        assert!(output.contains("<osmatch name=\"Linux 5.x\" accuracy=\"92\">"));
        assert!(output.contains("<osclass osfamily=\"Linux\" osgen=\"5.x\" accuracy=\"92\"/>"));
        assert!(output.contains("</osmatch>"));
    }

    #[test]
    fn xml_extraports_for_many_closed() {
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<extraports state=\"closed\" count=\"15\">"));
        assert!(output.contains("<extrareasons reason=\"resets\" count=\"15\"/>"));
        assert!(output.contains("</extraports>"));
        // Open port should still appear
        assert!(output.contains("<port protocol=\"tcp\" portid=\"80\">"));
        // Closed ports should NOT appear as individual entries
        assert!(!output.contains("portid=\"1\""));
    }

    #[test]
    fn xml_runstats() {
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<hosts up=\"1\" down=\"1\" total=\"2\"/>"));
        assert!(output.contains("exit=\"success\""));
    }

    #[test]
    fn xml_host_down() {
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<status state=\"down\" reason=\"no-response\"/>"));
        // Should NOT have ports section
        assert!(!output.contains("<ports>"));
    }

    #[test]
    fn xml_empty_scan() {
        let result = make_scan_result(vec![]);

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.starts_with("<?xml"));
        assert!(output.contains("<nmaprun "));
        assert!(output.contains("</nmaprun>"));
        assert!(output.contains("<hosts up=\"0\" down=\"0\" total=\"0\"/>"));
    }

    #[test]
    fn xml_hostname() {
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<hostnames><hostname name=\"example.com\" type=\"user\"/></hostnames>"));
    }

    #[test]
    fn xml_command_args_escaped() {
        let mut result = make_scan_result(vec![]);
        result.command_args = Some("rustmap -p 80 \"target\" & more".into());

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("args=\"rustmap -p 80 &quot;target&quot; &amp; more\""));
    }

    #[test]
    fn xml_explicit_reason_used() {
        let result = make_scan_result(vec![HostScanResult {
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
        }]);

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("reason=\"custom-reason\""));
    }

    #[test]
    fn xml_ipv6_address() {
        let result = make_scan_result(vec![HostScanResult {
            host: Host {
                ip: IpAddr::V6("::1".parse().unwrap()),
                hostname: None,
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("addrtype=\"ipv6\""));
        assert!(output.contains("addr=\"::1\""));
    }

    #[test]
    fn xml_confidence_mapping() {
        assert_eq!(confidence_for_method(DetectionMethod::Probe), 10);
        assert_eq!(confidence_for_method(DetectionMethod::TlsProbe), 9);
        assert_eq!(confidence_for_method(DetectionMethod::Banner), 8);
        assert_eq!(confidence_for_method(DetectionMethod::PortBased), 3);
        assert_eq!(confidence_for_method(DetectionMethod::None), 0);
    }

    #[test]
    fn xml_tls_element() {
        use rustmap_types::TlsServerFingerprint;
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<tls "));
        assert!(output.contains("version=\"1.3\""));
        assert!(output.contains("cipher=\"1301\""));
        assert!(output.contains("alpn=\"h2\""));
        assert!(output.contains("ja4s=\"t1302_1301_abcdef012345\""));
        assert!(output.contains("sni=\"example.com\""));
    }

    #[test]
    fn unix_timestamp_formatting() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let s = format_unix_timestamp(1704067200);
        assert!(s.contains("2024"), "Expected 2024 in '{s}'");
        assert!(s.contains("Jan"), "Expected Jan in '{s}'");
        assert!(s.contains("00:00:00"), "Expected 00:00:00 in '{s}'");
    }

    #[test]
    fn days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2024-01-01 is day 19723 since epoch
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn xml_port_script_results() {
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<script id=\"http-title\" output=\"Title: Welcome\"/>"));
    }

    #[test]
    fn xml_script_with_elements() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
            ports: vec![Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: None,
                service_info: None,
                reason: None,
                script_results: vec![ScriptResult {
                    id: "http-title".into(),
                    output: "Title: Example".into(),
                    elements: Some(ScriptValue::Map(vec![
                        ("title".into(), ScriptValue::String("Example".into())),
                    ])),
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<script id=\"http-title\" output=\"Title: Example\">"));
        assert!(output.contains("<elem key=\"title\">Example</elem>"));
        assert!(output.contains("</script>"));
    }

    #[test]
    fn xml_hostscript_element() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([192, 168, 1, 1]),
            ports: vec![make_port(80, PortState::Open)],
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
        }]);

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<hostscript>"));
        assert!(output.contains("<script id=\"smb-os-discovery\" output=\"Windows 10\"/>"));
        assert!(output.contains("</hostscript>"));
    }

    #[test]
    fn xml_prescript_postscript() {
        let mut result = make_scan_result(vec![]);
        result.pre_script_results = vec![ScriptResult {
            id: "broadcast-ping".into(),
            output: "Found hosts".into(),
            elements: None,
        }];
        result.post_script_results = vec![ScriptResult {
            id: "summary".into(),
            output: "Done".into(),
            elements: None,
        }];

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<prescript>"));
        assert!(output.contains("<script id=\"broadcast-ping\" output=\"Found hosts\"/>"));
        assert!(output.contains("</prescript>"));
        assert!(output.contains("<postscript>"));
        assert!(output.contains("<script id=\"summary\" output=\"Done\"/>"));
        assert!(output.contains("</postscript>"));
    }

    #[test]
    fn xml_script_output_escaped() {
        let result = make_scan_result(vec![HostScanResult {
            host: make_host([10, 0, 0, 1]),
            ports: vec![Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: None,
                service_info: None,
                reason: None,
                script_results: vec![ScriptResult {
                    id: "test".into(),
                    output: "a <b> & \"c\"".into(),
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("output=\"a &lt;b&gt; &amp; &quot;c&quot;\""));
    }

    #[test]
    fn xml_geoip_element() {
        use rustmap_types::GeoInfo;
        let result = make_scan_result(vec![HostScanResult {
            host: Host {
                ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                hostname: None,
                geo_info: Some(GeoInfo {
                    country_code: Some("US".into()),
                    country: Some("United States".into()),
                    city: Some("Seattle".into()),
                    latitude: Some(47.6),
                    longitude: Some(-122.3),
                    timezone: None,
                    asn: Some(13335),
                    as_org: Some("Cloudflare, Inc.".into()),
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

        let output = XmlFormatter.format(&result).unwrap();
        assert!(output.contains("<geoip "));
        assert!(output.contains("country_code=\"US\""));
        assert!(output.contains("city=\"Seattle\""));
        assert!(output.contains("asn=\"13335\""));
    }
}
