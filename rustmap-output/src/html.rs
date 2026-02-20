use std::fmt::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustmap_types::{HostStatus, PortState, ScanResult};

use crate::traits::{OutputError, OutputFormatter};

/// Self-contained HTML report with inline CSS/JS, sortable tables, and
/// collapsible host sections.
pub struct HtmlFormatter;

impl OutputFormatter for HtmlFormatter {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError> {
        let mut out = String::with_capacity(32_768);
        write_html_report(&mut out, result)
            .map_err(|e| OutputError::FormatError(e.to_string()))?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn port_state_class(state: PortState) -> &'static str {
    match state {
        PortState::Open => "state-open",
        PortState::Closed => "state-closed",
        PortState::Filtered => "state-filtered",
        PortState::Unfiltered => "state-unfiltered",
        PortState::OpenFiltered => "state-filtered",
        PortState::ClosedFiltered => "state-closed",
    }
}

fn risk_class(score: f64) -> &'static str {
    if score >= 8.0 {
        "risk-critical"
    } else if score >= 6.0 {
        "risk-high"
    } else if score >= 4.0 {
        "risk-medium"
    } else {
        "risk-low"
    }
}

fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

fn format_timestamp(t: SystemTime) -> String {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs();
            // Simple UTC ISO-8601 without pulling in chrono
            let days = secs / 86400;
            let time_secs = secs % 86400;
            let h = time_secs / 3600;
            let m = (time_secs % 3600) / 60;
            let s = time_secs % 60;
            // Days since 1970-01-01 → Y/M/D (simplified calendar)
            let (y, mo, da) = days_to_ymd(days);
            format!("{y:04}-{mo:02}-{da:02}T{h:02}:{m:02}:{s:02}Z")
        }
        Err(_) => "unknown".into(),
    }
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Adapted from Howard Hinnant's algorithm
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// report builder
// ---------------------------------------------------------------------------

fn write_html_report(out: &mut String, result: &ScanResult) -> std::fmt::Result {
    // Precompute stats
    let total_hosts = result.hosts.len();
    let up_hosts = result
        .hosts
        .iter()
        .filter(|h| h.host_status == HostStatus::Up)
        .count();
    let total_open: usize = result
        .hosts
        .iter()
        .flat_map(|h| &h.ports)
        .filter(|p| p.state == PortState::Open)
        .count();

    // Service distribution: count occurrences
    let mut svc_counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for host in &result.hosts {
        for port in &host.ports {
            if port.state == PortState::Open {
                let svc = port.service.as_deref().unwrap_or("unknown");
                *svc_counts.entry(svc).or_default() += 1;
            }
        }
    }
    let max_svc_count = svc_counts.values().copied().max().unwrap_or(1).max(1);

    // --- HTML head ---
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
    out.push_str("<title>RustMap Scan Report</title>\n");
    write_css(out)?;
    out.push_str("</head>\n<body>\n");

    // --- Header ---
    out.push_str("<header><h1>RustMap Scan Report</h1></header>\n");

    // --- Summary cards ---
    out.push_str("<section class=\"summary\">\n");
    writeln!(
        out,
        "<div class=\"card\"><span class=\"card-val\">{up_hosts}</span><span class=\"card-lbl\">Hosts Up</span></div>"
    )?;
    writeln!(
        out,
        "<div class=\"card\"><span class=\"card-val\">{total_hosts}</span><span class=\"card-lbl\">Total Hosts</span></div>"
    )?;
    writeln!(
        out,
        "<div class=\"card\"><span class=\"card-val\">{total_open}</span><span class=\"card-lbl\">Open Ports</span></div>"
    )?;
    writeln!(
        out,
        "<div class=\"card\"><span class=\"card-val\">{}</span><span class=\"card-lbl\">Services</span></div>",
        result.num_services,
    )?;
    out.push_str("</section>\n");

    // --- Scan metadata ---
    out.push_str("<section class=\"meta\">\n<table class=\"meta-tbl\">\n");
    writeln!(out, "<tr><td>Scan Type</td><td>{}</td></tr>", result.scan_type)?;
    writeln!(
        out,
        "<tr><td>Duration</td><td>{}</td></tr>",
        format_duration(result.total_duration),
    )?;
    if let Some(start) = result.start_time {
        writeln!(
            out,
            "<tr><td>Start Time</td><td>{}</td></tr>",
            format_timestamp(start),
        )?;
    }
    if let Some(ref cmd) = result.command_args {
        writeln!(
            out,
            "<tr><td>Command</td><td><code>{}</code></td></tr>",
            html_escape(cmd),
        )?;
    }
    out.push_str("</table>\n</section>\n");

    // --- Service distribution ---
    if !svc_counts.is_empty() {
        out.push_str("<section class=\"svc-dist\">\n<h2>Service Distribution</h2>\n");
        for (svc, count) in &svc_counts {
            let pct = (*count as f64 / max_svc_count as f64) * 100.0;
            writeln!(
                out,
                "<div class=\"bar-row\"><span class=\"bar-lbl\">{}</span>\
                 <div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{pct:.0}%\"></div></div>\
                 <span class=\"bar-val\">{count}</span></div>",
                html_escape(svc),
            )?;
        }
        out.push_str("</section>\n");
    }

    // --- Risk overview ---
    let hosts_with_risk: Vec<_> = result
        .hosts
        .iter()
        .filter_map(|h| h.risk_score.map(|r| (h, r)))
        .collect();
    if !hosts_with_risk.is_empty() {
        out.push_str("<section class=\"risk-overview\">\n<h2>Risk Overview</h2>\n");
        out.push_str("<table class=\"data-tbl sortable\"><thead><tr>");
        out.push_str("<th>Host</th><th>Risk Score</th></tr></thead>\n<tbody>\n");
        for (host, risk) in &hosts_with_risk {
            writeln!(
                out,
                "<tr><td>{}</td><td><span class=\"badge {}\">{risk:.1}</span></td></tr>",
                host.host.ip,
                risk_class(*risk),
            )?;
        }
        out.push_str("</tbody></table>\n</section>\n");
    }

    // --- Expand/collapse controls ---
    out.push_str("<div class=\"controls\">\n");
    out.push_str("<button onclick=\"document.querySelectorAll('details.host').forEach(d=>d.open=true)\">Expand All</button>\n");
    out.push_str("<button onclick=\"document.querySelectorAll('details.host').forEach(d=>d.open=false)\">Collapse All</button>\n");
    out.push_str("</div>\n");

    // --- Per-host sections ---
    for host_result in &result.hosts {
        let ip = &host_result.host.ip;
        let hn = host_result
            .host
            .hostname
            .as_deref()
            .unwrap_or("");

        let open_attr = if host_result.host_status == HostStatus::Up {
            " open"
        } else {
            ""
        };

        write!(
            out,
            "<details class=\"host\"{open_attr}>\n<summary>{ip}",
        )?;
        if !hn.is_empty() {
            write!(out, " <span class=\"hostname\">({})</span>", html_escape(hn))?;
        }
        write!(
            out,
            " &mdash; <span class=\"status-{}\">{}</span>",
            match host_result.host_status {
                HostStatus::Up => "up",
                HostStatus::Down => "down",
                HostStatus::Unknown => "unknown",
            },
            host_result.host_status,
        )?;
        out.push_str("</summary>\n<div class=\"host-body\">\n");

        // Host info row
        out.push_str("<div class=\"host-info\">\n");
        if let Some(ref os) = host_result.os_fingerprint
            && let Some(ref fam) = os.os_family
        {
            write!(out, "<span class=\"tag\">OS: {}", html_escape(fam))?;
            if let Some(ref generation) = os.os_generation {
                write!(out, " {}", html_escape(generation))?;
            }
            if let Some(acc) = os.accuracy {
                write!(out, " ({acc}%)")?;
            }
            out.push_str("</span>\n");
        }
        if let Some(lat) = host_result.discovery_latency {
            writeln!(out, "<span class=\"tag\">Latency: {}</span>", format_duration(lat))?;
        }
        if let Some(mtu) = host_result.mtu {
            writeln!(out, "<span class=\"tag\">MTU: {mtu}</span>")?;
        }
        if let Some(ref uptime) = host_result.uptime_estimate {
            let hrs = uptime.as_secs() / 3600;
            writeln!(out, "<span class=\"tag\">Uptime: ~{hrs}h</span>")?;
        }
        if let Some(risk) = host_result.risk_score {
            writeln!(
                out,
                "<span class=\"badge {}\">Risk: {risk:.1}</span>",
                risk_class(risk),
            )?;
        }
        out.push_str("</div>\n");

        // Port table
        if !host_result.ports.is_empty() {
            out.push_str("<table class=\"data-tbl sortable\">\n<thead><tr>");
            out.push_str("<th>Port</th><th>Proto</th><th>State</th><th>Service</th>");
            out.push_str("<th>Product / Version</th><th>Reason</th><th>TLS</th>");
            out.push_str("</tr></thead>\n<tbody>\n");
            for port in &host_result.ports {
                write!(
                    out,
                    "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td>",
                    port.number,
                    port.protocol,
                    port_state_class(port.state),
                    port.state,
                )?;
                // Service
                write!(
                    out,
                    "<td>{}</td>",
                    html_escape(port.service.as_deref().unwrap_or("")),
                )?;
                // Product / Version
                let prod_ver = match &port.service_info {
                    Some(si) => {
                        let mut pv = String::new();
                        if let Some(ref p) = si.product {
                            pv.push_str(p);
                        }
                        if let Some(ref v) = si.version {
                            if !pv.is_empty() {
                                pv.push(' ');
                            }
                            pv.push_str(v);
                        }
                        if let Some(ref info) = si.info {
                            if !pv.is_empty() {
                                pv.push_str(" - ");
                            }
                            pv.push_str(info);
                        }
                        pv
                    }
                    None => String::new(),
                };
                write!(out, "<td>{}</td>", html_escape(&prod_ver))?;
                // Reason
                write!(
                    out,
                    "<td>{}</td>",
                    html_escape(port.reason.as_deref().unwrap_or("")),
                )?;
                // TLS
                let tls_str = match &port.tls_info {
                    Some(tls) => {
                        let ver = match tls.tls_version {
                            0x0304 => "TLS 1.3",
                            0x0303 => "TLS 1.2",
                            0x0302 => "TLS 1.1",
                            0x0301 => "TLS 1.0",
                            _ => "TLS",
                        };
                        let mut s = html_escape(ver);
                        if let Some(ref alpn) = tls.alpn {
                            write!(s, " ({})", html_escape(alpn)).unwrap();
                        }
                        if let Some(ref chain) = tls.certificate_chain {
                            if let Some(leaf) = chain.first() {
                                if let Some(ref cn) = leaf.subject_cn {
                                    write!(s, "<br/>Cert: {}", html_escape(cn)).unwrap();
                                }
                                if let Some(ref iss) = leaf.issuer_cn {
                                    write!(s, " (issuer: {})", html_escape(iss)).unwrap();
                                }
                            }
                        } else if tls.tls_version >= 0x0304 {
                            s.push_str("<br/><em>certs encrypted</em>");
                        }
                        s
                    }
                    None => String::new(),
                };
                write!(out, "<td>{}</td>", tls_str)?;
                out.push_str("</tr>\n");
            }
            out.push_str("</tbody></table>\n");
        }

        // Script results
        let all_scripts: Vec<_> = host_result
            .ports
            .iter()
            .flat_map(|p| p.script_results.iter().map(move |sr| (Some(p.number), sr)))
            .chain(host_result.host_script_results.iter().map(|sr| (None, sr)))
            .collect();
        if !all_scripts.is_empty() {
            out.push_str("<details class=\"scripts\"><summary>Scripts</summary>\n");
            for (port_num, sr) in &all_scripts {
                let ctx = match port_num {
                    Some(p) => format!("port {p}"),
                    None => "host".into(),
                };
                writeln!(
                    out,
                    "<div class=\"script-block\"><strong>{} ({})</strong><pre>{}</pre></div>",
                    html_escape(&sr.id),
                    html_escape(&ctx),
                    html_escape(&sr.output),
                )?;
            }
            out.push_str("</details>\n");
        }

        // Traceroute
        if let Some(ref tr) = host_result.traceroute {
            out.push_str("<details class=\"traceroute\"><summary>Traceroute</summary>\n");
            out.push_str("<table class=\"data-tbl\"><thead><tr>");
            out.push_str("<th>TTL</th><th>IP</th><th>Hostname</th><th>RTT</th>");
            out.push_str("</tr></thead>\n<tbody>\n");
            for hop in &tr.hops {
                let rtt_str = match hop.rtt {
                    Some(d) => format_duration(d),
                    None => "*".into(),
                };
                let ip_str = hop
                    .ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "*".into());
                writeln!(
                    out,
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    hop.ttl,
                    html_escape(&ip_str),
                    html_escape(hop.hostname.as_deref().unwrap_or("")),
                    rtt_str,
                )?;
            }
            out.push_str("</tbody></table>\n</details>\n");
        }

        // Scan error
        if let Some(ref err) = host_result.scan_error {
            writeln!(
                out,
                "<div class=\"scan-error\">Error: {}</div>",
                html_escape(err),
            )?;
        }

        out.push_str("</div>\n</details>\n");
    }

    // --- Pre/post script results ---
    if !result.pre_script_results.is_empty() || !result.post_script_results.is_empty() {
        out.push_str("<section class=\"global-scripts\">\n<h2>Global Scripts</h2>\n");
        for sr in result.pre_script_results.iter().chain(&result.post_script_results) {
            writeln!(
                out,
                "<div class=\"script-block\"><strong>{}</strong><pre>{}</pre></div>",
                html_escape(&sr.id),
                html_escape(&sr.output),
            )?;
        }
        out.push_str("</section>\n");
    }

    // --- Footer ---
    out.push_str("<footer>Generated by RustMap</footer>\n");

    // --- Inline JS ---
    write_js(out)?;

    out.push_str("</body>\n</html>\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// inline CSS
// ---------------------------------------------------------------------------

fn write_css(out: &mut String) -> std::fmt::Result {
    out.push_str("<style>\n");
    out.push_str(
        ":root{--bg:#1a1a2e;--surface:#16213e;--card:#0f3460;--accent:#e94560;\
         --text:#eee;--muted:#888;--green:#4ade80;--red:#f87171;--orange:#fb923c;\
         --blue:#60a5fa}\n\
         *{margin:0;padding:0;box-sizing:border-box}\n\
         body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);padding:1rem 2rem;line-height:1.5}\n\
         header{text-align:center;padding:1.5rem 0;border-bottom:2px solid var(--accent)}\n\
         h1{font-size:1.8rem;color:var(--accent)}\n\
         h2{font-size:1.2rem;margin:1rem 0 .5rem;color:var(--blue)}\n\
         .summary{display:flex;gap:1rem;flex-wrap:wrap;margin:1.5rem 0}\n\
         .card{background:var(--card);border-radius:8px;padding:1rem 1.5rem;display:flex;flex-direction:column;align-items:center;min-width:120px}\n\
         .card-val{font-size:2rem;font-weight:700;color:var(--accent)}\n\
         .card-lbl{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}\n\
         .meta{margin:1rem 0}\n\
         .meta-tbl{border-collapse:collapse}\n\
         .meta-tbl td{padding:.3rem .8rem}\n\
         .meta-tbl td:first-child{color:var(--muted);font-weight:600}\n\
         code{background:var(--surface);padding:.15rem .4rem;border-radius:4px;font-size:.9em}\n\
         .svc-dist{margin:1rem 0}\n\
         .bar-row{display:flex;align-items:center;gap:.5rem;margin:.2rem 0}\n\
         .bar-lbl{width:100px;text-align:right;font-size:.85rem;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n\
         .bar-track{flex:1;height:18px;background:var(--surface);border-radius:4px;overflow:hidden}\n\
         .bar-fill{height:100%;background:var(--accent);border-radius:4px}\n\
         .bar-val{width:30px;font-size:.85rem;color:var(--muted)}\n\
         .data-tbl{width:100%;border-collapse:collapse;margin:.5rem 0;font-size:.9rem}\n\
         .data-tbl th,.data-tbl td{padding:.4rem .6rem;text-align:left;border-bottom:1px solid var(--surface)}\n\
         .data-tbl th{background:var(--surface);cursor:pointer;user-select:none;position:sticky;top:0}\n\
         .data-tbl th:hover{color:var(--accent)}\n\
         .data-tbl tbody tr:hover{background:rgba(233,69,96,.08)}\n\
         .state-open{color:var(--green);font-weight:600}\n\
         .state-closed{color:var(--red)}\n\
         .state-filtered{color:var(--orange)}\n\
         .state-unfiltered{color:var(--muted)}\n\
         .badge{padding:.15rem .5rem;border-radius:4px;font-size:.8rem;font-weight:600}\n\
         .risk-critical{background:#991b1b;color:#fecaca}\n\
         .risk-high{background:#9a3412;color:#fed7aa}\n\
         .risk-medium{background:#854d0e;color:#fef08a}\n\
         .risk-low{background:#166534;color:#bbf7d0}\n\
         .tag{display:inline-block;background:var(--surface);padding:.2rem .6rem;border-radius:4px;margin:.2rem;font-size:.85rem}\n\
         .host{background:var(--surface);border-radius:8px;margin:1rem 0;border:1px solid #333}\n\
         .host>summary{padding:.8rem 1rem;cursor:pointer;font-weight:600;font-size:1.05rem;list-style:none}\n\
         .host>summary::before{content:'\\25B6';margin-right:.5rem;font-size:.8rem;display:inline-block;transition:transform .2s}\n\
         .host[open]>summary::before{transform:rotate(90deg)}\n\
         .host-body{padding:0 1rem 1rem}\n\
         .host-info{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.8rem}\n\
         .hostname{color:var(--muted);font-weight:400}\n\
         .status-up{color:var(--green)}\n\
         .status-down{color:var(--red)}\n\
         .status-unknown{color:var(--muted)}\n\
         .scripts,.traceroute{margin:.5rem 0}\n\
         .scripts>summary,.traceroute>summary{cursor:pointer;color:var(--blue);font-weight:600;font-size:.95rem}\n\
         .script-block{margin:.5rem 0}\n\
         .script-block pre{background:var(--bg);padding:.5rem;border-radius:4px;overflow-x:auto;font-size:.85rem;white-space:pre-wrap}\n\
         .scan-error{color:var(--red);padding:.5rem;border:1px solid var(--red);border-radius:4px;margin:.5rem 0}\n\
         .risk-overview{margin:1rem 0}\n\
         .global-scripts{margin:1rem 0}\n\
         .controls{margin:1rem 0;display:flex;gap:.5rem}\n\
         .controls button{background:var(--card);color:var(--text);border:1px solid #555;padding:.4rem 1rem;border-radius:4px;cursor:pointer;font-size:.85rem}\n\
         .controls button:hover{border-color:var(--accent)}\n\
         footer{text-align:center;padding:1.5rem 0;color:var(--muted);font-size:.8rem;border-top:1px solid #333;margin-top:2rem}\n\
         @media(max-width:600px){body{padding:.5rem}.summary{flex-direction:column}.bar-lbl{width:60px}}\n",
    );
    out.push_str("</style>\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// inline JS — sortable tables
// ---------------------------------------------------------------------------

fn write_js(out: &mut String) -> std::fmt::Result {
    out.push_str("<script>\n");
    out.push_str(
        "document.querySelectorAll('.sortable th').forEach(th=>{\n\
         th.addEventListener('click',()=>{\n\
         const tbl=th.closest('table'),tbody=tbl.querySelector('tbody');\n\
         const idx=[...th.parentNode.children].indexOf(th);\n\
         const rows=[...tbody.querySelectorAll('tr')];\n\
         const dir=th.dataset.dir==='asc'?'desc':'asc';th.dataset.dir=dir;\n\
         rows.sort((a,b)=>{\n\
         let av=a.children[idx].textContent.trim(),bv=b.children[idx].textContent.trim();\n\
         let an=parseFloat(av),bn=parseFloat(bv);\n\
         if(!isNaN(an)&&!isNaN(bn))return dir==='asc'?an-bn:bn-an;\n\
         return dir==='asc'?av.localeCompare(bv):bv.localeCompare(av);\n\
         });rows.forEach(r=>tbody.appendChild(r));});});\n",
    );
    out.push_str("</script>\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{
        DetectionMethod, Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanType,
        ServiceInfo,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn make_result() -> ScanResult {
        ScanResult {
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
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn html_report_contains_doctype() {
        let result = make_result();
        let output = HtmlFormatter.format(&result).unwrap();
        assert!(output.starts_with("<!DOCTYPE html>"));
    }

    #[test]
    fn html_report_contains_host_ip() {
        let result = make_result();
        let output = HtmlFormatter.format(&result).unwrap();
        assert!(output.contains("192.168.1.1"));
    }

    #[test]
    fn html_report_ports_in_table() {
        let result = make_result();
        let output = HtmlFormatter.format(&result).unwrap();
        assert!(output.contains("<td>80</td>"));
        assert!(output.contains("state-open"));
    }

    #[test]
    fn html_report_escapes_special_chars() {
        let mut result = make_result();
        result.hosts[0].ports[0].service_info = Some(ServiceInfo {
            name: "http".into(),
            product: Some("<script>alert('xss')</script>".into()),
            version: None,
            info: None,
            method: DetectionMethod::Probe,
        });
        let output = HtmlFormatter.format(&result).unwrap();
        assert!(!output.contains("<script>alert"));
        assert!(output.contains("&lt;script&gt;alert"));
    }
}
