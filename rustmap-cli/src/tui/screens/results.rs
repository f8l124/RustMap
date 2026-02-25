//! Results viewer screen — browse completed scan results with drill-down.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};

use rustmap_types::{HostStatus, PortState, ScanResult};

use crate::tui::app::{Action, ResultsPanel, ResultsScreenState, Screen};
use crate::tui::theme;

pub fn render(
    frame: &mut ratatui::Frame,
    area: Rect,
    state: &mut ResultsScreenState,
    scan_result: &Option<ScanResult>,
) {
    let result = match scan_result {
        Some(r) => r,
        None => {
            let msg = Paragraph::new("No scan results available. Run a scan first.")
                .style(theme::TEXT_DIM);
            frame.render_widget(msg, area);
            return;
        }
    };

    // Summary bar (1) + main (flex)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(6)])
        .split(area);

    // Summary
    let total_hosts = result.hosts.len();
    let total_open: usize = result
        .hosts
        .iter()
        .flat_map(|h| &h.ports)
        .filter(|p| p.state == PortState::Open)
        .count();
    let duration = result.total_duration;
    let secs = duration.as_secs();
    let summary = format!(
        " {} host(s) | {} open port(s) | {:?} | {:02}:{:02}:{:02}{}",
        total_hosts,
        total_open,
        result.scan_type,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
        if state.open_only {
            " | Filter: open only"
        } else {
            ""
        },
    );
    frame.render_widget(Paragraph::new(summary).style(theme::STATUS_BAR), chunks[0]);

    // Main: hosts(40%) + detail(60%)
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[1]);

    render_host_list(frame, main_chunks[0], state, result);
    render_detail(frame, main_chunks[1], state, result);
}

pub fn handle_key(key: KeyEvent, state: &mut ResultsScreenState) -> Vec<Action> {
    let mut actions = Vec::new();
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            actions.push(Action::SwitchScreen(Screen::Config));
        }
        KeyCode::Up | KeyCode::Char('k') => match state.active_panel {
            ResultsPanel::Hosts => nav_prev(&mut state.host_table_state),
            ResultsPanel::Ports => nav_prev(&mut state.port_table_state),
        },
        KeyCode::Down | KeyCode::Char('j') => match state.active_panel {
            ResultsPanel::Hosts => nav_next(&mut state.host_table_state),
            ResultsPanel::Ports => nav_next(&mut state.port_table_state),
        },
        KeyCode::Tab => {
            state.active_panel = match state.active_panel {
                ResultsPanel::Hosts => ResultsPanel::Ports,
                ResultsPanel::Ports => ResultsPanel::Hosts,
            };
        }
        KeyCode::Enter | KeyCode::Char('l') if state.active_panel == ResultsPanel::Hosts => {
            state.active_panel = ResultsPanel::Ports;
            state.port_table_state.select(Some(0));
        }
        KeyCode::Char('h') | KeyCode::Backspace if state.active_panel == ResultsPanel::Ports => {
            state.active_panel = ResultsPanel::Hosts;
        }
        KeyCode::Char('o') => {
            state.open_only = !state.open_only;
        }
        _ => {}
    }
    actions
}

pub fn footer_hints() -> Vec<(&'static str, &'static str)> {
    vec![
        ("j/k", "navigate"),
        ("Tab", "panel"),
        ("l/Enter", "drill in"),
        ("h", "back"),
        ("o", "open only"),
        ("q", "back"),
    ]
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render_host_list(
    frame: &mut ratatui::Frame,
    area: Rect,
    state: &mut ResultsScreenState,
    result: &rustmap_types::ScanResult,
) {
    let highlight_style = if state.active_panel == ResultsPanel::Hosts {
        theme::PANEL_ACTIVE_HIGHLIGHT
    } else {
        theme::PANEL_INACTIVE_HIGHLIGHT
    };

    let header =
        Row::new(vec!["IP", "Status", "Open"]).style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = result
        .hosts
        .iter()
        .map(|h| {
            let open_count = h
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .count();
            let status_str = match h.host_status {
                HostStatus::Up => "up",
                HostStatus::Down => "down",
                HostStatus::Unknown => "?",
            };
            Row::new(vec![
                Cell::from(h.host.ip.to_string()),
                Cell::from(status_str),
                Cell::from(open_count.to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(16),
            Constraint::Length(6),
            Constraint::Length(5),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(" Hosts "))
    .row_highlight_style(highlight_style);

    frame.render_stateful_widget(table, area, &mut state.host_table_state);
}

fn render_detail(
    frame: &mut ratatui::Frame,
    area: Rect,
    state: &mut ResultsScreenState,
    result: &rustmap_types::ScanResult,
) {
    let host = state
        .host_table_state
        .selected()
        .and_then(|i| result.hosts.get(i));

    let host = match host {
        Some(h) => h,
        None => {
            let block = Block::default().borders(Borders::ALL).title(" Details ");
            let msg = Paragraph::new("No host selected")
                .block(block)
                .style(theme::TEXT_DIM);
            frame.render_widget(msg, area);
            return;
        }
    };

    let title = format!(" {} ", host.host.ip);
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    // Port table header
    lines.push(Line::from(Span::styled("=== Ports ===", theme::TEXT_BOLD)));

    let ports: Vec<&rustmap_types::Port> = if state.open_only {
        host.ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .collect()
    } else {
        host.ports.iter().collect()
    };

    let selected_port_idx = state.port_table_state.selected();

    for (i, p) in ports.iter().enumerate() {
        let marker = if state.active_panel == ResultsPanel::Ports && selected_port_idx == Some(i) {
            ">"
        } else {
            " "
        };
        let state_style = match p.state {
            PortState::Open => theme::PORT_OPEN,
            PortState::Closed => theme::PORT_CLOSED,
            PortState::Filtered => theme::PORT_FILTERED,
            _ => Style::default(),
        };
        let service = p.service.as_deref().unwrap_or("");
        let version = p
            .service_info
            .as_ref()
            .and_then(|si| si.version_display())
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::raw(format!(
                "{marker} {}/{:<5}",
                p.number,
                format!("{}", p.protocol)
            )),
            Span::styled(format!(" {:<10}", p.state), state_style),
            Span::raw(format!(" {:<10} {}", service, version)),
        ]));
    }

    // TLS info for selected port
    if let Some(idx) = selected_port_idx
        && let Some(port) = ports.get(idx)
    {
        if let Some(ref tls) = port.tls_info {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("=== TLS Info ({}/{}) ===", port.number, port.protocol),
                theme::TEXT_BOLD,
            )));
            lines.push(Line::from(format!(
                "  Version:  TLS 1.{}",
                tls.tls_version.saturating_sub(0x0301)
            )));
            lines.push(Line::from(format!(
                "  Cipher:   0x{:04X}",
                tls.cipher_suite
            )));
            if let Some(ref alpn) = tls.alpn {
                lines.push(Line::from(format!("  ALPN:     {alpn}")));
            }
            if let Some(ref ja4s) = tls.ja4s {
                lines.push(Line::from(format!("  JA4S:     {ja4s}")));
            }
            if let Some(ref certs) = tls.certificate_chain {
                for cert in certs {
                    if let Some(ref cn) = cert.subject_cn {
                        lines.push(Line::from(format!("  Subject:  {cn}")));
                    }
                    if let Some(ref issuer) = cert.issuer_cn {
                        lines.push(Line::from(format!("  Issuer:   {issuer}")));
                    }
                    if let Some(ref na) = cert.not_after {
                        lines.push(Line::from(format!("  Expires:  {na}")));
                    }
                    if !cert.san_dns.is_empty() {
                        lines.push(Line::from(format!(
                            "  SANs:     {}",
                            cert.san_dns.join(", ")
                        )));
                    }
                }
            }
        }

        // Script results for selected port
        if !port.script_results.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "=== Scripts ===",
                theme::TEXT_BOLD,
            )));
            for sr in &port.script_results {
                lines.push(Line::from(format!("  {}: {}", sr.id, sr.output)));
            }
        }
    }

    // GeoIP info
    if let Some(ref geo) = host.host.geo_info {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("=== GeoIP ===", theme::TEXT_BOLD)));
        if let Some(ref country) = geo.country {
            let code = geo.country_code.as_deref().unwrap_or("");
            lines.push(Line::from(format!("  Country: {code} - {country}")));
        }
        if let Some(ref city) = geo.city {
            lines.push(Line::from(format!("  City:    {city}")));
        }
        if let Some(asn) = geo.asn {
            let org = geo.as_org.as_deref().unwrap_or("");
            lines.push(Line::from(format!("  ASN:     AS{asn} {org}")));
        }
        if let Some(lat) = geo.latitude
            && let Some(lon) = geo.longitude
        {
            lines.push(Line::from(format!("  Coords:  {lat:.4}, {lon:.4}")));
        }
        if let Some(ref tz) = geo.timezone {
            lines.push(Line::from(format!("  TZ:      {tz}")));
        }
    }

    // OS fingerprint
    if let Some(ref os) = host.os_fingerprint
        && let Some(ref family) = os.os_family
    {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "=== OS Fingerprint ===",
            theme::TEXT_BOLD,
        )));
        let generation = os.os_generation.as_deref().unwrap_or("");
        let acc = os.accuracy.map(|a| format!(" ({a}%)")).unwrap_or_default();
        lines.push(Line::from(Span::styled(
            format!("  {family} {generation}{acc}"),
            theme::TEXT_OS,
        )));
    }

    // Traceroute
    if let Some(ref tr) = host.traceroute {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "=== Traceroute ===",
            theme::TEXT_BOLD,
        )));
        for hop in &tr.hops {
            let ip = hop.ip.map(|a| a.to_string()).unwrap_or_else(|| "*".into());
            let host_name = hop.hostname.as_deref().unwrap_or("");
            let rtt = hop
                .rtt
                .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "*".into());
            lines.push(Line::from(format!(
                "  {:>3}  {:<16} {:<20} {}",
                hop.ttl, ip, host_name, rtt
            )));
        }
    }

    // Host-level script results
    if !host.host_script_results.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "=== Host Scripts ===",
            theme::TEXT_BOLD,
        )));
        for sr in &host.host_script_results {
            lines.push(Line::from(format!("  {}: {}", sr.id, sr.output)));
        }
    }

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

// ---------------------------------------------------------------------------
// Navigation helpers
// ---------------------------------------------------------------------------

fn nav_prev(table: &mut TableState) {
    let i = table.selected().unwrap_or(0);
    if i > 0 {
        table.select(Some(i - 1));
    }
}

fn nav_next(table: &mut TableState) {
    let i = table.selected().unwrap_or(0);
    table.select(Some(i + 1));
}
