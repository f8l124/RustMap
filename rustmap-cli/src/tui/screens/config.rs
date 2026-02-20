//! Config screen — form for setting scan parameters.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use rustmap_types::{DiscoveryMode, Host, ScanConfig, ScanType, TimingTemplate};

use crate::tui::app::{Action, ConfigScreenState};
use crate::tui::theme;

// ---------------------------------------------------------------------------
// Field indices
// ---------------------------------------------------------------------------

const FIELD_TARGETS: usize = 0;
const FIELD_PORTS: usize = 1;
const FIELD_SCAN_TYPE: usize = 2;
const FIELD_TIMING: usize = 3;
const FIELD_CONCURRENCY: usize = 4;
const FIELD_TIMEOUT: usize = 5;
const FIELD_DISCOVERY: usize = 6;
const FIELD_SERVICE: usize = 7;
const FIELD_INTENSITY: usize = 8;
const FIELD_OS: usize = 9;
const FIELD_TRACEROUTE: usize = 10;
const FIELD_RANDOMIZE: usize = 11;
const FIELD_FRAGMENT: usize = 12;
const FIELD_MTU: usize = 13;
const FIELD_COUNT: usize = 14;

// ---------------------------------------------------------------------------
// Option arrays
// ---------------------------------------------------------------------------

const SCAN_TYPES: &[(&str, ScanType)] = &[
    ("TCP Connect", ScanType::TcpConnect),
    ("TCP SYN", ScanType::TcpSyn),
    ("UDP", ScanType::Udp),
    ("TCP FIN", ScanType::TcpFin),
    ("TCP NULL", ScanType::TcpNull),
    ("TCP Xmas", ScanType::TcpXmas),
    ("TCP ACK", ScanType::TcpAck),
    ("TCP Window", ScanType::TcpWindow),
    ("TCP Maimon", ScanType::TcpMaimon),
    ("SCTP INIT", ScanType::SctpInit),
    ("Ping Only", ScanType::Ping),
];

const TIMING_TEMPLATES: &[(&str, TimingTemplate)] = &[
    ("T0 Paranoid", TimingTemplate::Paranoid),
    ("T1 Sneaky", TimingTemplate::Sneaky),
    ("T2 Polite", TimingTemplate::Polite),
    ("T3 Normal", TimingTemplate::Normal),
    ("T4 Aggressive", TimingTemplate::Aggressive),
    ("T5 Insane", TimingTemplate::Insane),
];

const DISCOVERY_MODES: &[&str] = &["Default", "Skip (-Pn)", "Ping Only (-sn)"];

// ---------------------------------------------------------------------------
// State initialization from ScanConfig
// ---------------------------------------------------------------------------

pub fn initial_state(config: &ScanConfig) -> ConfigScreenState {
    let targets = config
        .targets
        .iter()
        .map(|h| h.ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let ports = format_ports(&config.ports);

    let scan_type_idx = SCAN_TYPES
        .iter()
        .position(|(_, st)| *st == config.scan_type)
        .unwrap_or(0);

    let timing_idx = TIMING_TEMPLATES
        .iter()
        .position(|(_, tt)| *tt == config.timing_template)
        .unwrap_or(3);

    let discovery_mode_idx = match config.discovery.mode {
        DiscoveryMode::Skip => 1,
        DiscoveryMode::PingOnly => 2,
        _ => 0,
    };

    ConfigScreenState {
        targets,
        ports,
        scan_type_idx,
        timing_idx,
        concurrency: config.concurrency.to_string(),
        timeout_ms: config.timeout.as_millis().to_string(),
        discovery_mode_idx,
        service_detection: config.service_detection.enabled,
        version_intensity: config.service_detection.intensity,
        os_detection: config.os_detection.enabled,
        traceroute: config.traceroute,
        randomize_ports: config.randomize_ports,
        fragment_packets: config.fragment_packets,
        mtu_discovery: config.mtu_discovery,
        focused_field: 0,
        cursor_pos: 0,
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Apply form state back to ScanConfig
// ---------------------------------------------------------------------------

pub fn apply_to_config(state: &ConfigScreenState, config: &mut ScanConfig) -> Result<(), String> {
    config.targets = parse_targets(&state.targets)?;
    config.ports = parse_ports(&state.ports)?;
    config.scan_type = SCAN_TYPES
        .get(state.scan_type_idx)
        .map(|(_, st)| *st)
        .unwrap_or(ScanType::TcpConnect);
    config.timing_template = TIMING_TEMPLATES
        .get(state.timing_idx)
        .map(|(_, tt)| *tt)
        .unwrap_or(TimingTemplate::Normal);
    config.concurrency = state
        .concurrency
        .parse::<usize>()
        .map_err(|_| "Invalid concurrency value".to_string())?;
    if config.concurrency == 0 {
        return Err("Concurrency must be >= 1".into());
    }
    config.timeout = Duration::from_millis(
        state
            .timeout_ms
            .parse::<u64>()
            .map_err(|_| "Invalid timeout value".to_string())?,
    );
    config.discovery.mode = match state.discovery_mode_idx {
        1 => DiscoveryMode::Skip,
        2 => DiscoveryMode::PingOnly,
        _ => DiscoveryMode::Default,
    };
    config.service_detection.enabled = state.service_detection;
    config.service_detection.intensity = state.version_intensity;
    config.os_detection.enabled = state.os_detection;
    config.traceroute = state.traceroute;
    config.randomize_ports = state.randomize_ports;
    config.fragment_packets = state.fragment_packets;
    config.mtu_discovery = state.mtu_discovery;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn render(frame: &mut ratatui::Frame, area: Rect, state: &mut ConfigScreenState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Scan Configuration ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let f = state.focused_field;
    let mut lines: Vec<Line> = Vec::new();

    // === Targets ===
    lines.push(section_header("Targets"));
    lines.push(text_field(
        "  Targets:     ",
        &state.targets,
        "IPs, CIDRs (e.g. 192.168.1.0/24)",
        f == FIELD_TARGETS,
    ));
    lines.push(text_field(
        "  Ports:       ",
        &state.ports,
        "default: top-1000",
        f == FIELD_PORTS,
    ));
    lines.push(Line::from(""));

    // === Scan ===
    lines.push(section_header("Scan"));
    lines.push(cycle_field(
        "  Type:        ",
        SCAN_TYPES[state.scan_type_idx].0,
        f == FIELD_SCAN_TYPE,
    ));
    lines.push(cycle_field(
        "  Timing:      ",
        TIMING_TEMPLATES[state.timing_idx].0,
        f == FIELD_TIMING,
    ));
    lines.push(text_field(
        "  Concurrency: ",
        &state.concurrency,
        "100",
        f == FIELD_CONCURRENCY,
    ));
    lines.push(text_field(
        "  Timeout(ms): ",
        &state.timeout_ms,
        "3000",
        f == FIELD_TIMEOUT,
    ));
    lines.push(Line::from(""));

    // === Discovery ===
    lines.push(section_header("Discovery"));
    lines.push(cycle_field(
        "  Mode:        ",
        DISCOVERY_MODES[state.discovery_mode_idx],
        f == FIELD_DISCOVERY,
    ));
    lines.push(Line::from(""));

    // === Detection ===
    lines.push(section_header("Detection"));
    lines.push(toggle_field(
        "  Service -sV: ",
        state.service_detection,
        f == FIELD_SERVICE,
    ));
    let intensity_str = state.version_intensity.to_string();
    lines.push(cycle_field(
        "  Intensity:   ",
        &intensity_str,
        f == FIELD_INTENSITY,
    ));
    lines.push(toggle_field("  OS -O:       ", state.os_detection, f == FIELD_OS));
    lines.push(Line::from(""));

    // === Features ===
    lines.push(section_header("Features"));
    lines.push(toggle_field(
        "  Traceroute:  ",
        state.traceroute,
        f == FIELD_TRACEROUTE,
    ));
    lines.push(toggle_field(
        "  Randomize:   ",
        state.randomize_ports,
        f == FIELD_RANDOMIZE,
    ));
    lines.push(toggle_field(
        "  Fragment:    ",
        state.fragment_packets,
        f == FIELD_FRAGMENT,
    ));
    lines.push(toggle_field(
        "  MTU Disc.:   ",
        state.mtu_discovery,
        f == FIELD_MTU,
    ));
    lines.push(Line::from(""));

    // Error
    if let Some(ref err) = state.error {
        lines.push(Line::from(Span::styled(
            format!("  Error: {err}"),
            theme::TEXT_ERROR,
        )));
    }

    // Hint
    lines.push(Line::from(Span::styled(
        "  Enter: start  Tab/\u{2191}\u{2193}: navigate  Space: toggle  \u{2190}\u{2192}: cycle",
        theme::TEXT_DIM,
    )));

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

pub fn handle_key(
    key: KeyEvent,
    state: &mut ConfigScreenState,
    _scan_running: bool,
) -> Vec<Action> {
    let mut actions = Vec::new();
    match key.code {
        KeyCode::Esc => {
            actions.push(Action::Quit);
        }
        KeyCode::Tab | KeyCode::Down => {
            state.focused_field = (state.focused_field + 1) % FIELD_COUNT;
            state.cursor_pos = active_text(state).map(|s| s.len()).unwrap_or(0);
        }
        KeyCode::BackTab | KeyCode::Up => {
            state.focused_field = if state.focused_field == 0 {
                FIELD_COUNT - 1
            } else {
                state.focused_field - 1
            };
            state.cursor_pos = active_text(state).map(|s| s.len()).unwrap_or(0);
        }
        KeyCode::Enter => {
            if state.targets.trim().is_empty() {
                state.error = Some("Targets required".into());
            } else {
                state.error = None;
                actions.push(Action::StartScan);
            }
        }
        KeyCode::Char(' ') if is_toggle_field(state.focused_field) => {
            toggle_value(state);
        }
        KeyCode::Left if is_cycle_field(state.focused_field) => {
            cycle_prev(state);
        }
        KeyCode::Right if is_cycle_field(state.focused_field) => {
            cycle_next(state);
        }
        KeyCode::Backspace if is_text_field(state.focused_field) => {
            if let Some(field) = active_text_mut(state) {
                field.pop();
            }
        }
        KeyCode::Char(c) if is_text_field(state.focused_field) => {
            if is_numeric_field(state.focused_field) {
                if c.is_ascii_digit() {
                    if let Some(field) = active_text_mut(state) {
                        field.push(c);
                    }
                }
            } else if let Some(field) = active_text_mut(state) {
                field.push(c);
            }
        }
        KeyCode::Char('q') => {
            actions.push(Action::Quit);
        }
        _ => {}
    }
    actions
}

pub fn footer_hints() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Tab", "navigate"),
        ("</>", "cycle"),
        ("Space", "toggle"),
        ("Enter", "start scan"),
        ("q", "quit"),
    ]
}

// ---------------------------------------------------------------------------
// Field type helpers
// ---------------------------------------------------------------------------

fn is_text_field(idx: usize) -> bool {
    matches!(
        idx,
        FIELD_TARGETS | FIELD_PORTS | FIELD_CONCURRENCY | FIELD_TIMEOUT
    )
}

fn is_cycle_field(idx: usize) -> bool {
    matches!(
        idx,
        FIELD_SCAN_TYPE | FIELD_TIMING | FIELD_DISCOVERY | FIELD_INTENSITY
    )
}

fn is_toggle_field(idx: usize) -> bool {
    matches!(
        idx,
        FIELD_SERVICE | FIELD_OS | FIELD_TRACEROUTE | FIELD_RANDOMIZE | FIELD_FRAGMENT | FIELD_MTU
    )
}

fn is_numeric_field(idx: usize) -> bool {
    matches!(idx, FIELD_CONCURRENCY | FIELD_TIMEOUT)
}

fn active_text(state: &ConfigScreenState) -> Option<&str> {
    match state.focused_field {
        FIELD_TARGETS => Some(&state.targets),
        FIELD_PORTS => Some(&state.ports),
        FIELD_CONCURRENCY => Some(&state.concurrency),
        FIELD_TIMEOUT => Some(&state.timeout_ms),
        _ => None,
    }
}

fn active_text_mut(state: &mut ConfigScreenState) -> Option<&mut String> {
    match state.focused_field {
        FIELD_TARGETS => Some(&mut state.targets),
        FIELD_PORTS => Some(&mut state.ports),
        FIELD_CONCURRENCY => Some(&mut state.concurrency),
        FIELD_TIMEOUT => Some(&mut state.timeout_ms),
        _ => None,
    }
}

fn toggle_value(state: &mut ConfigScreenState) {
    match state.focused_field {
        FIELD_SERVICE => state.service_detection = !state.service_detection,
        FIELD_OS => state.os_detection = !state.os_detection,
        FIELD_TRACEROUTE => state.traceroute = !state.traceroute,
        FIELD_RANDOMIZE => state.randomize_ports = !state.randomize_ports,
        FIELD_FRAGMENT => state.fragment_packets = !state.fragment_packets,
        FIELD_MTU => state.mtu_discovery = !state.mtu_discovery,
        _ => {}
    }
}

fn cycle_next(state: &mut ConfigScreenState) {
    match state.focused_field {
        FIELD_SCAN_TYPE => {
            state.scan_type_idx = (state.scan_type_idx + 1) % SCAN_TYPES.len();
        }
        FIELD_TIMING => {
            state.timing_idx = (state.timing_idx + 1) % TIMING_TEMPLATES.len();
        }
        FIELD_DISCOVERY => {
            state.discovery_mode_idx = (state.discovery_mode_idx + 1) % DISCOVERY_MODES.len();
        }
        FIELD_INTENSITY => {
            state.version_intensity = if state.version_intensity >= 9 {
                0
            } else {
                state.version_intensity + 1
            };
        }
        _ => {}
    }
}

fn cycle_prev(state: &mut ConfigScreenState) {
    match state.focused_field {
        FIELD_SCAN_TYPE => {
            state.scan_type_idx = if state.scan_type_idx == 0 {
                SCAN_TYPES.len() - 1
            } else {
                state.scan_type_idx - 1
            };
        }
        FIELD_TIMING => {
            state.timing_idx = if state.timing_idx == 0 {
                TIMING_TEMPLATES.len() - 1
            } else {
                state.timing_idx - 1
            };
        }
        FIELD_DISCOVERY => {
            state.discovery_mode_idx = if state.discovery_mode_idx == 0 {
                DISCOVERY_MODES.len() - 1
            } else {
                state.discovery_mode_idx - 1
            };
        }
        FIELD_INTENSITY => {
            state.version_intensity = if state.version_intensity == 0 {
                9
            } else {
                state.version_intensity - 1
            };
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

fn section_header(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("  === {title} ==="),
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    ))
}

fn text_field(label: &str, value: &str, placeholder: &str, focused: bool) -> Line<'static> {
    let style = if focused {
        theme::TEXT_ACCENT
    } else {
        Style::default()
    };
    let display = if value.is_empty() {
        Span::styled(
            format!("[{placeholder}]"),
            if focused {
                theme::TEXT_ACCENT
            } else {
                theme::TEXT_DIM
            },
        )
    } else {
        Span::styled(format!("[{value}]"), style)
    };
    Line::from(vec![
        Span::styled(
            label.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        display,
    ])
}

fn cycle_field(label: &str, value: &str, focused: bool) -> Line<'static> {
    let style = if focused {
        theme::TEXT_ACCENT
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(
            label.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("\u{25C0} {value} \u{25B6}"), style),
    ])
}

fn toggle_field(label: &str, checked: bool, focused: bool) -> Line<'static> {
    let style = if focused {
        theme::TEXT_ACCENT
    } else {
        Style::default()
    };
    let mark = if checked { "x" } else { " " };
    Line::from(vec![
        Span::styled(
            label.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("[{mark}]"), style),
    ])
}

// ---------------------------------------------------------------------------
// Target & port parsing
// ---------------------------------------------------------------------------

fn parse_targets(input: &str) -> Result<Vec<Host>, String> {
    let mut hosts = Vec::new();
    for token in input.split(|c: char| c == ',' || c == ';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Ok(ip) = token.parse::<IpAddr>() {
            hosts.push(Host::new(ip));
        } else if token.contains('/') {
            for ip in expand_cidr(token)? {
                hosts.push(Host::new(ip));
            }
        } else if token.contains('-') {
            for ip in expand_range(token)? {
                hosts.push(Host::new(ip));
            }
        } else {
            // Try DNS resolution (blocking, brief)
            match resolve_hostname(token) {
                Ok(ips) => {
                    for ip in ips {
                        hosts.push(Host::new(ip));
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
    if hosts.is_empty() {
        return Err("No valid targets specified".into());
    }
    Ok(hosts)
}

fn expand_cidr(s: &str) -> Result<Vec<IpAddr>, String> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR: {s}"));
    }
    let base_ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| format!("Invalid IP in CIDR: {}", parts[0]))?;
    let prefix: u32 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid prefix: {}", parts[1]))?;
    if prefix > 32 {
        return Err(format!("Prefix length too large: {prefix}"));
    }
    if prefix == 32 {
        return Ok(vec![IpAddr::V4(base_ip)]);
    }
    let mask = !0u32 << (32 - prefix);
    let network = u32::from(base_ip) & mask;
    let broadcast = network | !mask;
    let (start, end) = if prefix <= 30 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    };
    let mut ips = Vec::new();
    for addr in start..=end {
        ips.push(IpAddr::V4(Ipv4Addr::from(addr)));
    }
    Ok(ips)
}

fn expand_range(s: &str) -> Result<Vec<IpAddr>, String> {
    let dash_pos = s
        .rfind('-')
        .ok_or_else(|| format!("Invalid range: {s}"))?;
    let base = &s[..dash_pos];
    let end_str = &s[dash_pos + 1..];

    let base_ip: Ipv4Addr = base
        .parse()
        .map_err(|_| format!("Invalid IP in range: {base}"))?;
    let end_octet: u8 = end_str
        .parse()
        .map_err(|_| format!("Invalid range end: {end_str}"))?;

    let octets = base_ip.octets();
    let start = octets[3];
    if end_octet < start {
        return Err(format!("Range end ({end_octet}) < start ({start})"));
    }
    let mut ips = Vec::new();
    for last in start..=end_octet {
        ips.push(IpAddr::V4(Ipv4Addr::new(
            octets[0], octets[1], octets[2], last,
        )));
    }
    Ok(ips)
}

fn resolve_hostname(s: &str) -> Result<Vec<IpAddr>, String> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<IpAddr> = format!("{s}:0")
        .to_socket_addrs()
        .map_err(|e| format!("Cannot resolve '{s}': {e}"))?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err(format!("No addresses found for '{s}'"));
    }
    Ok(addrs)
}

fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut ports = Vec::new();
    for token in input.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if token.contains('-') {
            let parts: Vec<&str> = token.split('-').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid port range: {token}"));
            }
            let start: u16 = parts[0]
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: {}", parts[0].trim()))?;
            let end: u16 = parts[1]
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: {}", parts[1].trim()))?;
            if start > end {
                return Err(format!("Invalid port range: {start}-{end}"));
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let p: u16 = token
                .parse()
                .map_err(|_| format!("Invalid port: {token}"))?;
            ports.push(p);
        }
    }
    Ok(ports)
}

fn format_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    if ports.len() <= 20 {
        return ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
    }
    format!("{} ports", ports.len())
}
