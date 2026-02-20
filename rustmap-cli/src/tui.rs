//! Interactive terminal UI for real-time scan monitoring.
//!
//! Renders a three-panel layout: host list, port detail, and log.
//! Receives streaming scan events and updates the display at 10 FPS.

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Terminal;
use tokio::sync::mpsc;

use rustmap_core::ScanEvent;
use rustmap_output::{OutputConfig, OutputManager};
use rustmap_types::{
    HostScanResult, HostStatus, PortState, ScanConfig, ScanResult, ScanType,
};

// ---------------------------------------------------------------------------
// TUI state
// ---------------------------------------------------------------------------

/// Current scan phase.
#[derive(Debug, Clone, PartialEq)]
enum ScanPhase {
    Discovering,
    Scanning,
    Complete,
    Error(String),
}

impl ScanPhase {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete | Self::Error(_))
    }

    fn label(&self) -> &str {
        match self {
            Self::Discovering => "Discovering",
            Self::Scanning => "Scanning",
            Self::Complete => "Complete",
            Self::Error(_) => "Error",
        }
    }
}

/// Active panel for keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Panel {
    HostList,
    PortDetail,
    Log,
}

/// All TUI state in one struct.
pub struct TuiState {
    // Scan progress
    hosts_total: usize,
    hosts_completed: usize,
    phase: ScanPhase,
    scan_type: ScanType,

    // Results
    host_results: Vec<HostScanResult>,

    // Log
    log_lines: Vec<String>,

    // UI state
    host_table_state: TableState,
    active_panel: Panel,
    show_help: bool,

    // Timing
    start_time: Instant,
}

impl TuiState {
    fn new(scan_type: ScanType) -> Self {
        Self {
            hosts_total: 0,
            hosts_completed: 0,
            phase: ScanPhase::Discovering,
            scan_type,
            host_results: Vec::new(),
            log_lines: Vec::new(),
            host_table_state: TableState::default(),
            active_panel: Panel::HostList,
            show_help: false,
            start_time: Instant::now(),
        }
    }

    fn handle_scan_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::DiscoveryComplete { hosts_total } => {
                self.hosts_total = hosts_total;
                self.phase = ScanPhase::Scanning;
                self.log(format!("Discovery complete: {hosts_total} host(s) up"));
            }
            ScanEvent::HostResult { result, hosts_completed, hosts_total, .. } => {
                let open = result.ports.iter().filter(|p| p.state == PortState::Open).count();
                self.log(format!(
                    "Host {}: {} open port(s)",
                    result.host.ip, open
                ));
                self.host_results.push(*result);
                self.hosts_completed = hosts_completed;
                self.hosts_total = hosts_total;
                // Auto-select first host
                if self.host_results.len() == 1 {
                    self.host_table_state.select(Some(0));
                }
            }
            ScanEvent::Complete(_) => {
                self.phase = ScanPhase::Complete;
                self.log("Scan complete.".into());
            }
            ScanEvent::Error(msg) => {
                self.phase = ScanPhase::Error(msg.clone());
                self.log(format!("Error: {msg}"));
            }
        }
    }

    fn log(&mut self, msg: String) {
        let elapsed = self.start_time.elapsed();
        let mins = elapsed.as_secs() / 60;
        let secs = elapsed.as_secs() % 60;
        self.log_lines.push(format!("[{mins:02}:{secs:02}] {msg}"));
        // Keep last 200 lines
        if self.log_lines.len() > 200 {
            self.log_lines.remove(0);
        }
    }

    fn next_host(&mut self) {
        if self.host_results.is_empty() {
            return;
        }
        let i = self.host_table_state.selected().unwrap_or(0);
        let next = if i + 1 >= self.host_results.len() { 0 } else { i + 1 };
        self.host_table_state.select(Some(next));
    }

    fn previous_host(&mut self) {
        if self.host_results.is_empty() {
            return;
        }
        let i = self.host_table_state.selected().unwrap_or(0);
        let prev = if i == 0 { self.host_results.len() - 1 } else { i - 1 };
        self.host_table_state.select(Some(prev));
    }

    fn next_panel(&mut self) {
        self.active_panel = match self.active_panel {
            Panel::HostList => Panel::PortDetail,
            Panel::PortDetail => Panel::Log,
            Panel::Log => Panel::HostList,
        };
    }

    fn selected_host(&self) -> Option<&HostScanResult> {
        self.host_table_state
            .selected()
            .and_then(|i| self.host_results.get(i))
    }

    fn progress_ratio(&self) -> f64 {
        if self.hosts_total == 0 {
            0.0
        } else {
            self.hosts_completed as f64 / self.hosts_total as f64
        }
    }

    fn elapsed_display(&self) -> String {
        let secs = self.start_time.elapsed().as_secs();
        format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
    }

    /// Assemble final ScanResult from collected host results.
    fn build_scan_result(&self) -> ScanResult {
        ScanResult {
            hosts: self.host_results.clone(),
            total_duration: self.start_time.elapsed(),
            scan_type: self.scan_type,
            start_time: None,
            command_args: Some(std::env::args().collect::<Vec<_>>().join(" ")),
            num_services: self.host_results.iter().map(|h| h.ports.len()).sum(),
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }
}

// ---------------------------------------------------------------------------
// Terminal RAII guard
// ---------------------------------------------------------------------------

/// RAII guard that restores terminal state on drop (including panics).
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), terminal::LeaveAlternateScreen);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the interactive TUI, driving a scan in the background.
pub async fn run_tui(config: ScanConfig, output_config: OutputConfig) -> anyhow::Result<()> {
    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let _terminal_guard = TerminalGuard;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let scan_type = config.scan_type;

    // Start scan engine
    let (tx, mut rx) = mpsc::channel::<ScanEvent>(64);
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        if let Err(e) = rustmap_core::ScanEngine::run_streaming(&config, tx, cancel_clone).await {
            eprintln!("Engine error: {e}");
        }
    });

    // Main loop
    let mut state = TuiState::new(scan_type);
    let tick_rate = Duration::from_millis(100); // 10 FPS

    loop {
        // Draw
        terminal.draw(|frame| render(frame, &mut state))?;

        // Poll for keyboard input (non-blocking)
        if event::poll(tick_rate)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    cancel.cancel();
                    break;
                }
                KeyCode::Up | KeyCode::Char('k') => state.previous_host(),
                KeyCode::Down | KeyCode::Char('j') => state.next_host(),
                KeyCode::Tab => state.next_panel(),
                KeyCode::Char('?') => state.show_help = !state.show_help,
                _ => {}
            }
        }

        // Drain scan events (non-blocking)
        while let Ok(evt) = rx.try_recv() {
            state.handle_scan_event(evt);
        }

        if state.phase.is_terminal() && rx.is_closed() {
            // Show final state briefly
            terminal.draw(|frame| render(frame, &mut state))?;
            tokio::time::sleep(Duration::from_secs(1)).await;
            break;
        }
    }

    // Terminal state is restored by TerminalGuard on drop.
    // Explicitly drop the ratatui terminal first so the guard can restore the underlying stdout.
    drop(terminal);
    drop(_terminal_guard);

    // Output results to files if configured
    if !output_config.outputs.is_empty() {
        let result = state.build_scan_result();
        OutputManager::new(output_config).run(&result)?;
    }

    // Print summary to stdout
    let total_open: usize = state
        .host_results
        .iter()
        .flat_map(|h| &h.ports)
        .filter(|p| p.state == PortState::Open)
        .count();
    println!(
        "\nScan complete: {} host(s), {} open port(s) in {}",
        state.host_results.len(),
        total_open,
        state.elapsed_display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn render(frame: &mut ratatui::Frame, state: &mut TuiState) {
    let size = frame.area();

    // Help overlay takes precedence
    if state.show_help {
        render_help(frame, size);
        return;
    }

    // Main layout: Header(3) | Middle (flex) | Log(8) | Footer(1)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header + progress
            Constraint::Min(8),    // main split
            Constraint::Length(8), // log
            Constraint::Length(1), // footer
        ])
        .split(size);

    render_header(frame, chunks[0], state);
    render_main(frame, chunks[1], state);
    render_log(frame, chunks[2], state);
    render_footer(frame, chunks[3], state);
}

fn render_header(frame: &mut ratatui::Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(area);

    // Status line
    let status = format!(
        " RustMap TUI | {} | {}/{} hosts | {} ",
        state.phase.label(),
        state.hosts_completed,
        state.hosts_total,
        state.elapsed_display(),
    );
    let status_widget = Paragraph::new(status)
        .style(Style::default().fg(Color::White).bg(Color::DarkGray));
    frame.render_widget(status_widget, chunks[0]);

    // Progress bar
    let ratio = state.progress_ratio();
    let label = format!("{:.1}%", ratio * 100.0);
    let gauge = Gauge::default()
        .block(Block::default())
        .gauge_style(Style::default().fg(Color::Green).bg(Color::Black))
        .ratio(ratio.min(1.0))
        .label(label);
    frame.render_widget(gauge, chunks[1]);
}

fn render_main(frame: &mut ratatui::Frame, area: Rect, state: &mut TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    render_host_list(frame, chunks[0], state);
    render_port_detail(frame, chunks[1], state);
}

fn render_host_list(frame: &mut ratatui::Frame, area: Rect, state: &mut TuiState) {
    let highlight_style = if state.active_panel == Panel::HostList {
        Style::default().fg(Color::Black).bg(Color::Cyan)
    } else {
        Style::default().fg(Color::Black).bg(Color::DarkGray)
    };

    let header = Row::new(vec!["IP", "Status", "Open"])
        .style(Style::default().add_modifier(Modifier::BOLD))
        .bottom_margin(0);

    let rows: Vec<Row> = state
        .host_results
        .iter()
        .map(|h| {
            let open_count = h.ports.iter().filter(|p| p.state == PortState::Open).count();
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
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Hosts "),
    )
    .row_highlight_style(highlight_style);

    frame.render_stateful_widget(table, area, &mut state.host_table_state);
}

fn render_port_detail(frame: &mut ratatui::Frame, area: Rect, state: &TuiState) {
    let selected = state.selected_host();

    let title = match selected {
        Some(h) => format!(" Ports ({}) ", h.host.ip),
        None => " Ports ".into(),
    };

    let block = Block::default().borders(Borders::ALL).title(title);

    if let Some(host) = selected {
        let header = Row::new(vec!["Port", "State", "Service", "Version"])
            .style(Style::default().add_modifier(Modifier::BOLD));

        let rows: Vec<Row> = host
            .ports
            .iter()
            .map(|p| {
                let state_style = match p.state {
                    PortState::Open => Style::default().fg(Color::Green),
                    PortState::Closed => Style::default().fg(Color::Red),
                    PortState::Filtered => Style::default().fg(Color::Yellow),
                    _ => Style::default(),
                };
                let service = p.service.as_deref().unwrap_or("");
                let version = p
                    .service_info
                    .as_ref()
                    .and_then(|si| si.version_display())
                    .unwrap_or_default();
                Row::new(vec![
                    Cell::from(format!("{}/{}",  p.number, p.protocol)),
                    Cell::from(p.state.to_string()).style(state_style),
                    Cell::from(service.to_string()),
                    Cell::from(version),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(12),
                Constraint::Min(10),
            ],
        )
        .header(header)
        .block(block);

        frame.render_widget(table, area);

        // OS info below port table if available
        if let Some(ref os) = host.os_fingerprint
            && let Some(ref family) = os.os_family
        {
            let generation = os.os_generation.as_deref().unwrap_or("");
            let acc = os.accuracy.map(|a| format!(" ({a}%)")).unwrap_or_default();
            let os_line = format!("OS: {family} {generation}{acc}");
            // Render in the last line of the area
            let os_area = Rect {
                x: area.x + 1,
                y: area.y + area.height.saturating_sub(2),
                width: area.width.saturating_sub(2),
                height: 1,
            };
            frame.render_widget(
                Paragraph::new(os_line).style(Style::default().fg(Color::Magenta)),
                os_area,
            );
        }
    } else {
        let msg = Paragraph::new("No host selected")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, area);
    }
}

fn render_log(frame: &mut ratatui::Frame, area: Rect, state: &TuiState) {
    let border_style = if state.active_panel == Panel::Log {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Log ")
        .border_style(border_style);

    // Show last N lines that fit
    let inner_height = area.height.saturating_sub(2) as usize;
    let start = state.log_lines.len().saturating_sub(inner_height);
    let visible: Vec<Line> = state.log_lines[start..]
        .iter()
        .map(|l| Line::from(l.as_str()))
        .collect();

    let log_widget = Paragraph::new(visible).block(block).wrap(Wrap { trim: false });
    frame.render_widget(log_widget, area);
}

fn render_footer(frame: &mut ratatui::Frame, area: Rect, state: &TuiState) {
    let _ = state;
    let keys = vec![
        Span::styled(" q", Style::default().fg(Color::Yellow)),
        Span::raw(":quit  "),
        Span::styled("↑↓", Style::default().fg(Color::Yellow)),
        Span::raw(":navigate  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(":panel  "),
        Span::styled("?", Style::default().fg(Color::Yellow)),
        Span::raw(":help"),
    ];
    let footer = Paragraph::new(Line::from(keys))
        .style(Style::default().bg(Color::DarkGray));
    frame.render_widget(footer, area);
}

fn render_help(frame: &mut ratatui::Frame, area: Rect) {
    let help_text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  RustMap TUI — Keyboard Shortcuts",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  q / Esc       Quit"),
        Line::from("  ↑ / k         Previous host"),
        Line::from("  ↓ / j         Next host"),
        Line::from("  Tab           Switch panel"),
        Line::from("  ?             Toggle this help"),
        Line::from(""),
        Line::from("  Press any key to close."),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help ")
        .style(Style::default().fg(Color::White).bg(Color::DarkGray));

    // Center the help popup
    let popup_area = centered_rect(50, 60, area);
    frame.render_widget(ratatui::widgets::Clear, popup_area);
    let help = Paragraph::new(help_text).block(block);
    frame.render_widget(help, popup_area);
}

/// Create a centered rectangle within `area`.
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{Host, Port, PortState, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn host_event(index: usize, host: HostScanResult, completed: usize, total: usize) -> ScanEvent {
        ScanEvent::HostResult {
            index,
            result: Box::new(host),
            hosts_completed: completed,
            hosts_total: total,
        }
    }

    fn dummy_scan_result() -> Box<ScanResult> {
        Box::new(ScanResult {
            hosts: vec![],
            scan_type: ScanType::TcpConnect,
            total_duration: Duration::from_secs(1),
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        })
    }

    fn make_host_result(ip: [u8; 4], ports: Vec<(u16, PortState)>) -> HostScanResult {
        HostScanResult {
            host: Host::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))),
            ports: ports
                .into_iter()
                .map(|(num, state)| Port {
                    number: num,
                    protocol: Protocol::Tcp,
                    state,
                    service: None,
                    service_info: None,
                    reason: None,
                    script_results: vec![],
                    tls_info: None,
                })
                .collect(),
            scan_duration: Duration::from_millis(100),
            host_status: HostStatus::Up,
            discovery_latency: Some(Duration::from_millis(2)),
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
    fn tui_state_handle_discovery() {
        let mut state = TuiState::new(ScanType::TcpConnect);
        assert_eq!(state.phase, ScanPhase::Discovering);

        state.handle_scan_event(ScanEvent::DiscoveryComplete { hosts_total: 5 });
        assert_eq!(state.phase, ScanPhase::Scanning);
        assert_eq!(state.hosts_total, 5);
    }

    #[test]
    fn tui_state_handle_host_result() {
        let mut state = TuiState::new(ScanType::TcpConnect);
        state.handle_scan_event(ScanEvent::DiscoveryComplete { hosts_total: 2 });

        let result = make_host_result([192, 168, 1, 1], vec![(22, PortState::Open), (80, PortState::Open)]);
        state.handle_scan_event(host_event(0, result, 1, 2));

        assert_eq!(state.host_results.len(), 1);
        assert_eq!(state.hosts_completed, 1);
        assert_eq!(state.host_table_state.selected(), Some(0));
    }

    #[test]
    fn tui_state_handle_complete() {
        let mut state = TuiState::new(ScanType::TcpConnect);
        state.handle_scan_event(ScanEvent::DiscoveryComplete { hosts_total: 1 });
        state.handle_scan_event(host_event(
            0, make_host_result([10, 0, 0, 1], vec![(443, PortState::Open)]), 1, 1,
        ));
        state.handle_scan_event(ScanEvent::Complete(dummy_scan_result()));

        assert!(state.phase.is_terminal());
        assert_eq!(state.phase, ScanPhase::Complete);
    }

    #[test]
    fn tui_state_navigation() {
        let mut state = TuiState::new(ScanType::TcpConnect);
        state.handle_scan_event(ScanEvent::DiscoveryComplete { hosts_total: 3 });
        for i in 1..=3u8 {
            state.handle_scan_event(host_event(
                (i - 1) as usize,
                make_host_result([192, 168, 1, i], vec![(80, PortState::Open)]),
                i as usize,
                3,
            ));
        }

        // First host auto-selected
        assert_eq!(state.host_table_state.selected(), Some(0));

        state.next_host();
        assert_eq!(state.host_table_state.selected(), Some(1));

        state.next_host();
        assert_eq!(state.host_table_state.selected(), Some(2));

        // Wrap around
        state.next_host();
        assert_eq!(state.host_table_state.selected(), Some(0));

        state.previous_host();
        assert_eq!(state.host_table_state.selected(), Some(2));

        // Panel cycling
        assert_eq!(state.active_panel, Panel::HostList);
        state.next_panel();
        assert_eq!(state.active_panel, Panel::PortDetail);
        state.next_panel();
        assert_eq!(state.active_panel, Panel::Log);
        state.next_panel();
        assert_eq!(state.active_panel, Panel::HostList);
    }

    #[test]
    fn tui_state_build_scan_result() {
        let mut state = TuiState::new(ScanType::TcpSyn);
        state.handle_scan_event(ScanEvent::DiscoveryComplete { hosts_total: 2 });
        state.handle_scan_event(host_event(
            0, make_host_result([10, 0, 0, 1], vec![(22, PortState::Open), (80, PortState::Open)]), 1, 2,
        ));
        state.handle_scan_event(host_event(
            1, make_host_result([10, 0, 0, 2], vec![(443, PortState::Open)]), 2, 2,
        ));
        state.handle_scan_event(ScanEvent::Complete(dummy_scan_result()));

        let result = state.build_scan_result();
        assert_eq!(result.hosts.len(), 2);
        assert_eq!(result.scan_type, ScanType::TcpSyn);
        assert_eq!(result.num_services, 3);
        assert!(result.command_args.is_some());
    }
}
