//! Scan monitor screen — live scan progress with host/port tables.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, Wrap};

use rustmap_types::{HostStatus, PortState};

use crate::tui::app::{Action, ScanPanel, ScanScreenState, Screen};
use crate::tui::theme;

pub fn render(
    frame: &mut ratatui::Frame,
    area: Rect,
    state: &mut ScanScreenState,
) {
    // Layout: header(3) + main(flex) + log(8)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(8),
        ])
        .split(area);

    render_header(frame, chunks[0], state);
    render_main(frame, chunks[1], state);
    render_log(frame, chunks[2], state);
}

pub fn handle_key(
    key: KeyEvent,
    state: &mut ScanScreenState,
    scan_running: bool,
) -> Vec<Action> {
    let mut actions = Vec::new();
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => actions.push(Action::SwitchScreen(Screen::Config)),
        KeyCode::Up | KeyCode::Char('k') => state.previous_host(),
        KeyCode::Down | KeyCode::Char('j') => state.next_host(),
        KeyCode::Tab => state.next_panel(),
        KeyCode::Char('c') if scan_running => actions.push(Action::CancelScan),
        KeyCode::Enter if state.phase.is_terminal() => {
            actions.push(Action::SwitchScreen(Screen::Results));
        }
        _ => {}
    }
    actions
}

pub fn footer_hints(state: &ScanScreenState) -> Vec<(&'static str, &'static str)> {
    let mut hints = vec![("j/k", "navigate"), ("Tab", "panel")];
    if !state.phase.is_terminal() {
        hints.push(("c", "cancel"));
    } else {
        hints.push(("Enter", "results"));
    }
    hints.push(("q", "back"));
    hints
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

fn render_header(frame: &mut ratatui::Frame, area: Rect, state: &ScanScreenState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(2)])
        .split(area);

    let status = format!(
        " {} | {:?} | {}/{} hosts | {} ",
        state.phase.label(),
        state.scan_type,
        state.hosts_completed,
        state.hosts_total,
        state.elapsed_display(),
    );
    let status_widget = Paragraph::new(status).style(theme::STATUS_BAR);
    frame.render_widget(status_widget, chunks[0]);

    let ratio = state.progress_ratio();
    let label = format!("{:.1}%", ratio * 100.0);
    let gauge = Gauge::default()
        .block(Block::default())
        .gauge_style(Style::default().fg(theme::GAUGE_FG).bg(theme::GAUGE_BG))
        .ratio(ratio.min(1.0))
        .label(label);
    frame.render_widget(gauge, chunks[1]);
}

fn render_main(frame: &mut ratatui::Frame, area: Rect, state: &mut ScanScreenState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    render_host_list(frame, chunks[0], state);
    render_port_detail(frame, chunks[1], state);
}

fn render_host_list(frame: &mut ratatui::Frame, area: Rect, state: &mut ScanScreenState) {
    let highlight_style = if state.active_panel == ScanPanel::HostList {
        theme::PANEL_ACTIVE_HIGHLIGHT
    } else {
        theme::PANEL_INACTIVE_HIGHLIGHT
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

fn render_port_detail(frame: &mut ratatui::Frame, area: Rect, state: &ScanScreenState) {
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
                Row::new(vec![
                    Cell::from(format!("{}/{}", p.number, p.protocol)),
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

        // OS info
        if let Some(ref os) = host.os_fingerprint
            && let Some(ref family) = os.os_family
        {
            let generation = os.os_generation.as_deref().unwrap_or("");
            let acc = os.accuracy.map(|a| format!(" ({a}%)")).unwrap_or_default();
            let os_line = format!("OS: {family} {generation}{acc}");
            let os_area = Rect {
                x: area.x + 1,
                y: area.y + area.height.saturating_sub(2),
                width: area.width.saturating_sub(2),
                height: 1,
            };
            frame.render_widget(
                Paragraph::new(os_line).style(theme::TEXT_OS),
                os_area,
            );
        }
    } else {
        let msg = Paragraph::new("No host selected")
            .block(block)
            .style(theme::TEXT_DIM);
        frame.render_widget(msg, area);
    }
}

fn render_log(frame: &mut ratatui::Frame, area: Rect, state: &ScanScreenState) {
    let border_style = if state.active_panel == ScanPanel::Log {
        theme::PANEL_BORDER_ACTIVE
    } else {
        theme::PANEL_BORDER_INACTIVE
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Log ")
        .border_style(border_style);

    let inner_height = area.height.saturating_sub(2) as usize;
    let start = state.log_lines.len().saturating_sub(inner_height);
    let visible: Vec<Line> = state.log_lines[start..]
        .iter()
        .map(|l| Line::from(l.as_str()))
        .collect();

    let log_widget = Paragraph::new(visible).block(block).wrap(Wrap { trim: false });
    frame.render_widget(log_widget, area);
}
