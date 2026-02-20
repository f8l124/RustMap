//! History browser screen — list, load, and diff past scans.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};

use crate::tui::app::{Action, HistoryScreenState, Screen};
use crate::tui::theme;

pub fn render(
    frame: &mut ratatui::Frame,
    area: Rect,
    state: &mut HistoryScreenState,
    has_db: bool,
) {
    if !has_db {
        let msg = Paragraph::new("Database unavailable.").style(theme::TEXT_DIM);
        frame.render_widget(msg, area);
        return;
    }

    let count = state.scans.len();
    let title = if state.diff_first.is_some() {
        format!(" History ({count} scans) \u{2014} Diff: select second scan ")
    } else {
        format!(" History ({count} scans) ")
    };

    let header = Row::new(vec!["Scan ID", "Type", "Hosts", "Ports", "Duration", "Started"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = state
        .scans
        .iter()
        .map(|s| {
            let duration = format!("{:.1}s", s.total_duration_ms as f64 / 1000.0);
            let started = format_timestamp(s.started_at);
            Row::new(vec![
                Cell::from(truncate_id(&s.scan_id)),
                Cell::from(s.scan_type.clone()),
                Cell::from(s.num_hosts.to_string()),
                Cell::from(s.num_services.to_string()),
                Cell::from(duration),
                Cell::from(started),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title))
    .row_highlight_style(theme::PANEL_ACTIVE_HIGHLIGHT);

    frame.render_stateful_widget(table, area, &mut state.table_state);

    // Diff overlay
    if state.show_diff {
        if let Some(ref diff) = state.diff_result {
            render_diff_overlay(frame, area, diff);
        }
    }
}

pub fn handle_key(
    key: KeyEvent,
    state: &mut HistoryScreenState,
    db: &Option<rustmap_db::ScanStore>,
) -> Vec<Action> {
    let mut actions = Vec::new();

    // Dismiss diff overlay first
    if state.show_diff {
        if matches!(
            key.code,
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter
        ) {
            state.show_diff = false;
            state.diff_result = None;
            state.diff_first = None;
        }
        return actions;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            if state.diff_first.is_some() {
                state.diff_first = None; // Cancel diff selection
            } else {
                actions.push(Action::SwitchScreen(Screen::Config));
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            let i = state.table_state.selected().unwrap_or(0);
            if i > 0 {
                state.table_state.select(Some(i - 1));
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let i = state.table_state.selected().unwrap_or(0);
            if i + 1 < state.scans.len() {
                state.table_state.select(Some(i + 1));
            }
        }
        KeyCode::Enter => {
            if let Some(idx) = state.table_state.selected() {
                if let Some(scan) = state.scans.get(idx) {
                    actions.push(Action::LoadScan(scan.scan_id.clone()));
                }
            }
        }
        KeyCode::Char('d') => {
            if let Some(idx) = state.table_state.selected() {
                if let Some(scan) = state.scans.get(idx) {
                    if let Some(ref first_id) = state.diff_first.clone() {
                        // Second scan selected — perform diff via action
                        let second_id = scan.scan_id.clone();
                        actions.push(Action::DiffScans(first_id.clone(), second_id));
                    } else {
                        state.diff_first = Some(scan.scan_id.clone());
                    }
                }
            }
        }
        KeyCode::Char('r') => {
            // Refresh via direct DB call (state-only, no App mutation needed)
            if let Some(db) = db {
                if let Ok(scans) = db.list_scans() {
                    state.scans = scans;
                    if !state.scans.is_empty() && state.table_state.selected().is_none() {
                        state.table_state.select(Some(0));
                    }
                }
            }
        }
        _ => {}
    }
    actions
}

pub fn footer_hints(state: &HistoryScreenState) -> Vec<(&'static str, &'static str)> {
    if state.show_diff {
        return vec![("Esc", "close")];
    }
    let mut hints = vec![
        ("j/k", "navigate"),
        ("Enter", "load"),
        ("d", "diff"),
        ("r", "refresh"),
    ];
    if state.diff_first.is_some() {
        hints.push(("Esc", "cancel diff"));
    } else {
        hints.push(("q", "back"));
    }
    hints
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn truncate_id(id: &str) -> String {
    if id.len() > 16 {
        format!("{}...", &id[..13])
    } else {
        id.to_string()
    }
}

fn format_timestamp(epoch_secs: u64) -> String {
    let secs = epoch_secs;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;

    let (year, month, day) = epoch_to_date(days_since_epoch);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{mins:02}")
}

fn epoch_to_date(days: u64) -> (u64, u64, u64) {
    // Adapted from Howard Hinnant's algorithm
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn render_diff_overlay(frame: &mut ratatui::Frame, area: Rect, diff: &rustmap_db::ScanDiff) {
    let popup = centered_rect(60, 70, area);
    frame.render_widget(Clear, popup);

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled("Scan Diff", theme::TEXT_BOLD)));
    lines.push(Line::from(""));

    if !diff.new_hosts.is_empty() {
        lines.push(Line::from(Span::styled("New Hosts:", theme::PORT_OPEN)));
        for h in &diff.new_hosts {
            lines.push(Line::from(format!("  + {h}")));
        }
        lines.push(Line::from(""));
    }

    if !diff.removed_hosts.is_empty() {
        lines.push(Line::from(Span::styled(
            "Removed Hosts:",
            theme::PORT_CLOSED,
        )));
        for h in &diff.removed_hosts {
            lines.push(Line::from(format!("  - {h}")));
        }
        lines.push(Line::from(""));
    }

    if !diff.port_changes.is_empty() {
        lines.push(Line::from(Span::styled(
            "Port Changes:",
            theme::PORT_FILTERED,
        )));
        for c in &diff.port_changes {
            let old = c.old_state.as_deref().unwrap_or("none");
            let new = c.new_state.as_deref().unwrap_or("none");
            lines.push(Line::from(format!(
                "  {}:{}/{} {} -> {}",
                c.ip, c.port, c.protocol, old, new
            )));
        }
    }

    if diff.new_hosts.is_empty() && diff.removed_hosts.is_empty() && diff.port_changes.is_empty() {
        lines.push(Line::from("No differences found."));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press Esc to close",
        theme::TEXT_DIM,
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Diff ")
        .style(theme::HELP_BG);
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, popup);
}

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
