//! Help screen — keybinding reference and scan type documentation.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::tui::app::{Action, HelpScreenState, Screen};
use crate::tui::theme;

pub fn render(frame: &mut ratatui::Frame, area: Rect, state: &mut HelpScreenState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help \u{2014} RustMap TUI ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = build_help_content();

    // Apply scroll offset
    let visible: Vec<Line> = lines.into_iter().skip(state.scroll as usize).collect();

    let paragraph = Paragraph::new(visible).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

pub fn handle_key(key: KeyEvent, state: &mut HelpScreenState) -> Vec<Action> {
    let mut actions = Vec::new();
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            actions.push(Action::SwitchScreen(Screen::Config));
        }
        KeyCode::Down | KeyCode::Char('j') => state.scroll = state.scroll.saturating_add(1),
        KeyCode::Up | KeyCode::Char('k') => state.scroll = state.scroll.saturating_sub(1),
        KeyCode::PageDown => state.scroll = state.scroll.saturating_add(10),
        KeyCode::PageUp => state.scroll = state.scroll.saturating_sub(10),
        KeyCode::Home => state.scroll = 0,
        _ => {}
    }
    actions
}

pub fn footer_hints() -> Vec<(&'static str, &'static str)> {
    vec![("j/k", "scroll"), ("PgUp/Dn", "page"), ("q", "back")]
}

fn build_help_content<'a>() -> Vec<Line<'a>> {
    let bold = |s: &'a str| Line::from(Span::styled(s, theme::TEXT_BOLD));
    let dim = |s: &'a str| Line::from(Span::styled(s, theme::TEXT_DIM));
    let normal = |s: &'a str| Line::from(s);

    vec![
        normal(""),
        bold("  === Global Keys ==="),
        normal(""),
        normal("  F1 / 1        Config screen"),
        normal("  F2 / 2        Scan screen"),
        normal("  F3 / 3        Results screen"),
        normal("  F4 / 4        History screen"),
        normal("  F5 / ? / 5    Help screen"),
        normal("  Ctrl+C        Cancel scan & quit"),
        normal(""),
        bold("  === Navigation ==="),
        normal(""),
        normal("  j / Down      Next item"),
        normal("  k / Up        Previous item"),
        normal("  Tab           Next panel / field"),
        normal("  Shift+Tab     Previous field"),
        normal("  l / Enter     Drill in / Select"),
        normal("  h / Backspace Back / Collapse"),
        normal(""),
        bold("  === Config Screen ==="),
        normal(""),
        normal("  Tab / Down    Next field"),
        normal("  Shift+Tab/Up  Previous field"),
        normal("  Left / Right  Cycle selector values (scan type, timing, etc.)"),
        normal("  Space         Toggle checkboxes (service, OS, features)"),
        normal("  Type chars    Edit text fields (targets, ports, numbers)"),
        normal("  Enter         Start scan"),
        normal("  Esc           Quit"),
        normal(""),
        bold("  === Scan Screen ==="),
        normal(""),
        normal("  j / k         Navigate hosts"),
        normal("  Tab           Cycle panels (Hosts / Ports / Log)"),
        normal("  c             Cancel running scan"),
        normal("  Enter         Go to results (when complete)"),
        normal(""),
        bold("  === Results Screen ==="),
        normal(""),
        normal("  j / k         Navigate in active panel"),
        normal("  Tab           Switch panel (Hosts / Ports)"),
        normal("  l / Enter     Drill into port detail"),
        normal("  h / Backspace Back to host list"),
        normal("  o             Toggle open-only filter"),
        normal(""),
        bold("  === History Screen ==="),
        normal(""),
        normal("  j / k         Navigate scans"),
        normal("  Enter         Load scan into results viewer"),
        normal("  d             Diff (select two scans)"),
        normal("  r             Refresh scan list"),
        normal("  Esc           Cancel diff selection"),
        normal(""),
        bold("  === Scan Types ==="),
        normal(""),
        normal("  SYN    (-sS)  Half-open stealth scan. Sends SYN, waits for"),
        normal("                SYN/ACK (open) or RST (closed). Requires privileges."),
        normal(""),
        normal("  Connect(-sT)  Full TCP handshake. Works without privileges."),
        normal("                Default when running unprivileged."),
        normal(""),
        normal("  UDP    (-sU)  UDP port scan. Sends empty UDP or protocol-specific"),
        normal("                payloads. Slow due to rate limiting. Requires privileges."),
        normal(""),
        normal("  FIN    (-sF)  Sends TCP FIN. Open/filtered ports don't respond;"),
        normal("                closed ports send RST. IDS evasion technique."),
        normal(""),
        normal("  NULL   (-sN)  Sends TCP with no flags set. Similar to FIN scan."),
        normal(""),
        normal("  Xmas   (-sX)  Sends FIN+PSH+URG flags. Similar to FIN/NULL."),
        normal(""),
        normal("  ACK    (-sA)  Maps firewall rules. All ports respond with RST;"),
        normal("                filtered = no response. Can't determine open/closed."),
        normal(""),
        normal("  Window (-sW)  Like ACK scan but examines TCP window field in RST"),
        normal("                response to distinguish open from closed."),
        normal(""),
        normal("  Maimon (-sM)  Sends FIN/ACK. Some BSD systems drop open ports."),
        normal(""),
        normal("  SCTP   (-sZ)  SCTP INIT scan. Like TCP SYN for SCTP protocol."),
        normal(""),
        bold("  === Timing Templates ==="),
        normal(""),
        normal("  T0 (Paranoid)   IDS evasion, very slow"),
        normal("  T1 (Sneaky)     IDS evasion, slow"),
        normal("  T2 (Polite)     Uses less bandwidth"),
        normal("  T3 (Normal)     Default balanced timing"),
        normal("  T4 (Aggressive) Fast, assumes reliable network"),
        normal("  T5 (Insane)     Fastest, may miss results"),
        normal(""),
        dim("  Scroll with j/k or PgUp/PgDn"),
        normal(""),
    ]
}
