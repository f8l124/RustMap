//! Color constants and styling helpers for the TUI.

use ratatui::style::{Color, Modifier, Style};

// Tab bar
pub const TAB_ACTIVE: Style = Style::new().fg(Color::Black).bg(Color::Cyan);
pub const TAB_INACTIVE: Style = Style::new().fg(Color::DarkGray).bg(Color::Reset);

// Status bar
pub const STATUS_BAR: Style = Style::new().fg(Color::White).bg(Color::DarkGray);

// Progress gauge
pub const GAUGE_FG: Color = Color::Green;
pub const GAUGE_BG: Color = Color::Black;

// Panels
pub const PANEL_ACTIVE_HIGHLIGHT: Style = Style::new().fg(Color::Black).bg(Color::Cyan);
pub const PANEL_INACTIVE_HIGHLIGHT: Style = Style::new().fg(Color::Black).bg(Color::DarkGray);
pub const PANEL_BORDER_ACTIVE: Style = Style::new().fg(Color::Cyan);
pub const PANEL_BORDER_INACTIVE: Style = Style::new();

// Port states
pub const PORT_OPEN: Style = Style::new().fg(Color::Green);
pub const PORT_CLOSED: Style = Style::new().fg(Color::Red);
pub const PORT_FILTERED: Style = Style::new().fg(Color::Yellow);

// Text
pub const TEXT_DIM: Style = Style::new().fg(Color::DarkGray);
pub const TEXT_ACCENT: Style = Style::new().fg(Color::Cyan);
pub const TEXT_OS: Style = Style::new().fg(Color::Magenta);
pub const TEXT_ERROR: Style = Style::new().fg(Color::Red);
pub const TEXT_BOLD: Style = Style::new().add_modifier(Modifier::BOLD);

// Footer
pub const FOOTER_KEY: Style = Style::new().fg(Color::Yellow);
pub const FOOTER_BG: Style = Style::new().bg(Color::DarkGray);

// Help overlay
pub const HELP_BG: Style = Style::new().fg(Color::White).bg(Color::DarkGray);
