//! Terminal setup/teardown with RAII guard.

use std::io;

use crossterm::terminal::{self, EnterAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

/// RAII guard that restores terminal state on drop (including panics).
pub struct TerminalGuard;

impl TerminalGuard {
    /// Enable raw mode + alternate screen.  Returns the guard.
    pub fn setup() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        crossterm::execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), terminal::LeaveAlternateScreen);
    }
}

/// Create a ratatui terminal on stdout.
pub fn create_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}
