//! Interactive terminal UI for RustMap.
//!
//! Five screens: Config, Scan, Results, History, Help.
//! Navigate with F1-F5.  Full keyboard-driven interface.

mod app;
mod event;
mod screens;
mod terminal;
mod theme;

use std::time::Duration;

use rustmap_output::{OutputConfig, OutputManager};
use rustmap_types::{PortState, ScanConfig};

use app::App;
use event::{AppEvent, EventHandler};
use terminal::TerminalGuard;

/// Run the interactive TUI.
///
/// If `config` has targets, auto-starts a scan.
/// Otherwise opens the Config screen for interactive setup.
pub async fn run_tui(config: ScanConfig, output_config: OutputConfig) -> anyhow::Result<()> {
    let has_targets = !config.targets.is_empty();

    // Setup terminal
    let _guard = TerminalGuard::setup()?;
    let mut term = terminal::create_terminal()?;

    // Open database (once, optional)
    let db = rustmap_db::ScanStore::open_default().ok();

    // Create app
    let mut app = App::new(config, db);

    if has_targets {
        app.start_scan();
        app.screen = app::Screen::Scan;
    }

    // Create event handler
    let mut events = EventHandler::new(Duration::from_millis(100));

    // If scan started, feed scan events into the handler
    if let Some(rx) = app.take_scan_rx() {
        events.set_scan_receiver(rx);
    }

    // Main loop
    loop {
        term.draw(|frame| app.render(frame))?;

        match events.next().await? {
            AppEvent::Key(key) => {
                app.handle_key(key);
                // If a scan was just started (from Config screen),
                // pass the new receiver to the event handler
                if let Some(rx) = app.take_scan_rx() {
                    events.set_scan_receiver(rx);
                }
            }
            AppEvent::Scan(evt) => app.handle_scan_event(evt),
            AppEvent::Tick => {}
            AppEvent::Resize(_, _) => {}
        }

        if app.should_quit {
            break;
        }
    }

    drop(term);
    drop(_guard);

    // Output results if configured
    if let Some(ref result) = app.scan_result {
        if !output_config.outputs.is_empty() {
            OutputManager::new(output_config).run(result)?;
        }
        let total_open: usize = result
            .hosts
            .iter()
            .flat_map(|h| &h.ports)
            .filter(|p| p.state == PortState::Open)
            .count();
        println!(
            "\nScan complete: {} host(s), {} open port(s)",
            result.hosts.len(),
            total_open,
        );
    }

    Ok(())
}
