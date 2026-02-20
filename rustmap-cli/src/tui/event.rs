//! Unified event loop merging crossterm input, tick, and scan events.

use std::time::Duration;

use crossterm::event::{self, Event, KeyEvent, KeyEventKind};
use tokio::sync::mpsc;

use rustmap_core::ScanEvent;

/// Unified event type consumed by the main loop.
#[derive(Debug)]
pub enum AppEvent {
    /// Keyboard input (already filtered to Press only).
    Key(KeyEvent),
    /// 100ms render tick.
    Tick,
    /// Scan engine event.
    Scan(ScanEvent),
    /// Terminal resized.
    #[allow(dead_code)]
    Resize(u16, u16),
}

/// Merges crossterm input and scan events into a single stream.
pub struct EventHandler {
    tick_rate: Duration,
    scan_rx: Option<mpsc::Receiver<ScanEvent>>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        Self {
            tick_rate,
            scan_rx: None,
        }
    }

    /// Attach a scan event receiver.
    pub fn set_scan_receiver(&mut self, rx: mpsc::Receiver<ScanEvent>) {
        self.scan_rx = Some(rx);
    }

    /// Wait for the next event.  Returns `Tick` if nothing happens within the tick rate.
    pub async fn next(&mut self) -> anyhow::Result<AppEvent> {
        // Drain any pending scan events first (non-blocking)
        if let Some(ref mut rx) = self.scan_rx
            && let Ok(evt) = rx.try_recv()
        {
            return Ok(AppEvent::Scan(evt));
        }

        // Poll crossterm with the tick timeout
        if event::poll(self.tick_rate)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    return Ok(AppEvent::Key(key));
                }
                Event::Resize(w, h) => return Ok(AppEvent::Resize(w, h)),
                _ => {}
            }
        }

        // Check scan events again after the poll wait
        if let Some(ref mut rx) = self.scan_rx
            && let Ok(evt) = rx.try_recv()
        {
            return Ok(AppEvent::Scan(evt));
        }

        Ok(AppEvent::Tick)
    }
}
