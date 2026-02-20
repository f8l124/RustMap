//! App state machine and screen routing.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, TableState};
use tokio::sync::mpsc;

use rustmap_core::{CancellationToken, ScanEvent};
use rustmap_types::{HostScanResult, PortState, ScanConfig, ScanResult, ScanType};

use super::screens;
use super::theme;

// ---------------------------------------------------------------------------
// Screen enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Config,
    Scan,
    Results,
    History,
    Help,
}

impl Screen {
    pub const ALL: [Screen; 5] = [
        Screen::Config,
        Screen::Scan,
        Screen::Results,
        Screen::History,
        Screen::Help,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Self::Config => "Config",
            Self::Scan => "Scan",
            Self::Results => "Results",
            Self::History => "History",
            Self::Help => "Help",
        }
    }
}

// ---------------------------------------------------------------------------
// Actions that screens can request
// ---------------------------------------------------------------------------

pub enum Action {
    Quit,
    SwitchScreen(Screen),
    CancelScan,
    StartScan,
    LoadScan(String),
    DiffScans(String, String),
}

// ---------------------------------------------------------------------------
// Scan phase
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ScanPhase {
    Idle,
    Discovering,
    Scanning,
    Complete,
    Error(String),
}

impl ScanPhase {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete | Self::Error(_))
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Idle => "Idle",
            Self::Discovering => "Discovering",
            Self::Scanning => "Scanning",
            Self::Complete => "Complete",
            Self::Error(_) => "Error",
        }
    }
}

// ---------------------------------------------------------------------------
// Per-screen state structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanPanel {
    HostList,
    PortDetail,
    Log,
}

pub struct ScanScreenState {
    pub hosts_total: usize,
    pub hosts_completed: usize,
    pub phase: ScanPhase,
    pub scan_type: ScanType,
    pub host_results: Vec<HostScanResult>,
    pub log_lines: Vec<String>,
    pub host_table_state: TableState,
    pub active_panel: ScanPanel,
    pub start_time: Instant,
}

impl Default for ScanScreenState {
    fn default() -> Self {
        Self {
            hosts_total: 0,
            hosts_completed: 0,
            phase: ScanPhase::Idle,
            scan_type: ScanType::TcpConnect,
            host_results: Vec::new(),
            log_lines: Vec::new(),
            host_table_state: TableState::default(),
            active_panel: ScanPanel::HostList,
            start_time: Instant::now(),
        }
    }
}

impl ScanScreenState {
    pub fn reset(&mut self, scan_type: ScanType) {
        self.hosts_total = 0;
        self.hosts_completed = 0;
        self.phase = ScanPhase::Discovering;
        self.scan_type = scan_type;
        self.host_results.clear();
        self.log_lines.clear();
        self.host_table_state = TableState::default();
        self.active_panel = ScanPanel::HostList;
        self.start_time = Instant::now();
    }

    pub fn log(&mut self, msg: String) {
        let elapsed = self.start_time.elapsed();
        let mins = elapsed.as_secs() / 60;
        let secs = elapsed.as_secs() % 60;
        self.log_lines.push(format!("[{mins:02}:{secs:02}] {msg}"));
        if self.log_lines.len() > 200 {
            self.log_lines.remove(0);
        }
    }

    pub fn progress_ratio(&self) -> f64 {
        if self.hosts_total == 0 {
            0.0
        } else {
            self.hosts_completed as f64 / self.hosts_total as f64
        }
    }

    pub fn elapsed_display(&self) -> String {
        let secs = self.start_time.elapsed().as_secs();
        format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        )
    }

    pub fn next_host(&mut self) {
        if self.host_results.is_empty() {
            return;
        }
        let i = self.host_table_state.selected().unwrap_or(0);
        let next = if i + 1 >= self.host_results.len() {
            0
        } else {
            i + 1
        };
        self.host_table_state.select(Some(next));
    }

    pub fn previous_host(&mut self) {
        if self.host_results.is_empty() {
            return;
        }
        let i = self.host_table_state.selected().unwrap_or(0);
        let prev = if i == 0 {
            self.host_results.len() - 1
        } else {
            i - 1
        };
        self.host_table_state.select(Some(prev));
    }

    pub fn next_panel(&mut self) {
        self.active_panel = match self.active_panel {
            ScanPanel::HostList => ScanPanel::PortDetail,
            ScanPanel::PortDetail => ScanPanel::Log,
            ScanPanel::Log => ScanPanel::HostList,
        };
    }

    pub fn selected_host(&self) -> Option<&HostScanResult> {
        self.host_table_state
            .selected()
            .and_then(|i| self.host_results.get(i))
    }

    #[allow(dead_code)]
    pub fn build_scan_result(&self) -> ScanResult {
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResultsPanel {
    Hosts,
    Ports,
}

pub struct ResultsScreenState {
    pub host_table_state: TableState,
    pub port_table_state: TableState,
    pub active_panel: ResultsPanel,
    pub open_only: bool,
}

impl Default for ResultsScreenState {
    fn default() -> Self {
        Self {
            host_table_state: TableState::default(),
            port_table_state: TableState::default(),
            active_panel: ResultsPanel::Hosts,
            open_only: false,
        }
    }
}

#[derive(Default)]
pub struct HistoryScreenState {
    pub scans: Vec<rustmap_db::ScanSummary>,
    pub table_state: TableState,
    pub loaded: bool,
    pub diff_first: Option<String>,
    pub diff_result: Option<rustmap_db::ScanDiff>,
    pub show_diff: bool,
}

#[derive(Default)]
pub struct HelpScreenState {
    pub scroll: u16,
}

pub struct ConfigScreenState {
    // Target
    pub targets: String,
    pub ports: String,

    // Scan type & performance
    pub scan_type_idx: usize,
    pub timing_idx: usize,
    pub concurrency: String,
    pub timeout_ms: String,

    // Discovery
    pub discovery_mode_idx: usize,

    // Detection
    pub service_detection: bool,
    pub version_intensity: u8,
    pub os_detection: bool,

    // Features
    pub traceroute: bool,
    pub randomize_ports: bool,
    pub fragment_packets: bool,
    pub mtu_discovery: bool,

    // Form state
    pub focused_field: usize,
    pub cursor_pos: usize,
    pub error: Option<String>,
}

impl Default for ConfigScreenState {
    fn default() -> Self {
        Self {
            targets: String::new(),
            ports: String::new(),
            scan_type_idx: 0,
            timing_idx: 3,
            concurrency: "100".into(),
            timeout_ms: "3000".into(),
            discovery_mode_idx: 0,
            service_detection: false,
            version_intensity: 7,
            os_detection: false,
            traceroute: false,
            randomize_ports: false,
            fragment_packets: false,
            mtu_discovery: false,
            focused_field: 0,
            cursor_pos: 0,
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub screen: Screen,
    pub config: ScanConfig,

    pub config_state: ConfigScreenState,
    pub scan_state: ScanScreenState,
    pub results_state: ResultsScreenState,
    pub history_state: HistoryScreenState,
    pub help_state: HelpScreenState,

    pub scan_running: bool,
    pub scan_result: Option<ScanResult>,
    pub db: Option<rustmap_db::ScanStore>,
    pub cancel: Option<CancellationToken>,
    pub should_quit: bool,

    scan_tx: Option<mpsc::Sender<ScanEvent>>,
    scan_rx: Option<mpsc::Receiver<ScanEvent>>,
}

impl App {
    pub fn new(config: ScanConfig, db: Option<rustmap_db::ScanStore>) -> Self {
        let config_state = screens::config::initial_state(&config);
        Self {
            screen: Screen::Config,
            config,
            config_state,
            scan_state: ScanScreenState::default(),
            results_state: ResultsScreenState::default(),
            history_state: HistoryScreenState::default(),
            help_state: HelpScreenState::default(),
            scan_running: false,
            scan_result: None,
            db,
            cancel: None,
            should_quit: false,
            scan_tx: None,
            scan_rx: None,
        }
    }

    pub fn take_scan_rx(&mut self) -> Option<mpsc::Receiver<ScanEvent>> {
        self.scan_rx.take()
    }

    pub fn start_scan(&mut self) {
        let (tx, rx) = mpsc::channel::<ScanEvent>(64);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        let config = self.config.clone();

        self.scan_state.reset(config.scan_type);
        self.scan_running = true;
        self.cancel = Some(cancel);
        self.scan_tx = Some(tx.clone());
        self.scan_rx = Some(rx);

        tokio::spawn(async move {
            if let Err(e) = rustmap_core::ScanEngine::run_streaming(&config, tx, cancel_clone).await
            {
                eprintln!("Engine error: {e}");
            }
        });
    }

    pub fn handle_scan_event(&mut self, event: ScanEvent) {
        match &event {
            ScanEvent::DiscoveryComplete { hosts_total } => {
                self.scan_state.hosts_total = *hosts_total;
                self.scan_state.phase = ScanPhase::Scanning;
                self.scan_state
                    .log(format!("Discovery complete: {hosts_total} host(s) up"));
            }
            ScanEvent::HostResult {
                result,
                hosts_completed,
                hosts_total,
                ..
            } => {
                let open = result
                    .ports
                    .iter()
                    .filter(|p| p.state == PortState::Open)
                    .count();
                self.scan_state
                    .log(format!("Host {}: {} open port(s)", result.host.ip, open));
                self.scan_state.host_results.push(*result.clone());
                self.scan_state.hosts_completed = *hosts_completed;
                self.scan_state.hosts_total = *hosts_total;
                if self.scan_state.host_results.len() == 1 {
                    self.scan_state.host_table_state.select(Some(0));
                }
            }
            ScanEvent::Complete(scan_result) => {
                self.scan_state.phase = ScanPhase::Complete;
                self.scan_state.log("Scan complete.".into());
                self.scan_running = false;
                self.scan_result = Some(*scan_result.clone());
                self.scan_tx = None;
                self.screen = Screen::Results;
                self.results_state = ResultsScreenState::default();
                if let Some(ref r) = self.scan_result
                    && !r.hosts.is_empty()
                {
                    self.results_state.host_table_state.select(Some(0));
                }
            }
            ScanEvent::Error(msg) => {
                self.scan_state.phase = ScanPhase::Error(msg.clone());
                self.scan_state.log(format!("Error: {msg}"));
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Ctrl+C always quits
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            if let Some(ref cancel) = self.cancel {
                cancel.cancel();
            }
            self.should_quit = true;
            return;
        }

        // Global screen switching: F1-F5
        let global_screen = match key.code {
            KeyCode::F(1) => Some(Screen::Config),
            KeyCode::F(2) => Some(Screen::Scan),
            KeyCode::F(3) => Some(Screen::Results),
            KeyCode::F(4) => Some(Screen::History),
            KeyCode::F(5) => Some(Screen::Help),
            _ => None,
        };
        if let Some(s) = global_screen {
            self.switch_screen(s);
            return;
        }

        // Delegate to screen, collect actions
        let actions = match self.screen {
            Screen::Config => {
                screens::config::handle_key(key, &mut self.config_state, self.scan_running)
            }
            Screen::Scan => screens::scan::handle_key(key, &mut self.scan_state, self.scan_running),
            Screen::Results => screens::results::handle_key(key, &mut self.results_state),
            Screen::History => screens::history::handle_key(key, &mut self.history_state, &self.db),
            Screen::Help => screens::help::handle_key(key, &mut self.help_state),
        };

        for action in actions {
            self.apply_action(action);
        }
    }

    fn apply_action(&mut self, action: Action) {
        match action {
            Action::Quit => {
                if let Some(ref cancel) = self.cancel {
                    cancel.cancel();
                }
                self.should_quit = true;
            }
            Action::SwitchScreen(s) => self.switch_screen(s),
            Action::CancelScan => {
                if let Some(ref cancel) = self.cancel {
                    cancel.cancel();
                }
                self.scan_running = false;
                self.scan_state.phase = ScanPhase::Error("Cancelled".into());
                self.scan_state.log("Scan cancelled.".into());
            }
            Action::StartScan => {
                match screens::config::apply_to_config(&self.config_state, &mut self.config) {
                    Ok(()) => {
                        self.start_scan();
                        self.screen = Screen::Scan;
                    }
                    Err(msg) => {
                        self.config_state.error = Some(msg);
                    }
                }
            }
            Action::LoadScan(scan_id) => {
                if let Some(ref db) = self.db
                    && let Ok(Some(result)) = db.load_scan(&scan_id)
                {
                    self.scan_result = Some(result);
                    self.results_state = ResultsScreenState::default();
                    if let Some(ref r) = self.scan_result
                        && !r.hosts.is_empty()
                    {
                        self.results_state.host_table_state.select(Some(0));
                    }
                    self.switch_screen(Screen::Results);
                }
            }
            Action::DiffScans(old_id, new_id) => {
                if let Some(ref db) = self.db
                    && let Ok(diff) = db.diff_scans(&old_id, &new_id)
                {
                    self.history_state.diff_result = Some(diff);
                    self.history_state.show_diff = true;
                }
            }
        }
    }

    fn switch_screen(&mut self, screen: Screen) {
        if screen == Screen::History && !self.history_state.loaded {
            if let Some(ref db) = self.db
                && let Ok(scans) = db.list_scans()
            {
                self.history_state.scans = scans;
                if !self.history_state.scans.is_empty() {
                    self.history_state.table_state.select(Some(0));
                }
            }
            self.history_state.loaded = true;
        }
        self.screen = screen;
    }

    pub fn render(&mut self, frame: &mut ratatui::Frame) {
        let size = frame.area();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(6),
                Constraint::Length(1),
            ])
            .split(size);

        render_tab_bar(frame, chunks[0], self.screen);

        // Pass specific fields to avoid borrow-checker conflicts with &mut state + &self
        match self.screen {
            Screen::Config => screens::config::render(frame, chunks[1], &mut self.config_state),
            Screen::Scan => screens::scan::render(frame, chunks[1], &mut self.scan_state),
            Screen::Results => screens::results::render(
                frame,
                chunks[1],
                &mut self.results_state,
                &self.scan_result,
            ),
            Screen::History => screens::history::render(
                frame,
                chunks[1],
                &mut self.history_state,
                self.db.is_some(),
            ),
            Screen::Help => screens::help::render(frame, chunks[1], &mut self.help_state),
        }

        let hints = match self.screen {
            Screen::Config => screens::config::footer_hints(),
            Screen::Scan => screens::scan::footer_hints(&self.scan_state),
            Screen::Results => screens::results::footer_hints(),
            Screen::History => screens::history::footer_hints(&self.history_state),
            Screen::Help => screens::help::footer_hints(),
        };
        render_footer(frame, chunks[2], &hints);
    }
}

// ---------------------------------------------------------------------------
// Shared widgets
// ---------------------------------------------------------------------------

fn render_tab_bar(frame: &mut ratatui::Frame, area: Rect, active: Screen) {
    let mut spans = Vec::new();
    for screen in Screen::ALL {
        let style = if screen == active {
            theme::TAB_ACTIVE
        } else {
            theme::TAB_INACTIVE
        };
        spans.push(Span::styled(format!(" {} ", screen.label()), style));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        format!("  RustMap v{}", env!("CARGO_PKG_VERSION")),
        theme::TEXT_DIM,
    ));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_footer(frame: &mut ratatui::Frame, area: Rect, hints: &[(&str, &str)]) {
    let mut spans = Vec::new();
    for (key, desc) in hints {
        spans.push(Span::styled(format!(" {key}"), theme::FOOTER_KEY));
        spans.push(Span::raw(format!(":{desc}  ")));
    }
    spans.push(Span::styled(" F1-F5", theme::FOOTER_KEY));
    spans.push(Span::raw(":screens"));
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(theme::FOOTER_BG),
        area,
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{Host, Port, PortState, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

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
            host_status: rustmap_types::HostStatus::Up,
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
    fn scan_state_navigation() {
        let mut state = ScanScreenState::default();
        state.reset(ScanType::TcpConnect);

        for i in 1..=3u8 {
            state.host_results.push(make_host_result(
                [192, 168, 1, i],
                vec![(80, PortState::Open)],
            ));
        }
        state.host_table_state.select(Some(0));

        state.next_host();
        assert_eq!(state.host_table_state.selected(), Some(1));
        state.next_host();
        assert_eq!(state.host_table_state.selected(), Some(2));
        state.next_host();
        assert_eq!(state.host_table_state.selected(), Some(0));
        state.previous_host();
        assert_eq!(state.host_table_state.selected(), Some(2));
    }

    #[test]
    fn scan_state_panel_cycling() {
        let mut state = ScanScreenState::default();
        assert_eq!(state.active_panel, ScanPanel::HostList);
        state.next_panel();
        assert_eq!(state.active_panel, ScanPanel::PortDetail);
        state.next_panel();
        assert_eq!(state.active_panel, ScanPanel::Log);
        state.next_panel();
        assert_eq!(state.active_panel, ScanPanel::HostList);
    }

    #[test]
    fn scan_state_progress() {
        let mut state = ScanScreenState::default();
        assert_eq!(state.progress_ratio(), 0.0);
        state.hosts_total = 10;
        state.hosts_completed = 5;
        assert!((state.progress_ratio() - 0.5).abs() < 0.001);
    }

    #[test]
    fn scan_state_build_result() {
        let mut state = ScanScreenState::default();
        state.scan_type = ScanType::TcpSyn;
        state.host_results.push(make_host_result(
            [10, 0, 0, 1],
            vec![(22, PortState::Open), (80, PortState::Open)],
        ));
        state.host_results.push(make_host_result(
            [10, 0, 0, 2],
            vec![(443, PortState::Open)],
        ));

        let result = state.build_scan_result();
        assert_eq!(result.hosts.len(), 2);
        assert_eq!(result.scan_type, ScanType::TcpSyn);
        assert_eq!(result.num_services, 3);
    }

    #[test]
    fn screen_labels() {
        assert_eq!(Screen::Config.label(), "Config");
        assert_eq!(Screen::Scan.label(), "Scan");
        assert_eq!(Screen::Results.label(), "Results");
        assert_eq!(Screen::History.label(), "History");
        assert_eq!(Screen::Help.label(), "Help");
    }
}
