# Architecture

RustMap is organized as a 16-crate Cargo workspace (edition 2024, resolver 3). Each crate has a focused responsibility with minimal coupling between layers.

## Crate Dependency Graph

```
rustmap-cli ──────────────────────────────────────┐
rustmap-gui ──────────────────────────────────────┤
rustmap-api ──────────────────────────────────────┤
rustmap-python ───────────────────────────────────┤
  │                                               │
  ▼                                               ▼
rustmap-core ───────────── rustmap-output ── rustmap-db
  │        │ \                │
  │        │  \               ▼
  │        │   ▼          rustmap-types
  │        │ rustmap-detect    ▲
  │        │   │ │             │
  │        │   │ ▼             │
  │        ▼   │ rustmap-geoip │
  │  rustmap-script            │
  │        │                   │
  ▼        ▼                   │
rustmap-scan ──────────────────┘
  │
  ▼
rustmap-packet ── rustmap-timing

rustmap-vuln (standalone, uses rustmap-types)
rustmap-cloud (standalone, uses rustmap-types)
```

## Crate Details

### rustmap-types

Shared type definitions used across all crates. No logic, pure data.

- `ScanConfig` — full scan configuration (100+ fields)
- `Host`, `Port`, `PortState` — target and result types
- `ScanResult`, `HostScanResult` — scan output types
- `ScanType` — TcpConnect, TcpSyn, TcpFin, TcpNull, TcpXmas, TcpAck, TcpWindow, TcpMaimon, Udp, SctpInit, Ping
- `DiscoveryMethod` — IcmpEcho, TcpSyn, TcpAck, IcmpTimestamp, UdpPing, ArpPing, HttpPing, HttpsPing
- `TimingTemplate` — T0 (Paranoid) through T5 (Insane)
- `PortRange` — port specification parser
- `top_tcp_ports()` — frequency-ranked port lists
- OS, service, script, GeoIP, TLS certificate, traceroute, vulnerability, and timing result types

### rustmap-packet

Low-level packet construction and raw socket I/O via pcap/Npcap.

- `PacketSender` trait — abstraction over raw socket backends
- `NpcapSender` (Windows) / `LinuxSender` — platform-specific implementations
- TCP, UDP, ICMP, ARP, SCTP packet builders (via etherparse)
- IP fragmentation support for evasion
- RST suppression via iptables/ip6tables
- Packet parsing for response classification
- Privilege detection (`check_privileges()`)
- Configurable snaplen (256 bytes for IPv6+TCP options)

### rustmap-timing

TCP-like congestion control and rate limiting engine.

- `TimingController` — central coordinator (thread-safe via `Mutex`)
- `RttEstimator` — Jacobson/Karels smoothed RTT + RTO calculation
- `CongestionWindow` — slow start + congestion avoidance
- `RateLimiter` — token-bucket rate limiter
- `TimingParams` — per-template configuration (T0 through T5)
- Learned timing support — apply historical RTT/CWND/ssthresh data
- NaN/Infinity guards on all floating-point inputs

### rustmap-scan

Scanner implementations, host discovery, and traceroute.

- `Scanner` trait — `async fn scan_host(&self, host, config) -> HostScanResult`
- `TcpConnectScanner` — full TCP handshake via `tokio::net::TcpStream` (SOCKS5 proxy support)
- `TcpSynScanner` — SYN scan using raw packets
- `RawTcpScanner` — FIN, NULL, Xmas, ACK, Window, Maimon (configurable flags)
- `UdpScanner` — UDP probes with ICMP unreachable detection
- `SctpScanner` — SCTP INIT chunk scanning with INIT-ACK/ABORT detection
- `HostDiscovery` — parallel discovery using ICMP, TCP, UDP, ARP, HTTP, HTTPS probes
- `DiscoveryTracker` — per-probe send time tracking for accurate latency measurement
- `Traceroute` — hop-by-hop path discovery with TCP SYN and UDP probes, loop detection
- `MtuDiscovery` — IPv4 path MTU discovery via ICMP
- OS probe helpers (`run_os_probes`, `find_open_port`, `find_closed_port`)
- Source port management with atomic wraparound
- Probe state machine with priority-based state transitions (Filtered→Open upgrades)

### rustmap-detect

Service and OS detection engines.

- `ServiceDetector` — banner grabbing, pattern matching, active probes
- `OsDetector` — combines active TCP probes, p0f database, TLS fingerprints
- `UptimeEstimator` — TCP timestamp-based uptime estimation
- QUIC/HTTP3 probing — version negotiation, HTTP/3 detection
- HTTP/2 cleartext (h2c) detection
- gRPC service detection
- TLS certificate chain parsing and fingerprinting
- Port-to-service name mapping
- Regex-based service identification patterns

### rustmap-script

Scripting engine with Lua, Python, and WASM support.

- `ScriptRunner` — discovers, filters, and executes scripts
- `LuaSandbox` — secure Lua 5.4 runtime with memory/instruction limits
- `nmap` library — `nmap.registry`, `nmap.log`, `nmap.new_socket`
- `shortport` library — `port_or_service`, `http`, `ssl` matchers
- Full TCP/UDP socket API with SOCKS5 proxy integration
- Python script support — subprocess execution via JSON stdin/stdout protocol
- WASM sandbox (optional) — WebAssembly script execution via wasmtime
- Script categories, argument parsing, glob selection
- 54 built-in scripts (50 Lua, 4 Python)

### rustmap-output

Output formatting, file management, and topology graph generation.

- `OutputFormatter` trait — `fn format(&self, result: &ScanResult) -> String`
- **9 formatters:**
  - `StdoutFormatter` — nmap-style normal text output
  - `XmlFormatter` — XML output compatible with nmap DTD
  - `JsonFormatter` — structured JSON output
  - `GrepableFormatter` — one-line-per-host format
  - `YamlFormatter` — YAML serialization
  - `CsvFormatter` — comma-separated values
  - `CefFormatter` — Common Event Format (ArcSight/Splunk SIEM)
  - `LeefFormatter` — Log Event Extended Format (IBM QRadar)
  - `HtmlFormatter` — self-contained HTML report with charts and tables
- `OutputManager` — multi-format file writing, `--oA` support
- `TopologyFormatter` — DOT (Graphviz), GraphML, JSON graph export
- `filter_open_ports()` — `--open` flag filtering

### rustmap-core

Scan orchestration and target parsing.

- `ScanEngine::run()` — full scan pipeline (discovery → scan → detect → script → results)
- `ScanEngine::run_streaming()` — streaming variant with per-host events via `mpsc`
- `ScanEvent` enum — `DiscoveryComplete`, `HostResult` (with progress), `Complete`, `Error`
- `CancellationToken` support for graceful abort
- `parse_target()` / `parse_targets()` — IP, CIDR, range, hostname parsing
- Multi-phase per-host pipeline:
  1. Port scanning (configurable scan type)
  2. MTU discovery (optional, IPv4 only)
  3. Service name enrichment (always)
  4. Active service/version detection (`--sV`)
  5. OS detection (`-O`) with TLS fingerprint fallback
  6. Uptime estimation from TCP timestamps
  7. Traceroute (`--traceroute`)
- Hostgroup size management with clamping to target count
- HashMap-based O(1) discovery result lookups

### rustmap-db

SQLite-backed persistence layer for scan data.

- `ScanStore` — CRUD operations for scan results
- Scan history with summary metadata (ID, timing, host/service counts)
- `ScanDiff` — compare two scans (new hosts, removed hosts, port changes, service changes)
- Checkpoint system for scan pause/resume
- `HostProfile` — per-host behavioral tracking (times scanned, times up, discovery latency)
- `NetworkProfile` — per-subnet profiling (avg RTT, loss rate, jitter, stability score)
- `LearnedTimingParams` — historical timing recommendations (initial RTO, CWND, ssthresh)
- `PortPrediction` — predict likely-open ports from scan history
- `CachedService` — service cache with change tracking
- Profile storage — save/load/list scan configurations (TOML format)
- CRC32C integrity checking for stored data
- Transactional upserts for data integrity

### rustmap-vuln

Vulnerability correlation engine.

- `VulnChecker` — match detected services against CVE database
- Bundled seed CVE data with matching rules
- NVD API integration for database updates (optional `update` feature)
- CISA KEV (Known Exploited Vulnerabilities) feed integration
- CVSS score filtering (`--vuln-min-cvss`)
- Product name normalization for fuzzy matching
- Risk score computation per host
- URL-safe encoding for NVD API queries
- Retry logic with backoff for failed API requests

### rustmap-geoip

GeoIP and ASN enrichment using MaxMind GeoLite2 databases.

- Country, city, latitude/longitude, timezone lookup
- ASN (Autonomous System Number) and organization lookup
- Automatic database discovery (~/.rustmap/geoip/, env var, custom path)
- Path canonicalization for security
- File size validation (rejects >200MB files)
- Skips private/loopback IP addresses

### rustmap-cloud

Cloud provider asset discovery for scan target enumeration.

- `AwsDiscovery` — EC2 instance enumeration via aws-sdk-ec2
- `AzureDiscovery` — VM discovery via Azure REST API
- `GcpDiscovery` — Compute Engine discovery via GCP REST API
- Region filtering and running-only instance filtering
- Tag/label-based filtering (key=value pairs)
- Returns `Vec<Host>` for direct scan pipeline integration
- Configurable timeouts for API requests

### rustmap-api

REST API server for remote scan management.

- Built on axum with WebSocket support
- `POST /api/scans` — start new scan, returns scan ID
- `GET /api/scans` — list scans with status filtering
- `GET /api/scans/{id}` — get scan result
- `DELETE /api/scans/{id}` — delete completed scan
- `POST /api/scans/{id}/stop` — cancel running scan
- `GET /api/scans/{id}/export` — export in any format (json, xml, grepable, normal, yaml, csv)
- `GET /api/scans/{id}/diff/{other_id}` — diff two scans
- `WS /api/scans/{id}/events` — real-time scan event streaming
- `POST /api/vuln/check` — vulnerability correlation
- `POST /api/vuln/update` — update CVE database
- `GET /api/system/health` — health check (no auth)
- `GET /api/system/privileges` — privilege detection
- Bearer token authentication (`--api-key`)
- Rate limiting (1 scan/sec per target)
- WebSocket connection limits
- Maximum 10 concurrent scans
- Background scan cleanup sweep
- CORS configuration for localhost development

### rustmap-python

Python bindings via PyO3.

- `scan()` — synchronous scan function
- `async_scan()` — async scan coroutine
- `scan_with_config()` / `async_scan_with_config()` — config-based variants
- `stream_scan()` — async iterator with real-time events and `cancel()` method
- `parse_target()` / `parse_targets()` — target parsing utilities
- Exposed classes: ScanConfig, ScanResult, HostScanResult, Host, Port, ServiceInfo, OsFingerprint, GeoInfo, TlsFingerprint, CertificateInfo, TracerouteResult, TracerouteHop, ScriptResult, TimingSnapshot, ScanStream
- Python 3.9+ via abi3 stable ABI
- Built with maturin

### rustmap-cli

Command-line interface binary.

- Argument parsing via clap (100+ flags, nmap-compatible)
- `-A` flag expansion (OS + service + scripts)
- Timing template selection and validation
- Multi-scan-type support (e.g., `-s SU` for SYN + UDP)
- Script execution integration
- Output format selection and multi-file writing
- Watch/continuous mode with webhook and on-change command support
- Scan profiles (7 built-in + user-defined, TOML persistence)
- Self-test diagnostics (8 checks: privileges, pcap, raw sockets, interfaces, DNS, loopback, DB, GeoIP)
- Interactive TUI (ratatui + crossterm, 3-panel layout, 10 FPS)
- Sensitive argument redaction in logs
- Checkpoint management for scan resume

### rustmap-gui

Tauri 2 desktop application.

**Rust backend:**
- `GuiScanConfig` DTO — JSON-serializable config for Tauri IPC
- 5 Tauri commands: `start_scan`, `stop_scan`, `get_scan_history`, `export_results`, `check_privileges_cmd`
- `ScanState` — tracks active scans and history with error propagation
- `ScanStore` — persistent SQLite storage with graceful error handling

**Svelte 5 frontend:**
- Reactive stores using Svelte 5 runes ($state, $derived)
- Event listeners for real-time scan progress
- 27+ components: config form, results display, progress bar, history sidebar
- Dark theme with CSS custom properties
- Efficient host accumulation (push-based, not O(n^2) spread)

## Data Flow

### CLI Scan Pipeline

```
CLI args → ScanConfig → ScanEngine::run()
  → Host Discovery (parallel, 8 probe types)
  → Port Scan (parallel per host, semaphore-bounded)
    → MTU Discovery (optional, IPv4)
    → Service Enrichment (port map)
    → Service Detection (banner grab + probes + QUIC)
    → OS Detection (active + passive + TLS)
    → Uptime Estimation (TCP timestamps)
    → Traceroute (TCP SYN / UDP probes)
  → Script Execution (portrule, hostrule, pre/post)
  → GeoIP Enrichment (optional)
  → Vulnerability Correlation (optional)
  → Output Formatting → stdout / files (9 formats)
  → Database Storage (optional, SQLite)
  → Topology Graph Export (optional, DOT/GraphML/JSON)
```

### GUI Streaming Pipeline

```
GuiScanConfig → into_scan_config() → ScanEngine::run_streaming()
  → mpsc::Sender<ScanEvent>
    → Tauri event relay task
      → app.emit("host-result", payload)
        → Svelte event listener
          → scanState store update (push-based)
            → UI re-render (HostCard)
```

### API Server Pipeline

```
POST /api/scans (JSON body) → ScanConfig validation
  → spawn tokio task → ScanEngine::run_streaming()
    → mpsc channel → WebSocket broadcast
    → ScanState tracking (status, progress)
    → Result storage on completion
  → GET /api/scans/{id} → JSON response
  → WS /api/scans/{id}/events → real-time ScanEvent stream
```

### Python Binding Pipeline

```
Python: rustmap.scan("target") → PyO3 → ScanConfig
  → tokio runtime → ScanEngine::run()
    → ScanResult → PyO3 → Python ScanResult object

Python: async for event in rustmap.stream_scan(config):
  → PyO3 → ScanEngine::run_streaming()
    → mpsc channel → Python async iterator
      → ScanEvent → PyO3 → Python StreamEvent object
```

## Concurrency Model

- **Host parallelism**: `tokio::task::JoinSet` + `tokio::sync::Semaphore` bounds concurrent host scans
- **Per-host probes**: Scanner implementations manage their own concurrency (connect scan uses tokio::spawn per port, raw scans use send/receive/timeout task pattern)
- **Timing**: `TimingController` is `Send + Sync` via `Mutex<TimingInner>`, shared across probe tasks via `Arc`
- **GUI**: Scan runs in spawned tokio task, events flow through `mpsc` channel to Tauri event relay task
- **API**: Each scan runs in an independent tokio task, WebSocket connections get their own broadcast receiver
- **Python**: tokio runtime managed internally, GIL released during scan execution

## Key Design Decisions

1. **Edition 2024** — enables let-chains, reserves `gen` keyword (use `r#gen()` for rand)
2. **Resolver 3** — workspace-level dependency resolution
3. **`ScanConfig: Clone`** — allows sharing across spawned tasks
4. **`Scanner: Send + Sync`** — enables `Arc<dyn Scanner>` for parallel host scanning
5. **`Box<HostScanResult>` in ScanEvent** — clippy large_enum_variant compliance
6. **GuiScanConfig DTO** — clean JSON-serializable boundary between frontend and Rust, avoids adding Serialize to internal types with Duration fields
7. **Best-effort event sending** — `let _ = tx.send(...)` so dropped receivers don't crash scans
8. **Feature-gated optional crates** — cloud, wasm, tui are opt-in to keep default binary small
9. **PyO3 abi3** — single Python wheel works across Python 3.9+
10. **Bundled SQLite** — no system dependency, consistent behavior across platforms
