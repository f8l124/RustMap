# RustMap

A fast, comprehensive network scanner written in Rust, inspired by nmap. Features 10 scan types including SCTP, service/OS detection, 54 built-in scripts, vulnerability correlation, GeoIP enrichment, cloud asset discovery, a REST API, an interactive TUI, Python bindings, and a Tauri desktop GUI.

## Features

### Core Scanning
- **10 scan types** — TCP Connect, SYN, FIN, NULL, Xmas, ACK, Window, Maimon, UDP, SCTP INIT
- **Host discovery** — ICMP echo/timestamp, TCP SYN/ACK ping, UDP ping, ARP ping, HTTP/HTTPS ping
- **Service detection** — Banner grabbing, pattern matching, active probes, QUIC/HTTP3 detection (`--sV`)
- **OS fingerprinting** — Active TCP probes, passive p0f database, TLS fingerprinting (`-O`)
- **Traceroute** — Hop-by-hop path discovery with loop detection (`--traceroute`)
- **MTU discovery** — Path MTU detection for IPv4 hosts (`--mtu-discovery`)

### Scripting & Detection
- **54 built-in scripts** — HTTP, SMB, DNS, SNMP, LDAP, RDP, VNC, MQTT, NTP, SIP, databases, Docker, and more
- **Lua scripting engine** — nmap-compatible script API with sandbox, TCP/UDP socket support (`--script`)
- **Python script support** — Subprocess-based execution via JSON stdin/stdout protocol
- **WASM script support** — Optional WebAssembly sandbox via wasmtime (feature flag)
- **Vulnerability correlation** — Match detected services against bundled CVEs, with NVD API updates (`--vuln-check`)
- **QUIC/HTTP3 probing** — Detect QUIC-enabled services and HTTP/3 support on UDP ports

### Intelligence & Enrichment
- **GeoIP enrichment** — Country, city, coordinates, ASN, and organization via GeoLite2 (`--geoip`)
- **Cloud asset discovery** — Enumerate AWS EC2, Azure VMs, and GCP Compute instances as scan targets (`--cloud`)
- **Risk scoring** — Automated risk assessment based on open ports, services, and vulnerabilities
- **Uptime estimation** — TCP timestamp-based uptime calculation

### Advanced Features
- **Scan profiles** — 7 built-in profiles: quick, network-discovery, web-audit, full-audit, stealth, iot-scan, aggressive (`--profile`)
- **Watch/continuous mode** — Rescan at intervals, detect changes, send webhooks or run commands (`--watch`)
- **Scan resume/pause** — Checkpoint interrupted scans and resume later (`--resume`)
- **REST API server** — HTTP/WebSocket API for remote scan management (`--api`)
- **Interactive TUI** — Real-time terminal dashboard with host list, port detail, and event log (`--tui`)
- **Network topology** — Generate DOT, GraphML, or JSON graphs from traceroute data (`--topology`)
- **Scan history & diff** — SQLite-backed scan storage with change comparison (`--history`, `--diff`)
- **Port prediction** — Use historical scan data to prioritize likely-open ports (`--predict-ports`)
- **Adaptive timing** — TCP-like congestion control, RTT estimation, learned timing from history (`-T0` to `-T5`)
- **SOCKS5 proxy** — Route TCP scans through a SOCKS5 proxy with optional authentication (`--proxy`)
- **Custom DNS** — Specify DNS servers for hostname resolution (`--dns-servers`)
- **Evasion** — Decoy scanning, IP fragmentation, source port spoofing, custom payloads
- **Self-test diagnostics** — Built-in system checks for privileges, pcap, DNS, interfaces (`--self-test`)

### Output & Integration
- **9 output formats** — Normal, XML, JSON, Grepable, YAML, CSV, CEF (ArcSight/Splunk), LEEF (QRadar), HTML report
- **Desktop GUI** — Tauri 2 app with Svelte 5, real-time per-host result streaming
- **Python bindings** — PyO3-based sync/async API with streaming support (`pip install rustmap`)

## Quick Start

```bash
# TCP Connect scan (no privileges required)
rustmap 192.168.1.1

# SYN scan on specific ports (requires admin/root)
rustmap -s S -p 22,80,443 192.168.1.0/24

# Aggressive scan: OS + service detection + scripts
rustmap -A 10.0.0.1

# Fast scan (top 100 ports) with service detection
rustmap -F --sV scanme.nmap.org

# UDP scan with timing template
rustmap -s U -T4 192.168.1.1

# SCTP INIT scan
rustmap -s Z -p 2905,3868,5060 10.0.0.1

# Interactive terminal UI
rustmap --tui -A 192.168.1.0/24

# Use a scan profile
rustmap --profile web-audit 10.0.0.0/24

# Watch mode: rescan every 5 minutes, notify on changes
rustmap --watch --interval 300 --webhook http://slack.example.com/hook 192.168.1.0/24

# Check for known vulnerabilities
rustmap -A --vuln-check 10.0.0.1

# GeoIP enrichment
rustmap --geoip --sV scanme.nmap.org

# Cloud asset discovery (scan all running AWS EC2 instances)
rustmap --cloud aws --cloud-running-only -A

# Route through a SOCKS5 proxy
rustmap --proxy socks5://127.0.0.1:9050 -s T 10.0.0.1

# Start as an API server
rustmap --api --listen 127.0.0.1:8080 --api-key mysecret

# Generate network topology graph
rustmap --traceroute --topology dot --topology-output network.dot 192.168.1.0/24

# Resume an interrupted scan
rustmap --resume scan-abc123

# Export in multiple formats at once
rustmap -A --oA scan_results 10.0.0.1

# Self-test diagnostics
rustmap --self-test
```

## Installation

### Pre-built Binaries

Download from the [Releases](https://github.com/f8l124/rustmap/releases) page:

| Platform | CLI | GUI |
|----------|-----|-----|
| Windows x86_64 | `rustmap-windows-x86_64.exe` | `RustMap_x64-setup.exe` (NSIS installer) |
| Linux x86_64 | `rustmap-linux-x86_64` | `.AppImage` / `.deb` |
| macOS x86_64 | `rustmap-macos-x86_64` | `rustmap-macos-x86_64.dmg` |
| macOS arm64 (Apple Silicon) | `rustmap-macos-arm64` | `rustmap-macos-arm64.dmg` |

### From Source

Requires Rust 1.85+ and platform-specific dependencies. See [BUILDING.md](BUILDING.md) for full instructions.

```bash
git clone https://github.com/f8l124/rustmap.git
cd rustmap

# Build CLI with default features (watch + API + TUI)
cargo build --release -p rustmap-cli --features tui

# Build with cloud discovery support
cargo build --release -p rustmap-cli --features "tui,cloud"
```

### Runtime Dependencies

| Platform | Requirement | Purpose |
|----------|-------------|---------|
| Windows | [Npcap](https://npcap.com) | Raw socket access (SYN, UDP, SCTP, discovery scans) |
| Linux | libpcap (`apt install libpcap0.8`) | Raw socket access |
| macOS | libpcap (built-in) | Raw socket access |
| All | Admin/root | Required for SYN, UDP, SCTP, and all raw-socket scans |

TCP Connect scans (`-s T`) work without elevated privileges or pcap libraries.

## CLI Reference

```
rustmap [OPTIONS] <TARGET>...
```

### Targets

Supports IPs, CIDR notation, ranges, and hostnames:

```
rustmap 192.168.1.1                   # Single IP
rustmap 192.168.1.0/24                # CIDR
rustmap 192.168.1.1-50                # Range
rustmap scanme.nmap.org               # Hostname
rustmap 10.0.0.1 10.0.0.2 10.0.0.3   # Multiple targets
```

### Scan Options

| Flag | Description |
|------|-------------|
| `-p PORTS` | Port spec: `80`, `80,443`, `1-1024`, `22,80,100-200` |
| `-s TYPE` | Scan type: `S`=SYN, `T`=Connect, `U`=UDP, `F`=FIN, `N`=NULL, `X`=Xmas, `A`=ACK, `W`=Window, `M`=Maimon, `Z`=SCTP |
| `-T 0-5` | Timing: 0=Paranoid, 1=Sneaky, 2=Polite, 3=Normal, 4=Aggressive, 5=Insane |
| `-A` | Aggressive: enables `-O`, `--sV`, `-sC` |
| `-F` | Fast mode: top 100 ports |
| `--top-ports N` | Scan N most common ports |
| `--sV` | Service/version detection |
| `--version-intensity 0-9` | Detection probe intensity (default: 7) |
| `--no-quic` | Disable QUIC/HTTP3 probing during service detection |
| `-O` | OS detection |
| `--Pn` | Skip host discovery |
| `--sn` | Ping scan only (no port scan) |
| `-v`, `-vv` | Increase verbosity |
| `--open` | Show only open ports |
| `--reason` | Show reason for port state |
| `--traceroute` | Perform traceroute after port scan |
| `--mtu-discovery` | Discover path MTU (IPv4 only, requires raw sockets) |

### Host Discovery

| Flag | Description |
|------|-------------|
| `--PE` | ICMP echo ping |
| `--PP` | ICMP timestamp ping |
| `--PS [PORTS]` | TCP SYN ping (default: 443) |
| `--PA [PORTS]` | TCP ACK ping (default: 80) |
| `--PU [PORTS]` | UDP ping (default: 40125) |
| `--PR` | ARP ping (local subnet only) |
| `--PH [PORTS]` | HTTP HEAD ping (default: 80, no raw sockets needed) |
| `--PHT [PORTS]` | HTTPS/TLS handshake ping (default: 443, no raw sockets needed) |

### Scripting

| Flag | Description |
|------|-------------|
| `-C` / `--sC` | Run default category scripts |
| `--script SCRIPTS` | Run specific scripts (names, categories, or globs) |
| `--script-args ARGS` | Script arguments (`key1=val1,key2=val2`) |

### Timing & Performance

| Flag | Description |
|------|-------------|
| `--timeout MS` | Connection timeout in milliseconds |
| `--max-parallelism N` | Max concurrent connections per host |
| `--min-rate N` | Minimum packets per second |
| `--max-rate N` | Maximum packets per second |
| `--scan-delay MS` | Delay between probes |
| `--max-scan-delay MS` | Maximum probe delay (jitter) |
| `--min-hostgroup N` | Minimum parallel hosts |
| `--max-hostgroup N` | Maximum parallel hosts (default: 256) |
| `--host-timeout MS` | Per-host timeout (0 = no timeout) |
| `--no-adaptive` | Disable adaptive timing |

### Profiles

| Flag | Description |
|------|-------------|
| `--profile NAME` | Use a scan profile |
| `--save-profile NAME` | Save current CLI args as a custom profile |
| `--list-profiles` | List available profiles |

Built-in profiles:

| Profile | Description |
|---------|-------------|
| `quick` | Top 100 ports, T4 timing |
| `network-discovery` | Host discovery + top 100 ports, no service detection |
| `web-audit` | HTTP/HTTPS ports (80, 443, 8080, 8443, 8000, 3000, 5000) with scripts |
| `full-audit` | All 65535 ports, full detection, diff enabled |
| `stealth` | T1 timing, randomized ports, source port 53, fragmentation |
| `iot-scan` | IoT device ports (22, 23, 80, 443, 554, 1883, 5683, 8080, etc.) |
| `aggressive` | Full detection with traceroute, T4 timing |

### Watch Mode

| Flag | Description |
|------|-------------|
| `--watch` | Enable continuous rescan mode |
| `--interval SECS` | Time between scans (default: 300) |
| `--webhook URL` | POST JSON change notifications to URL |
| `--on-change CMD` | Run shell command when changes detected |

### Vulnerability Checking

| Flag | Description |
|------|-------------|
| `--vuln-check` | Correlate services against known CVEs |
| `--vuln-update` | Update local CVE database from NVD |
| `--vuln-min-cvss SCORE` | Minimum CVSS score to report (default: 0.0) |

### GeoIP Enrichment

| Flag | Description |
|------|-------------|
| `--geoip` | Enrich results with geolocation and ASN data |
| `--geoip-db DIR` | Custom GeoLite2 MMDB directory |

Requires GeoLite2 City and ASN MMDB files. Place them in `~/.rustmap/geoip/` or specify a directory with `--geoip-db`. Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

### Cloud Asset Discovery

| Flag | Description |
|------|-------------|
| `--cloud PROVIDER` | Discover targets from cloud provider (`aws`, `azure`, `gcp`) |
| `--cloud-regions REGIONS` | Comma-separated regions to enumerate |
| `--cloud-running-only` | Include only running instances |
| `--cloud-tag KEY=VALUE` | Filter by instance tag (repeatable) |

Uses standard cloud SDK credentials (AWS profiles, Azure CLI, GCP application default credentials).

### Network Topology

| Flag | Description |
|------|-------------|
| `--topology FORMAT` | Generate graph: `dot`, `graphml`, or `json` |
| `--topology-output FILE` | Write graph to file (default: stdout) |

### Scan Resume & History

| Flag | Description |
|------|-------------|
| `--resume SCAN_ID` | Resume an interrupted scan from checkpoint |
| `--no-db` | Don't save results to database |
| `--history` | Show past scan history |
| `--diff` | Compare against last scan of same targets |
| `--diff-scans OLD,NEW` | Compare two stored scan IDs |
| `--predict-ports` | Use history to prioritize likely-open ports |
| `--fast-discovery` | Skip discovery for known-up hosts |

### Evasion

| Flag | Description |
|------|-------------|
| `-g PORT` | Use specified source port |
| `-D DECOYS` | Decoy scanning (`decoy1,ME,decoy2`) |
| `-f` | Fragment IP packets |
| `--randomize-ports` | Randomize port scan order |
| `--data-hex HEX` | Append hex-encoded payload to probes |
| `--data-string TEXT` | Append ASCII string to probes |
| `--data-length N` | Append N random bytes to probes |

### Networking

| Flag | Description |
|------|-------------|
| `--proxy URL` | SOCKS5 proxy (`socks5://[user:pass@]host:port`) |
| `--dns-servers IPS` | Custom DNS servers (comma-separated) |
| `--resolve-timeout MS` | DNS query timeout (default: 5000) |

### API Server

| Flag | Description |
|------|-------------|
| `--api` | Start as HTTP/WebSocket API server |
| `--listen ADDR:PORT` | Listen address (default: `127.0.0.1:8080`) |
| `--api-key TOKEN` | Bearer token for authentication (optional) |

### Interactive TUI

| Flag | Description |
|------|-------------|
| `--tui` | Launch interactive terminal dashboard |

Three-panel layout: host list, port detail for selected host, and real-time event log. Keyboard navigation with 10 FPS refresh.

### Output

| Flag | Format |
|------|--------|
| `--oN FILE` | Normal text output |
| `--oX FILE` | XML output |
| `--oJ FILE` | JSON output |
| `--oG FILE` | Grepable output |
| `--oY FILE` | YAML output |
| `--oC FILE` | CSV output |
| `--oCEF FILE` | Common Event Format (ArcSight/Splunk) |
| `--oLEEF FILE` | Log Event Extended Format (QRadar) |
| `--oH FILE` | Self-contained HTML report with charts |
| `--oA BASE` | All formats (creates BASE.nmap, .xml, .json, .gnmap, .yaml, .csv) |

### Diagnostics

| Flag | Description |
|------|-------------|
| `--self-test` | Run 8 built-in diagnostic checks |

Checks: privilege level, Npcap/libpcap, raw socket access, network interfaces, DNS resolution, loopback connectivity, scan database, GeoIP database.

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for the complete reference.

## REST API

Start the API server with `rustmap --api`. Endpoints:

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans` | List scans (filter by status) |
| GET | `/api/scans/{id}` | Get scan result |
| DELETE | `/api/scans/{id}` | Delete a completed scan |
| POST | `/api/scans/{id}/stop` | Cancel a running scan |
| GET | `/api/scans/{id}/export?format=json` | Export in json/xml/grepable/normal/yaml/csv |
| GET | `/api/scans/{id}/diff/{other_id}` | Diff two scans |
| WS | `/api/scans/{id}/events` | Stream real-time scan events |
| POST | `/api/vuln/check` | Run vulnerability check |
| POST | `/api/vuln/update` | Update CVE database |
| GET | `/api/system/health` | Health check (no auth) |
| GET | `/api/system/privileges` | Check raw socket privileges |

Authentication: pass `--api-key TOKEN` at startup, then include `Authorization: Bearer TOKEN` header. WebSocket clients can use `?token=TOKEN` query parameter.

Rate limiting: 1 scan per second per target, maximum 10 concurrent scans.

## Built-in Scripts (54)

| Category | Scripts |
|----------|---------|
| HTTP/HTTPS | http-title, http-server-header, http-methods, http-robots, http-security-headers, http-favicon-hash, http-open-redirect, http-cors, py-http-title, py-http-headers-full |
| SMB/Windows | smb-os-discovery, smb-protocols, smb-security-mode, smb2-time, nbstat |
| DNS | dns-nsid, dns-recursion, dns-zone-transfer, dns-service-discovery |
| SNMP | snmp-info, snmp-sysdescr, snmp-interfaces |
| LDAP | ldap-rootdse, ldap-search, py-ldap-info |
| RDP/VNC | rdp-ntlm-info, rdp-enum-encryption, vnc-info |
| Databases | mysql-info, mongodb-info, redis-info, memcached-info, postgresql-info |
| Mail | smtp-commands, imap-capabilities, imap-ntlm-info, pop3-capabilities |
| SSH/TLS | ssh-hostkey, ssl-cert, py-ssh-version |
| MQTT/IoT | mqtt-subscribe, mqtt-version |
| NTP | ntp-info, ntp-monlist |
| SIP/VoIP | sip-methods, sip-enum-users |
| Docker | docker-version, docker-containers |
| Other | banner, telnet-banner, ftp-anon, pptp-version, rtsp-methods |

Scripts are written in Lua 5.4 (50) and Python (4). Custom scripts can be added to the `scripts/` directory. WASM scripts are supported when built with the `wasm` feature flag.

## Python Bindings

RustMap provides native Python bindings via PyO3:

```python
import rustmap

# Simple scan
result = rustmap.scan("192.168.1.1", ports="22,80,443", service_detection=True)
for host in result.hosts:
    print(f"{host.ip} - {host.status}")
    for port in host.ports:
        print(f"  {port.number}/{port.protocol} {port.state} {port.service_name}")

# Async scan
import asyncio
result = asyncio.run(rustmap.async_scan("10.0.0.1", timing=4))

# Streaming scan (real-time results)
async def stream():
    config = rustmap.ScanConfig(targets=["192.168.1.0/24"], service_detection=True)
    stream = rustmap.stream_scan(config)
    async for event in stream:
        if event.host_result:
            print(f"Host: {event.host_result.ip}")
    # stream.cancel() to abort early

asyncio.run(stream())
```

Build from source with `maturin develop` in the `rustmap-python/` directory.

## GUI

RustMap includes a Tauri 2 desktop application with a Svelte 5 frontend:

- Dark-themed interface with scan configuration forms
- Real-time per-host result streaming during scans
- Expandable host cards with port tables, OS info, and script results
- Export results in JSON, XML, Normal, or Grepable format
- Scan history sidebar
- Privilege detection and scan type availability

Installers are available on the [Releases](https://github.com/f8l124/rustmap/releases) page for Windows (NSIS), Linux (AppImage/deb), and macOS (dmg).

Build the GUI from source — see [BUILDING.md](BUILDING.md) for instructions.

## Interactive TUI

Launch with `rustmap --tui` for a real-time terminal dashboard:

- **Host list panel** — Table of discovered hosts with status, ports, OS
- **Port detail panel** — Ports and services for the selected host
- **Event log panel** — Real-time scan events and progress
- Keyboard navigation, 10 FPS refresh rate

The TUI is built with ratatui and crossterm. It requires the `tui` feature flag (enabled by default).

## Project Structure

```
rustmap/
  rustmap-types/      Type definitions (Host, Port, ScanConfig, ScanResult)
  rustmap-packet/     Raw packet construction and parsing (pcap/Npcap)
  rustmap-timing/     Congestion control, RTT estimation, rate limiting
  rustmap-scan/       Scanner implementations (TCP, UDP, SCTP, discovery, traceroute)
  rustmap-detect/     Service detection, OS fingerprinting, QUIC/HTTP3 probing
  rustmap-script/     Lua + Python + WASM scripting engine (54 built-in scripts)
  rustmap-output/     Output formatters (9 formats) + topology graph export
  rustmap-core/       Scan engine orchestration and target parsing
  rustmap-db/         SQLite scan storage, history, diff, checkpoints, profiles
  rustmap-vuln/       CVE correlation (bundled CVEs + NVD API updates)
  rustmap-geoip/      GeoIP and ASN enrichment (MaxMind GeoLite2)
  rustmap-cloud/      Cloud asset discovery (AWS, Azure, GCP)
  rustmap-api/        REST API server (axum, WebSocket streaming)
  rustmap-python/     Python bindings (PyO3, sync + async + streaming)
  rustmap-cli/        CLI binary (clap, TUI, watch mode)
  rustmap-gui/        Tauri 2 desktop GUI (Svelte 5 + TypeScript)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the detailed architecture guide.

## Known Issues

- **SYN/UDP/SCTP scans require elevated privileges.** TCP Connect (`-s T`) works without admin/root.
- **Npcap must be installed** on Windows for any raw-socket scan type. The Npcap SDK is only needed for building from source.
- **OS detection accuracy** depends on the target responding to all TCP probes. Firewalled hosts may produce incomplete fingerprints.
- **SCTP scanning** requires raw socket access and is not available through SOCKS5 proxies.
- **Watch mode** (`--watch`) does not currently support SYN scans on Windows without a persistent Npcap handle — use TCP Connect for long-running watch sessions.
- **API server** binds to `127.0.0.1` by default. To expose externally, use `--listen 0.0.0.0:8080` with `--api-key` for authentication.
- **Script execution** on TLS ports (443, 993, 995, etc.) is limited since the Lua socket API does not support TLS. Python scripts can use their own TLS libraries.
- **SOCKS5 proxy** only supports TCP Connect scans. Raw-socket scan types cannot be proxied.
- **GeoIP enrichment** requires MaxMind GeoLite2 MMDB files (free registration at maxmind.com).
- **Cloud discovery** requires valid cloud provider credentials configured in the environment.
- **MTU discovery** is IPv4 only and requires raw socket access.

## License

TBD
