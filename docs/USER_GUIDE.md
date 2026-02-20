# RustMap User Guide

## Table of Contents

- [Target Specification](#target-specification)
- [Scan Types](#scan-types)
- [Port Specification](#port-specification)
- [Host Discovery](#host-discovery)
- [Service Detection](#service-detection)
- [OS Detection](#os-detection)
- [Timing and Performance](#timing-and-performance)
- [Scripting](#scripting)
- [Vulnerability Checking](#vulnerability-checking)
- [GeoIP Enrichment](#geoip-enrichment)
- [Cloud Asset Discovery](#cloud-asset-discovery)
- [Network Topology](#network-topology)
- [Scan Profiles](#scan-profiles)
- [Watch Mode](#watch-mode)
- [Scan History and Diff](#scan-history-and-diff)
- [Evasion Techniques](#evasion-techniques)
- [Networking](#networking)
- [Interactive TUI](#interactive-tui)
- [REST API Server](#rest-api-server)
- [Python Bindings](#python-bindings)
- [Output](#output)
- [Self-Test Diagnostics](#self-test-diagnostics)
- [Examples](#examples)

---

## Target Specification

RustMap accepts one or more targets in the following formats:

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.1` | Scan one host |
| CIDR | `192.168.1.0/24` | Scan a subnet (254 hosts) |
| Range | `192.168.1.1-50` | Scan IPs 1 through 50 |
| Hostname | `scanme.nmap.org` | Resolved via DNS |
| Multiple | `10.0.0.1 10.0.0.2` | Space-separated |

```bash
rustmap 192.168.1.1
rustmap 192.168.1.0/24
rustmap 10.0.0.1-100
rustmap host1.example.com host2.example.com
```

## Scan Types

Select a scan type with `-s TYPE`. Multiple types can be combined (e.g., `-s SU` for SYN + UDP):

| Flag | Name | Privileges | Description |
|------|------|------------|-------------|
| `-s T` | TCP Connect | None | Full TCP handshake. Default when unprivileged. |
| `-s S` | TCP SYN | Admin/root | Half-open scan. Fast and stealthy. Default when privileged. |
| `-s U` | UDP | Admin/root | Sends UDP probes, detects via ICMP unreachable. |
| `-s F` | TCP FIN | Admin/root | Sends FIN flag only. May bypass stateless firewalls. |
| `-s N` | TCP Null | Admin/root | No flags set. May bypass stateless firewalls. |
| `-s X` | TCP Xmas | Admin/root | FIN+PSH+URG flags. |
| `-s A` | TCP ACK | Admin/root | Detects firewall rules (filtered vs unfiltered). |
| `-s W` | TCP Window | Admin/root | Like ACK but checks TCP window size for open/closed. |
| `-s M` | TCP Maimon | Admin/root | FIN+ACK. Exploits BSD-derived TCP stack behavior. |
| `-s Z` | SCTP INIT | Admin/root | SCTP INIT chunk scan. Detects SCTP services. |

If no scan type is specified, RustMap defaults to SYN scan when running with privileges, or TCP Connect when unprivileged.

```bash
# SYN + UDP scan
rustmap -s SU -p 22,80,443,53 target

# SCTP scan for telecom ports
rustmap -s Z -p 2905,3868,5060 target
```

## Port Specification

Use `-p` to specify ports:

```bash
rustmap -p 80 target              # Single port
rustmap -p 22,80,443 target       # Comma-separated
rustmap -p 1-1024 target          # Range
rustmap -p 22,80,100-200 target   # Mixed
```

### Port Presets

| Flag | Ports |
|------|-------|
| (default) | Top 1000 most common ports |
| `-F` | Top 100 most common ports (fast mode) |
| `--top-ports N` | Top N most common ports |
| `-p 1-65535` | All 65535 ports |

Port frequency data is sourced from the nmap-services database.

## Host Discovery

Before scanning ports, RustMap determines which hosts are alive. Control this behavior with:

| Flag | Method | Description |
|------|--------|-------------|
| `--PE` | ICMP Echo | Classic ping (requires privileges) |
| `--PP` | ICMP Timestamp | Alternative ping that may bypass firewalls |
| `--PS [PORTS]` | TCP SYN Ping | Send SYN to port(s), default 443 |
| `--PA [PORTS]` | TCP ACK Ping | Send ACK to port(s), default 80 |
| `--PU [PORTS]` | UDP Ping | Send UDP to port(s), default 40125 |
| `--PR` | ARP Ping | For local subnet only |
| `--PH [PORTS]` | HTTP Ping | HTTP HEAD request, default port 80 (no raw sockets needed) |
| `--PHT [PORTS]` | HTTPS Ping | TLS handshake, default port 443 (no raw sockets needed) |
| `--Pn` | Skip Discovery | Treat all hosts as up |
| `--sn` | Ping Only | Discovery only, no port scan |

Default behavior: When privileged, uses ICMP echo + TCP SYN(443) + TCP ACK(80). When unprivileged, uses TCP Connect probes.

```bash
# Ping scan only (discover hosts, no port scan)
rustmap --sn 192.168.1.0/24

# Skip discovery and scan all hosts
rustmap --Pn 10.0.0.1-254

# Custom discovery probes
rustmap --PE --PS 22,80 --PA 443 10.0.0.0/24

# Unprivileged discovery via HTTP/HTTPS
rustmap --PH 80,8080 --PHT 443,8443 10.0.0.0/24

# Use historical data to skip discovery for known-up hosts
rustmap --fast-discovery 10.0.0.0/24
```

## Service Detection

Enable with `--sV` or `-A`:

```bash
rustmap --sV -p 22,80,443 target
```

RustMap identifies services through:
1. **Port mapping** — well-known port-to-service associations (always active)
2. **Banner grabbing** — reads initial data sent by the service
3. **Pattern matching** — regex patterns against banner data
4. **Active probes** — sends protocol-specific requests for version extraction
5. **QUIC/HTTP3 probing** — detects QUIC-enabled services on UDP ports
6. **TLS fingerprinting** — cipher suites, extensions, certificate chain analysis

Control intensity with `--version-intensity LEVEL` (0-9, default 7). Higher values try more probes but take longer.

```bash
# Service detection with high intensity
rustmap --sV --version-intensity 9 target

# Disable QUIC probing
rustmap --sV --no-quic target
```

## OS Detection

Enable with `-O` or `-A`:

```bash
rustmap -O target
```

RustMap uses multiple techniques:
- **Active TCP probes** — SYN with specific options, ECN probes
- **Passive TCP fingerprinting** — TTL, window size, TCP options analysis (p0f database)
- **TLS fingerprinting** — Cipher suites and extensions from TLS handshake
- **Combined scoring** — Weighted results from all sources

OS detection works best when at least one open and one closed port are found.

## Timing and Performance

### Timing Templates

Use `-T` to select a template:

| Template | Name | Scan Delay | Max Retries | Initial Cwnd |
|----------|------|-----------|-------------|--------------|
| `-T0` | Paranoid | 5 minutes | 10 | 1 |
| `-T1` | Sneaky | 15 seconds | 10 | 1 |
| `-T2` | Polite | 400ms | 10 | 2 |
| `-T3` | Normal | None | 6 | 4 |
| `-T4` | Aggressive | None | 3 | 8 |
| `-T5` | Insane | None | 2 | 16 |

### Rate Limiting

```bash
# Set minimum send rate (packets/sec)
rustmap --min-rate 1000 target

# Set maximum send rate
rustmap --max-rate 500 target

# Both
rustmap --min-rate 100 --max-rate 1000 target
```

### Parallelism

```bash
# Max concurrent connections per host
rustmap --max-parallelism 200 target

# Control parallel host scanning
rustmap --min-hostgroup 4 --max-hostgroup 32 10.0.0.0/24

# Per-host timeout (milliseconds, 0 = no timeout)
rustmap --host-timeout 30000 10.0.0.0/24

# Connection timeout
rustmap --timeout 5000 target
```

### Scan Delay and Jitter

```bash
# Fixed delay between probes
rustmap --scan-delay 100 target

# Delay with jitter (random between scan-delay and max-scan-delay)
rustmap --scan-delay 50 --max-scan-delay 200 target

# Disable adaptive timing
rustmap --no-adaptive target
```

### Learned Timing

When scan history is available, RustMap can use previously observed network performance to optimize timing:

```bash
# Use historical data for timing
rustmap --predict-ports target
```

## Scripting

RustMap includes a Lua 5.4 scripting engine compatible with the nmap NSE API, plus Python and optional WASM script support.

```bash
# Run specific scripts
rustmap --script http-title,ssh-hostkey target

# Run default category scripts
rustmap -sC target
# or
rustmap --script default target

# Run all scripts matching a glob
rustmap --script "http*" target

# Pass arguments to scripts
rustmap --script http-title --script-args "http-title.url=/admin" target
```

### Script Categories

Scripts are organized into categories. Use `--script CATEGORY` to run all scripts in a category:
- `default` — safe, generally useful scripts
- `discovery` — service and host discovery
- `vuln` — vulnerability detection
- `auth` — authentication testing
- `safe` — scripts that don't send excessive traffic

### Built-in Scripts (54)

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

Scripts are sandboxed with memory and instruction limits. The `shortport` library provides port matching helpers (`shortport.http`, `shortport.ssl`, `shortport.port_or_service`).

## Vulnerability Checking

```bash
# Check for known vulnerabilities
rustmap -A --vuln-check target

# Update CVE database from NVD
rustmap --vuln-update

# Only report CVEs with CVSS >= 7.0
rustmap --vuln-check --vuln-min-cvss 7.0 target
```

RustMap correlates detected services against a local CVE database. The database includes bundled seed rules and can be updated from the National Vulnerability Database (NVD) API and CISA Known Exploited Vulnerabilities (KEV) catalog.

## GeoIP Enrichment

```bash
# Enrich results with geolocation and ASN data
rustmap --geoip --sV target

# Use a custom GeoLite2 database directory
rustmap --geoip --geoip-db /path/to/mmdb target
```

Requires MaxMind GeoLite2 City and ASN MMDB files. Download from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free registration required).

**Database search order:**
1. `--geoip-db DIR` (CLI flag)
2. `$RUSTMAP_GEOIP_DIR` environment variable
3. `~/.rustmap/geoip/`
4. Current working directory

**Data provided:**
- Country code and name
- City
- Latitude / longitude
- Timezone
- ASN (Autonomous System Number)
- AS Organization

## Cloud Asset Discovery

Automatically enumerate cloud instances as scan targets:

```bash
# Scan all AWS EC2 instances
rustmap --cloud aws -A

# Scan running Azure VMs in specific regions
rustmap --cloud azure --cloud-running-only --cloud-regions eastus,westus2 --sV

# Scan GCP instances with specific tags
rustmap --cloud gcp --cloud-tag env=production --cloud-running-only -A

# Filter by multiple tags
rustmap --cloud aws --cloud-tag env=staging --cloud-tag team=security --sV
```

**Supported providers:**
- **AWS** — EC2 instances (requires aws-sdk credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or AWS CLI profiles)
- **Azure** — Virtual Machines (requires Azure CLI login or `AZURE_SUBSCRIPTION_ID` + `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`)
- **GCP** — Compute Engine instances (requires application default credentials: `gcloud auth application-default login`)

Cloud discovery requires building with the `cloud` feature flag.

## Network Topology

Generate network topology graphs from traceroute data:

```bash
# DOT format (for Graphviz)
rustmap --traceroute --topology dot --topology-output network.dot 10.0.0.0/24
dot -Tpng network.dot -o network.png

# GraphML (for Gephi, yEd, Cytoscape)
rustmap --traceroute --topology graphml --topology-output network.graphml 10.0.0.0/24

# JSON (for programmatic processing)
rustmap --traceroute --topology json --topology-output network.json 10.0.0.0/24
```

**Graph features:**
- Node types: Scanner (blue), Router (yellow), Target (green), Unknown (gray)
- Node properties: IP, hostname, open ports, OS info, services
- Edge properties: TTL, RTT, weight
- Shared routers are deduplicated across traceroutes

## Scan Profiles

### Built-in Profiles

| Profile | Description |
|---------|-------------|
| `quick` | Top 100 ports, T4 timing |
| `network-discovery` | Host discovery + top 100 ports, no service detection |
| `web-audit` | HTTP/HTTPS ports (80, 443, 8080, 8443, 8000, 3000, 5000) with service detection and scripts |
| `full-audit` | All 65535 ports, service + OS detection, scripts, T4 timing, diff enabled |
| `stealth` | T1 timing, randomized ports, source port 53, IP fragmentation, max 1 host at a time |
| `iot-scan` | IoT device ports (22, 23, 80, 443, 554, 1883, 5683, 8080, 8443, 8883, 9100, 49152) |
| `aggressive` | Service + OS detection, scripts, traceroute, T4 timing |

```bash
# Use a built-in profile
rustmap --profile web-audit 10.0.0.0/24

# List available profiles
rustmap --list-profiles

# Save current args as a custom profile
rustmap -A -T4 --traceroute --save-profile my-audit 10.0.0.1
# Then use it later:
rustmap --profile my-audit 10.0.0.0/24
```

Custom profiles are saved as TOML files in `~/.rustmap/profiles/` (Linux/macOS) or `%APPDATA%\rustmap\profiles\` (Windows).

## Watch Mode

Continuously rescan targets and detect changes:

```bash
# Rescan every 5 minutes
rustmap --watch --interval 300 192.168.1.0/24

# Notify via webhook when changes detected
rustmap --watch --webhook https://hooks.slack.com/services/... 10.0.0.0/24

# Run a command on changes
rustmap --watch --on-change "notify-send 'Network change detected'" 10.0.0.0/24
```

**Change detection tracks:**
- New hosts appearing on the network
- Hosts going offline
- Port state changes (open/closed/filtered)
- Service changes (new, version changed, disappeared)

The `--on-change` command receives environment variables:
- `RUSTMAP_CHANGES_JSON` — JSON-encoded change details
- `RUSTMAP_SCAN_ID` — current scan ID
- `RUSTMAP_ITERATION` — scan iteration number

## Scan History and Diff

RustMap stores scan results in a SQLite database for comparison and analysis:

```bash
# View scan history
rustmap --history

# Compare against last scan of same targets
rustmap --diff 10.0.0.0/24

# Compare two specific scans
rustmap --diff-scans abc123,def456

# Use historical data to predict open ports
rustmap --predict-ports 10.0.0.0/24

# Skip discovery for previously-seen-up hosts
rustmap --fast-discovery 10.0.0.0/24

# Resume an interrupted scan
rustmap --resume abc123

# Disable database storage
rustmap --no-db 10.0.0.1
```

## Evasion Techniques

```bash
# Decoy scanning (sends from multiple source IPs)
rustmap -D 10.0.0.1,ME,10.0.0.3 -s S target

# IP fragmentation (split packets to evade IDS)
rustmap -f -s S target

# Use source port 53 (DNS) to bypass firewalls
rustmap -g 53 -s S target

# Randomize port scan order
rustmap --randomize-ports -s S target

# Custom packet payload
rustmap --data-hex "deadbeef" -s U target
rustmap --data-string "HELLO" -s U target
rustmap --data-length 32 -s U target

# Stealth profile (combines multiple evasion techniques)
rustmap --profile stealth target
```

## Networking

### SOCKS5 Proxy

Route TCP Connect scans through a SOCKS5 proxy:

```bash
# Basic SOCKS5 proxy
rustmap --proxy socks5://127.0.0.1:9050 -s T target

# SOCKS5 with authentication
rustmap --proxy socks5://user:pass@proxy.example.com:1080 -s T target
```

Only TCP Connect scans (`-s T`) can be proxied. Raw-socket scan types bypass the proxy.

### Custom DNS

```bash
# Use specific DNS servers
rustmap --dns-servers 8.8.8.8,1.1.1.1 target

# Increase DNS timeout (default: 5000ms)
rustmap --resolve-timeout 10000 target
```

### MTU Discovery

```bash
# Discover path MTU (IPv4 only)
rustmap --mtu-discovery target
```

## Interactive TUI

Launch a real-time terminal dashboard:

```bash
rustmap --tui -A 192.168.1.0/24
```

**Three-panel layout:**
1. **Host list** — Table of discovered hosts with status, port counts, OS
2. **Port detail** — Ports and services for the selected host
3. **Event log** — Real-time scan events, progress, and timing information

**Keyboard controls:**
- Arrow keys / j/k — Navigate host list
- q — Quit
- h — Toggle help panel

Refreshes at 10 FPS. Requires the `tui` feature flag (enabled by default).

## REST API Server

Start an HTTP/WebSocket API server for remote scan management:

```bash
# Start API server with authentication
rustmap --api --listen 127.0.0.1:8080 --api-key mysecret

# Start without authentication (local use only)
rustmap --api
```

### API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans` | List scans (filter by `?status=running`) |
| GET | `/api/scans/{id}` | Get scan result |
| DELETE | `/api/scans/{id}` | Delete a completed scan |
| POST | `/api/scans/{id}/stop` | Cancel a running scan |
| GET | `/api/scans/{id}/export?format=json` | Export (json/xml/grepable/normal/yaml/csv) |
| GET | `/api/scans/{id}/diff/{other_id}` | Diff two scans |
| WS | `/api/scans/{id}/events` | Stream real-time scan events |
| POST | `/api/vuln/check` | Run vulnerability check |
| POST | `/api/vuln/update` | Update CVE database |
| GET | `/api/system/health` | Health check (no auth required) |
| GET | `/api/system/privileges` | Check raw socket privileges |

### Authentication

Pass `--api-key TOKEN` at startup. Clients must include `Authorization: Bearer TOKEN` header. WebSocket clients can use `?token=TOKEN` query parameter.

### Example: Start a Scan via API

```bash
# Start a scan
curl -X POST http://localhost:8080/api/scans \
  -H "Authorization: Bearer mysecret" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.0/24"], "scan_type": "S", "service_detection": true}'

# Get scan result
curl http://localhost:8080/api/scans/SCAN_ID \
  -H "Authorization: Bearer mysecret"

# Stream events via WebSocket
websocat ws://localhost:8080/api/scans/SCAN_ID/events?token=mysecret
```

**Limits:** Rate limited to 1 scan per second per target, maximum 10 concurrent scans.

## Python Bindings

RustMap provides native Python bindings via PyO3:

```python
import rustmap

# Simple synchronous scan
result = rustmap.scan("192.168.1.1", ports="22,80,443", service_detection=True)
for host in result.hosts:
    print(f"{host.ip} - {host.status}")
    for port in host.ports:
        print(f"  {port.number}/{port.protocol} {port.state} {port.service_name}")

# Async scan
import asyncio

async def main():
    result = await rustmap.async_scan("10.0.0.1", timing=4, os_detection=True)
    for host in result.hosts:
        print(f"{host.ip}: {host.os_fingerprint}")

asyncio.run(main())

# Streaming scan (real-time results)
async def stream():
    config = rustmap.ScanConfig(
        targets=["192.168.1.0/24"],
        service_detection=True,
        timing=4,
    )
    stream = rustmap.stream_scan(config)
    async for event in stream:
        if event.host_result:
            host = event.host_result
            print(f"Host: {host.ip} ({len(host.ports)} ports)")
    # Call stream.cancel() to abort early

asyncio.run(stream())

# Target parsing
hosts = rustmap.parse_targets(["192.168.1.0/24", "10.0.0.1-5"])
print(f"Total targets: {len(hosts)}")
```

Build from source with `maturin develop --release` in the `rustmap-python/` directory.

## Output

### Formats

```bash
# Normal text
rustmap --oN scan.txt target

# XML
rustmap --oX scan.xml target

# JSON
rustmap --oJ scan.json target

# Grepable
rustmap --oG scan.gnmap target

# YAML
rustmap --oY scan.yaml target

# CSV
rustmap --oC scan.csv target

# Common Event Format (ArcSight/Splunk)
rustmap --oCEF scan.cef target

# Log Event Extended Format (IBM QRadar)
rustmap --oLEEF scan.leef target

# Self-contained HTML report
rustmap --oH scan.html target

# All formats at once
rustmap --oA scan_results target
# Creates: scan_results.nmap, scan_results.xml, scan_results.json,
#          scan_results.gnmap, scan_results.yaml, scan_results.csv
```

### Filtering

```bash
# Show only open ports
rustmap --open target

# Show reason for port state
rustmap --reason target
```

### Verbosity

```bash
rustmap -v target    # Verbose
rustmap -vv target   # Very verbose (includes timing stats)
```

## Self-Test Diagnostics

Run built-in diagnostic checks to verify your system is properly configured:

```bash
rustmap --self-test
```

**8 checks performed:**
1. Privilege level (admin/root)
2. Npcap/libpcap availability
3. Raw socket access
4. Network interface detection
5. DNS resolution
6. Loopback connectivity
7. Scan database accessibility
8. GeoIP database discovery

Each check reports PASS, WARN, or FAIL. Exit code 1 if any check fails.

## Examples

```bash
# Quick scan of a web server
rustmap -F --sV 93.184.216.34

# Full audit of a subnet
rustmap -A -T4 192.168.1.0/24

# Stealth SYN scan with rate limiting
rustmap -s S --max-rate 100 -T2 10.0.0.1

# UDP scan of DNS and SNMP ports
rustmap -s U -p 53,161,162 10.0.0.1-20

# Firewall detection with ACK scan
rustmap -s A -p 80,443 target

# Fast discovery sweep
rustmap --sn -T4 10.0.0.0/24

# Scan with JSON output, open ports only
rustmap --sV --oJ results.json --open 192.168.1.1

# Full vulnerability assessment with HTML report
rustmap -A --vuln-check --geoip --oH report.html 10.0.0.0/24

# Cloud security audit
rustmap --cloud aws --cloud-running-only --cloud-tag env=production \
  -A --vuln-check --oJ audit.json

# Network topology mapping
rustmap --traceroute --topology dot --topology-output map.dot \
  -sn 10.0.0.0/24

# Watch mode with Slack notifications
rustmap --watch --interval 600 \
  --webhook https://hooks.slack.com/services/T.../B.../xxx \
  192.168.1.0/24

# SCTP scan for telecom infrastructure
rustmap -s Z -p 2905,3868,5060,5061 --sV 10.0.0.1-50

# Stealth scan through Tor
rustmap --proxy socks5://127.0.0.1:9050 -s T -T2 target

# Interactive TUI with full detection
rustmap --tui -A -T4 192.168.1.0/24

# API server for team use
rustmap --api --listen 0.0.0.0:8080 --api-key $(openssl rand -hex 32)

# Run diagnostics
rustmap --self-test
```
