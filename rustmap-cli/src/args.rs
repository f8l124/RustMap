use clap::Parser;

/// Default max hostgroup size (matches nmap).
pub const DEFAULT_MAX_HOSTGROUP: usize = 256;

/// rustmap — a network scanner written in Rust
#[derive(Parser, Debug)]
#[command(name = "rustmap", version, about = "Network scanner inspired by nmap")]
pub struct Args {
    /// Target host(s): IP, CIDR, range, or hostname
    #[arg(value_name = "TARGET", required_unless_present_any = ["list_profiles", "history", "vuln_update", "api", "resume", "self_test"], num_args = 1..)]
    pub targets: Vec<String>,

    /// Port specification (e.g., 80, 80,443, 1-1024). Defaults to top 1000 ports.
    #[arg(short = 'p', long = "ports", value_name = "PORTS")]
    pub ports: Option<String>,

    /// Aggressive scan: enable OS detection, version detection, default scripts
    #[arg(short = 'A')]
    pub aggressive: bool,

    /// Fast mode: scan top 100 ports
    #[arg(short = 'F', conflicts_with = "top_ports")]
    pub fast_mode: bool,

    /// Scan the N most common ports
    #[arg(long = "top-ports", value_name = "N")]
    pub top_ports: Option<usize>,

    /// Scan type: S=SYN, T=connect, U=UDP, F=FIN, N=NULL, X=Xmas, A=ACK, W=Window, M=Maimon, Z=SCTP
    #[arg(short = 's', long = "scan-type", value_name = "TYPE")]
    pub scan_type: Option<String>,

    /// Timing template (0-5): 0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane
    #[arg(short = 'T', value_name = "0-5", value_parser = clap::value_parser!(u8).range(0..=5))]
    pub timing: Option<u8>,

    /// Increase verbosity level (use -v or -vv)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Connection timeout in milliseconds (default: auto from timing template)
    #[arg(long = "timeout", value_name = "MS")]
    pub timeout_ms: Option<u64>,

    /// Maximum concurrent connections (default: auto from timing template)
    #[arg(long = "max-parallelism", value_name = "N")]
    pub concurrency: Option<usize>,

    // --- Rate limiting ---
    /// Minimum packet send rate (packets/sec)
    #[arg(long = "min-rate", value_name = "N")]
    pub min_rate: Option<f64>,

    /// Maximum packet send rate (packets/sec)
    #[arg(long = "max-rate", value_name = "N")]
    pub max_rate: Option<f64>,

    /// Minimum inter-probe delay in milliseconds (overrides timing template)
    #[arg(long = "scan-delay", value_name = "MS")]
    pub scan_delay_ms: Option<u64>,

    /// Maximum inter-probe delay in milliseconds (when > scan-delay, delay is randomized for jitter)
    #[arg(long = "max-scan-delay", value_name = "MS")]
    pub max_scan_delay_ms: Option<u64>,

    // --- Host parallelism ---
    /// Minimum hosts to scan in parallel
    #[arg(long = "min-hostgroup", default_value = "1", value_name = "N")]
    pub min_hostgroup: usize,

    /// Maximum hosts to scan in parallel
    #[arg(long = "max-hostgroup", default_value = "256", value_name = "N")]
    pub max_hostgroup: usize,

    /// Per-host timeout in milliseconds (0 = no timeout)
    #[arg(long = "host-timeout", default_value = "0", value_name = "MS")]
    pub host_timeout_ms: u64,

    // --- Service/version detection flags ---
    /// Enable service/version detection
    #[arg(long = "sV")]
    pub service_version: bool,

    /// Version detection intensity (0-9)
    #[arg(long = "version-intensity", value_name = "LEVEL", default_value = "7", value_parser = clap::value_parser!(u8).range(0..=9))]
    pub version_intensity: u8,

    /// Disable QUIC/HTTP3 probing during service detection
    #[arg(long = "no-quic")]
    pub no_quic: bool,

    // --- OS detection flags ---
    /// Enable OS detection
    #[arg(short = 'O')]
    pub os_detection: bool,

    // --- Host discovery flags ---
    /// Ping scan only, no port scan
    #[arg(long = "sn")]
    pub ping_only: bool,

    /// Skip host discovery, treat all hosts as up
    #[arg(long = "Pn")]
    pub skip_discovery: bool,

    /// ICMP echo discovery
    #[arg(long = "PE")]
    pub icmp_echo: bool,

    /// TCP SYN ping discovery (comma-separated ports, default: 443)
    #[arg(long = "PS", value_name = "PORTS")]
    pub tcp_syn_ping: Option<String>,

    /// TCP ACK ping discovery (comma-separated ports, default: 80)
    #[arg(long = "PA", value_name = "PORTS")]
    pub tcp_ack_ping: Option<String>,

    /// ICMP timestamp discovery
    #[arg(long = "PP")]
    pub icmp_timestamp: bool,

    /// UDP ping discovery (comma-separated ports, default: 40125)
    #[arg(long = "PU", value_name = "PORTS")]
    pub udp_ping: Option<String>,

    /// ARP ping discovery (local subnet only)
    #[arg(long = "PR")]
    pub arp_ping: bool,

    /// HTTP ping discovery (comma-separated ports, default: 80)
    #[arg(long = "PH", value_name = "PORTS")]
    pub http_ping: Option<String>,

    /// HTTPS/TLS ping discovery (comma-separated ports, default: 443)
    #[arg(long = "PHT", value_name = "PORTS")]
    pub https_ping: Option<String>,

    // --- Scripting flags ---
    /// Run scripts (comma-separated names, categories, or globs)
    #[arg(long = "script", value_name = "SCRIPTS")]
    pub script: Option<String>,

    /// Script arguments (key1=val1,key2=val2)
    #[arg(long = "script-args", value_name = "ARGS")]
    pub script_args: Option<String>,

    /// Shorthand for --script=default (run default category scripts)
    #[arg(short = 'C', long = "sC")]
    pub default_scripts: bool,

    // --- Output flags ---
    /// Normal output to file
    #[arg(long = "oN", value_name = "FILE")]
    pub output_normal: Option<String>,

    /// XML output to file
    #[arg(long = "oX", value_name = "FILE")]
    pub output_xml: Option<String>,

    /// Grepable output to file
    #[arg(long = "oG", value_name = "FILE")]
    pub output_grepable: Option<String>,

    /// JSON output to file
    #[arg(long = "oJ", value_name = "FILE")]
    pub output_json: Option<String>,

    /// YAML output to file
    #[arg(long = "oY", value_name = "FILE")]
    pub output_yaml: Option<String>,

    /// CSV output to file
    #[arg(long = "oC", value_name = "FILE")]
    pub output_csv: Option<String>,

    /// CEF (Common Event Format) output to file (for ArcSight/Splunk)
    #[arg(long = "oCEF", value_name = "FILE")]
    pub output_cef: Option<String>,

    /// LEEF (Log Event Extended Format) output to file (for IBM QRadar)
    #[arg(long = "oLEEF", value_name = "FILE")]
    pub output_leef: Option<String>,

    /// HTML report to file (self-contained with charts and tables)
    #[arg(long = "oH", value_name = "FILE")]
    pub output_html: Option<String>,

    /// Output in all formats (creates basename.nmap, .xml, .gnmap, .json, .yaml, .csv)
    #[arg(long = "oA", value_name = "BASENAME")]
    pub output_all: Option<String>,

    /// Only show open ports in output
    #[arg(long = "open")]
    pub open_only: bool,

    /// Show reason for port state
    #[arg(long = "reason")]
    pub show_reason: bool,

    /// Randomize the order in which ports are scanned
    #[arg(long = "randomize-ports")]
    pub randomize_ports: bool,

    // --- Evasion flags ---
    /// Use the specified source port for all probes
    #[arg(short = 'g', long = "source-port", value_name = "PORT")]
    pub source_port: Option<u16>,

    /// Decoy scanning: -D decoy1,ME,decoy2
    #[arg(short = 'D', long = "decoy", value_name = "DECOYS")]
    pub decoys: Option<String>,

    /// Fragment IP packets for IDS evasion
    #[arg(short = 'f', long = "frag")]
    pub fragment: bool,

    /// Append hex-encoded data to outgoing packets (e.g., "deadbeef")
    #[arg(long = "data-hex", value_name = "HEX")]
    pub data_hex: Option<String>,

    /// Append ASCII string as data to outgoing packets
    #[arg(long = "data-string", value_name = "STRING")]
    pub data_string: Option<String>,

    /// Append N random bytes to outgoing packets (for padding/evasion)
    #[arg(long = "data-length", value_name = "N")]
    pub data_length: Option<usize>,

    /// Perform traceroute after port scan
    #[arg(long = "traceroute")]
    pub traceroute: bool,

    /// Discover path MTU to each host (IPv4 only, requires raw sockets)
    #[arg(long = "mtu-discovery")]
    pub mtu_discovery: bool,

    /// Route TCP connections through a SOCKS5 proxy (e.g., socks5://127.0.0.1:9050)
    #[arg(long = "proxy", value_name = "URL")]
    pub proxy: Option<String>,

    /// Custom DNS server(s) for hostname resolution (comma-separated IPs)
    #[arg(long = "dns-servers", value_name = "IPS")]
    pub dns_servers: Option<String>,

    /// DNS query timeout in milliseconds (default: 5000)
    #[arg(long = "resolve-timeout", value_name = "MS", default_value = "5000")]
    pub resolve_timeout: u64,

    // --- Topology flags ---
    /// Generate network topology graph (dot, graphml, json)
    #[arg(long = "topology", value_name = "FORMAT")]
    pub topology: Option<String>,

    /// Write topology graph to file (default: stdout)
    #[arg(long = "topology-output", value_name = "FILE")]
    pub topology_output: Option<String>,

    // --- Database flags ---
    /// Do not save scan results to the database
    #[arg(long = "no-db")]
    pub no_db: bool,

    /// Show changes compared to the last scan of the same target(s)
    #[arg(long = "diff")]
    pub diff: bool,

    /// List scan history from the database
    #[arg(long = "history")]
    pub history: bool,

    /// Compare two scan IDs (format: OLD_ID,NEW_ID)
    #[arg(long = "diff-scans", value_name = "OLD_ID,NEW_ID")]
    pub diff_scans: Option<String>,

    /// Resume an interrupted scan by scan ID
    #[arg(long = "resume", value_name = "SCAN_ID")]
    pub resume: Option<String>,

    /// Use historical data to prioritize likely-open ports first
    #[arg(long = "predict-ports")]
    pub predict_ports: bool,

    /// Disable adaptive timing (use template defaults only)
    #[arg(long = "no-adaptive")]
    pub no_adaptive: bool,

    /// Skip discovery for hosts known to always be up (requires scan history)
    #[arg(long = "fast-discovery")]
    pub fast_discovery: bool,

    /// Show the learned network profile for targets and exit
    #[arg(long = "show-profile")]
    pub show_profile: bool,

    // --- Profile flags ---
    /// Use a named scan profile (built-in or user-defined)
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// Save current CLI arguments as a named profile
    #[arg(long = "save-profile", value_name = "NAME")]
    pub save_profile: Option<String>,

    /// List available scan profiles and exit
    #[arg(long = "list-profiles")]
    pub list_profiles: bool,

    // --- Watch mode flags ---
    /// Enable continuous watch mode: rescan at intervals and report changes
    #[arg(long = "watch")]
    pub watch: bool,

    /// Interval between scans in seconds (default: 300)
    #[arg(long = "interval", value_name = "SECS", default_value = "300")]
    pub watch_interval: u64,

    /// POST change notifications to this webhook URL (JSON payload)
    #[arg(long = "webhook", value_name = "URL")]
    pub webhook_url: Option<String>,

    /// Run this shell command when changes are detected
    #[arg(long = "on-change", value_name = "CMD")]
    pub on_change_cmd: Option<String>,

    // --- Vulnerability flags ---
    /// Correlate detected services against known CVEs
    #[arg(long = "vuln-check")]
    pub vuln_check: bool,

    /// Update the local CVE database from NVD
    #[arg(long = "vuln-update")]
    pub vuln_update: bool,

    /// Minimum CVSS score to report (default: 0.0 = all)
    #[arg(long = "vuln-min-cvss", value_name = "SCORE", default_value = "0.0")]
    pub vuln_min_cvss: f64,

    // --- GeoIP flags ---
    /// Enrich results with geolocation and ASN data (requires GeoLite2 MMDB files)
    #[arg(long = "geoip")]
    pub geoip: bool,

    /// Directory containing GeoLite2 MMDB files (default: auto-detect)
    #[arg(long = "geoip-db", value_name = "DIR")]
    pub geoip_db: Option<String>,

    // --- Cloud discovery flags ---
    /// Discover targets from a cloud provider (aws, azure, gcp)
    #[arg(long = "cloud", value_name = "PROVIDER")]
    pub cloud_provider: Option<String>,

    /// Cloud regions to enumerate (comma-separated; default: all)
    #[arg(long = "cloud-regions", value_name = "REGIONS")]
    pub cloud_regions: Option<String>,

    /// Only include running instances in cloud discovery
    #[arg(long = "cloud-running-only")]
    pub cloud_running_only: bool,

    /// Filter cloud instances by tag (format: key=value, can be repeated)
    #[arg(long = "cloud-tag", value_name = "KEY=VALUE")]
    pub cloud_tags: Vec<String>,

    // --- TUI flag ---
    /// Launch interactive terminal UI
    #[arg(long = "tui")]
    pub tui: bool,

    // --- API server flags ---
    /// Start as an HTTP/WebSocket API server
    #[arg(long = "api")]
    pub api: bool,

    /// Listen address for the API server (default: 127.0.0.1:8080)
    #[arg(long = "listen", value_name = "ADDR:PORT", default_value = "127.0.0.1:8080")]
    pub listen: String,

    /// Bearer token for API authentication (optional)
    #[arg(long = "api-key", value_name = "TOKEN")]
    pub api_key: Option<String>,

    /// Run built-in self-test diagnostics and exit
    #[arg(long = "self-test")]
    pub self_test: bool,
}
