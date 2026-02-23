// TypeScript interfaces mirroring Rust serde types from rustmap-types
//
// IMPORTANT: These must match the actual serde serialization from Rust.
// - PortState uses #[serde(rename_all = "lowercase")] → "open", "closed", etc.
// - Fields with skip_serializing_if may be absent from JSON.

export interface GeoInfo {
  country_code?: string;
  country?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  asn?: number;
  as_org?: string;
}

export interface Host {
  ip: string;
  hostname: string | null;
  geo_info?: GeoInfo;
}

export type HostStatus = "Up" | "Down" | "Unknown";

// Rust PortState uses #[serde(rename_all = "lowercase")]
// OpenFiltered → "openfiltered", ClosedFiltered → "closedfiltered"
export type PortState = "open" | "closed" | "filtered" | "unfiltered" | "openfiltered" | "closedfiltered";

// Matches Rust ServiceInfo struct
export interface ServiceInfo {
  name: string;
  product: string | null;
  version: string | null;
  info: string | null;
  method: "None" | "PortBased" | "Banner" | "Probe" | "TlsProbe";
}

export interface Port {
  number: number;
  protocol: "Tcp" | "Udp" | "Sctp";
  state: PortState;
  service: string | null;
  service_info: ServiceInfo | null;
  reason?: string | null;
  script_results?: ScriptResult[];
  tls_info?: TlsServerFingerprint;
}

export interface OsFingerprint {
  os_family: string | null;
  os_generation: string | null;
  os_detail: string | null;
  accuracy: number | null;
  probe_results: OsProbeResults;
}

export interface OsProbeResults {
  syn_open: TcpFingerprint | null;
  syn_closed: TcpFingerprint | null;
  ack_open: TcpFingerprint | null;
  passive: TcpFingerprint | null;
  tls: TlsServerFingerprint | null;
}

export interface TcpFingerprint {
  initial_ttl: number;
  window_size: number;
  tcp_options: unknown[];
  df_bit: boolean;
  mss: number | null;
}

export interface CertificateInfo {
  subject_cn?: string;
  subject_dn?: string;
  issuer_cn?: string;
  issuer_dn?: string;
  serial?: string;
  not_before?: string;
  not_after?: string;
  san_dns?: string[];
  signature_algorithm?: string;
  public_key_info?: string;
  sha256_fingerprint?: string;
  self_signed?: boolean;
  chain_position?: number;
}

export interface TlsServerFingerprint {
  tls_version: number;
  cipher_suite: number;
  extensions: number[];
  compression_method: number;
  alpn?: string;
  ja4s?: string;
  sni?: string;
  certificate_chain?: CertificateInfo[];
}

export interface ScriptResult {
  id: string;
  output: string;
  elements?: unknown;
}

export interface TracerouteHop {
  ttl: number;
  ip: string | null;
  hostname: string | null;
  rtt: { secs: number; nanos: number } | null;
}

export interface TracerouteResult {
  target: Host;
  hops: TracerouteHop[];
  port: number;
  protocol: string;
}

export interface TimingSnapshot {
  srtt_us?: number;
  rto_us: number;
  rttvar_us?: number;
  cwnd: number;
  probes_sent: number;
  probes_responded: number;
  probes_timed_out: number;
  loss_rate: number;
}

export interface HostScanResult {
  host: Host;
  ports: Port[];
  scan_duration: { secs: number; nanos: number };
  host_status: HostStatus;
  discovery_latency: { secs: number; nanos: number } | null;
  os_fingerprint: OsFingerprint | null;
  traceroute?: TracerouteResult | null;
  timing_snapshot?: TimingSnapshot | null;
  host_script_results?: ScriptResult[];
  scan_error?: string | null;
  uptime_estimate?: { secs: number; nanos: number } | null;
  risk_score?: number | null;
  mtu?: number | null;
}

export type ScanType =
  | "TcpConnect"
  | "TcpSyn"
  | "TcpFin"
  | "TcpNull"
  | "TcpXmas"
  | "TcpAck"
  | "TcpWindow"
  | "TcpMaimon"
  | "Udp"
  | "Ping"
  | "SctpInit";

export interface ScanResult {
  hosts: HostScanResult[];
  total_duration: { secs: number; nanos: number };
  scan_type: ScanType;
  start_time?: { secs_since_epoch: number; nanos_since_epoch: number } | null;
  command_args?: string | null;
  num_services: number;
  pre_script_results?: ScriptResult[];
  post_script_results?: ScriptResult[];
}

// GUI-specific types

export interface GuiScanConfig {
  targets: string[];
  ports: string | null;
  scan_type: string;
  timing: number;
  service_detection: boolean;
  os_detection: boolean;
  discovery_mode: string;
  discovery_methods: string[];
  tcp_syn_ports: string | null;
  tcp_ack_ports: string | null;
  udp_ping_ports: string | null;
  http_ports: string | null;
  https_ports: string | null;
  timeout_ms: number;
  concurrency: number;
  max_hostgroup: number;
  host_timeout_ms: number;
  min_rate: number | null;
  max_rate: number | null;
  randomize_ports: boolean;
  source_port: number | null;
  fragment_packets: boolean;
  traceroute: boolean;
  version_intensity: number;
  scan_delay_ms: number;
  mtu_discovery: boolean;
  verbose: boolean;
  min_hostgroup: number;
  max_scan_delay_ms: number;
  probe_timeout_ms: number;
  quic_probing: boolean;
  proxy_url: string | null;
  decoys: string | null;
  pre_resolved_up: string | null;
  payload_type: string;
  payload_value: string | null;
  script_enabled: boolean;
  scripts: string[];
  script_args: string | null;
  custom_script_paths: string[];
  geoip_enabled: boolean;
  spoof_mac: string | null;
  ip_ttl: number | null;
  badsum: boolean;
  top_ports: number | null;
  ipv6_only: boolean;
  watch_enabled: boolean;
  watch_interval_secs: number;
}

export interface WatchIterationPayload {
  scan_id: string;
  iteration: number;
  diff: ScanDiff | null;
}

export interface ScriptInfo {
  id: string;
  description: string;
  categories: string[];
  language: string;
}

export interface PrivilegeInfo {
  raw_socket: boolean;
  pcap: boolean;
  npcap_installed: boolean;
}

// Matches ScanSummary from rustmap-db (lightweight, no embedded result)
export interface ScanHistoryEntry {
  scan_id: string;
  started_at: number;
  finished_at: number;
  scan_type: string;
  num_hosts: number;
  num_services: number;
  total_duration_ms: number;
  command_args: string | null;
}

export interface PortChange {
  ip: string;
  port: number;
  protocol: string;
  old_state: string | null;
  new_state: string | null;
}

export interface ScanDiff {
  old_scan_id: string;
  new_scan_id: string;
  new_hosts: string[];
  removed_hosts: string[];
  port_changes: PortChange[];
}

// Event payloads from Tauri backend

export interface ScanStartedPayload {
  scan_id: string;
  hosts_total: number;
}

export interface HostResultPayload {
  scan_id: string;
  index: number;
  result: HostScanResult;
  hosts_completed: number;
  hosts_total: number;
}

export interface ScanCompletePayload {
  scan_id: string;
  result: ScanResult;
}

export interface ScanErrorPayload {
  scan_id: string;
  error: string;
}

export interface ScanLogPayload {
  scan_id: string;
  message: string;
}

export interface PresetInfo {
  name: string;
  targets: string;
  scan_type: string;
  port_summary: string;
}

// Vulnerability types (from rustmap-vuln)
export interface VulnMatch {
  cve_id: string;
  cvss_score: number | null;
  description: string;
  matched_product: string;
  matched_version: string;
}

export interface PortVulnResult {
  port: number;
  protocol: string;
  product: string | null;
  version: string | null;
  vulns: VulnMatch[];
}

export interface HostVulnResult {
  ip: string;
  port_vulns: PortVulnResult[];
  risk_score: number | null;
}

// Checkpoint / Resume types
export interface CheckpointInfo {
  scan_id: string;
  created_at: number;
  updated_at: number;
  total_hosts: number;
  completed_count: number;
}
