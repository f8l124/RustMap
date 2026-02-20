use crate::error::DbError;

const SCHEMA_SQL: &str = r#"
-- Scan metadata (one row per scan invocation)
CREATE TABLE IF NOT EXISTS scans (
    id                TEXT PRIMARY KEY,
    started_at        INTEGER NOT NULL,
    finished_at       INTEGER NOT NULL,
    scan_type         TEXT NOT NULL,
    command_args      TEXT,
    timing_template   INTEGER,
    total_duration_ms INTEGER NOT NULL,
    num_hosts         INTEGER NOT NULL,
    num_services      INTEGER NOT NULL,
    result_json       TEXT NOT NULL
);

-- Per-host results (denormalized for fast queries)
CREATE TABLE IF NOT EXISTS host_results (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id              TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip                   TEXT NOT NULL,
    hostname             TEXT,
    host_status          TEXT NOT NULL,
    scan_duration_ms     INTEGER NOT NULL,
    discovery_latency_ms INTEGER,
    open_port_count      INTEGER NOT NULL,
    total_port_count     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_host_ip ON host_results(ip);
CREATE INDEX IF NOT EXISTS idx_host_scan ON host_results(scan_id);

-- Per-port results (for querying port history across scans)
CREATE TABLE IF NOT EXISTS port_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_result_id  INTEGER NOT NULL REFERENCES host_results(id) ON DELETE CASCADE,
    port_number     INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    state           TEXT NOT NULL,
    service         TEXT,
    service_product TEXT,
    service_version TEXT
);
CREATE INDEX IF NOT EXISTS idx_port_host ON port_results(host_result_id);

-- Learned network timing profiles
CREATE TABLE IF NOT EXISTS network_profiles (
    subnet             TEXT PRIMARY KEY,
    avg_rtt_ms         REAL,
    avg_loss_rate      REAL,
    recommended_timing INTEGER,
    last_updated       INTEGER NOT NULL,
    scan_count         INTEGER NOT NULL DEFAULT 0
);

-- Port history for prediction (times_open / times_scanned = probability)
CREATE TABLE IF NOT EXISTS port_history (
    ip              TEXT NOT NULL,
    subnet          TEXT NOT NULL,
    port_number     INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    times_open      INTEGER NOT NULL DEFAULT 0,
    times_scanned   INTEGER NOT NULL DEFAULT 0,
    last_seen_open  INTEGER,
    last_scanned    INTEGER NOT NULL,
    PRIMARY KEY (ip, port_number, protocol)
);
CREATE INDEX IF NOT EXISTS idx_port_history_subnet ON port_history(subnet, port_number);

-- Service cache for tracking service changes across scans
CREATE TABLE IF NOT EXISTS service_cache (
    ip              TEXT NOT NULL,
    port_number     INTEGER NOT NULL,
    protocol        TEXT NOT NULL,
    service_name    TEXT NOT NULL,
    product         TEXT,
    version         TEXT,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    times_seen      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (ip, port_number, protocol)
);

-- Host behavior profiles (tracks up/down patterns over time)
CREATE TABLE IF NOT EXISTS host_profiles (
    ip                  TEXT PRIMARY KEY,
    subnet              TEXT NOT NULL,
    times_scanned       INTEGER NOT NULL DEFAULT 0,
    times_up            INTEGER NOT NULL DEFAULT 0,
    times_down          INTEGER NOT NULL DEFAULT 0,
    avg_discovery_ms    REAL,
    last_seen_up        INTEGER,
    last_scanned        INTEGER NOT NULL,
    behavior            TEXT NOT NULL DEFAULT 'unknown'
);
CREATE INDEX IF NOT EXISTS idx_host_profiles_subnet ON host_profiles(subnet);

-- Timing telemetry per scan (aggregated from per-host TimingSnapshots)
CREATE TABLE IF NOT EXISTS scan_timing (
    scan_id                TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    avg_srtt_us            INTEGER,
    avg_rto_us             INTEGER NOT NULL,
    avg_cwnd               REAL NOT NULL,
    total_probes_sent      INTEGER NOT NULL,
    total_probes_responded INTEGER NOT NULL,
    total_probes_timed_out INTEGER NOT NULL,
    loss_rate              REAL NOT NULL,
    scan_timestamp         INTEGER NOT NULL
);

-- Network time-of-day patterns
CREATE TABLE IF NOT EXISTS network_time_patterns (
    subnet       TEXT NOT NULL,
    hour_of_day  INTEGER NOT NULL,
    avg_rtt_ms   REAL NOT NULL,
    avg_loss     REAL NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (subnet, hour_of_day)
);

-- CVE entries (known vulnerabilities)
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id          TEXT PRIMARY KEY,
    cvss_score      REAL,
    cvss_vector     TEXT,
    description     TEXT NOT NULL,
    published_date  TEXT,
    last_modified   TEXT,
    source          TEXT NOT NULL DEFAULT 'bundled'
);

-- CVE product matching rules
CREATE TABLE IF NOT EXISTS cve_product_rules (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id                TEXT NOT NULL REFERENCES cve_entries(cve_id) ON DELETE CASCADE,
    product_pattern       TEXT NOT NULL,
    version_start         TEXT,
    version_end           TEXT,
    version_exact         TEXT,
    version_end_exclusive INTEGER NOT NULL DEFAULT 0,
    UNIQUE(cve_id, product_pattern, version_start, version_end, version_exact)
);
CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_product_rules(product_pattern);

-- CVE metadata (tracks bundled version, last NVD update, etc.)
CREATE TABLE IF NOT EXISTS cve_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Scan checkpoints for resume/pause
CREATE TABLE IF NOT EXISTS scan_checkpoints (
    scan_id          TEXT PRIMARY KEY,
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    command_args     TEXT NOT NULL,
    targets_json     TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'in_progress',
    completed_hosts  TEXT NOT NULL DEFAULT '[]',
    partial_results  TEXT NOT NULL DEFAULT '[]',
    total_hosts      INTEGER NOT NULL,
    timing_template  INTEGER
);
"#;

pub fn initialize(conn: &rusqlite::Connection) -> Result<(), DbError> {
    // Set WAL mode and foreign keys BEFORE schema creation for crash safety
    // and foreign key enforcement during initial DDL.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(SCHEMA_SQL)?;

    // Safe migration: add characterization columns to existing network_profiles.
    // Only swallow "duplicate column name" errors; propagate other DB errors.
    for stmt in &[
        "ALTER TABLE network_profiles ADD COLUMN avg_jitter_us REAL",
        "ALTER TABLE network_profiles ADD COLUMN stability_score REAL",
        "ALTER TABLE network_profiles ADD COLUMN total_probes_historical INTEGER DEFAULT 0",
        "ALTER TABLE cve_product_rules ADD COLUMN version_end_exclusive INTEGER NOT NULL DEFAULT 0",
    ] {
        if let Err(e) = conn.execute(stmt, []) {
            let msg = e.to_string();
            if !msg.contains("duplicate column name") {
                return Err(e.into());
            }
        }
    }

    Ok(())
}
