use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};
use rustmap_types::{HostScanResult, PortState, ScanResult};
use tracing::debug;

use crate::error::DbError;
use crate::schema;

/// Persistent scan database backed by SQLite.
pub struct ScanStore {
    conn: Connection,
}

/// Lightweight scan metadata (no full result JSON).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub scan_type: String,
    pub num_hosts: usize,
    pub num_services: usize,
    pub total_duration_ms: u64,
    pub command_args: Option<String>,
}

/// Learned network characteristics for a subnet.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetworkProfile {
    pub subnet: String,
    pub avg_rtt_ms: f64,
    pub avg_loss_rate: f64,
    pub recommended_timing: u8,
    pub scan_count: u64,
    pub avg_jitter_us: Option<f64>,
    pub stability_score: Option<f64>,
}

/// Time-of-day pattern for a subnet.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TimePattern {
    pub hour: u8,
    pub avg_rtt_ms: f64,
    pub avg_loss: f64,
    pub sample_count: u64,
}

/// Timing telemetry record for a scan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanTimingRecord {
    pub scan_id: String,
    pub avg_srtt_us: Option<i64>,
    pub avg_rto_us: i64,
    pub avg_cwnd: f64,
    pub total_probes_sent: i64,
    pub total_probes_responded: i64,
    pub total_probes_timed_out: i64,
    pub loss_rate: f64,
    pub scan_timestamp: u64,
}

/// Source of a port prediction.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum PredictionSource {
    PerHost,
    Subnet,
}

/// A predicted port with open probability.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortPrediction {
    pub port: u16,
    pub protocol: String,
    pub open_probability: f64,
    pub source: PredictionSource,
}

/// Learned timing parameters from historical scan data.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LearnedTimingParams {
    pub recommended_template: u8,
    pub suggested_initial_rto_us: Option<u64>,
    pub suggested_initial_cwnd: Option<f64>,
    pub suggested_ssthresh: Option<f64>,
    pub suggested_max_retries: Option<u8>,
    pub confidence: f64,
}

/// Cached service information for a host:port.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CachedService {
    pub service_name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub last_seen: u64,
    pub times_seen: u64,
}

/// A detected service change between scans.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceChange {
    pub ip: String,
    pub port: u16,
    pub change_type: ServiceChangeType,
    pub old_service: Option<String>,
    pub new_service: Option<String>,
}

/// Type of service change detected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum ServiceChangeType {
    New,
    Changed,
    VersionChanged,
    Disappeared,
}

/// Host behavior profile tracking up/down patterns.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HostProfile {
    pub ip: String,
    pub subnet: String,
    pub times_scanned: u64,
    pub times_up: u64,
    pub behavior: String,
    pub avg_discovery_ms: Option<f64>,
    pub last_seen_up: Option<u64>,
}

/// Differences between two scans.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanDiff {
    pub old_scan_id: String,
    pub new_scan_id: String,
    pub new_hosts: Vec<String>,
    pub removed_hosts: Vec<String>,
    pub port_changes: Vec<PortChange>,
}

/// A single port that changed state between scans.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortChange {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub old_state: Option<String>,
    pub new_state: Option<String>,
}

/// A CVE entry from the database.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CveEntry {
    pub cve_id: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub description: String,
    pub published_date: Option<String>,
    pub last_modified: Option<String>,
    pub source: String,
}

/// A product matching rule for a CVE.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CveRule {
    pub cve_id: String,
    pub product_pattern: String,
    pub version_start: Option<String>,
    pub version_end: Option<String>,
    pub version_exact: Option<String>,
    /// When true, `version_end` is exclusive (from NVD `versionEndExcluding`).
    /// When false (default), `version_end` is inclusive (`versionEndIncluding`).
    #[serde(default)]
    pub version_end_exclusive: bool,
}

fn default_db_path() -> PathBuf {
    if cfg!(windows) {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(appdata).join("rustmap").join("rustmap.db")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".rustmap").join("rustmap.db")
    }
}

impl ScanStore {
    /// Open (or create) the database at the default location.
    pub fn open_default() -> Result<Self, DbError> {
        let path = default_db_path();
        Self::open(&path)
    }

    /// Open a database at a specific path.
    pub fn open(path: &Path) -> Result<Self, DbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DbError::Other(format!(
                    "failed to create db directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let conn = Connection::open(path)?;
        schema::initialize(&conn)?;
        debug!(path = %path.display(), "scan database opened");
        Ok(Self { conn })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;
        schema::initialize(&conn)?;
        Ok(Self { conn })
    }

    /// Save a completed scan to the database.
    pub fn save_scan(
        &self,
        scan_id: &str,
        result: &ScanResult,
        started_at: u64,
        finished_at: u64,
        timing_template: Option<u8>,
    ) -> Result<(), DbError> {
        let result_json = serde_json::to_string(result)?;
        let scan_type = format!("{}", result.scan_type);
        let total_duration_ms = result.total_duration.as_millis().min(i64::MAX as u128) as i64;
        let num_hosts = result.hosts.len() as i64;
        let num_services = result.num_services as i64;
        let command_args = result.command_args.as_deref();

        let tx = self.conn.unchecked_transaction()?;

        tx.execute(
            "INSERT OR REPLACE INTO scans (id, started_at, finished_at, scan_type, command_args, \
             timing_template, total_duration_ms, num_hosts, num_services, result_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                scan_id,
                started_at as i64,
                finished_at as i64,
                scan_type,
                command_args,
                timing_template.map(|t| t as i64),
                total_duration_ms,
                num_hosts,
                num_services,
                result_json,
            ],
        )?;

        for host_result in &result.hosts {
            let ip = host_result.host.ip.to_string();
            let hostname = host_result.host.hostname.as_deref();
            let host_status = format!("{}", host_result.host_status);
            let scan_duration_ms = host_result.scan_duration.as_millis() as i64;
            let discovery_latency_ms = host_result.discovery_latency.map(|d| d.as_millis() as i64);
            let open_port_count = host_result
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .count() as i64;
            let total_port_count = host_result.ports.len() as i64;

            tx.execute(
                "INSERT INTO host_results (scan_id, ip, hostname, host_status, scan_duration_ms, \
                 discovery_latency_ms, open_port_count, total_port_count) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    scan_id,
                    ip,
                    hostname,
                    host_status,
                    scan_duration_ms,
                    discovery_latency_ms,
                    open_port_count,
                    total_port_count,
                ],
            )?;

            let host_result_id = tx.last_insert_rowid();

            for port in &host_result.ports {
                let (service_product, service_version) = port
                    .service_info
                    .as_ref()
                    .map(|si| {
                        (
                            si.product.as_deref().map(String::from),
                            si.version.as_deref().map(String::from),
                        )
                    })
                    .unwrap_or((None, None));

                tx.execute(
                    "INSERT INTO port_results (host_result_id, port_number, protocol, state, \
                     service, service_product, service_version) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        host_result_id,
                        port.number as i64,
                        format!("{}", port.protocol),
                        format!("{}", port.state),
                        port.service.as_deref(),
                        service_product,
                        service_version,
                    ],
                )?;
            }
        }

        tx.commit()?;
        debug!(
            scan_id,
            hosts = result.hosts.len(),
            "scan saved to database"
        );
        Ok(())
    }

    /// Load a scan result by ID (deserializes the full JSON).
    pub fn load_scan(&self, scan_id: &str) -> Result<Option<ScanResult>, DbError> {
        let mut stmt = self
            .conn
            .prepare("SELECT result_json FROM scans WHERE id = ?1")?;
        let mut rows = stmt.query(params![scan_id])?;

        if let Some(row) = rows.next()? {
            let json: String = row.get(0)?;
            let result: ScanResult = serde_json::from_str(&json)?;
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// List all scans (metadata only, ordered by most recent first).
    pub fn list_scans(&self) -> Result<Vec<ScanSummary>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, finished_at, scan_type, num_hosts, num_services, \
             total_duration_ms, command_args FROM scans ORDER BY started_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ScanSummary {
                scan_id: row.get(0)?,
                started_at: row.get::<_, i64>(1)? as u64,
                finished_at: row.get::<_, i64>(2)? as u64,
                scan_type: row.get(3)?,
                num_hosts: row.get::<_, i64>(4)? as usize,
                num_services: row.get::<_, i64>(5)? as usize,
                total_duration_ms: row.get::<_, i64>(6)? as u64,
                command_args: row.get(7)?,
            })
        })?;

        let mut summaries = Vec::new();
        for row in rows {
            summaries.push(row?);
        }
        Ok(summaries)
    }

    /// Delete a scan and its associated host/port results (cascaded).
    pub fn delete_scan(&self, scan_id: &str) -> Result<bool, DbError> {
        let deleted = self
            .conn
            .execute("DELETE FROM scans WHERE id = ?1", params![scan_id])?;
        Ok(deleted > 0)
    }

    /// Get the most recent scan summary for a specific target IP.
    pub fn last_scan_for_host(&self, ip: &str) -> Result<Option<ScanSummary>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.started_at, s.finished_at, s.scan_type, s.num_hosts, \
             s.num_services, s.total_duration_ms, s.command_args \
             FROM scans s INNER JOIN host_results h ON s.id = h.scan_id \
             WHERE h.ip = ?1 ORDER BY s.started_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![ip])?;

        if let Some(row) = rows.next()? {
            Ok(Some(ScanSummary {
                scan_id: row.get(0)?,
                started_at: row.get::<_, i64>(1)? as u64,
                finished_at: row.get::<_, i64>(2)? as u64,
                scan_type: row.get(3)?,
                num_hosts: row.get::<_, i64>(4)? as usize,
                num_services: row.get::<_, i64>(5)? as usize,
                total_duration_ms: row.get::<_, i64>(6)? as u64,
                command_args: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Get previously-open ports for a target IP (from most recent scan).
    pub fn known_open_ports(&self, ip: &str) -> Result<Vec<u16>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT p.port_number FROM port_results p \
             INNER JOIN host_results h ON p.host_result_id = h.id \
             WHERE h.ip = ?1 AND p.state = 'open' \
             AND h.scan_id = ( \
                 SELECT s.id FROM scans s \
                 INNER JOIN host_results h2 ON s.id = h2.scan_id \
                 WHERE h2.ip = ?1 ORDER BY s.started_at DESC LIMIT 1 \
             ) \
             ORDER BY p.port_number",
        )?;

        let rows = stmt.query_map(params![ip], |row| row.get::<_, i64>(0))?;
        let mut ports = Vec::new();
        for row in rows {
            let port_i64 = row?;
            if let Ok(port) = u16::try_from(port_i64) {
                ports.push(port);
            }
        }
        Ok(ports)
    }

    /// Get the network profile for a subnet.
    pub fn network_profile(&self, subnet: &str) -> Result<Option<NetworkProfile>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT subnet, avg_rtt_ms, avg_loss_rate, recommended_timing, scan_count, \
             avg_jitter_us, stability_score \
             FROM network_profiles WHERE subnet = ?1",
        )?;
        let mut rows = stmt.query(params![subnet])?;

        if let Some(row) = rows.next()? {
            Ok(Some(NetworkProfile {
                subnet: row.get(0)?,
                avg_rtt_ms: row.get(1)?,
                avg_loss_rate: row.get(2)?,
                recommended_timing: row.get::<_, i64>(3)? as u8,
                scan_count: row.get::<_, i64>(4)? as u64,
                avg_jitter_us: row.get(5)?,
                stability_score: row.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Update the network profile with timing data from a completed scan.
    /// Uses exponential moving average to smooth values via atomic upsert.
    pub fn update_network_profile(
        &self,
        subnet: &str,
        rtt_ms: f64,
        loss_rate: f64,
    ) -> Result<(), DbError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let recommended = recommend_timing(rtt_ms, loss_rate) as i64;

        // Wrap both statements in a transaction so the profile is always
        // consistent (upsert + recompute must be atomic).
        let tx = self.conn.unchecked_transaction()?;

        // Atomic upsert: INSERT with EMA on conflict
        tx.execute(
            "INSERT INTO network_profiles (subnet, avg_rtt_ms, avg_loss_rate, \
             recommended_timing, last_updated, scan_count) VALUES (?1, ?2, ?3, ?4, ?5, 1) \
             ON CONFLICT(subnet) DO UPDATE SET \
             avg_rtt_ms = avg_rtt_ms * 0.7 + ?2 * 0.3, \
             avg_loss_rate = avg_loss_rate * 0.7 + ?3 * 0.3, \
             recommended_timing = ?4, \
             last_updated = ?5, \
             scan_count = scan_count + 1",
            params![subnet, rtt_ms, loss_rate, recommended, now_ms],
        )?;

        // Recompute recommended_timing from the EMA'd values (not from the raw input)
        tx.execute(
            "UPDATE network_profiles SET recommended_timing = CASE \
             WHEN avg_loss_rate > 0.25 OR avg_rtt_ms > 1000.0 THEN 1 \
             WHEN avg_loss_rate > 0.1 OR avg_rtt_ms > 500.0 THEN 2 \
             WHEN avg_rtt_ms > 100.0 THEN 3 \
             WHEN avg_rtt_ms > 20.0 THEN 4 \
             ELSE 5 END \
             WHERE subnet = ?1",
            params![subnet],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Compute a diff between two scans.
    pub fn diff_scans(&self, old_scan_id: &str, new_scan_id: &str) -> Result<ScanDiff, DbError> {
        // Collect host IPs from each scan
        let old_hosts = self.hosts_in_scan(old_scan_id)?;
        let new_hosts = self.hosts_in_scan(new_scan_id)?;

        let old_set: std::collections::HashSet<&str> =
            old_hosts.iter().map(|s| s.as_str()).collect();
        let new_set: std::collections::HashSet<&str> =
            new_hosts.iter().map(|s| s.as_str()).collect();

        let new_host_ips: Vec<String> = new_hosts
            .iter()
            .filter(|ip| !old_set.contains(ip.as_str()))
            .cloned()
            .collect();
        let removed_host_ips: Vec<String> = old_hosts
            .iter()
            .filter(|ip| !new_set.contains(ip.as_str()))
            .cloned()
            .collect();

        // Collect port states from each scan
        let old_ports = self.ports_in_scan(old_scan_id)?;
        let new_ports = self.ports_in_scan(new_scan_id)?;

        let mut port_changes = Vec::new();

        // Find ports that changed state or appeared
        for (key, new_state) in &new_ports {
            match old_ports.get(key) {
                Some(old_state) if old_state != new_state => {
                    port_changes.push(PortChange {
                        ip: key.0.clone(),
                        port: key.1,
                        protocol: key.2.clone(),
                        old_state: Some(old_state.clone()),
                        new_state: Some(new_state.clone()),
                    });
                }
                None => {
                    port_changes.push(PortChange {
                        ip: key.0.clone(),
                        port: key.1,
                        protocol: key.2.clone(),
                        old_state: None,
                        new_state: Some(new_state.clone()),
                    });
                }
                _ => {}
            }
        }

        // Find ports that disappeared
        for (key, old_state) in &old_ports {
            if !new_ports.contains_key(key) {
                port_changes.push(PortChange {
                    ip: key.0.clone(),
                    port: key.1,
                    protocol: key.2.clone(),
                    old_state: Some(old_state.clone()),
                    new_state: None,
                });
            }
        }

        Ok(ScanDiff {
            old_scan_id: old_scan_id.to_string(),
            new_scan_id: new_scan_id.to_string(),
            new_hosts: new_host_ips,
            removed_hosts: removed_host_ips,
            port_changes,
        })
    }

    /// Get the most recent scan ID that includes a given host IP.
    pub fn last_scan_id_for_host(&self, ip: &str) -> Result<Option<String>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id FROM scans s \
             INNER JOIN host_results h ON s.id = h.scan_id \
             WHERE h.ip = ?1 ORDER BY s.started_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![ip])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Get the most recent scan ID for a host, excluding a specific scan.
    pub fn previous_scan_id_for_host(
        &self,
        ip: &str,
        exclude_scan_id: &str,
    ) -> Result<Option<String>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT s.id FROM scans s \
             INNER JOIN host_results h ON s.id = h.scan_id \
             WHERE h.ip = ?1 AND s.id != ?2 \
             ORDER BY s.started_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![ip, exclude_scan_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Save aggregated timing telemetry for a scan.
    #[allow(clippy::too_many_arguments)]
    pub fn save_scan_timing(
        &self,
        scan_id: &str,
        avg_srtt_us: Option<i64>,
        avg_rto_us: i64,
        avg_cwnd: f64,
        total_probes_sent: i64,
        total_probes_responded: i64,
        total_probes_timed_out: i64,
        loss_rate: f64,
        scan_timestamp: u64,
    ) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_timing (scan_id, avg_srtt_us, avg_rto_us, avg_cwnd, \
             total_probes_sent, total_probes_responded, total_probes_timed_out, loss_rate, \
             scan_timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                scan_id,
                avg_srtt_us,
                avg_rto_us,
                avg_cwnd,
                total_probes_sent,
                total_probes_responded,
                total_probes_timed_out,
                loss_rate,
                scan_timestamp as i64,
            ],
        )?;
        Ok(())
    }

    /// Get timing history for a subnet (most recent first).
    ///
    /// Matches scans that contain hosts within the subnet by checking the IP
    /// prefix (e.g., "192.168.1." for "192.168.1.0/24").
    pub fn scan_timing_history(
        &self,
        subnet: &str,
        limit: usize,
    ) -> Result<Vec<ScanTimingRecord>, DbError> {
        // Extract the IP prefix from the subnet using CIDR prefix length.
        // e.g., "192.168.1.0/24" → "192.168.1.", "10.0.0.0/8" → "10."
        let ip_prefix = extract_subnet_prefix(subnet);

        let like_pattern = format!("{ip_prefix}%");

        let mut stmt = self.conn.prepare(
            "SELECT st.scan_id, st.avg_srtt_us, st.avg_rto_us, st.avg_cwnd, \
             st.total_probes_sent, st.total_probes_responded, st.total_probes_timed_out, \
             st.loss_rate, st.scan_timestamp \
             FROM scan_timing st \
             WHERE st.scan_id IN ( \
                 SELECT DISTINCT scan_id FROM host_results WHERE ip LIKE ?1 \
             ) \
             ORDER BY st.scan_timestamp DESC LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![like_pattern, limit as i64], |row| {
            Ok(ScanTimingRecord {
                scan_id: row.get(0)?,
                avg_srtt_us: row.get(1)?,
                avg_rto_us: row.get(2)?,
                avg_cwnd: row.get(3)?,
                total_probes_sent: row.get(4)?,
                total_probes_responded: row.get(5)?,
                total_probes_timed_out: row.get(6)?,
                loss_rate: row.get(7)?,
                scan_timestamp: row.get::<_, i64>(8)? as u64,
            })
        })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    /// Update port history after a scan (called per-host, per-port).
    pub fn update_port_history(
        &self,
        ip: &str,
        subnet: &str,
        port: u16,
        protocol: &str,
        was_open: bool,
        timestamp: u64,
    ) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO port_history (ip, subnet, port_number, protocol, times_open, \
             times_scanned, last_seen_open, last_scanned) \
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7) \
             ON CONFLICT(ip, port_number, protocol) DO UPDATE SET \
             subnet = ?2, \
             times_open = times_open + ?5, \
             times_scanned = times_scanned + 1, \
             last_seen_open = CASE WHEN ?5 = 1 THEN ?7 ELSE last_seen_open END, \
             last_scanned = ?7",
            params![
                ip,
                subnet,
                port as i64,
                protocol,
                i64::from(was_open),
                if was_open {
                    Some(timestamp as i64)
                } else {
                    None::<i64>
                },
                timestamp as i64,
            ],
        )?;
        Ok(())
    }

    /// Get ports ordered by open probability for a specific host.
    pub fn predict_ports_for_host(
        &self,
        ip: &str,
        limit: usize,
    ) -> Result<Vec<PortPrediction>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT port_number, protocol, times_open, times_scanned \
             FROM port_history WHERE ip = ?1 AND times_scanned > 0 \
             ORDER BY CAST(times_open AS REAL) / times_scanned DESC, times_scanned DESC \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![ip, limit as i64], |row| {
            let open: i64 = row.get(2)?;
            let scanned: i64 = row.get(3)?;
            let port_i64: i64 = row.get(0)?;
            Ok((port_i64, row.get::<_, String>(1)?, open, scanned))
        })?;

        let mut predictions = Vec::new();
        for row in rows {
            let (port_i64, protocol, open, scanned) = row?;
            if let Ok(port) = u16::try_from(port_i64) {
                predictions.push(PortPrediction {
                    port,
                    protocol,
                    open_probability: if scanned > 0 {
                        open as f64 / scanned as f64
                    } else {
                        0.0
                    },
                    source: PredictionSource::PerHost,
                });
            }
        }
        Ok(predictions)
    }

    /// Get ports commonly open across a subnet.
    pub fn predict_ports_for_subnet(
        &self,
        subnet: &str,
        limit: usize,
    ) -> Result<Vec<PortPrediction>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT port_number, protocol, SUM(times_open) as total_open, \
             SUM(times_scanned) as total_scanned \
             FROM port_history WHERE subnet = ?1 \
             GROUP BY port_number, protocol \
             HAVING total_scanned > 0 \
             ORDER BY CAST(total_open AS REAL) / total_scanned DESC, total_scanned DESC \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![subnet, limit as i64], |row| {
            let open: i64 = row.get(2)?;
            let scanned: i64 = row.get(3)?;
            let port_i64: i64 = row.get(0)?;
            Ok((port_i64, row.get::<_, String>(1)?, open, scanned))
        })?;

        let mut predictions = Vec::new();
        for row in rows {
            let (port_i64, protocol, open, scanned) = row?;
            if let Ok(port) = u16::try_from(port_i64) {
                predictions.push(PortPrediction {
                    port,
                    protocol,
                    open_probability: if scanned > 0 {
                        open as f64 / scanned as f64
                    } else {
                        0.0
                    },
                    source: PredictionSource::Subnet,
                });
            }
        }
        Ok(predictions)
    }

    /// Compute learned timing parameters from historical data for a subnet.
    pub fn learned_timing_params(
        &self,
        subnet: &str,
    ) -> Result<Option<LearnedTimingParams>, DbError> {
        let profile = match self.network_profile(subnet)? {
            Some(p) => p,
            None => return Ok(None),
        };

        // Query recent scan timing history for this subnet
        let history = self.scan_timing_history(subnet, 5)?;

        let confidence = (profile.scan_count as f64 / 10.0).min(1.0);

        // Compute suggested initial RTO from historical SRTT (SRTT * 3, conservative)
        let suggested_rto = if !history.is_empty() {
            let srtt_values: Vec<i64> = history.iter().filter_map(|h| h.avg_srtt_us).collect();
            if !srtt_values.is_empty() {
                let avg_srtt = srtt_values.iter().sum::<i64>() / srtt_values.len() as i64;
                if avg_srtt > 0 {
                    Some(avg_srtt as u64 * 3)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Compute suggested initial cwnd from historical final cwnd
        let suggested_cwnd = if !history.is_empty() {
            let avg_cwnd = history.iter().map(|h| h.avg_cwnd).sum::<f64>() / history.len() as f64;
            Some(avg_cwnd)
        } else {
            None
        };

        // Suggested ssthresh = historical cwnd * 0.8
        let suggested_ssthresh = suggested_cwnd.map(|c| c * 0.8);

        // Max retries based on loss rate
        let suggested_retries = if profile.avg_loss_rate < 0.01 {
            Some(2)
        } else if profile.avg_loss_rate < 0.05 {
            Some(3)
        } else if profile.avg_loss_rate < 0.10 {
            Some(4)
        } else {
            None // Use template default for high loss
        };

        Ok(Some(LearnedTimingParams {
            recommended_template: profile.recommended_timing,
            suggested_initial_rto_us: suggested_rto,
            suggested_initial_cwnd: suggested_cwnd,
            suggested_ssthresh,
            suggested_max_retries: suggested_retries,
            confidence,
        }))
    }

    /// Upsert service data after a scan.
    #[allow(clippy::too_many_arguments)]
    pub fn update_service_cache(
        &self,
        ip: &str,
        port: u16,
        protocol: &str,
        service: &str,
        product: Option<&str>,
        version: Option<&str>,
        timestamp: u64,
    ) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO service_cache (ip, port_number, protocol, service_name, product, \
             version, first_seen, last_seen, times_seen) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 1) \
             ON CONFLICT(ip, port_number, protocol) DO UPDATE SET \
             service_name = ?4, product = ?5, version = ?6, \
             last_seen = ?7, times_seen = times_seen + 1",
            params![
                ip,
                port as i64,
                protocol,
                service,
                product,
                version,
                timestamp as i64,
            ],
        )?;
        Ok(())
    }

    /// Get cached service for a host:port.
    pub fn get_cached_service(
        &self,
        ip: &str,
        port: u16,
        protocol: &str,
    ) -> Result<Option<CachedService>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT service_name, product, version, last_seen, times_seen \
             FROM service_cache WHERE ip = ?1 AND port_number = ?2 AND protocol = ?3",
        )?;
        let mut rows = stmt.query(params![ip, port as i64, protocol])?;

        if let Some(row) = rows.next()? {
            Ok(Some(CachedService {
                service_name: row.get(0)?,
                product: row.get(1)?,
                version: row.get(2)?,
                last_seen: row.get::<_, i64>(3)? as u64,
                times_seen: row.get::<_, i64>(4)? as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Compare current port results against cache, return changes.
    pub fn detect_service_changes(
        &self,
        ip: &str,
        ports: &[rustmap_types::Port],
    ) -> Result<Vec<ServiceChange>, DbError> {
        let mut changes = Vec::new();

        // Track which cached (port, protocol) pairs we've seen in the current scan
        let mut seen_cached_ports = std::collections::HashSet::new();

        for port in ports {
            if port.state != rustmap_types::PortState::Open {
                continue;
            }
            let protocol = format!("{}", port.protocol);
            let cached = self.get_cached_service(ip, port.number, &protocol)?;
            let current_service = port.service.as_deref();

            if cached.is_some() {
                seen_cached_ports.insert((port.number, protocol.clone()));
            }

            match (cached, current_service) {
                (None, Some(svc)) => {
                    changes.push(ServiceChange {
                        ip: ip.to_string(),
                        port: port.number,
                        change_type: ServiceChangeType::New,
                        old_service: None,
                        new_service: Some(svc.to_string()),
                    });
                }
                (Some(ref cached), Some(svc)) if cached.service_name != svc => {
                    changes.push(ServiceChange {
                        ip: ip.to_string(),
                        port: port.number,
                        change_type: ServiceChangeType::Changed,
                        old_service: Some(cached.service_name.clone()),
                        new_service: Some(svc.to_string()),
                    });
                }
                (Some(ref cached), Some(_svc)) => {
                    // Same service name — check version
                    let new_version = port
                        .service_info
                        .as_ref()
                        .and_then(|si| si.version.as_deref());
                    if new_version != cached.version.as_deref() && new_version.is_some() {
                        changes.push(ServiceChange {
                            ip: ip.to_string(),
                            port: port.number,
                            change_type: ServiceChangeType::VersionChanged,
                            old_service: Some(format!(
                                "{} {}",
                                cached.service_name,
                                cached.version.as_deref().unwrap_or("")
                            )),
                            new_service: Some(format!(
                                "{} {}",
                                cached.service_name,
                                new_version.unwrap_or("")
                            )),
                        });
                    }
                }
                _ => {}
            }
        }

        // Check for disappeared services: cached services not present in current open ports
        let mut stmt = self.conn.prepare(
            "SELECT port_number, protocol, service_name FROM service_cache WHERE ip = ?1",
        )?;
        let rows = stmt.query_map(params![ip], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (port_i64, protocol, service_name) = row?;
            let Ok(port_num) = u16::try_from(port_i64) else {
                continue;
            };
            if !seen_cached_ports.contains(&(port_num, protocol.clone())) {
                // This cached service was not seen as open in the current scan
                let is_scanned = ports
                    .iter()
                    .any(|p| p.number == port_num && format!("{}", p.protocol) == protocol);
                if is_scanned {
                    changes.push(ServiceChange {
                        ip: ip.to_string(),
                        port: port_num,
                        change_type: ServiceChangeType::Disappeared,
                        old_service: Some(service_name),
                        new_service: None,
                    });
                }
            }
        }

        Ok(changes)
    }

    // --- helpers ---

    fn hosts_in_scan(&self, scan_id: &str) -> Result<Vec<String>, DbError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT ip FROM host_results WHERE scan_id = ?1")?;
        let rows = stmt.query_map(params![scan_id], |row| row.get::<_, String>(0))?;
        let mut hosts = Vec::new();
        for row in rows {
            hosts.push(row?);
        }
        Ok(hosts)
    }

    // --- 12E: Host Behavior Profiles ---

    /// Update host behavior profile after a scan.
    pub fn update_host_profile(
        &self,
        ip: &str,
        subnet: &str,
        was_up: bool,
        discovery_ms: Option<f64>,
        timestamp: u64,
    ) -> Result<(), DbError> {
        let tx = self.conn.unchecked_transaction()?;

        // Upsert the profile
        tx.execute(
            "INSERT INTO host_profiles (ip, subnet, times_scanned, times_up, times_down, \
             avg_discovery_ms, last_seen_up, last_scanned, behavior) \
             VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, 'unknown') \
             ON CONFLICT(ip) DO UPDATE SET \
             subnet = ?2, \
             times_scanned = times_scanned + 1, \
             times_up = times_up + ?3, \
             times_down = times_down + ?4, \
             avg_discovery_ms = CASE \
                 WHEN ?5 IS NOT NULL AND avg_discovery_ms IS NOT NULL \
                 THEN avg_discovery_ms * 0.7 + ?5 * 0.3 \
                 WHEN ?5 IS NOT NULL THEN ?5 \
                 ELSE avg_discovery_ms END, \
             last_seen_up = CASE WHEN ?3 = 1 THEN ?7 ELSE last_seen_up END, \
             last_scanned = ?7",
            params![
                ip,
                subnet,
                if was_up { 1i64 } else { 0 },
                if was_up { 0i64 } else { 1 },
                discovery_ms,
                if was_up {
                    Some(timestamp as i64)
                } else {
                    None::<i64>
                },
                timestamp as i64,
            ],
        )?;

        // Recompute behavior classification
        let mut stmt =
            tx.prepare("SELECT times_up, times_scanned FROM host_profiles WHERE ip = ?1")?;
        let (times_up, times_scanned): (i64, i64) =
            stmt.query_row(params![ip], |row| Ok((row.get(0)?, row.get(1)?)))?;
        drop(stmt);
        let behavior = classify_behavior(times_up as u64, times_scanned as u64);
        tx.execute(
            "UPDATE host_profiles SET behavior = ?1 WHERE ip = ?2",
            params![behavior, ip],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Get host behavior profile.
    pub fn get_host_profile(&self, ip: &str) -> Result<Option<HostProfile>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, subnet, times_scanned, times_up, behavior, \
             avg_discovery_ms, last_seen_up FROM host_profiles WHERE ip = ?1",
        )?;
        let mut rows = stmt.query(params![ip])?;
        if let Some(row) = rows.next()? {
            Ok(Some(HostProfile {
                ip: row.get(0)?,
                subnet: row.get(1)?,
                times_scanned: row.get::<_, i64>(2)? as u64,
                times_up: row.get::<_, i64>(3)? as u64,
                behavior: row.get(4)?,
                avg_discovery_ms: row.get(5)?,
                last_seen_up: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
            }))
        } else {
            Ok(None)
        }
    }

    /// Get IPs in a subnet that are always up (for skip-discovery optimization).
    pub fn hosts_always_up(&self, subnet: &str, min_scans: u64) -> Result<Vec<String>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT ip FROM host_profiles \
             WHERE subnet = ?1 AND behavior = 'always_up' AND times_scanned >= ?2",
        )?;
        let rows = stmt.query_map(params![subnet, min_scans as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut ips = Vec::new();
        for row in rows {
            ips.push(row?);
        }
        Ok(ips)
    }

    // --- 12F: Network Characterization ---

    /// Update time-of-day pattern for a subnet.
    pub fn update_time_pattern(
        &self,
        subnet: &str,
        hour: u8,
        rtt_ms: f64,
        loss_rate: f64,
    ) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO network_time_patterns (subnet, hour_of_day, avg_rtt_ms, avg_loss, sample_count) \
             VALUES (?1, ?2, ?3, ?4, 1) \
             ON CONFLICT(subnet, hour_of_day) DO UPDATE SET \
             avg_rtt_ms = avg_rtt_ms * 0.7 + ?3 * 0.3, \
             avg_loss = avg_loss * 0.7 + ?4 * 0.3, \
             sample_count = sample_count + 1",
            params![subnet, hour as i64, rtt_ms, loss_rate],
        )?;
        Ok(())
    }

    /// Get time-of-day patterns for a subnet, ordered by hour.
    pub fn get_time_patterns(&self, subnet: &str) -> Result<Vec<TimePattern>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT hour_of_day, avg_rtt_ms, avg_loss, sample_count \
             FROM network_time_patterns WHERE subnet = ?1 ORDER BY hour_of_day",
        )?;
        let rows = stmt.query_map(params![subnet], |row| {
            Ok(TimePattern {
                hour: row.get::<_, i64>(0)? as u8,
                avg_rtt_ms: row.get(1)?,
                avg_loss: row.get(2)?,
                sample_count: row.get::<_, i64>(3)? as u64,
            })
        })?;
        let mut patterns = Vec::new();
        for row in rows {
            patterns.push(row?);
        }
        Ok(patterns)
    }

    /// Update jitter and stability score on the network profile.
    pub fn update_network_stability(&self, subnet: &str, jitter_us: f64) -> Result<(), DbError> {
        // Get current profile data; return Ok if no profile exists yet
        let mut stmt = self.conn.prepare(
            "SELECT avg_rtt_ms, avg_loss_rate, avg_jitter_us FROM network_profiles WHERE subnet = ?1",
        )?;
        let result: Option<(f64, f64, Option<f64>)> = match stmt.query_row(params![subnet], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        }) {
            Ok(row) => Some(row),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        if let Some((avg_rtt_ms, avg_loss_rate, existing_jitter)) = result {
            let avg_jitter = match existing_jitter {
                Some(existing) => existing * 0.7 + jitter_us * 0.3,
                None => jitter_us,
            };
            let avg_rtt_us = avg_rtt_ms * 1000.0;
            let jitter_ratio = if avg_rtt_us > 0.0 {
                avg_jitter / avg_rtt_us
            } else {
                0.0
            };
            let stability = compute_stability_score(avg_loss_rate, jitter_ratio);
            self.conn.execute(
                "UPDATE network_profiles SET avg_jitter_us = ?1, stability_score = ?2 WHERE subnet = ?3",
                params![avg_jitter, stability, subnet],
            )?;
        }
        Ok(())
    }

    /// Returns (ip, port, protocol) -> state mapping for a scan.
    fn ports_in_scan(
        &self,
        scan_id: &str,
    ) -> Result<HashMap<(String, u16, String), String>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT h.ip, p.port_number, p.protocol, p.state \
             FROM port_results p \
             INNER JOIN host_results h ON p.host_result_id = h.id \
             WHERE h.scan_id = ?1",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        let mut map = HashMap::new();
        for row in rows {
            let (ip, port_i64, proto, state) = row?;
            if let Ok(port) = u16::try_from(port_i64) {
                map.insert((ip, port, proto), state);
            }
        }
        Ok(map)
    }

    // -----------------------------------------------------------------------
    // CVE / Vulnerability methods
    // -----------------------------------------------------------------------

    /// Insert or update a CVE entry.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_cve(
        &self,
        cve_id: &str,
        cvss_score: Option<f64>,
        cvss_vector: Option<&str>,
        description: &str,
        published_date: Option<&str>,
        last_modified: Option<&str>,
        source: &str,
    ) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO cve_entries (cve_id, cvss_score, cvss_vector, description,
                                      published_date, last_modified, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(cve_id) DO UPDATE SET
                cvss_score = ?2, cvss_vector = ?3, description = ?4,
                published_date = ?5, last_modified = ?6, source = ?7",
            params![
                cve_id,
                cvss_score,
                cvss_vector,
                description,
                published_date,
                last_modified,
                source
            ],
        )?;
        Ok(())
    }

    /// Insert a product matching rule for a CVE.
    pub fn insert_cve_rule(
        &self,
        cve_id: &str,
        product_pattern: &str,
        version_exact: Option<&str>,
        version_start: Option<&str>,
        version_end: Option<&str>,
    ) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO cve_product_rules
                (cve_id, product_pattern, version_exact, version_start, version_end, version_end_exclusive)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![cve_id, product_pattern, version_exact, version_start, version_end],
        )?;
        Ok(())
    }

    /// Find all CVE rules matching a product pattern (case-insensitive).
    pub fn find_cve_rules_for_product(&self, product: &str) -> Result<Vec<CveRule>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT cve_id, product_pattern, version_start, version_end, version_exact, version_end_exclusive
             FROM cve_product_rules
             WHERE product_pattern = ?1 COLLATE NOCASE",
        )?;
        let rows = stmt.query_map(params![product], |row| {
            Ok(CveRule {
                cve_id: row.get(0)?,
                product_pattern: row.get(1)?,
                version_start: row.get(2)?,
                version_end: row.get(3)?,
                version_exact: row.get(4)?,
                version_end_exclusive: row.get::<_, i32>(5).unwrap_or(0) != 0,
            })
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Get a CVE entry by ID.
    pub fn get_cve(&self, cve_id: &str) -> Result<Option<CveEntry>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT cve_id, cvss_score, cvss_vector, description,
                    published_date, last_modified, source
             FROM cve_entries WHERE cve_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![cve_id], |row| {
            Ok(CveEntry {
                cve_id: row.get(0)?,
                cvss_score: row.get(1)?,
                cvss_vector: row.get(2)?,
                description: row.get(3)?,
                published_date: row.get(4)?,
                last_modified: row.get(5)?,
                source: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Get a CVE metadata value.
    pub fn get_cve_metadata(&self, key: &str) -> Result<Option<String>, DbError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM cve_metadata WHERE key = ?1")?;
        let mut rows = stmt.query_map(params![key], |row| row.get::<_, String>(0))?;
        match rows.next() {
            Some(val) => Ok(Some(val?)),
            None => Ok(None),
        }
    }

    /// Set a CVE metadata value.
    pub fn set_cve_metadata(&self, key: &str, value: &str) -> Result<(), DbError> {
        self.conn.execute(
            "INSERT INTO cve_metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    /// Count total CVE entries in the database.
    pub fn count_cves(&self) -> Result<u64, DbError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM cve_entries", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Bulk import CVEs (entry + rules). Returns number of entries inserted.
    pub fn bulk_import_cves(&self, entries: &[(CveEntry, Vec<CveRule>)]) -> Result<usize, DbError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut count = 0;

        for (entry, rules) in entries {
            tx.execute(
                "INSERT INTO cve_entries (cve_id, cvss_score, cvss_vector, description,
                                          published_date, last_modified, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(cve_id) DO UPDATE SET
                    cvss_score = ?2, cvss_vector = ?3, description = ?4,
                    published_date = ?5, last_modified = ?6, source = ?7",
                params![
                    entry.cve_id,
                    entry.cvss_score,
                    entry.cvss_vector,
                    entry.description,
                    entry.published_date,
                    entry.last_modified,
                    entry.source,
                ],
            )?;

            for rule in rules {
                // Use entry's CVE ID (rules may have empty cve_id from helpers)
                let rule_cve_id = if rule.cve_id.is_empty() {
                    &entry.cve_id
                } else {
                    &rule.cve_id
                };
                tx.execute(
                    "INSERT OR IGNORE INTO cve_product_rules
                        (cve_id, product_pattern, version_exact, version_start, version_end, version_end_exclusive)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        rule_cve_id,
                        rule.product_pattern,
                        rule.version_exact,
                        rule.version_start,
                        rule.version_end,
                        rule.version_end_exclusive as i32,
                    ],
                )?;
            }
            count += 1;
        }

        tx.commit()?;
        Ok(count)
    }

    /// Bulk import CISA KEV entries. Uses COALESCE to preserve existing NVD data
    /// (CVSS scores, vectors, detailed descriptions) while adding KEV-sourced rules.
    pub fn bulk_import_kev(&self, entries: &[(CveEntry, Vec<CveRule>)]) -> Result<usize, DbError> {
        let tx = self.conn.unchecked_transaction()?;
        let mut count = 0;

        for (entry, rules) in entries {
            // Use COALESCE to never overwrite existing non-null NVD data with KEV nulls.
            // Only fill in fields that are currently NULL.
            tx.execute(
                "INSERT INTO cve_entries (cve_id, cvss_score, cvss_vector, description,
                                          published_date, last_modified, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(cve_id) DO UPDATE SET
                    cvss_score = COALESCE(cve_entries.cvss_score, ?2),
                    cvss_vector = COALESCE(cve_entries.cvss_vector, ?3),
                    description = COALESCE(cve_entries.description, ?4),
                    published_date = COALESCE(cve_entries.published_date, ?5),
                    last_modified = COALESCE(cve_entries.last_modified, ?6)",
                params![
                    entry.cve_id,
                    entry.cvss_score,
                    entry.cvss_vector,
                    entry.description,
                    entry.published_date,
                    entry.last_modified,
                    entry.source,
                ],
            )?;

            for rule in rules {
                let rule_cve_id = if rule.cve_id.is_empty() {
                    &entry.cve_id
                } else {
                    &rule.cve_id
                };
                tx.execute(
                    "INSERT OR IGNORE INTO cve_product_rules
                        (cve_id, product_pattern, version_exact, version_start, version_end, version_end_exclusive)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        rule_cve_id,
                        rule.product_pattern,
                        rule.version_exact,
                        rule.version_start,
                        rule.version_end,
                        rule.version_end_exclusive as i32,
                    ],
                )?;
            }
            count += 1;
        }

        tx.commit()?;
        Ok(count)
    }
}

/// Recommend a timing template based on network characteristics.
fn recommend_timing(avg_rtt_ms: f64, avg_loss_rate: f64) -> u8 {
    if avg_loss_rate > 0.25 || avg_rtt_ms > 1000.0 {
        1 // Sneaky — extremely lossy or slow network
    } else if avg_loss_rate > 0.1 || avg_rtt_ms > 500.0 {
        2 // Polite — lossy or slow network
    } else if avg_rtt_ms > 100.0 {
        3 // Normal
    } else if avg_rtt_ms > 20.0 {
        4 // Aggressive — fast, reliable
    } else {
        5 // Insane — very fast LAN
    }
}

/// Classify host behavior based on up/down ratio.
fn classify_behavior(times_up: u64, times_scanned: u64) -> &'static str {
    if times_scanned == 0 {
        return "unknown";
    }
    let ratio = times_up as f64 / times_scanned as f64;
    if ratio >= 1.0 {
        "always_up"
    } else if ratio >= 0.8 {
        "mostly_up"
    } else if ratio >= 0.2 {
        "intermittent"
    } else if ratio > 0.0 {
        "mostly_down"
    } else {
        "always_down"
    }
}

/// Compute network stability: 0.0 (unstable) to 1.0 (very stable).
fn compute_stability_score(loss_rate: f64, jitter_ratio: f64) -> f64 {
    let loss_factor = (1.0 - loss_rate).clamp(0.0, 1.0);
    let jitter_factor = (1.0 - jitter_ratio).clamp(0.0, 1.0);
    (loss_factor * 0.5 + jitter_factor * 0.5).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Scan checkpoints (resume/pause)
// ---------------------------------------------------------------------------

/// A checkpoint for an interrupted scan that can be resumed later.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanCheckpoint {
    pub scan_id: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub command_args: String,
    pub targets: Vec<String>,
    pub status: String,
    pub completed_hosts: Vec<String>,
    pub partial_results: Vec<HostScanResult>,
    pub total_hosts: usize,
    pub timing_template: Option<u8>,
}

impl ScanStore {
    /// Create a new checkpoint for a scan that is about to start.
    pub fn create_checkpoint(&self, cp: &ScanCheckpoint) -> Result<(), DbError> {
        let targets_json = serde_json::to_string(&cp.targets)?;
        let completed_json = serde_json::to_string(&cp.completed_hosts)?;
        let results_json = serde_json::to_string(&cp.partial_results)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO scan_checkpoints
             (scan_id, created_at, updated_at, command_args, targets_json,
              status, completed_hosts, partial_results, total_hosts, timing_template)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                cp.scan_id,
                cp.created_at,
                cp.updated_at,
                cp.command_args,
                targets_json,
                cp.status,
                completed_json,
                results_json,
                cp.total_hosts as i64,
                cp.timing_template.map(|t| t as i64),
            ],
        )?;

        Ok(())
    }

    /// Update a checkpoint after a host completes scanning.
    pub fn update_checkpoint(
        &self,
        scan_id: &str,
        host_ip: &str,
        result: &HostScanResult,
    ) -> Result<(), DbError> {
        // Wrap load-modify-write in a transaction to prevent lost updates
        // if two callers update the same checkpoint concurrently.
        let tx = self.conn.unchecked_transaction()?;

        let mut cp = {
            let mut stmt = tx.prepare(
                "SELECT scan_id, created_at, updated_at, command_args, targets_json,
                        status, completed_hosts, partial_results, total_hosts, timing_template
                 FROM scan_checkpoints WHERE scan_id = ?1",
            )?;

            let row_data = stmt
                .query_row(params![scan_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                })
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => {
                        DbError::NotFound(format!("checkpoint not found: {scan_id}"))
                    }
                    other => other.into(),
                })?;

            let targets: Vec<String> = serde_json::from_str(&row_data.4).unwrap_or_default();
            let completed_hosts: Vec<String> =
                serde_json::from_str(&row_data.6).unwrap_or_default();
            let partial_results: Vec<HostScanResult> =
                serde_json::from_str(&row_data.7).unwrap_or_default();

            ScanCheckpoint {
                scan_id: row_data.0,
                created_at: row_data.1,
                updated_at: row_data.2,
                command_args: row_data.3,
                targets,
                status: row_data.5,
                completed_hosts,
                partial_results,
                total_hosts: row_data.8 as usize,
                timing_template: row_data.9.map(|t| t as u8),
            }
        };

        if !cp.completed_hosts.contains(&host_ip.to_string()) {
            cp.completed_hosts.push(host_ip.to_string());
        }
        cp.partial_results.push(result.clone());
        cp.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let completed_json = serde_json::to_string(&cp.completed_hosts)?;
        let results_json = serde_json::to_string(&cp.partial_results)?;

        tx.execute(
            "UPDATE scan_checkpoints
             SET updated_at = ?1, completed_hosts = ?2, partial_results = ?3
             WHERE scan_id = ?4",
            params![cp.updated_at, completed_json, results_json, scan_id],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Load a checkpoint by scan ID.
    pub fn load_checkpoint(&self, scan_id: &str) -> Result<Option<ScanCheckpoint>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT scan_id, created_at, updated_at, command_args, targets_json,
                    status, completed_hosts, partial_results, total_hosts, timing_template
             FROM scan_checkpoints WHERE scan_id = ?1",
        )?;

        let result = stmt.query_row(params![scan_id], |row| {
            let targets_json: String = row.get(4)?;
            let completed_json: String = row.get(6)?;
            let results_json: String = row.get(7)?;
            let timing: Option<i64> = row.get(9)?;

            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, String>(3)?,
                targets_json,
                row.get::<_, String>(5)?,
                completed_json,
                results_json,
                row.get::<_, i64>(8)?,
                timing,
            ))
        });

        match result {
            Ok((
                scan_id,
                created_at,
                updated_at,
                command_args,
                targets_json,
                status,
                completed_json,
                results_json,
                total_hosts,
                timing,
            )) => {
                let targets: Vec<String> = serde_json::from_str(&targets_json)?;
                let completed_hosts: Vec<String> = serde_json::from_str(&completed_json)?;
                let partial_results: Vec<HostScanResult> = serde_json::from_str(&results_json)?;

                Ok(Some(ScanCheckpoint {
                    scan_id,
                    created_at,
                    updated_at,
                    command_args,
                    targets,
                    status,
                    completed_hosts,
                    partial_results,
                    total_hosts: total_hosts as usize,
                    timing_template: timing.map(|t| t as u8),
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a checkpoint (e.g., after successful completion or resume).
    pub fn delete_checkpoint(&self, scan_id: &str) -> Result<(), DbError> {
        self.conn.execute(
            "DELETE FROM scan_checkpoints WHERE scan_id = ?1",
            params![scan_id],
        )?;
        Ok(())
    }

    /// List all in-progress checkpoints.
    pub fn list_checkpoints(&self) -> Result<Vec<ScanCheckpoint>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT scan_id, created_at, updated_at, command_args, targets_json,
                    status, completed_hosts, partial_results, total_hosts, timing_template
             FROM scan_checkpoints WHERE status = 'in_progress'
             ORDER BY updated_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let targets_json: String = row.get(4)?;
            let completed_json: String = row.get(6)?;
            let results_json: String = row.get(7)?;
            let timing: Option<i64> = row.get(9)?;

            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, String>(3)?,
                targets_json,
                row.get::<_, String>(5)?,
                completed_json,
                results_json,
                row.get::<_, i64>(8)?,
                timing,
            ))
        })?;

        let mut checkpoints = Vec::new();
        for row in rows {
            let (
                scan_id,
                created_at,
                updated_at,
                command_args,
                targets_json,
                status,
                completed_json,
                results_json,
                total_hosts,
                timing,
            ) = row?;

            let targets: Vec<String> = serde_json::from_str(&targets_json).unwrap_or_default();
            let completed_hosts: Vec<String> =
                serde_json::from_str(&completed_json).unwrap_or_default();
            let partial_results: Vec<HostScanResult> =
                serde_json::from_str(&results_json).unwrap_or_default();

            checkpoints.push(ScanCheckpoint {
                scan_id,
                created_at,
                updated_at,
                command_args,
                targets,
                status,
                completed_hosts,
                partial_results,
                total_hosts: total_hosts as usize,
                timing_template: timing.map(|t| t as u8),
            });
        }

        Ok(checkpoints)
    }
}

/// Extract a CIDR-aware IP prefix string for LIKE queries.
///
/// Given a subnet like "192.168.1.0/24", returns "192.168.1." (3 octets).
/// For "10.0.0.0/8", returns "10." (1 octet). For non-standard masks like
/// "/20", returns the nearest full-octet prefix (rounded down to /16 → "10.0.").
///
/// Falls back to the full subnet IP (without mask) with a trailing dot if
/// the format is unrecognised.
fn extract_subnet_prefix(subnet: &str) -> String {
    let (ip_part, prefix_len) = match subnet.split_once('/') {
        Some((ip, bits)) => (ip, bits.parse::<u8>().unwrap_or(24)),
        None => return format!("{subnet}."),
    };

    let octets: Vec<&str> = ip_part.split('.').collect();
    if octets.len() != 4 {
        // IPv6 or malformed — use full ip
        return format!("{ip_part}.");
    }

    // Number of full octets to keep (round down: /20 → 2 octets, /8 → 1)
    let full_octets = (prefix_len / 8) as usize;
    let kept = full_octets.clamp(1, 4);

    let prefix: Vec<&str> = octets[..kept].to_vec();
    format!("{}.", prefix.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{
        DetectionMethod, Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanResult,
        ScanType, ServiceInfo,
    };
    use std::net::IpAddr;
    use std::time::Duration;

    fn mock_scan_result() -> ScanResult {
        ScanResult {
            hosts: vec![HostScanResult {
                host: Host {
                    ip: IpAddr::from([192, 168, 1, 1]),
                    hostname: Some("test.local".into()),
                    geo_info: None,
                },
                ports: vec![
                    Port {
                        number: 22,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service: Some("ssh".into()),
                        service_info: None,
                        reason: Some("syn-ack".into()),
                        script_results: vec![],
                        tls_info: None,
                    },
                    Port {
                        number: 80,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service: Some("http".into()),
                        service_info: None,
                        reason: Some("syn-ack".into()),
                        script_results: vec![],
                        tls_info: None,
                    },
                ],
                scan_duration: Duration::from_millis(500),
                host_status: HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(1)),
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_secs(1),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: Some("rustmap -sS 192.168.1.1".into()),
            num_services: 2,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    fn test_host_result(ip: &str) -> HostScanResult {
        HostScanResult {
            host: Host {
                ip: ip.parse().unwrap(),
                hostname: None,
                geo_info: None,
            },
            ports: vec![Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some("http".into()),
                service_info: None,
                reason: None,
                script_results: vec![],
                tls_info: None,
            }],
            scan_duration: Duration::from_millis(50),
            host_status: HostStatus::Up,
            discovery_latency: None,
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

    fn mock_scan_result_v2() -> ScanResult {
        // Same host but port 22 closed, port 443 appeared
        ScanResult {
            hosts: vec![HostScanResult {
                host: Host {
                    ip: IpAddr::from([192, 168, 1, 1]),
                    hostname: Some("test.local".into()),
                    geo_info: None,
                },
                ports: vec![
                    Port {
                        number: 22,
                        protocol: Protocol::Tcp,
                        state: PortState::Closed,
                        service: Some("ssh".into()),
                        service_info: None,
                        reason: Some("rst".into()),
                        script_results: vec![],
                        tls_info: None,
                    },
                    Port {
                        number: 80,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service: Some("http".into()),
                        service_info: None,
                        reason: Some("syn-ack".into()),
                        script_results: vec![],
                        tls_info: None,
                    },
                    Port {
                        number: 443,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service: Some("https".into()),
                        service_info: None,
                        reason: Some("syn-ack".into()),
                        script_results: vec![],
                        tls_info: None,
                    },
                ],
                scan_duration: Duration::from_millis(600),
                host_status: HostStatus::Up,
                discovery_latency: Some(Duration::from_millis(2)),
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_secs(1),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 3,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    #[test]
    fn save_and_load_scan() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();

        store
            .save_scan("scan-1", &result, 1000, 2000, Some(3))
            .unwrap();

        let loaded = store.load_scan("scan-1").unwrap().unwrap();
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].ports.len(), 2);
        assert_eq!(loaded.scan_type, ScanType::TcpSyn);
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let store = ScanStore::open_in_memory().unwrap();
        assert!(store.load_scan("no-such-scan").unwrap().is_none());
    }

    #[test]
    fn list_scans_returns_summaries() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();

        store
            .save_scan("scan-a", &result, 1000, 2000, Some(3))
            .unwrap();
        store
            .save_scan("scan-b", &result, 3000, 4000, None)
            .unwrap();

        let scans = store.list_scans().unwrap();
        assert_eq!(scans.len(), 2);
        // Most recent first
        assert_eq!(scans[0].scan_id, "scan-b");
        assert_eq!(scans[1].scan_id, "scan-a");
        assert_eq!(scans[0].num_hosts, 1);
        assert_eq!(scans[0].num_services, 2);
    }

    #[test]
    fn delete_scan_cascades() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();

        store
            .save_scan("scan-del", &result, 1000, 2000, None)
            .unwrap();
        assert!(store.delete_scan("scan-del").unwrap());
        assert!(store.load_scan("scan-del").unwrap().is_none());

        // Host and port results should also be gone
        let hosts = store.hosts_in_scan("scan-del").unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn known_open_ports_from_history() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();

        store
            .save_scan("scan-ports", &result, 1000, 2000, None)
            .unwrap();

        let ports = store.known_open_ports("192.168.1.1").unwrap();
        assert_eq!(ports, vec![22, 80]);
    }

    #[test]
    fn known_open_ports_unknown_host() {
        let store = ScanStore::open_in_memory().unwrap();
        let ports = store.known_open_ports("10.0.0.1").unwrap();
        assert!(ports.is_empty());
    }

    #[test]
    fn network_profile_create_and_update() {
        let store = ScanStore::open_in_memory().unwrap();

        store
            .update_network_profile("192.168.1.0/24", 5.0, 0.0)
            .unwrap();
        let profile = store.network_profile("192.168.1.0/24").unwrap().unwrap();
        assert_eq!(profile.scan_count, 1);
        assert!((profile.avg_rtt_ms - 5.0).abs() < 0.01);
        assert_eq!(profile.recommended_timing, 5); // very fast LAN

        // Update with slower data
        store
            .update_network_profile("192.168.1.0/24", 150.0, 0.02)
            .unwrap();
        let profile = store.network_profile("192.168.1.0/24").unwrap().unwrap();
        assert_eq!(profile.scan_count, 2);
        // EMA: 5.0 * 0.7 + 150.0 * 0.3 = 3.5 + 45.0 = 48.5
        assert!((profile.avg_rtt_ms - 48.5).abs() < 0.01);
    }

    #[test]
    fn diff_scans_detects_changes() {
        let store = ScanStore::open_in_memory().unwrap();

        store
            .save_scan("old", &mock_scan_result(), 1000, 2000, None)
            .unwrap();
        store
            .save_scan("new", &mock_scan_result_v2(), 3000, 4000, None)
            .unwrap();

        let diff = store.diff_scans("old", "new").unwrap();
        assert!(diff.new_hosts.is_empty());
        assert!(diff.removed_hosts.is_empty());

        // Port 22 changed open -> closed
        let p22 = diff
            .port_changes
            .iter()
            .find(|c| c.port == 22)
            .expect("port 22 should have changed");
        assert_eq!(p22.old_state.as_deref(), Some("open"));
        assert_eq!(p22.new_state.as_deref(), Some("closed"));

        // Port 443 is new
        let p443 = diff
            .port_changes
            .iter()
            .find(|c| c.port == 443)
            .expect("port 443 should be new");
        assert!(p443.old_state.is_none());
        assert_eq!(p443.new_state.as_deref(), Some("open"));
    }

    #[test]
    fn diff_scans_detects_removed_hosts() {
        let store = ScanStore::open_in_memory().unwrap();

        store
            .save_scan("with-host", &mock_scan_result(), 1000, 2000, None)
            .unwrap();
        // Empty scan — host disappeared
        let empty = ScanResult {
            hosts: vec![],
            total_duration: Duration::from_secs(1),
            scan_type: ScanType::TcpSyn,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };
        store
            .save_scan("without-host", &empty, 3000, 4000, None)
            .unwrap();

        let diff = store.diff_scans("with-host", "without-host").unwrap();
        assert_eq!(diff.removed_hosts, vec!["192.168.1.1"]);
        assert!(diff.new_hosts.is_empty());
    }

    #[test]
    fn last_scan_for_host_returns_most_recent() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();

        store
            .save_scan("scan-old", &result, 1000, 2000, None)
            .unwrap();
        store
            .save_scan("scan-new", &result, 3000, 4000, None)
            .unwrap();

        let summary = store.last_scan_for_host("192.168.1.1").unwrap().unwrap();
        assert_eq!(summary.scan_id, "scan-new");
    }

    #[test]
    fn last_scan_id_for_host_returns_most_recent() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();

        store
            .save_scan("scan-first", &result, 1000, 2000, None)
            .unwrap();
        store
            .save_scan("scan-second", &result, 3000, 4000, None)
            .unwrap();

        let id = store.last_scan_id_for_host("192.168.1.1").unwrap().unwrap();
        assert_eq!(id, "scan-second");

        // Unknown host returns None
        assert!(store.last_scan_id_for_host("10.0.0.99").unwrap().is_none());
    }

    #[test]
    fn previous_scan_id_excludes_current() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();

        store
            .save_scan("scan-a", &result, 1000, 2000, None)
            .unwrap();
        store
            .save_scan("scan-b", &result, 3000, 4000, None)
            .unwrap();

        // Excluding scan-b, should get scan-a
        let prev = store
            .previous_scan_id_for_host("192.168.1.1", "scan-b")
            .unwrap()
            .unwrap();
        assert_eq!(prev, "scan-a");

        // Excluding scan-a, should get scan-b
        let prev = store
            .previous_scan_id_for_host("192.168.1.1", "scan-a")
            .unwrap()
            .unwrap();
        assert_eq!(prev, "scan-b");

        // Only one scan exists after excluding both? Excluding scan-a leaves scan-b
        // If only one scan, excluding it returns None
        let store2 = ScanStore::open_in_memory().unwrap();
        store2
            .save_scan("only-scan", &result, 1000, 2000, None)
            .unwrap();
        let prev = store2
            .previous_scan_id_for_host("192.168.1.1", "only-scan")
            .unwrap();
        assert!(prev.is_none());
    }

    #[test]
    fn recommend_timing_values() {
        assert_eq!(recommend_timing(5.0, 0.0), 5); // LAN -> Insane
        assert_eq!(recommend_timing(50.0, 0.0), 4); // Fast -> Aggressive
        assert_eq!(recommend_timing(150.0, 0.0), 3); // Medium -> Normal
        assert_eq!(recommend_timing(600.0, 0.0), 2); // Slow -> Polite
        assert_eq!(recommend_timing(10.0, 0.15), 2); // Lossy -> Polite
        assert_eq!(recommend_timing(1500.0, 0.0), 1); // Very slow -> Sneaky
        assert_eq!(recommend_timing(10.0, 0.30), 1); // Very lossy -> Sneaky
    }

    #[test]
    fn save_scan_timing_stores_data() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();
        store
            .save_scan("scan-t1", &result, 1000, 2000, Some(3))
            .unwrap();

        store
            .save_scan_timing("scan-t1", Some(5000), 15000, 4.0, 100, 95, 5, 0.05, 2000)
            .unwrap();

        // Verify by querying directly
        let mut stmt = store
            .conn
            .prepare("SELECT avg_srtt_us, loss_rate FROM scan_timing WHERE scan_id = ?1")
            .unwrap();
        let mut rows = stmt.query(params!["scan-t1"]).unwrap();
        let row = rows.next().unwrap().unwrap();
        let srtt: Option<i64> = row.get(0).unwrap();
        let loss: f64 = row.get(1).unwrap();
        assert_eq!(srtt, Some(5000));
        assert!((loss - 0.05).abs() < 0.001);
    }

    #[test]
    fn save_scan_timing_null_srtt() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();
        store
            .save_scan("scan-t2", &result, 1000, 2000, None)
            .unwrap();

        store
            .save_scan_timing("scan-t2", None, 3000000, 100.0, 50, 50, 0, 0.0, 2000)
            .unwrap();

        let mut stmt = store
            .conn
            .prepare("SELECT avg_srtt_us FROM scan_timing WHERE scan_id = ?1")
            .unwrap();
        let mut rows = stmt.query(params!["scan-t2"]).unwrap();
        let row = rows.next().unwrap().unwrap();
        let srtt: Option<i64> = row.get(0).unwrap();
        assert_eq!(srtt, None);
    }

    #[test]
    fn loss_rate_computed_correctly() {
        // Test that loss rate is correctly computed from probes
        let total_sent: u64 = 100;
        let total_responded: u64 = 85;
        let loss = 1.0 - (total_responded as f64 / total_sent as f64);
        assert!((loss - 0.15).abs() < 0.001);

        // Zero probes: loss = 0.0
        let zero_sent: u64 = 0;
        let loss_zero = if zero_sent > 0 {
            1.0 - (0.0_f64 / zero_sent as f64)
        } else {
            0.0
        };
        assert_eq!(loss_zero, 0.0);
    }

    #[test]
    fn update_port_history_increments() {
        let store = ScanStore::open_in_memory().unwrap();

        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 80, "tcp", true, 1000)
            .unwrap();
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 80, "tcp", true, 2000)
            .unwrap();
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 80, "tcp", false, 3000)
            .unwrap();

        let mut stmt = store.conn.prepare(
            "SELECT times_open, times_scanned FROM port_history WHERE ip = ?1 AND port_number = ?2"
        ).unwrap();
        let mut rows = stmt.query(params!["10.0.0.1", 80i64]).unwrap();
        let row = rows.next().unwrap().unwrap();
        let open: i64 = row.get(0).unwrap();
        let scanned: i64 = row.get(1).unwrap();
        assert_eq!(open, 2);
        assert_eq!(scanned, 3);
    }

    #[test]
    fn predict_ports_for_host_sorted() {
        let store = ScanStore::open_in_memory().unwrap();

        // Port 80: open 3/3 = 1.0
        for _ in 0..3 {
            store
                .update_port_history("10.0.0.1", "10.0.0.0/24", 80, "tcp", true, 1000)
                .unwrap();
        }
        // Port 22: open 1/3 = 0.33
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 22, "tcp", true, 1000)
            .unwrap();
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 22, "tcp", false, 2000)
            .unwrap();
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 22, "tcp", false, 3000)
            .unwrap();

        let predictions = store.predict_ports_for_host("10.0.0.1", 10).unwrap();
        assert_eq!(predictions.len(), 2);
        assert_eq!(predictions[0].port, 80);
        assert!((predictions[0].open_probability - 1.0).abs() < 0.01);
        assert_eq!(predictions[1].port, 22);
        assert!(predictions[1].open_probability < 0.5);
    }

    #[test]
    fn predict_ports_for_subnet_aggregates() {
        let store = ScanStore::open_in_memory().unwrap();

        // Two hosts in same subnet, both have port 443 open
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 443, "tcp", true, 1000)
            .unwrap();
        store
            .update_port_history("10.0.0.2", "10.0.0.0/24", 443, "tcp", true, 1000)
            .unwrap();
        // Port 22 only open on one host
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 22, "tcp", true, 1000)
            .unwrap();
        store
            .update_port_history("10.0.0.2", "10.0.0.0/24", 22, "tcp", false, 1000)
            .unwrap();

        let predictions = store.predict_ports_for_subnet("10.0.0.0/24", 10).unwrap();
        assert_eq!(predictions.len(), 2);
        // Port 443 should have higher probability (2/2 = 1.0)
        assert_eq!(predictions[0].port, 443);
        assert!((predictions[0].open_probability - 1.0).abs() < 0.01);
        // Port 22: 1/2 = 0.5
        assert_eq!(predictions[1].port, 22);
        assert!((predictions[1].open_probability - 0.5).abs() < 0.01);
        assert_eq!(predictions[0].source, PredictionSource::Subnet);
    }

    #[test]
    fn port_history_upsert_idempotent() {
        let store = ScanStore::open_in_memory().unwrap();

        // Insert same port twice — should upsert, not create duplicate
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 80, "tcp", true, 1000)
            .unwrap();
        store
            .update_port_history("10.0.0.1", "10.0.0.0/24", 80, "tcp", false, 2000)
            .unwrap();

        let mut stmt = store
            .conn
            .prepare("SELECT COUNT(*) FROM port_history WHERE ip = ?1 AND port_number = ?2")
            .unwrap();
        let count: i64 = stmt
            .query_row(params!["10.0.0.1", 80i64], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "should be exactly one row after upsert");
    }

    #[test]
    fn predict_ports_empty_history() {
        let store = ScanStore::open_in_memory().unwrap();
        let predictions = store.predict_ports_for_host("10.0.0.1", 10).unwrap();
        assert!(predictions.is_empty());
    }

    #[test]
    fn learned_timing_params_from_history() {
        let store = ScanStore::open_in_memory().unwrap();
        let result = mock_scan_result();

        // Build up enough history for confidence
        for i in 0..5 {
            let scan_id = format!("scan-ltp-{i}");
            store
                .save_scan(&scan_id, &result, 1000 + i * 1000, 2000 + i * 1000, Some(3))
                .unwrap();
            store
                .update_network_profile("192.168.1.0/24", 25.0, 0.02)
                .unwrap();
            store
                .save_scan_timing(
                    &scan_id,
                    Some(25000),
                    75000,
                    8.0,
                    100,
                    98,
                    2,
                    0.02,
                    2000 + i * 1000,
                )
                .unwrap();
        }

        let learned = store
            .learned_timing_params("192.168.1.0/24")
            .unwrap()
            .unwrap();
        assert!(learned.confidence >= 0.3);
        assert!(learned.suggested_initial_rto_us.is_some());
        assert!(learned.suggested_initial_cwnd.is_some());
        assert!(learned.suggested_max_retries.is_some());
        // With 2% loss, max_retries should be 3
        assert_eq!(learned.suggested_max_retries, Some(3));
    }

    #[test]
    fn learned_params_insufficient_data() {
        let store = ScanStore::open_in_memory().unwrap();
        // No data at all
        let learned = store.learned_timing_params("10.0.0.0/24").unwrap();
        assert!(learned.is_none());
    }

    #[test]
    fn learned_params_confidence_threshold() {
        let store = ScanStore::open_in_memory().unwrap();
        // Only 1 scan = confidence 0.1 (below 0.3 threshold)
        store
            .update_network_profile("10.0.0.0/24", 10.0, 0.0)
            .unwrap();
        let learned = store.learned_timing_params("10.0.0.0/24").unwrap().unwrap();
        assert!(learned.confidence < 0.3);
    }

    // --- 12D: Service Memory ---

    #[test]
    fn update_service_cache_creates() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_service_cache(
                "10.0.0.1",
                80,
                "tcp",
                "http",
                Some("Apache"),
                Some("2.4"),
                1000,
            )
            .unwrap();
        let cached = store
            .get_cached_service("10.0.0.1", 80, "tcp")
            .unwrap()
            .unwrap();
        assert_eq!(cached.service_name, "http");
        assert_eq!(cached.product.as_deref(), Some("Apache"));
        assert_eq!(cached.version.as_deref(), Some("2.4"));
        assert_eq!(cached.times_seen, 1);
        assert_eq!(cached.last_seen, 1000);
    }

    #[test]
    fn update_service_cache_updates() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_service_cache(
                "10.0.0.1",
                80,
                "tcp",
                "http",
                Some("Apache"),
                Some("2.4"),
                1000,
            )
            .unwrap();
        store
            .update_service_cache(
                "10.0.0.1",
                80,
                "tcp",
                "http",
                Some("Apache"),
                Some("2.6"),
                2000,
            )
            .unwrap();
        let cached = store
            .get_cached_service("10.0.0.1", 80, "tcp")
            .unwrap()
            .unwrap();
        assert_eq!(cached.version.as_deref(), Some("2.6"));
        assert_eq!(cached.times_seen, 2);
        assert_eq!(cached.last_seen, 2000);
    }

    #[test]
    fn get_cached_service_not_found() {
        let store = ScanStore::open_in_memory().unwrap();
        let cached = store.get_cached_service("10.0.0.1", 80, "tcp").unwrap();
        assert!(cached.is_none());
    }

    #[test]
    fn detect_new_service() {
        let store = ScanStore::open_in_memory().unwrap();
        // No cache exists — a port with a service should be flagged as New
        let ports = vec![Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        let changes = store.detect_service_changes("10.0.0.1", &ports).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ServiceChangeType::New);
        assert_eq!(changes[0].new_service.as_deref(), Some("http"));
    }

    #[test]
    fn detect_changed_service() {
        let store = ScanStore::open_in_memory().unwrap();
        // Cache has "http", now we see "https"
        store
            .update_service_cache("10.0.0.1", 443, "tcp", "http", None, None, 1000)
            .unwrap();
        let ports = vec![Port {
            number: 443,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("https".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        let changes = store.detect_service_changes("10.0.0.1", &ports).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ServiceChangeType::Changed);
        assert_eq!(changes[0].old_service.as_deref(), Some("http"));
        assert_eq!(changes[0].new_service.as_deref(), Some("https"));
    }

    #[test]
    fn detect_version_change() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_service_cache(
                "10.0.0.1",
                22,
                "tcp",
                "ssh",
                Some("OpenSSH"),
                Some("8.9"),
                1000,
            )
            .unwrap();
        let ports = vec![Port {
            number: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("ssh".into()),
            service_info: Some(ServiceInfo {
                name: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: Some("9.0".into()),
                info: None,
                method: DetectionMethod::Probe,
            }),
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        let changes = store.detect_service_changes("10.0.0.1", &ports).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ServiceChangeType::VersionChanged);
        assert!(changes[0].old_service.as_ref().unwrap().contains("8.9"));
        assert!(changes[0].new_service.as_ref().unwrap().contains("9.0"));
    }

    #[test]
    fn detect_no_change_same_service() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_service_cache("10.0.0.1", 80, "tcp", "http", None, None, 1000)
            .unwrap();
        let ports = vec![Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        let changes = store.detect_service_changes("10.0.0.1", &ports).unwrap();
        assert!(changes.is_empty(), "same service should produce no changes");
    }

    // --- 12E: Host Behavior Profiles ---

    #[test]
    fn update_host_profile_creates() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_host_profile("10.0.0.1", "10.0.0.0/24", true, Some(1.5), 1000)
            .unwrap();
        let profile = store.get_host_profile("10.0.0.1").unwrap().unwrap();
        assert_eq!(profile.times_scanned, 1);
        assert_eq!(profile.times_up, 1);
        assert_eq!(profile.behavior, "always_up");
        assert!(profile.avg_discovery_ms.is_some());
        assert_eq!(profile.last_seen_up, Some(1000));
    }

    #[test]
    fn update_host_profile_increments() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_host_profile("10.0.0.1", "10.0.0.0/24", true, Some(2.0), 1000)
            .unwrap();
        store
            .update_host_profile("10.0.0.1", "10.0.0.0/24", true, Some(3.0), 2000)
            .unwrap();
        store
            .update_host_profile("10.0.0.1", "10.0.0.0/24", false, None, 3000)
            .unwrap();
        let profile = store.get_host_profile("10.0.0.1").unwrap().unwrap();
        assert_eq!(profile.times_scanned, 3);
        assert_eq!(profile.times_up, 2);
        assert_eq!(profile.behavior, "intermittent"); // 2/3 ≈ 0.67 → intermittent
    }

    #[test]
    fn classify_behavior_always_up() {
        assert_eq!(classify_behavior(10, 10), "always_up");
    }

    #[test]
    fn classify_behavior_mostly_up() {
        assert_eq!(classify_behavior(9, 10), "mostly_up");
    }

    #[test]
    fn classify_behavior_intermittent() {
        assert_eq!(classify_behavior(5, 10), "intermittent");
    }

    #[test]
    fn classify_behavior_always_down() {
        assert_eq!(classify_behavior(0, 10), "always_down");
    }

    #[test]
    fn classify_behavior_unknown() {
        assert_eq!(classify_behavior(0, 0), "unknown");
    }

    #[test]
    fn hosts_always_up_min_scans() {
        let store = ScanStore::open_in_memory().unwrap();
        // Create a host that's always up with 5 scans
        for i in 0..5 {
            store
                .update_host_profile("10.0.0.1", "10.0.0.0/24", true, Some(1.0), 1000 + i)
                .unwrap();
        }
        // Another host always up but only 3 scans (below min_scans=5)
        for i in 0..3 {
            store
                .update_host_profile("10.0.0.2", "10.0.0.0/24", true, Some(1.0), 1000 + i)
                .unwrap();
        }
        let always_up = store.hosts_always_up("10.0.0.0/24", 5).unwrap();
        assert_eq!(always_up.len(), 1);
        assert_eq!(always_up[0], "10.0.0.1");
    }

    #[test]
    fn hosts_always_up_excludes_down() {
        let store = ScanStore::open_in_memory().unwrap();
        // Host that's intermittent
        for i in 0..5 {
            store
                .update_host_profile("10.0.0.1", "10.0.0.0/24", i % 2 == 0, None, 1000 + i)
                .unwrap();
        }
        let always_up = store.hosts_always_up("10.0.0.0/24", 3).unwrap();
        assert!(always_up.is_empty());
    }

    #[test]
    fn get_host_profile_not_found() {
        let store = ScanStore::open_in_memory().unwrap();
        let profile = store.get_host_profile("10.0.0.99").unwrap();
        assert!(profile.is_none());
    }

    // --- 12F: Network Characterization ---

    #[test]
    fn stability_score_perfect_network() {
        let score = compute_stability_score(0.0, 0.0);
        assert!((score - 1.0).abs() < 0.001);
    }

    #[test]
    fn stability_score_lossy_network() {
        let score = compute_stability_score(0.5, 0.5);
        assert!(score < 0.6);
        assert!(score > 0.4);
    }

    #[test]
    fn stability_score_high_jitter() {
        let score = compute_stability_score(0.0, 1.0);
        assert!((score - 0.5).abs() < 0.001);
    }

    #[test]
    fn update_time_pattern_creates() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_time_pattern("10.0.0.0/24", 14, 25.0, 0.01)
            .unwrap();
        let patterns = store.get_time_patterns("10.0.0.0/24").unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].hour, 14);
        assert!((patterns[0].avg_rtt_ms - 25.0).abs() < 0.1);
        assert_eq!(patterns[0].sample_count, 1);
    }

    #[test]
    fn update_time_pattern_averages() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_time_pattern("10.0.0.0/24", 14, 20.0, 0.01)
            .unwrap();
        store
            .update_time_pattern("10.0.0.0/24", 14, 40.0, 0.05)
            .unwrap();
        let patterns = store.get_time_patterns("10.0.0.0/24").unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].sample_count, 2);
        // EMA: 20.0 * 0.7 + 40.0 * 0.3 = 14.0 + 12.0 = 26.0
        assert!((patterns[0].avg_rtt_ms - 26.0).abs() < 0.1);
    }

    #[test]
    fn get_time_patterns_ordered() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_time_pattern("10.0.0.0/24", 22, 30.0, 0.01)
            .unwrap();
        store
            .update_time_pattern("10.0.0.0/24", 8, 15.0, 0.01)
            .unwrap();
        store
            .update_time_pattern("10.0.0.0/24", 14, 20.0, 0.01)
            .unwrap();
        let patterns = store.get_time_patterns("10.0.0.0/24").unwrap();
        assert_eq!(patterns.len(), 3);
        assert_eq!(patterns[0].hour, 8);
        assert_eq!(patterns[1].hour, 14);
        assert_eq!(patterns[2].hour, 22);
    }

    #[test]
    fn update_network_stability_computes() {
        let store = ScanStore::open_in_memory().unwrap();
        // First create a network profile
        store
            .update_network_profile("10.0.0.0/24", 25.0, 0.01)
            .unwrap();
        // Then update stability with jitter
        store
            .update_network_stability("10.0.0.0/24", 5000.0)
            .unwrap();
        let profile = store.network_profile("10.0.0.0/24").unwrap().unwrap();
        assert!(profile.avg_jitter_us.is_some());
        assert!(profile.stability_score.is_some());
        // Low loss (1%) and moderate jitter → high stability
        assert!(profile.stability_score.unwrap() > 0.7);
    }

    #[test]
    fn network_profile_includes_new_fields() {
        let store = ScanStore::open_in_memory().unwrap();
        store
            .update_network_profile("10.0.0.0/24", 10.0, 0.0)
            .unwrap();
        let profile = store.network_profile("10.0.0.0/24").unwrap().unwrap();
        // New fields should be None initially
        assert!(profile.avg_jitter_us.is_none());
        assert!(profile.stability_score.is_none());
    }

    #[test]
    fn rttvar_exposed_in_timing_stats() {
        // This test is in rustmap-timing, but we verify the struct field exists here
        let record = ScanTimingRecord {
            scan_id: "test".into(),
            avg_srtt_us: Some(25000),
            avg_rto_us: 75000,
            avg_cwnd: 8.0,
            total_probes_sent: 100,
            total_probes_responded: 98,
            total_probes_timed_out: 2,
            loss_rate: 0.02,
            scan_timestamp: 1000,
        };
        assert!(record.loss_rate < 0.03);
    }

    // --- Checkpoint tests ---

    fn test_checkpoint(scan_id: &str) -> ScanCheckpoint {
        ScanCheckpoint {
            scan_id: scan_id.into(),
            created_at: 1000,
            updated_at: 1000,
            command_args: "rustmap 192.168.1.0/24 -T4".into(),
            targets: vec![
                "192.168.1.1".into(),
                "192.168.1.2".into(),
                "192.168.1.3".into(),
            ],
            status: "in_progress".into(),
            completed_hosts: vec![],
            partial_results: vec![],
            total_hosts: 3,
            timing_template: Some(4),
        }
    }

    #[test]
    fn test_create_and_load_checkpoint() {
        let store = ScanStore::open_in_memory().unwrap();
        let cp = test_checkpoint("scan-cp-1");
        store.create_checkpoint(&cp).unwrap();

        let loaded = store.load_checkpoint("scan-cp-1").unwrap().unwrap();
        assert_eq!(loaded.scan_id, "scan-cp-1");
        assert_eq!(loaded.targets.len(), 3);
        assert_eq!(loaded.total_hosts, 3);
        assert_eq!(loaded.timing_template, Some(4));
        assert_eq!(loaded.status, "in_progress");
        assert!(loaded.completed_hosts.is_empty());
        assert!(loaded.partial_results.is_empty());
    }

    #[test]
    fn test_update_checkpoint_adds_host() {
        let store = ScanStore::open_in_memory().unwrap();
        let cp = test_checkpoint("scan-cp-2");
        store.create_checkpoint(&cp).unwrap();

        let host_result = test_host_result("192.168.1.1");
        store
            .update_checkpoint("scan-cp-2", "192.168.1.1", &host_result)
            .unwrap();

        let loaded = store.load_checkpoint("scan-cp-2").unwrap().unwrap();
        assert_eq!(loaded.completed_hosts.len(), 1);
        assert_eq!(loaded.completed_hosts[0], "192.168.1.1");
        assert_eq!(loaded.partial_results.len(), 1);
    }

    #[test]
    fn test_update_preserves_partial_results() {
        let store = ScanStore::open_in_memory().unwrap();
        let cp = test_checkpoint("scan-cp-3");
        store.create_checkpoint(&cp).unwrap();

        let host1 = test_host_result("192.168.1.1");
        let host2 = test_host_result("192.168.1.2");
        store
            .update_checkpoint("scan-cp-3", "192.168.1.1", &host1)
            .unwrap();
        store
            .update_checkpoint("scan-cp-3", "192.168.1.2", &host2)
            .unwrap();

        let loaded = store.load_checkpoint("scan-cp-3").unwrap().unwrap();
        assert_eq!(loaded.completed_hosts.len(), 2);
        assert_eq!(loaded.partial_results.len(), 2);
    }

    #[test]
    fn test_delete_checkpoint() {
        let store = ScanStore::open_in_memory().unwrap();
        let cp = test_checkpoint("scan-cp-4");
        store.create_checkpoint(&cp).unwrap();

        store.delete_checkpoint("scan-cp-4").unwrap();
        let loaded = store.load_checkpoint("scan-cp-4").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_list_checkpoints_only_in_progress() {
        let store = ScanStore::open_in_memory().unwrap();

        let cp1 = test_checkpoint("scan-cp-5");
        store.create_checkpoint(&cp1).unwrap();

        let mut cp2 = test_checkpoint("scan-cp-6");
        cp2.status = "completed".into();
        store.create_checkpoint(&cp2).unwrap();

        let list = store.list_checkpoints().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].scan_id, "scan-cp-5");
    }

    #[test]
    fn test_load_checkpoint_not_found() {
        let store = ScanStore::open_in_memory().unwrap();
        let loaded = store.load_checkpoint("nonexistent").unwrap();
        assert!(loaded.is_none());
    }
}
