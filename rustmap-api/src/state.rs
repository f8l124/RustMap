// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rustmap_db::ScanStore;
use rustmap_types::{HostScanResult, ScanResult};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, broadcast};
use tokio_util::sync::CancellationToken;

/// Status of a scan tracked by the API server.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Running,
    Completed,
    Cancelled,
    Error(String),
}

/// JSON-serializable event for WebSocket clients.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEvent {
    DiscoveryComplete {
        hosts_total: usize,
    },
    HostResult {
        index: usize,
        result: Box<HostScanResult>,
        hosts_completed: usize,
        hosts_total: usize,
    },
    Complete {
        result: Box<ScanResult>,
    },
    Error {
        message: String,
    },
    Warning {
        message: String,
    },
    Log {
        message: String,
    },
}

/// Metadata for a running or recently-completed scan.
pub struct TrackedScan {
    pub scan_id: String,
    pub status: ScanStatus,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub cancel: CancellationToken,
    /// Broadcast channel for relaying scan events to WebSocket clients.
    pub event_tx: broadcast::Sender<Arc<WsEvent>>,
}

/// Global application state for the API server.
pub struct AppState {
    /// Currently tracked scans (running + recently completed in-memory).
    pub scans: RwLock<HashMap<String, TrackedScan>>,
    /// Persistent scan database.
    pub store: Mutex<ScanStore>,
    /// Server start time for uptime reporting.
    pub started_at: Instant,
    /// SHA-256 hash of the API key (if configured). The plaintext key is never
    /// stored — only its hash is kept in memory so that a heap dump cannot
    /// directly reveal the credential.
    pub api_key_hash: Option<[u8; 32]>,
    /// Active WebSocket connection count (used to enforce connection limits).
    pub ws_connection_count: AtomicUsize,
    /// Simple per-key rate limiter for scan creation: maps key -> last creation
    /// time. Protected by a tokio Mutex to keep things simple.
    pub rate_limit_map: Mutex<HashMap<String, Instant>>,
}

/// Hash a plaintext API key to a 32-byte SHA-256 digest.
fn hash_api_key(key: &str) -> [u8; 32] {
    let digest = Sha256::digest(key.as_bytes());
    digest.into()
}

impl AppState {
    pub fn new(api_key: Option<String>) -> Self {
        let store = ScanStore::open_default().expect("failed to open scan database");
        Self {
            scans: RwLock::new(HashMap::new()),
            store: Mutex::new(store),
            started_at: Instant::now(),
            api_key_hash: api_key.as_deref().map(hash_api_key),
            ws_connection_count: AtomicUsize::new(0),
            rate_limit_map: Mutex::new(HashMap::new()),
        }
    }

    /// Create an AppState with an in-memory database (for testing).
    pub fn new_in_memory(api_key: Option<String>) -> Self {
        let store = ScanStore::open_in_memory().expect("failed to open in-memory database");
        Self {
            scans: RwLock::new(HashMap::new()),
            store: Mutex::new(store),
            started_at: Instant::now(),
            api_key_hash: api_key.as_deref().map(hash_api_key),
            ws_connection_count: AtomicUsize::new(0),
            rate_limit_map: Mutex::new(HashMap::new()),
        }
    }
}

/// Get the current timestamp in milliseconds since the UNIX epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
