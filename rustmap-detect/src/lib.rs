mod banner;
mod detector;
pub mod modern_probes;
pub mod os_detect;
pub mod os_signatures;
pub mod p0f_parser;
mod pattern;
mod patterns_db;
mod port_map;
mod probe;
mod probes_db;
mod proxy;
pub mod tls_fingerprint;
pub mod tls_signatures;
pub mod uptime;

pub use detector::ServiceDetector;
pub use modern_probes::{
    QuicProbeResult, probe_http2_cleartext, probe_quic, probe_quic_detailed, probe_tls_for_service,
};
pub use os_detect::{OsDetector, infer_os_from_services};
pub use port_map::PortServiceMap;
pub use tls_fingerprint::{is_tls_port, probe_tls_server};
pub use uptime::{estimate_uptime, format_uptime};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("timeout during detection")]
    Timeout,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
