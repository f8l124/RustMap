use async_trait::async_trait;
use rustmap_types::{Host, HostScanResult, ScanConfig};

/// Trait that all scan implementations must satisfy.
#[async_trait]
pub trait Scanner: Send + Sync {
    async fn scan_host(
        &self,
        host: &Host,
        config: &ScanConfig,
    ) -> Result<HostScanResult, ScanError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("scan timed out for host {host}")]
    Timeout { host: String },
    #[error("connection error: {0}")]
    ConnectionError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet error: {0}")]
    Packet(#[from] rustmap_packet::PacketError),
    #[error("insufficient privileges for {0} scan")]
    InsufficientPrivileges(String),
}
