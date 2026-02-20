use async_trait::async_trait;

use rustmap_types::{Host, HostScanResult, ScanConfig};

use crate::raw_tcp::RawTcpScanner;
use crate::traits::{ScanError, Scanner};

/// TCP SYN (half-open) scanner.
///
/// Thin wrapper around `RawTcpScanner` configured for SYN scanning.
/// Sends raw TCP SYN packets, correlates responses (SYN/ACK, RST, ICMP)
/// using unique source ports, with adaptive timing.
pub struct TcpSynScanner(RawTcpScanner);

impl TcpSynScanner {
    pub fn new() -> Self {
        Self(RawTcpScanner::syn())
    }
}

impl Default for TcpSynScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Scanner for TcpSynScanner {
    async fn scan_host(
        &self,
        host: &Host,
        config: &ScanConfig,
    ) -> Result<HostScanResult, ScanError> {
        self.0.scan_host(host, config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_creates_successfully() {
        let _scanner = TcpSynScanner::new();
    }

    #[test]
    fn scanner_default() {
        let _scanner = TcpSynScanner::default();
    }
}
