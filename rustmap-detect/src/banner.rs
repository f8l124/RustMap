use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::timeout;
use tracing::debug;

use crate::DetectionError;
use crate::proxy::connect_tcp;
use rustmap_types::ProxyConfig;

/// Maximum bytes to read for a banner.
const MAX_BANNER_SIZE: usize = 4096;

/// Banner grabber — connects to a port and reads the initial server response
/// (the "NULL probe" in nmap terminology).
#[derive(Clone)]
pub struct BannerGrabber {
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl BannerGrabber {
    pub fn new(probe_timeout: Duration) -> Self {
        Self {
            connect_timeout: probe_timeout,
            read_timeout: probe_timeout,
        }
    }

    /// Connect to a port and read any banner the server sends.
    ///
    /// Returns `Ok(Some(bytes))` if the server sends data, `Ok(None)` if the
    /// server connects but sends nothing within the timeout, or an error if the
    /// connection fails.
    pub async fn grab(
        &self,
        ip: IpAddr,
        port: u16,
        proxy: Option<&ProxyConfig>,
    ) -> Result<Option<Vec<u8>>, DetectionError> {
        let addr = SocketAddr::new(ip, port);

        let mut stream = match connect_tcp(addr, proxy, self.connect_timeout).await {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(DetectionError::Timeout);
            }
            Err(e) => return Err(DetectionError::Connection(e.to_string())),
        };

        debug!("connected to {} for banner grab", addr);

        let mut buf = vec![0u8; MAX_BANNER_SIZE];
        match timeout(self.read_timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) => Ok(None),
            Ok(Ok(n)) => {
                buf.truncate(n);
                debug!("received {} byte banner from {}", n, addr);
                Ok(Some(buf))
            }
            Ok(Err(e)) => Err(DetectionError::Io(e)),
            Err(_) => {
                // Timeout waiting for banner — not an error, just no banner
                debug!("no banner from {} (timeout)", addr);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn grab_reads_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a mock server that sends a banner
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream
                .write_all(b"SSH-2.0-OpenSSH_8.9p1\r\n")
                .await
                .unwrap();
        });

        let grabber = BannerGrabber::new(Duration::from_secs(2));
        let banner = grabber
            .grab(IpAddr::V4(Ipv4Addr::LOCALHOST), port, None)
            .await
            .unwrap();

        assert!(banner.is_some());
        let data = banner.unwrap();
        assert!(data.starts_with(b"SSH-2.0-OpenSSH"));
    }

    #[tokio::test]
    async fn grab_returns_none_on_silent_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a mock server that accepts but sends nothing
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            // Hold connection open but don't send anything
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let grabber = BannerGrabber::new(Duration::from_millis(200));
        let banner = grabber
            .grab(IpAddr::V4(Ipv4Addr::LOCALHOST), port, None)
            .await
            .unwrap();

        assert!(banner.is_none());
    }

    #[tokio::test]
    async fn grab_returns_error_on_refused() {
        // Use a port that's very unlikely to be in use
        let grabber = BannerGrabber::new(Duration::from_millis(500));
        let result = grabber.grab(IpAddr::V4(Ipv4Addr::LOCALHOST), 1, None).await;

        assert!(result.is_err());
    }
}
