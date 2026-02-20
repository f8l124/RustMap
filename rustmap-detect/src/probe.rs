use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::debug;

use crate::DetectionError;
use crate::proxy::connect_tcp;
use rustmap_types::ProxyConfig;

/// Maximum bytes to read from a probe response.
const MAX_RESPONSE_SIZE: usize = 8192;

/// An active service probe — sends data to a port and reads the response.
pub struct ServiceProbe {
    /// Probe name (e.g., "GetRequest").
    pub name: &'static str,
    /// Data to send to the target.
    pub payload: &'static [u8],
    /// Ports this probe is optimized for (empty = all ports).
    pub ports: &'static [u16],
    /// Rarity level (1-9). Lower = more common, tried first.
    pub rarity: u8,
}

impl ServiceProbe {
    /// Execute this probe: connect, send payload, read response.
    pub async fn execute(
        &self,
        ip: IpAddr,
        port: u16,
        probe_timeout: Duration,
        proxy: Option<&ProxyConfig>,
    ) -> Result<Option<Vec<u8>>, DetectionError> {
        let addr = SocketAddr::new(ip, port);

        let mut stream = match connect_tcp(addr, proxy, probe_timeout).await {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(DetectionError::Timeout)
            }
            Err(e) => return Err(DetectionError::Connection(e.to_string())),
        };

        // Send probe payload
        match timeout(probe_timeout, stream.write_all(self.payload)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(DetectionError::Io(e)),
            Err(_) => return Err(DetectionError::Timeout),
        }

        debug!("sent probe '{}' ({} bytes) to {}", self.name, self.payload.len(), addr);

        // Read response
        let mut buf = vec![0u8; MAX_RESPONSE_SIZE];
        match timeout(probe_timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) => Ok(None),
            Ok(Ok(n)) => {
                buf.truncate(n);
                debug!("received {} byte response from {} for probe '{}'", n, addr, self.name);
                Ok(Some(buf))
            }
            Ok(Err(e)) => Err(DetectionError::Io(e)),
            Err(_) => {
                debug!("timeout reading response from {} for probe '{}'", addr, self.name);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn probe_sends_and_receives() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Mock HTTP server
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nServer: test/1.0\r\n\r\n")
                .await
                .unwrap();
        });

        let probe = ServiceProbe {
            name: "GetRequest",
            payload: b"GET / HTTP/1.0\r\n\r\n",
            ports: &[80],
            rarity: 1,
        };

        let result = probe
            .execute(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                Duration::from_secs(2),
                None,
            )
            .await
            .unwrap();

        assert!(result.is_some());
        let response = result.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn probe_handles_connection_refused() {
        let probe = ServiceProbe {
            name: "test",
            payload: b"test",
            ports: &[],
            rarity: 1,
        };

        let result = probe
            .execute(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                1,
                Duration::from_millis(500),
                None,
            )
            .await;

        assert!(result.is_err());
    }
}
