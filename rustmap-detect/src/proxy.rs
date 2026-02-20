use std::net::SocketAddr;
use std::time::Duration;

use rustmap_types::ProxyConfig;
use tokio::net::TcpStream;

/// Connect to `addr` either directly or through a SOCKS5 proxy.
pub(crate) async fn connect_tcp(
    addr: SocketAddr,
    proxy: Option<&ProxyConfig>,
    timeout: Duration,
) -> Result<TcpStream, std::io::Error> {
    match proxy {
        None => tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))?,
        Some(p) => {
            let proxy_host = p.host.clone();
            let proxy_port = p.port;
            let username = p.username.clone();
            let password = p.password.clone();

            let stream = tokio::time::timeout(timeout, async move {
                match (username, password) {
                    (Some(u), Some(pw)) => {
                        tokio_socks::tcp::Socks5Stream::connect_with_password(
                            (proxy_host.as_str(), proxy_port),
                            addr,
                            &u,
                            &pw,
                        )
                        .await
                    }
                    _ => {
                        tokio_socks::tcp::Socks5Stream::connect(
                            (proxy_host.as_str(), proxy_port),
                            addr,
                        )
                        .await
                    }
                }
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "proxy connect timeout")
            })?
            .map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string())
            })?;

            Ok(stream.into_inner())
        }
    }
}
