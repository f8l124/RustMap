use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use rustmap_types::{
    Host, HostScanResult, Port, PortState, Protocol, ProxyConfig, ScanConfig, TimingSnapshot,
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::traits::{ScanError, Scanner};

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
            // Clone into owned values so they can be moved into the async block.
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

#[derive(Default)]
pub struct TcpConnectScanner;

impl TcpConnectScanner {
    pub fn new() -> Self {
        Self
    }

    /// Scan a single port on a single host using TCP connect().
    async fn scan_port(
        host_ip: std::net::IpAddr,
        port: u16,
        timeout: Duration,
        proxy: Option<&ProxyConfig>,
        custom_payload: Option<&[u8]>,
    ) -> Port {
        let addr = SocketAddr::new(host_ip, port);
        debug!("connecting to {}", addr);

        let state = match connect_tcp(addr, proxy, timeout).await {
            Ok(mut stream) => {
                // Connection succeeded — port is open.
                // Send custom payload if specified (useful for triggering service responses).
                if let Some(payload) = custom_payload {
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(payload).await;
                }
                debug!("{} -> open", addr);
                PortState::Open
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Timeout — port is filtered (no response).
                debug!("{} -> filtered (timeout)", addr);
                PortState::Filtered
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
                        // Connection was actively refused/reset — port is closed.
                        debug!("{} -> closed ({})", addr, e);
                        PortState::Closed
                    }
                    _ => {
                        // Host/network unreachable, permission denied, etc. — port is filtered.
                        debug!("{} -> filtered ({})", addr, e);
                        PortState::Filtered
                    }
                }
            }
        };

        Port {
            number: port,
            protocol: Protocol::Tcp,
            state,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }
    }
}

#[async_trait]
impl Scanner for TcpConnectScanner {
    async fn scan_host(
        &self,
        host: &Host,
        config: &ScanConfig,
    ) -> Result<HostScanResult, ScanError> {
        let start = Instant::now();
        let ip = host.ip;
        let timeout = config.timeout;

        // Cap TCP connect parallelism. Unlike raw scanners that work at the
        // packet level, connect() allocates full OS sockets with kernel buffers
        // and ephemeral ports. Blasting thousands of simultaneous connect() calls
        // overwhelms the OS TCP stack (especially on Windows), causing spurious
        // timeouts even for open ports.
        const MAX_CONNECT_PARALLEL: usize = 512;
        let batch_size = config.concurrency.min(MAX_CONNECT_PARALLEL);

        // Build port ordering: randomized via LCG or sequential
        let port_order: Vec<u16> = if config.randomize_ports {
            LcgPermutation::new(config.ports.len())
                .map(|i| config.ports[i])
                .collect()
        } else {
            config.ports.clone()
        };

        let proxy = config.proxy.as_ref();
        let custom_payload = config.custom_payload.as_deref();
        let mut ports_iter = port_order.into_iter();
        let mut futures = FuturesUnordered::new();
        let mut ports: Vec<Port> = Vec::with_capacity(config.ports.len());

        // Seed the sliding window with initial batch
        for port in ports_iter.by_ref().take(batch_size) {
            futures.push(Self::scan_port(ip, port, timeout, proxy, custom_payload));
        }

        // As each future completes, push the next port in
        while let Some(port_result) = futures.next().await {
            ports.push(port_result);

            if let Some(next_port) = ports_iter.next() {
                futures.push(Self::scan_port(
                    ip,
                    next_port,
                    timeout,
                    proxy,
                    custom_payload,
                ));
            }
        }

        // Sort results by port number for consistent output.
        ports.sort_by_key(|p| p.number);

        let elapsed = start.elapsed();
        info!(
            "scanned {} ports on {} in {:.2}s",
            ports.len(),
            host.ip,
            elapsed.as_secs_f64()
        );

        let probes_sent = config.ports.len() as u64;
        let responded = ports
            .iter()
            .filter(|p| p.state != PortState::Filtered)
            .count() as u64;
        let timing_snapshot = TimingSnapshot {
            srtt_us: None,
            rto_us: config.timeout.as_micros() as u64,
            rttvar_us: None,
            cwnd: config.concurrency,
            probes_sent,
            probes_responded: responded,
            probes_timed_out: probes_sent.saturating_sub(responded),
            loss_rate: if probes_sent > 0 {
                1.0 - (responded as f64 / probes_sent as f64)
            } else {
                0.0
            },
        };

        Ok(HostScanResult {
            host: host.clone(),
            ports,
            scan_duration: elapsed,
            host_status: rustmap_types::HostStatus::Up,
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: None,
            timing_snapshot: Some(timing_snapshot),
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        })
    }
}

/// Linear Congruential Generator for pseudo-random index permutation.
///
/// Visits every index in `[0, len)` exactly once using the recurrence:
///   `next = (current * A + C) mod M`
/// where `M` is the next power of two >= `len`.
///
/// Full-period guarantee: with M as power-of-2, A odd with A%4==1, and C odd,
/// the LCG has period exactly M. Indices >= len are skipped (rejection sampling).
/// Since M <= 2*len, at most half the steps are rejected, keeping iteration O(N).
pub(crate) struct LcgPermutation {
    a: usize,
    c: usize,
    m: usize,
    len: usize,
    current: usize,
    count: usize,
}

impl LcgPermutation {
    pub(crate) fn new(len: usize) -> Self {
        if len == 0 {
            return Self {
                a: 1,
                c: 1,
                m: 1,
                len: 0,
                current: 0,
                count: 0,
            };
        }

        let m = len.next_power_of_two();
        // Hull-Dobell full-period conditions for power-of-2 modulus:
        //   1. C is coprime to M (any odd C suffices)
        //   2. A ≡ 1 (mod 4) (since 4 divides M for M ≥ 4)
        //
        // Use golden-ratio-inspired multiplier (≈0.618*M) for good distribution,
        // snapped to A ≡ 1 (mod 4). C ≈ M/2 (odd) for varied offsets.
        let (a, c) = if m <= 4 {
            (1, 1)
        } else {
            let raw = m * 79 / 128; // ≈ 0.617 * M
            let a = (raw & !3) | 1; // snap to ≡ 1 (mod 4)
            let c = (m >> 1) | 1; // odd, ≈ M/2
            (a, c)
        };

        // Seed the starting position with a random value for non-deterministic ordering
        let start = {
            use rand::Rng;
            rand::thread_rng().r#gen::<usize>() % m
        };

        Self {
            a,
            c,
            m,
            len,
            current: start,
            count: 0,
        }
    }
}

impl Iterator for LcgPermutation {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        while self.count < self.len {
            self.current = (self.current.wrapping_mul(self.a).wrapping_add(self.c)) % self.m;
            if self.current < self.len {
                self.count += 1;
                return Some(self.current);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_connect_scanner_creates() {
        let _scanner = TcpConnectScanner::new();
    }

    #[test]
    fn lcg_visits_all_indices() {
        for &len in &[1, 2, 3, 7, 100, 1000, 65535] {
            let lcg = LcgPermutation::new(len);
            let mut visited = vec![false; len];
            let mut count = 0;
            for idx in lcg {
                assert!(idx < len, "index {idx} out of range for len {len}");
                assert!(!visited[idx], "index {idx} visited twice for len {len}");
                visited[idx] = true;
                count += 1;
            }
            assert_eq!(count, len, "wrong count for len {len}");
        }
    }

    #[test]
    fn lcg_empty() {
        let lcg = LcgPermutation::new(0);
        assert_eq!(lcg.count(), 0);
    }

    #[test]
    fn lcg_is_not_sequential_for_large_n() {
        let lcg = LcgPermutation::new(1000);
        let indices: Vec<usize> = lcg.collect();
        // Count how many consecutive pairs are sequential
        let sequential_count = indices.windows(2).filter(|w| w[1] == w[0] + 1).count();
        // A truly random permutation of 1000 elements has ~1 sequential pair on average.
        // Allow up to 100 to be safe but fail if it's nearly all sequential.
        assert!(
            sequential_count < 100,
            "LCG appears too sequential: {sequential_count}/999 consecutive pairs"
        );
    }
}
