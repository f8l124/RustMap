use std::net::IpAddr;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use rustmap_packet::{
    CaptureConfig, PacketReceiver, ResponseType, create_capture, create_sender, rand_seq,
};
use rustmap_types::{Host, TracerouteHop, TracerouteResult};

use crate::traits::ScanError;

/// Maximum number of hops to trace.
const MAX_HOPS: u8 = 30;
/// Timeout per hop before declaring it unreachable (*).
const HOP_TIMEOUT: Duration = Duration::from_secs(3);
/// Stop after this many consecutive timeouts — indicates raw packets aren't
/// reaching the network (e.g. wrong gateway MAC, firewall, etc.).
const MAX_CONSECUTIVE_TIMEOUTS: u8 = 5;

/// Perform a traceroute to the given host.
///
/// Uses TCP SYN probes to an open port if available (more reliable),
/// otherwise falls back to UDP probes to high ports (classic traceroute).
pub async fn trace_route(
    host: &Host,
    open_port: Option<u16>,
    interface_name: Option<&str>,
) -> Result<TracerouteResult, ScanError> {
    let target_ip = host.ip;

    // Decide probe type: TCP SYN to open port, or UDP to high port
    let (dst_port, use_tcp) = match open_port {
        Some(port) => (port, true),
        None => (33434, false), // classic traceroute starting port
    };

    debug!(
        target = %target_ip,
        port = dst_port,
        proto = if use_tcp { "tcp" } else { "udp" },
        "starting traceroute"
    );

    let sender = create_sender(target_ip)?;
    let src_ip = match target_ip {
        IpAddr::V4(_) => get_src_ip_v4(target_ip),
        IpAddr::V6(_) => get_src_ip_v6(target_ip),
    };

    // BPF filter: capture ICMP Time Exceeded, ICMP Unreachable,
    // TCP SYN/ACK, TCP RST, and ICMPv6
    let bpf_filter = traceroute_bpf_filter();
    let mut capture = create_capture(CaptureConfig {
        interface: interface_name.map(String::from),
        bpf_filter,
        ..CaptureConfig::default()
    })?;

    let mut hops = Vec::new();
    // Track recent hop IPs for routing loop detection
    let mut recent_hops: Vec<Option<IpAddr>> = Vec::new();
    let mut consecutive_timeouts: u8 = 0;

    for ttl in 1..=MAX_HOPS {
        let src_port = 40000 + (ttl as u16);

        // Send probe with this TTL
        let probe_result = if use_tcp {
            let pkt = rustmap_packet::build::build_syn_packet_with_ttl(
                src_ip,
                src_port,
                target_ip,
                dst_port,
                rand_seq(),
                ttl,
            )?;
            sender.send_raw(src_ip, target_ip, &pkt).await
        } else {
            // Classic traceroute: increment dst port per hop (saturating to avoid overflow)
            let udp_dst = dst_port.saturating_add(ttl as u16).saturating_sub(1);
            let pkt = rustmap_packet::build::build_udp_probe_with_ttl(
                src_ip, src_port, target_ip, udp_dst, ttl,
            )?;
            sender.send_raw(src_ip, target_ip, &pkt).await
        };

        if let Err(e) = probe_result {
            warn!(ttl, error = %e, "failed to send traceroute probe");
            hops.push(TracerouteHop {
                ttl,
                ip: None,
                hostname: None,
                rtt: None,
            });
            consecutive_timeouts += 1;
            if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                warn!(ttl, "too many consecutive send failures, stopping traceroute");
                break;
            }
            continue;
        }

        let send_time = Instant::now();

        // Wait for response
        match tokio::time::timeout(HOP_TIMEOUT, capture.recv()).await {
            Ok(Ok(resp)) => {
                let rtt = send_time.elapsed();
                let hop_ip = resp.src_ip;

                // Validate that this response corresponds to our probe:
                // For ICMP Time Exceeded, check the embedded src_port/dst_port.
                // For direct TCP responses (SYN/ACK, RST), the dst_port matches our src_port.
                let is_our_probe = match resp.response_type {
                    ResponseType::IcmpTimeExceeded => {
                        // IcmpTimeExceeded carries embedded original packet info;
                        // the parser puts our src_port in dst_port field.
                        resp.dst_port == src_port || resp.dst_port == 0
                    }
                    _ => resp.dst_port == src_port,
                };

                if !is_our_probe {
                    // Not a response to our probe, treat as timeout
                    debug!(ttl, "received unrelated packet, treating as timeout");
                    hops.push(TracerouteHop {
                        ttl,
                        ip: None,
                        hostname: None,
                        rtt: None,
                    });
                    recent_hops.push(None);
                    consecutive_timeouts += 1;
                } else {
                    consecutive_timeouts = 0;
                    hops.push(TracerouteHop {
                        ttl,
                        ip: Some(hop_ip),
                        hostname: None,
                        rtt: Some(rtt),
                    });

                    debug!(ttl, hop = %hop_ip, rtt_ms = rtt.as_millis(), "hop responded");

                    // Routing loop detection: if the same IP appears in 2 consecutive hops, break
                    recent_hops.push(Some(hop_ip));
                    if recent_hops.len() >= 2 {
                        let len = recent_hops.len();
                        if recent_hops[len - 1] == recent_hops[len - 2]
                            && recent_hops[len - 1].is_some()
                        {
                            warn!(ttl, hop = %hop_ip, "routing loop detected, stopping traceroute");
                            break;
                        }
                    }

                    // If we got a real response (not Time Exceeded), we've reached the target
                    if resp.response_type != ResponseType::IcmpTimeExceeded {
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                warn!(ttl, error = %e, "capture error during traceroute");
                hops.push(TracerouteHop {
                    ttl,
                    ip: None,
                    hostname: None,
                    rtt: None,
                });
                recent_hops.push(None);
                consecutive_timeouts += 1;
            }
            Err(_) => {
                // Timeout — hop didn't respond (*)
                debug!(ttl, "hop timed out");
                hops.push(TracerouteHop {
                    ttl,
                    ip: None,
                    hostname: None,
                    rtt: None,
                });
                recent_hops.push(None);
                consecutive_timeouts += 1;
            }
        }

        // Stop early if too many consecutive hops produced no response —
        // raw packets likely aren't reaching the network at all.
        if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
            warn!(
                ttl,
                consecutive_timeouts,
                "too many consecutive timeouts, stopping traceroute"
            );
            break;
        }
    }

    capture.stop();

    let protocol = if use_tcp {
        "tcp".to_string()
    } else {
        "udp".to_string()
    };

    Ok(TracerouteResult {
        target: host.clone(),
        hops,
        port: dst_port,
        protocol,
    })
}

/// BPF filter for traceroute: capture ICMP Time Exceeded, ICMP Unreachable,
/// TCP SYN/ACK, TCP RST, and all ICMPv6.
fn traceroute_bpf_filter() -> String {
    "(icmp[icmptype] = icmp-timxceed) \
     or (icmp[icmptype] = icmp-unreach) \
     or (tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)) \
     or (tcp[tcpflags] & tcp-rst != 0) \
     or icmp6"
        .to_string()
}

/// Get the local IPv4 source IP for reaching a target.
fn get_src_ip_v4(target: IpAddr) -> IpAddr {
    let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") else {
        warn!("failed to bind UDP socket for source IP detection");
        return IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    };
    if socket
        .connect(std::net::SocketAddr::new(target, 80))
        .is_err()
    {
        warn!(%target, "failed to connect UDP socket for source IP detection");
        return IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    }
    socket
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

/// Get the local IPv6 source IP for reaching a target.
fn get_src_ip_v6(target: IpAddr) -> IpAddr {
    let Ok(socket) = std::net::UdpSocket::bind("[::]:0") else {
        warn!("failed to bind IPv6 UDP socket for source IP detection");
        return IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
    };
    if socket
        .connect(std::net::SocketAddr::new(target, 80))
        .is_err()
    {
        warn!(%target, "failed to connect IPv6 UDP socket for source IP detection");
        return IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
    }
    socket
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceroute_bpf_filter_captures_time_exceeded() {
        let filter = traceroute_bpf_filter();
        assert!(filter.contains("icmp-timxceed"));
        assert!(filter.contains("icmp-unreach"));
        assert!(filter.contains("tcp-syn"));
        assert!(filter.contains("tcp-rst"));
        assert!(filter.contains("icmp6"));
    }
}
