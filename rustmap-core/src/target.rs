use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ipnetwork::IpNetwork;
use rustmap_types::{DnsConfig, Host};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TargetParseError {
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid CIDR notation: {0}")]
    InvalidCidr(String),
    #[error("invalid IP range: {0}")]
    InvalidRange(String),
    #[error("DNS resolution failed for '{0}': {1}")]
    DnsResolutionFailed(String, String),
    #[error("empty target specification")]
    Empty,
}

/// Parse a single target string into one or more Hosts.
///
/// Supports:
/// - Single IPv4/IPv6 addresses: `192.168.1.1`, `::1`
/// - CIDR notation: `192.168.1.0/24`, `10.0.0.0/8`
/// - Octet range: `192.168.1.1-100` (last octet range)
/// - Hostnames: `example.com` (resolved via DNS)
pub fn parse_target(input: &str) -> Result<Vec<Host>, TargetParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(TargetParseError::Empty);
    }

    // Try CIDR notation first (contains '/')
    if input.contains('/') {
        return parse_cidr(input);
    }

    // Try octet range (e.g., 192.168.1.1-100)
    if input.contains('-') && input.contains('.') {
        return parse_octet_range(input);
    }

    // Try plain IP address
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(vec![Host::new(ip)]);
    }

    // Must be a hostname — resolve via DNS
    resolve_hostname(input)
}

/// Minimum CIDR prefix length allowed for IPv4. A /8 contains 16M hosts.
const MIN_IPV4_PREFIX: u8 = 8;
/// Minimum CIDR prefix length allowed for IPv6. A /48 is a typical site allocation.
const MIN_IPV6_PREFIX: u8 = 48;

/// Parse CIDR notation like `192.168.1.0/24` into a list of hosts.
fn parse_cidr(input: &str) -> Result<Vec<Host>, TargetParseError> {
    let network: IpNetwork = input
        .parse()
        .map_err(|e| TargetParseError::InvalidCidr(format!("{input}: {e}")))?;

    // Reject excessively large CIDR ranges to prevent OOM
    let prefix = network.prefix();
    let (min_prefix, family) = match network {
        IpNetwork::V4(_) => (MIN_IPV4_PREFIX, "IPv4"),
        IpNetwork::V6(_) => (MIN_IPV6_PREFIX, "IPv6"),
    };
    if prefix < min_prefix {
        return Err(TargetParseError::InvalidCidr(format!(
            "{input}: /{prefix} is too large for {family} (minimum prefix: /{min_prefix})"
        )));
    }

    let hosts: Vec<Host> = network.iter().map(Host::new).collect();

    if hosts.is_empty() {
        return Err(TargetParseError::InvalidCidr(format!(
            "{input}: no addresses in range"
        )));
    }

    Ok(hosts)
}

/// Parse an octet range like `192.168.1.1-100`.
///
/// Only the last octet may contain a range. The format is `A.B.C.D-E`
/// where D is the start and E is the end (inclusive).
fn parse_octet_range(input: &str) -> Result<Vec<Host>, TargetParseError> {
    let parts: Vec<&str> = input.split('.').collect();
    if parts.len() != 4 {
        return Err(TargetParseError::InvalidRange(format!(
            "{input}: expected 4 octets"
        )));
    }

    let a: u8 = parts[0]
        .parse()
        .map_err(|_| TargetParseError::InvalidRange(format!("invalid octet: {}", parts[0])))?;
    let b: u8 = parts[1]
        .parse()
        .map_err(|_| TargetParseError::InvalidRange(format!("invalid octet: {}", parts[1])))?;
    let c: u8 = parts[2]
        .parse()
        .map_err(|_| TargetParseError::InvalidRange(format!("invalid octet: {}", parts[2])))?;

    let last = parts[3];
    if let Some((start_str, end_str)) = last.split_once('-') {
        let start: u8 = start_str
            .parse()
            .map_err(|_| TargetParseError::InvalidRange(format!("invalid octet: {start_str}")))?;
        let end: u8 = end_str
            .parse()
            .map_err(|_| TargetParseError::InvalidRange(format!("invalid octet: {end_str}")))?;

        if start > end {
            return Err(TargetParseError::InvalidRange(format!(
                "{input}: start ({start}) > end ({end})"
            )));
        }

        let hosts: Vec<Host> = (start..=end)
            .map(|d| Host::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d))))
            .collect();
        Ok(hosts)
    } else {
        let d: u8 = last
            .parse()
            .map_err(|_| TargetParseError::InvalidRange(format!("invalid octet: {last}")))?;
        Ok(vec![Host::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))])
    }
}

/// Resolve a hostname to IP addresses via DNS.
fn resolve_hostname(hostname: &str) -> Result<Vec<Host>, TargetParseError> {
    use std::net::ToSocketAddrs;

    let addr_str = format!("{hostname}:0");
    let addrs: Vec<_> = addr_str
        .to_socket_addrs()
        .map_err(|e| TargetParseError::DnsResolutionFailed(hostname.to_string(), e.to_string()))?
        .collect();

    if addrs.is_empty() {
        return Err(TargetParseError::DnsResolutionFailed(
            hostname.to_string(),
            "no addresses returned".to_string(),
        ));
    }

    // Deduplicate IPs
    let mut seen = std::collections::HashSet::new();
    let mut hosts = Vec::new();
    for addr in addrs {
        if seen.insert(addr.ip()) {
            let mut host = Host::new(addr.ip());
            host.hostname = Some(hostname.to_string());
            hosts.push(host);
        }
    }

    Ok(hosts)
}

/// Parse multiple target specifications into a combined host list.
pub fn parse_targets(inputs: &[String]) -> Result<Vec<Host>, TargetParseError> {
    let mut all_hosts = Vec::new();
    for input in inputs {
        let hosts = parse_target(input)?;
        all_hosts.extend(hosts);
    }
    Ok(all_hosts)
}

/// Parse a single target with custom DNS configuration (async).
///
/// When `dns.servers` is empty, falls back to the system resolver.
/// When custom DNS servers are provided, uses hickory-resolver for async resolution.
pub async fn parse_target_with_dns(
    input: &str,
    dns: &DnsConfig,
) -> Result<Vec<Host>, TargetParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(TargetParseError::Empty);
    }
    if input.contains('/') {
        return parse_cidr(input);
    }
    if input.contains('-') && input.contains('.') {
        return parse_octet_range(input);
    }
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(vec![Host::new(ip)]);
    }
    resolve_hostname_async(input, dns).await
}

/// Parse multiple targets with custom DNS configuration (async).
pub async fn parse_targets_with_dns(
    inputs: &[String],
    dns: &DnsConfig,
) -> Result<Vec<Host>, TargetParseError> {
    let mut all_hosts = Vec::new();
    for input in inputs {
        let hosts = parse_target_with_dns(input, dns).await?;
        all_hosts.extend(hosts);
    }
    Ok(all_hosts)
}

/// Async DNS resolution dispatcher.
async fn resolve_hostname_async(
    hostname: &str,
    dns: &DnsConfig,
) -> Result<Vec<Host>, TargetParseError> {
    // Treat timeout_ms=0 as the default (5 seconds) to avoid instant failure
    let timeout_dur = Duration::from_millis(if dns.timeout_ms == 0 {
        5000
    } else {
        dns.timeout_ms
    });

    if dns.servers.is_empty() {
        // System resolver — wrap sync call in spawn_blocking with timeout
        let hostname_owned = hostname.to_string();
        let hostname_err = hostname.to_string();
        tokio::time::timeout(
            timeout_dur,
            tokio::task::spawn_blocking(move || resolve_hostname(&hostname_owned)),
        )
        .await
        .map_err(|_| {
            TargetParseError::DnsResolutionFailed(
                hostname_err.clone(),
                format!(
                    "system DNS resolution timed out after {}ms",
                    timeout_dur.as_millis()
                ),
            )
        })?
        .map_err(|e| TargetParseError::DnsResolutionFailed(hostname_err, e.to_string()))?
    } else {
        resolve_hostname_custom(hostname, dns).await
    }
}

/// Resolve a hostname using custom DNS servers via hickory-resolver.
async fn resolve_hostname_custom(
    hostname: &str,
    dns: &DnsConfig,
) -> Result<Vec<Host>, TargetParseError> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

    let mut config = ResolverConfig::new();
    for server in &dns.servers {
        // Accept both bare IP and IP:port formats; default to port 53
        let (ip, port) = if let Ok(sock) = server.parse::<std::net::SocketAddr>() {
            (sock.ip(), sock.port())
        } else {
            let bare = server.trim_start_matches('[').trim_end_matches(']');
            let ip: IpAddr = bare.parse().map_err(|_| {
                TargetParseError::DnsResolutionFailed(
                    hostname.to_string(),
                    format!("invalid DNS server address: {server} (expected IP or IP:PORT)"),
                )
            })?;
            (ip, 53)
        };
        let addr = std::net::SocketAddr::new(ip, port);
        config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
        config.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
    }

    let mut opts = ResolverOpts::default();
    // Treat timeout_ms=0 as the default (5 seconds) to avoid instant failure
    opts.timeout = Duration::from_millis(if dns.timeout_ms == 0 {
        5000
    } else {
        dns.timeout_ms
    });
    opts.attempts = 1; // Single attempt for predictable wall-clock behavior

    let resolver = TokioAsyncResolver::tokio(config, opts);
    let response = resolver
        .lookup_ip(hostname)
        .await
        .map_err(|e| TargetParseError::DnsResolutionFailed(hostname.to_string(), e.to_string()))?;

    let mut seen = std::collections::HashSet::new();
    let mut hosts = Vec::new();
    for ip in response.iter() {
        if seen.insert(ip) {
            let mut host = Host::new(ip);
            host.hostname = Some(hostname.to_string());
            hosts.push(host);
        }
    }

    if hosts.is_empty() {
        return Err(TargetParseError::DnsResolutionFailed(
            hostname.to_string(),
            "no addresses returned".to_string(),
        ));
    }

    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parse_ipv4() {
        let hosts = parse_target("192.168.1.1").unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_ipv6_loopback() {
        let hosts = parse_target("::1").unwrap();
        assert_eq!(hosts.len(), 1);
        assert!(hosts[0].ip.is_loopback());
    }

    #[test]
    fn parse_localhost_ip() {
        let hosts = parse_target("127.0.0.1").unwrap();
        assert_eq!(hosts.len(), 1);
        assert!(hosts[0].ip.is_loopback());
    }

    #[test]
    fn parse_cidr_24() {
        let hosts = parse_target("10.0.0.0/24").unwrap();
        assert_eq!(hosts.len(), 256);
        assert_eq!(hosts[0].ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(hosts[255].ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)));
    }

    #[test]
    fn parse_cidr_30() {
        let hosts = parse_target("192.168.1.0/30").unwrap();
        assert_eq!(hosts.len(), 4);
    }

    #[test]
    fn parse_cidr_32() {
        let hosts = parse_target("192.168.1.1/32").unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_invalid_cidr() {
        assert!(parse_target("192.168.1.0/33").is_err());
    }

    #[test]
    fn parse_cidr_rejects_huge_range() {
        // /0 would produce ~4 billion hosts — must be rejected
        let result = parse_target("0.0.0.0/0");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "error should mention size: {err}"
        );

        // /7 should also be rejected (below /8 minimum)
        assert!(parse_target("10.0.0.0/7").is_err());

        // /8 should be allowed (16M hosts is the maximum)
        assert!(parse_target("10.0.0.0/8").is_ok());
    }

    #[test]
    fn parse_octet_range() {
        let hosts = parse_target("192.168.1.1-5").unwrap();
        assert_eq!(hosts.len(), 5);
        assert_eq!(hosts[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hosts[4].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
    }

    #[test]
    fn parse_octet_range_single() {
        let hosts = parse_target("10.0.0.5-5").unwrap();
        assert_eq!(hosts.len(), 1);
    }

    #[test]
    fn parse_octet_range_invalid_start_gt_end() {
        assert!(parse_target("192.168.1.100-50").is_err());
    }

    #[test]
    fn parse_invalid_input() {
        assert!(parse_target("not_valid_at_all").is_err());
    }

    #[test]
    fn parse_empty() {
        assert!(parse_target("").is_err());
    }

    #[test]
    fn parse_hostname_localhost() {
        let hosts = parse_target("localhost").unwrap();
        assert!(!hosts.is_empty());
        assert!(hosts[0].ip.is_loopback());
        assert_eq!(hosts[0].hostname.as_deref(), Some("localhost"));
    }

    #[test]
    fn parse_targets_multiple() {
        let inputs = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];
        let hosts = parse_targets(&inputs).unwrap();
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn parse_targets_mixed() {
        let inputs = vec!["192.168.1.1-3".to_string(), "10.0.0.1".to_string()];
        let hosts = parse_targets(&inputs).unwrap();
        assert_eq!(hosts.len(), 4);
    }

    #[tokio::test]
    async fn parse_target_with_default_dns() {
        let dns = DnsConfig::default();
        let hosts = parse_target_with_dns("localhost", &dns).await.unwrap();
        assert!(!hosts.is_empty());
        assert!(hosts[0].ip.is_loopback());
        assert_eq!(hosts[0].hostname.as_deref(), Some("localhost"));
    }

    #[tokio::test]
    async fn parse_target_with_dns_ip_passthrough() {
        let dns = DnsConfig::default();
        let hosts = parse_target_with_dns("192.168.1.1", &dns).await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn dns_config_default_empty_servers() {
        let dns = DnsConfig::default();
        assert!(dns.servers.is_empty());
        assert_eq!(dns.timeout_ms, 5000);
    }

    #[tokio::test]
    async fn resolve_hostname_custom_invalid_server() {
        let dns = DnsConfig {
            servers: vec!["not-an-ip".to_string()],
            timeout_ms: 1000,
        };
        let result = parse_target_with_dns("example.com", &dns).await;
        assert!(result.is_err());
    }
}
