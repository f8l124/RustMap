//! GeoIP API fallback using freeipapi.com.
//!
//! Used when local MMDB databases are not available.
//! Rate limited to 60 requests/minute (1 per second).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustmap_types::{GeoInfo, ScanResult};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::warn;

/// Response from freeipapi.com/api/json/{ip}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FreeIpApiResponse {
    country_code: Option<String>,
    country_name: Option<String>,
    city_name: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    time_zone: Option<String>,
}

/// HTTP client for GeoIP lookups via freeipapi.com.
pub struct GeoIpApiClient {
    client: reqwest::Client,
    last_request: Arc<Mutex<Instant>>,
}

impl Default for GeoIpApiClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpApiClient {
    /// Create a new API client with a 5-second timeout.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            client,
            last_request: Arc::new(Mutex::new(Instant::now() - Duration::from_secs(2))),
        }
    }

    /// Look up GeoIP data for a single IP address.
    ///
    /// Returns `None` for private/loopback IPs or on API errors.
    pub async fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        if !is_global_ip(ip) {
            return None;
        }

        // Rate limit: wait until at least 1 second since last request
        {
            let mut last = self.last_request.lock().await;
            let elapsed = last.elapsed();
            if elapsed < Duration::from_secs(1) {
                tokio::time::sleep(Duration::from_secs(1) - elapsed).await;
            }
            *last = Instant::now();
        }

        let url = format!("https://freeipapi.com/api/json/{ip}");
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(ip = %ip, error = %e, "GeoIP API request failed");
                return None;
            }
        };

        if !resp.status().is_success() {
            warn!(ip = %ip, status = %resp.status(), "GeoIP API returned error");
            return None;
        }

        let data: FreeIpApiResponse = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                warn!(ip = %ip, error = %e, "GeoIP API response parse failed");
                return None;
            }
        };

        let has_data = data.country_code.is_some()
            || data.country_name.is_some()
            || data.city_name.is_some()
            || data.latitude.is_some();

        if !has_data {
            return None;
        }

        Some(GeoInfo {
            country_code: data.country_code,
            country: data.country_name,
            city: data.city_name,
            latitude: data.latitude,
            longitude: data.longitude,
            timezone: data.time_zone,
            asn: None,
            as_org: None,
        })
    }

    /// Enrich all hosts in a `ScanResult` with geo data from the API.
    ///
    /// Skips hosts that already have `geo_info` or have private IPs.
    pub async fn enrich_scan_result(&self, result: &mut ScanResult) {
        for host_result in &mut result.hosts {
            if host_result.host.geo_info.is_some() {
                continue;
            }
            host_result.host.geo_info = self.lookup(host_result.host.ip).await;
        }
    }
}

/// Returns `true` if the IP is a globally routable (public) address.
fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !v4.is_documentation()
                // 100.64.0.0/10 (CGNAT)
                && !(v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                // fc00::/7 (unique local)
                && (v6.segments()[0] & 0xfe00) != 0xfc00
                // fe80::/10 (link-local)
                && (v6.segments()[0] & 0xffc0) != 0xfe80
                // ::ffff:0:0/96 (IPv4-mapped) — check the mapped address
                && !v6.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn is_global_ip_rejects_private() {
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    }

    #[test]
    fn is_global_ip_accepts_public() {
        assert!(is_global_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_global_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn is_global_ip_rejects_private_v6() {
        assert!(!is_global_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_global_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        // fc00::/7
        let ula = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        assert!(!is_global_ip(IpAddr::V6(ula)));
        // fe80::/10
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert!(!is_global_ip(IpAddr::V6(link_local)));
    }

    #[test]
    fn is_global_ip_accepts_public_v6() {
        // 2001:4860:4860::8888 (Google DNS)
        let google = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        assert!(is_global_ip(IpAddr::V6(google)));
    }
}
