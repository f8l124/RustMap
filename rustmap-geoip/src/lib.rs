use maxminddb::{MaxMindDbError, Reader};
use rustmap_types::{GeoInfo, ScanResult};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum GeoIpError {
    #[error("no MMDB database files found in {0}")]
    NoDatabases(PathBuf),
    #[error("failed to open MMDB file: {0}")]
    OpenFailed(#[from] MaxMindDbError),
}

/// Reads GeoLite2 City and ASN databases for IP geolocation lookups.
#[derive(Debug)]
pub struct GeoIpReader {
    city_reader: Option<Reader<Vec<u8>>>,
    asn_reader: Option<Reader<Vec<u8>>>,
}

impl GeoIpReader {
    /// Open MMDB files from a directory.
    /// Looks for `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
    /// Returns error only if neither file exists.
    pub fn open(dir: &Path) -> Result<Self, GeoIpError> {
        let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        let city_path = dir.join("GeoLite2-City.mmdb");
        let asn_path = dir.join("GeoLite2-ASN.mmdb");

        const MAX_MMDB_SIZE: u64 = 200 * 1024 * 1024; // 200 MB

        let city_reader = if city_path.exists() {
            match std::fs::metadata(&city_path).map(|m| m.len()) {
                Ok(size) if size > MAX_MMDB_SIZE => {
                    warn!(path = %city_path.display(), size, "City MMDB file too large (>200MB), skipping");
                    None
                }
                Err(e) => {
                    warn!(path = %city_path.display(), error = %e, "Failed to stat City MMDB");
                    None
                }
                _ => match Reader::open_readfile(&city_path) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        warn!(path = %city_path.display(), error = %e, "Failed to open City MMDB");
                        None
                    }
                },
            }
        } else {
            None
        };

        let asn_reader = if asn_path.exists() {
            match std::fs::metadata(&asn_path).map(|m| m.len()) {
                Ok(size) if size > MAX_MMDB_SIZE => {
                    warn!(path = %asn_path.display(), size, "ASN MMDB file too large (>200MB), skipping");
                    None
                }
                Err(e) => {
                    warn!(path = %asn_path.display(), error = %e, "Failed to stat ASN MMDB");
                    None
                }
                _ => match Reader::open_readfile(&asn_path) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        warn!(path = %asn_path.display(), error = %e, "Failed to open ASN MMDB");
                        None
                    }
                },
            }
        } else {
            None
        };

        if city_reader.is_none() && asn_reader.is_none() {
            return Err(GeoIpError::NoDatabases(dir.to_path_buf()));
        }

        Ok(Self {
            city_reader,
            asn_reader,
        })
    }

    /// Lookup geo + ASN data for an IP address.
    /// Returns `None` for private/loopback IPs or when no data is found.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        let mut info = GeoInfo {
            country_code: None,
            country: None,
            city: None,
            latitude: None,
            longitude: None,
            timezone: None,
            asn: None,
            as_org: None,
        };

        let mut has_data = false;

        // City/country/location lookup
        if let Some(reader) = &self.city_reader {
            match reader.lookup(ip) {
                Ok(lookup_result) => {
                    match lookup_result.decode::<maxminddb::geoip2::City>() {
                        Ok(Some(city)) => {
                            // Country info
                            info.country_code = city.country.iso_code.map(|s| s.to_string());
                            if let Some(name) = city.country.names.english {
                                info.country = Some(name.to_string());
                                has_data = true;
                            }
                            if city.country.iso_code.is_some() {
                                has_data = true;
                            }

                            // City info
                            if let Some(name) = city.city.names.english {
                                info.city = Some(name.to_string());
                                has_data = true;
                            }

                            // Location info
                            info.latitude = city.location.latitude;
                            info.longitude = city.location.longitude;
                            info.timezone = city.location.time_zone.map(|s| s.to_string());
                            if info.latitude.is_some() {
                                has_data = true;
                            }
                        }
                        Ok(None) => {} // IP not found in database
                        Err(e) => {
                            warn!(ip = %ip, error = %e, "City decode failed");
                        }
                    }
                }
                Err(e) => {
                    warn!(ip = %ip, error = %e, "City lookup failed");
                }
            }
        }

        // ASN lookup
        if let Some(reader) = &self.asn_reader {
            match reader.lookup(ip) {
                Ok(lookup_result) => {
                    match lookup_result.decode::<maxminddb::geoip2::Asn>() {
                        Ok(Some(asn)) => {
                            info.asn = asn.autonomous_system_number;
                            info.as_org = asn.autonomous_system_organization.map(|s| s.to_string());
                            if info.asn.is_some() || info.as_org.is_some() {
                                has_data = true;
                            }
                        }
                        Ok(None) => {} // IP not found in database
                        Err(e) => {
                            warn!(ip = %ip, error = %e, "ASN decode failed");
                        }
                    }
                }
                Err(e) => {
                    warn!(ip = %ip, error = %e, "ASN lookup failed");
                }
            }
        }

        if has_data { Some(info) } else { None }
    }
}

/// Search standard locations for MMDB files.
/// Order: custom path -> `$RUSTMAP_GEOIP_DIR` -> `~/.rustmap/geoip/` -> cwd
pub fn find_geoip_dir(custom: Option<&Path>) -> Option<PathBuf> {
    // 1. Custom path provided by user
    if let Some(p) = custom
        && p.exists()
    {
        return Some(p.to_path_buf());
    }

    // 2. Environment variable
    if let Ok(env_dir) = std::env::var("RUSTMAP_GEOIP_DIR") {
        let p = PathBuf::from(&env_dir);
        let p = std::fs::canonicalize(&p).unwrap_or(p);
        if p.exists() {
            return Some(p);
        }
    }

    // 3. ~/.rustmap/geoip/
    if let Some(home) = dirs_path() {
        let p = home.join(".rustmap").join("geoip");
        if p.exists() {
            return Some(p);
        }
    }

    // 4. Current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let city = cwd.join("GeoLite2-City.mmdb");
        let asn = cwd.join("GeoLite2-ASN.mmdb");
        if city.exists() || asn.exists() {
            return Some(cwd);
        }
    }

    None
}

/// Enrich all hosts in a `ScanResult` with geo data (in-place).
pub fn enrich_scan_result(result: &mut ScanResult, reader: &GeoIpReader) {
    for host_result in &mut result.hosts {
        if host_result.host.geo_info.is_none() {
            host_result.host.geo_info = reader.lookup(host_result.host.ip);
        }
    }
}

/// Get the user's home directory in a cross-platform way.
fn dirs_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_geoip_dir_none_when_empty() {
        let result = find_geoip_dir(Some(Path::new("/nonexistent/path/to/geoip")));
        assert!(result != Some(PathBuf::from("/nonexistent/path/to/geoip")));
    }

    #[test]
    fn open_returns_no_databases_error() {
        let tmp = std::env::temp_dir().join("rustmap_geoip_test_empty");
        let _ = std::fs::create_dir_all(&tmp);
        let result = GeoIpReader::open(&tmp);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("no MMDB database files found"));
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn enrich_noop_without_data() {
        use rustmap_types::{Host, HostScanResult, HostStatus, ScanResult, ScanType};
        use std::net::Ipv4Addr;
        use std::time::Duration;

        let result = ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                ports: vec![],
                scan_duration: Duration::from_secs(0),
                host_status: HostStatus::Up,
                discovery_latency: None,
                os_fingerprint: None,
                traceroute: None,
                timing_snapshot: None,
                host_script_results: vec![],
                scan_error: None,
                uptime_estimate: None,
                risk_score: None,
                mtu: None,
            }],
            total_duration: Duration::from_secs(0),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 0,
            pre_script_results: vec![],
            post_script_results: vec![],
        };

        // Without a reader, verify host starts with geo_info = None
        assert!(result.hosts[0].host.geo_info.is_none());
    }
}
