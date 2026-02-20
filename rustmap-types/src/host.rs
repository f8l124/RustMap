use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Geolocation and ASN information for an IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_org: Option<String>,
}

/// Represents a target host to scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_info: Option<GeoInfo>,
}

impl Host {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            hostname: None,
            geo_info: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn geo_info_serde_roundtrip() {
        let geo = GeoInfo {
            country_code: Some("US".into()),
            country: Some("United States".into()),
            city: Some("Seattle".into()),
            latitude: Some(47.6),
            longitude: Some(-122.3),
            timezone: Some("America/Los_Angeles".into()),
            asn: Some(13335),
            as_org: Some("Cloudflare, Inc.".into()),
        };
        let json = serde_json::to_string(&geo).unwrap();
        let back: GeoInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.country_code.as_deref(), Some("US"));
        assert_eq!(back.asn, Some(13335));
        assert_eq!(back.as_org.as_deref(), Some("Cloudflare, Inc."));
    }

    #[test]
    fn geo_info_none_skipped_in_json() {
        let host = Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let json = serde_json::to_string(&host).unwrap();
        assert!(!json.contains("geo_info"));

        // Old JSON without geo_info should deserialize cleanly
        let old_json = r#"{"ip":"10.0.0.1","hostname":null}"#;
        let parsed: Host = serde_json::from_str(old_json).unwrap();
        assert!(parsed.geo_info.is_none());
    }
}
