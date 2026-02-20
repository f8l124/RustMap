use serde::{Deserialize, Serialize};
use std::fmt;

/// How a service was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DetectionMethod {
    /// Not yet detected.
    #[default]
    None,
    /// From port-to-service map (e.g., 80 → http).
    PortBased,
    /// From banner grab (NULL probe).
    Banner,
    /// From active probe response.
    Probe,
    /// From TLS handshake analysis.
    TlsProbe,
}

impl fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::PortBased => write!(f, "table"),
            Self::Banner => write!(f, "banner"),
            Self::Probe => write!(f, "probe"),
            Self::TlsProbe => write!(f, "tls-probe"),
        }
    }
}

/// Service/version detection info for an open port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service name (e.g., "ssh", "http").
    pub name: String,
    /// Product name (e.g., "OpenSSH", "Apache httpd").
    pub product: Option<String>,
    /// Version string (e.g., "8.9p1", "2.4.52").
    pub version: Option<String>,
    /// Extra info (e.g., "Ubuntu Linux; protocol 2.0").
    pub info: Option<String>,
    /// How this service was detected.
    pub method: DetectionMethod,
}

impl ServiceInfo {
    /// Create a ServiceInfo from a port-map lookup.
    pub fn from_port_map(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            product: None,
            version: None,
            info: None,
            method: DetectionMethod::PortBased,
        }
    }

    /// Format the version string for display (product + version + info).
    pub fn version_display(&self) -> Option<String> {
        let mut parts: Vec<&str> = Vec::new();
        if let Some(ref product) = self.product {
            parts.push(product);
        }
        if let Some(ref version) = self.version {
            parts.push(version);
        }
        if let Some(ref info) = self.info {
            if parts.is_empty() {
                return Some(format!("({})", info));
            }
            return Some(format!("{} ({})", parts.join(" "), info));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_method_tls_probe_display() {
        assert_eq!(DetectionMethod::TlsProbe.to_string(), "tls-probe");
    }

    #[test]
    fn detection_method_display_all() {
        assert_eq!(DetectionMethod::None.to_string(), "none");
        assert_eq!(DetectionMethod::PortBased.to_string(), "table");
        assert_eq!(DetectionMethod::Banner.to_string(), "banner");
        assert_eq!(DetectionMethod::Probe.to_string(), "probe");
        assert_eq!(DetectionMethod::TlsProbe.to_string(), "tls-probe");
    }
}
