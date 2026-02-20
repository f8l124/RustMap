// ---------------------------------------------------------------------------
// Vulnerability types
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// A single CVE match for a detected service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnMatch {
    pub cve_id: String,
    pub cvss_score: Option<f64>,
    pub description: String,
    pub matched_product: String,
    pub matched_version: String,
}

/// Vulnerability results for all open ports on a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostVulnResult {
    pub ip: String,
    pub port_vulns: Vec<PortVulnResult>,
    /// Aggregate risk score for this host (0.0-10.0, CVSS scale).
    pub risk_score: Option<f64>,
}

/// Vulnerability results for a single port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortVulnResult {
    pub port: u16,
    pub protocol: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub vulns: Vec<VulnMatch>,
}
