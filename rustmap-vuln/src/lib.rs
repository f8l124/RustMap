pub mod bundled;
pub mod matcher;
pub mod types;
pub mod update;

pub use bundled::seed_bundled_cves;
pub use matcher::{check_host_vulns, compute_risk_score};
pub use types::{HostVulnResult, PortVulnResult, VulnMatch};

#[cfg(feature = "update")]
pub use update::update_cve_database;
