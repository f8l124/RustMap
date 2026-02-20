// ---------------------------------------------------------------------------
// CVE matching engine
// ---------------------------------------------------------------------------
//
// Correlates detected service versions with CVE entries stored in the database.

use rustmap_db::ScanStore;
use rustmap_types::Port;
use tracing::warn;

use crate::types::{HostVulnResult, PortVulnResult, VulnMatch};

/// Check all open ports on a host for CVE matches.
pub fn check_host_vulns(
    store: &ScanStore,
    ip: &str,
    ports: &[Port],
    min_cvss: Option<f64>,
) -> HostVulnResult {
    let mut port_vulns = Vec::new();

    for port in ports {
        if port.state != rustmap_types::PortState::Open {
            continue;
        }

        let (product, version) = extract_product_version(port);

        let product_str = match product {
            Some(ref p) => p.as_str(),
            None => continue, // No product info — can't match CVEs
        };

        let vulns = match_port_vulns(store, product_str, version.as_deref(), min_cvss);

        if !vulns.is_empty() {
            port_vulns.push(PortVulnResult {
                port: port.number,
                protocol: format!("{}", port.protocol),
                product: product.clone(),
                version: version.clone(),
                vulns,
            });
        }
    }

    let mut result = HostVulnResult {
        ip: ip.to_string(),
        port_vulns,
        risk_score: None,
    };
    let risk = compute_risk_score(&result);
    result.risk_score = if risk > 0.0 { Some(risk) } else { None };
    result
}

/// Extract product and version from a port's service info.
fn extract_product_version(port: &Port) -> (Option<String>, Option<String>) {
    if let Some(ref info) = port.service_info {
        (info.product.clone(), info.version.clone())
    } else {
        (None, None)
    }
}

/// Match a single product/version against CVE rules in the database.
fn match_port_vulns(
    store: &ScanStore,
    product: &str,
    version: Option<&str>,
    min_cvss: Option<f64>,
) -> Vec<VulnMatch> {
    let normalized = normalize_product(product);
    let rules = match store.find_cve_rules_for_product(&normalized) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, product, "failed to query CVE rules");
            return vec![];
        }
    };

    let mut matches = Vec::new();

    for rule in &rules {
        let version_ok = match version {
            None => {
                // No version detected — only match rules that don't require a version
                rule.version_exact.is_none()
                    && rule.version_start.is_none()
                    && rule.version_end.is_none()
            }
            Some(ver) => version_matches(
                ver,
                &rule.version_exact,
                &rule.version_start,
                &rule.version_end,
                rule.version_end_exclusive,
            ),
        };

        if !version_ok {
            continue;
        }

        // Fetch the CVE entry
        let entry = match store.get_cve(&rule.cve_id) {
            Ok(Some(e)) => e,
            Ok(None) => continue,
            Err(e) => {
                warn!(error = %e, cve = rule.cve_id, "failed to fetch CVE entry");
                continue;
            }
        };

        // Apply min CVSS filter
        if let Some(min) = min_cvss
            && min > 0.0
            && entry.cvss_score.is_none_or(|s| s < min)
        {
            continue;
        }

        matches.push(VulnMatch {
            cve_id: rule.cve_id.clone(),
            cvss_score: entry.cvss_score,
            description: entry.description,
            matched_product: product.to_string(),
            matched_version: version.unwrap_or("unknown").to_string(),
        });
    }

    matches
}

/// Normalize a product name for matching.
///
/// Lowercases and strips common suffixes like "httpd", "server", "daemon".
pub fn normalize_product(product: &str) -> String {
    let mut result = product.to_lowercase();
    // Loop suffix stripping until stable so "foo httpd server" strips both.
    loop {
        let before = result.clone();
        result = result
            .trim_end_matches(" httpd")
            .trim_end_matches(" server")
            .trim_end_matches(" daemon")
            .trim()
            .to_string();
        if result == before {
            break;
        }
    }
    result
}

/// Check if a detected version matches a CVE rule's version constraints.
///
/// When `end_exclusive` is true, the `end` boundary is exclusive (i.e., the
/// exact boundary version does NOT match). This corresponds to NVD's
/// `versionEndExcluding` field.
pub fn version_matches(
    detected: &str,
    exact: &Option<String>,
    start: &Option<String>,
    end: &Option<String>,
    end_exclusive: bool,
) -> bool {
    if let Some(ex) = exact {
        return detected == ex;
    }

    let has_start = start.is_some();
    let has_end = end.is_some();

    if !has_start && !has_end {
        // No version constraint — matches any version
        return true;
    }

    if let Some(s) = start
        && compare_versions(detected, s) == std::cmp::Ordering::Less
    {
        return false;
    }

    if let Some(e) = end {
        let cmp = compare_versions(detected, e);
        if cmp == std::cmp::Ordering::Greater {
            return false;
        }
        // For exclusive end, reject exact boundary match
        if end_exclusive && cmp == std::cmp::Ordering::Equal {
            return false;
        }
    }

    true
}

/// Compare two version strings segment by segment.
///
/// Splits on `.` and `-`, compares segments numerically when possible,
/// falls back to lexicographic for non-numeric segments like "p1", "rc2".
/// Trailing `.0` segments do not affect ordering (e.g., "1.2" == "1.2.0").
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let seg_a = split_version(a);
    let seg_b = split_version(b);

    for (sa, sb) in seg_a.iter().zip(seg_b.iter()) {
        let ord = compare_segments(sa, sb);
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }

    // Compare remaining segments against 0 so that trailing .0 segments
    // do not cause a difference (e.g., "1.2" == "1.2.0" == "1.2.0.0").
    let remaining = if seg_a.len() > seg_b.len() {
        &seg_a[seg_b.len()..]
    } else {
        &seg_b[seg_a.len()..]
    };
    for seg in remaining {
        let ord = compare_segments(seg, "0");
        if ord != std::cmp::Ordering::Equal {
            return if seg_a.len() > seg_b.len() {
                ord
            } else {
                ord.reverse()
            };
        }
    }

    std::cmp::Ordering::Equal
}

/// Split a version string into segments.
fn split_version(v: &str) -> Vec<&str> {
    v.split(['.', '-', '_']).filter(|s| !s.is_empty()).collect()
}

/// Compare two version segments (numeric or lexicographic).
fn compare_segments(a: &str, b: &str) -> std::cmp::Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(na), Ok(nb)) => na.cmp(&nb),
        _ => a.cmp(b),
    }
}

/// Compute a risk score (0.0-10.0) from vulnerability results.
///
/// Formula: 50% highest CVSS + 20% density bonus + 20% critical count + 10% service spread.
/// - density = min(num_vulns / 10, 1.0)
/// - critical = min(num_critical / 3, 1.0) where critical = CVSS >= 9.0
/// - spread = min(num_affected_services / 5, 1.0)
pub fn compute_risk_score(host_vuln: &HostVulnResult) -> f64 {
    if host_vuln.port_vulns.is_empty() {
        return 0.0;
    }

    let mut highest_cvss: f64 = 0.0;
    let mut num_vulns: usize = 0;
    let mut num_critical: usize = 0;
    let num_affected = host_vuln.port_vulns.len();

    for pv in &host_vuln.port_vulns {
        for vuln in &pv.vulns {
            num_vulns += 1;
            if let Some(score) = vuln.cvss_score {
                // Skip non-finite or out-of-range CVSS values (defense against bad data)
                if !score.is_finite() || !(0.0..=10.0).contains(&score) {
                    continue;
                }
                if score > highest_cvss {
                    highest_cvss = score;
                }
                if score >= 9.0 {
                    num_critical += 1;
                }
            }
        }
    }

    let density = (num_vulns as f64 / 10.0).min(1.0);
    let critical = (num_critical as f64 / 3.0).min(1.0);
    let spread = (num_affected as f64 / 5.0).min(1.0);

    // Critical component uses max scale (10.0) rather than highest_cvss because
    // having any CVSS >= 9.0 vulns is inherently severe regardless of exact score.
    (highest_cvss * 0.5
        + highest_cvss * density * 0.2
        + 10.0 * critical * 0.2
        + highest_cvss * spread * 0.1)
        .clamp(0.0, 10.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_versions_basic() {
        assert_eq!(compare_versions("1.0", "1.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("1.0", "2.0"), std::cmp::Ordering::Less);
        assert_eq!(compare_versions("2.0", "1.0"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn compare_versions_multi_segment() {
        assert_eq!(
            compare_versions("1.2.3", "1.2.3"),
            std::cmp::Ordering::Equal
        );
        assert_eq!(compare_versions("1.2.3", "1.2.4"), std::cmp::Ordering::Less);
        assert_eq!(
            compare_versions("1.3.0", "1.2.9"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("2.0.0", "1.9.9"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn compare_versions_different_lengths() {
        // Trailing .0 segments should not affect ordering
        assert_eq!(compare_versions("1.2", "1.2.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("1.2.0", "1.2"), std::cmp::Ordering::Equal);
        assert_eq!(
            compare_versions("1.2.0.0", "1.2"),
            std::cmp::Ordering::Equal
        );
        // But non-zero trailing segments still matter
        assert_eq!(compare_versions("1.2", "1.2.1"), std::cmp::Ordering::Less);
        assert_eq!(
            compare_versions("1.2.1", "1.2"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn compare_versions_with_suffix() {
        assert_eq!(
            compare_versions("1.0.0p1", "1.0.0p2"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn version_matches_exact() {
        assert!(version_matches(
            "8.9p1",
            &Some("8.9p1".into()),
            &None,
            &None,
            false
        ));
        assert!(!version_matches(
            "8.9p2",
            &Some("8.9p1".into()),
            &None,
            &None,
            false
        ));
    }

    #[test]
    fn version_matches_range() {
        // 8.5 through 9.7 (inclusive)
        assert!(version_matches(
            "8.9",
            &None,
            &Some("8.5".into()),
            &Some("9.7".into()),
            false,
        ));
        assert!(version_matches(
            "9.7",
            &None,
            &Some("8.5".into()),
            &Some("9.7".into()),
            false,
        ));
        assert!(!version_matches(
            "8.4",
            &None,
            &Some("8.5".into()),
            &Some("9.7".into()),
            false,
        ));
        assert!(!version_matches(
            "9.8",
            &None,
            &Some("8.5".into()),
            &Some("9.7".into()),
            false,
        ));
    }

    #[test]
    fn version_matches_range_exclusive_end() {
        // 8.5 through 9.7 (exclusive end — 9.7 should NOT match)
        assert!(version_matches(
            "8.9",
            &None,
            &Some("8.5".into()),
            &Some("9.7".into()),
            true,
        ));
        assert!(!version_matches(
            "9.7",
            &None,
            &Some("8.5".into()),
            &Some("9.7".into()),
            true,
        ));
        assert!(version_matches(
            "9.6",
            &None,
            &Some("8.5".into()),
            &Some("9.7".into()),
            true,
        ));
    }

    #[test]
    fn version_matches_no_constraint() {
        assert!(version_matches("anything", &None, &None, &None, false));
    }

    #[test]
    fn normalize_product_cases() {
        assert_eq!(normalize_product("Apache"), "apache");
        assert_eq!(normalize_product("Apache httpd"), "apache");
        assert_eq!(normalize_product("nginx"), "nginx");
        assert_eq!(normalize_product("OpenSSH"), "openssh");
        assert_eq!(normalize_product("MySQL Server"), "mysql");
        assert_eq!(normalize_product("Redis"), "redis");
        assert_eq!(normalize_product("sshd daemon"), "sshd");
    }

    #[test]
    fn check_host_vulns_no_service() {
        let store = ScanStore::open_in_memory().unwrap();
        let ports = vec![Port {
            number: 80,
            protocol: rustmap_types::Protocol::Tcp,
            state: rustmap_types::PortState::Open,
            service: None,
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }];
        let result = check_host_vulns(&store, "10.0.0.1", &ports, None);
        assert!(result.port_vulns.is_empty());
    }

    #[test]
    fn check_port_vulns_matching() {
        let store = ScanStore::open_in_memory().unwrap();

        // Insert a test CVE
        store
            .upsert_cve(
                "CVE-2024-0001",
                Some(8.1),
                None,
                "Test vulnerability in OpenSSH",
                None,
                None,
                "bundled",
            )
            .unwrap();
        store
            .insert_cve_rule("CVE-2024-0001", "openssh", None, Some("8.5"), Some("9.7"))
            .unwrap();

        let vulns = match_port_vulns(&store, "OpenSSH", Some("8.9"), None);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].cve_id, "CVE-2024-0001");
        assert_eq!(vulns[0].cvss_score, Some(8.1));
    }

    #[test]
    fn risk_score_no_vulns() {
        let host = HostVulnResult {
            ip: "10.0.0.1".into(),
            port_vulns: vec![],
            risk_score: None,
        };
        assert_eq!(compute_risk_score(&host), 0.0);
    }

    #[test]
    fn risk_score_single_critical() {
        let host = HostVulnResult {
            ip: "10.0.0.1".into(),
            port_vulns: vec![PortVulnResult {
                port: 22,
                protocol: "tcp".into(),
                product: Some("OpenSSH".into()),
                version: Some("8.9".into()),
                vulns: vec![VulnMatch {
                    cve_id: "CVE-2024-9999".into(),
                    cvss_score: Some(9.8),
                    description: "Critical vuln".into(),
                    matched_product: "openssh".into(),
                    matched_version: "8.9".into(),
                }],
            }],
            risk_score: None,
        };
        let score = compute_risk_score(&host);
        assert!(score >= 5.0, "expected score >= 5.0, got {score}");
        assert!(score <= 10.0);
    }

    #[test]
    fn risk_score_clamped() {
        // Many critical vulns across many services
        let vulns: Vec<VulnMatch> = (0..10)
            .map(|i| VulnMatch {
                cve_id: format!("CVE-2024-{i:04}"),
                cvss_score: Some(10.0),
                description: "max severity".into(),
                matched_product: "test".into(),
                matched_version: "1.0".into(),
            })
            .collect();
        let port_vulns: Vec<PortVulnResult> = (0..6)
            .map(|i| PortVulnResult {
                port: 80 + i,
                protocol: "tcp".into(),
                product: Some("test".into()),
                version: Some("1.0".into()),
                vulns: vulns.clone(),
            })
            .collect();
        let host = HostVulnResult {
            ip: "10.0.0.1".into(),
            port_vulns,
            risk_score: None,
        };
        let score = compute_risk_score(&host);
        assert!(score <= 10.0, "expected score <= 10.0, got {score}");
        assert!(
            score >= 9.0,
            "expected score >= 9.0 for many criticals, got {score}"
        );
    }

    #[test]
    fn check_port_vulns_min_cvss_filter() {
        let store = ScanStore::open_in_memory().unwrap();

        store
            .upsert_cve(
                "CVE-2024-0002",
                Some(3.5),
                None,
                "Low severity issue",
                None,
                None,
                "bundled",
            )
            .unwrap();
        store
            .insert_cve_rule("CVE-2024-0002", "openssh", None, None, None)
            .unwrap();

        // Without filter — should match
        let vulns = match_port_vulns(&store, "OpenSSH", Some("8.0"), None);
        assert_eq!(vulns.len(), 1);

        // With min CVSS 7.0 — should be filtered out
        let vulns = match_port_vulns(&store, "OpenSSH", Some("8.0"), Some(7.0));
        assert!(vulns.is_empty());
    }
}
