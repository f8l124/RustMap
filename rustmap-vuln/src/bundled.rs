// ---------------------------------------------------------------------------
// Bundled CVE dataset
// ---------------------------------------------------------------------------
//
// A curated set of high-impact CVEs for common network services.
// This provides out-of-the-box vulnerability detection without requiring
// an internet connection or NVD API key.

use rustmap_db::{CveEntry, CveRule, ScanStore};

/// Current bundled data version. Bump when adding/changing entries.
const BUNDLED_VERSION: &str = "1";

/// Seed the database with bundled CVEs (idempotent).
pub fn seed_bundled_cves(store: &ScanStore) -> Result<(), rustmap_db::DbError> {
    // Check if already seeded with this version
    if let Some(ver) = store.get_cve_metadata("bundled_version")?
        && ver == BUNDLED_VERSION
    {
        return Ok(());
    }

    let entries = bundled_entries();
    store.bulk_import_cves(&entries)?;
    store.set_cve_metadata("bundled_version", BUNDLED_VERSION)?;

    Ok(())
}

/// Return the bundled CVE dataset.
pub fn bundled_entries() -> Vec<(CveEntry, Vec<CveRule>)> {
    vec![
        // -------------------------------------------------------------------
        // OpenSSH
        // -------------------------------------------------------------------
        cve(
            "CVE-2024-6387",
            8.1,
            "OpenSSH signal handler race condition (regreSSHion). \
             Unauthenticated remote code execution on glibc-based Linux systems.",
            "2024-07-01",
            &[rule("openssh", None, Some("8.5"), Some("9.7"))],
        ),
        cve(
            "CVE-2023-38408",
            9.8,
            "OpenSSH ssh-agent remote code execution via forwarded agent socket.",
            "2023-07-20",
            &[rule("openssh", None, None, Some("9.3"))],
        ),
        cve(
            "CVE-2023-48795",
            5.9,
            "Terrapin attack: SSH prefix truncation allows downgrade of connection security.",
            "2023-12-18",
            &[rule("openssh", None, None, Some("9.6"))],
        ),
        cve(
            "CVE-2023-51385",
            6.5,
            "OpenSSH OS command injection via ProxyCommand/ProxyJump host expansion.",
            "2023-12-20",
            &[rule("openssh", None, None, Some("9.6"))],
        ),
        cve(
            "CVE-2021-41617",
            7.0,
            "OpenSSH privilege escalation via AuthorizedKeysCommand/AuthorizedPrincipalsCommand.",
            "2021-09-26",
            &[rule("openssh", None, Some("6.2"), Some("8.7"))],
        ),
        // -------------------------------------------------------------------
        // Apache HTTP Server
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-25690",
            9.8,
            "Apache HTTP Server mod_proxy HTTP Request Smuggling vulnerability.",
            "2023-03-07",
            &[rule("apache", None, Some("2.4.0"), Some("2.4.55"))],
        ),
        cve(
            "CVE-2023-43622",
            7.5,
            "Apache HTTP Server HTTP/2 stream handling DoS (RESET frames).",
            "2023-10-23",
            &[rule("apache", None, Some("2.4.55"), Some("2.4.57"))],
        ),
        cve(
            "CVE-2021-44790",
            9.8,
            "Apache HTTP Server mod_lua buffer overflow allows code execution.",
            "2021-12-20",
            &[rule("apache", None, Some("2.4.51"), Some("2.4.51"))],
        ),
        cve(
            "CVE-2021-41773",
            7.5,
            "Apache HTTP Server 2.4.49 path traversal and file disclosure.",
            "2021-10-05",
            &[rule("apache", Some("2.4.49"), None, None)],
        ),
        cve(
            "CVE-2021-42013",
            9.8,
            "Apache HTTP Server 2.4.50 path traversal (incomplete fix for CVE-2021-41773).",
            "2021-10-07",
            &[rule("apache", Some("2.4.50"), None, None)],
        ),
        // -------------------------------------------------------------------
        // nginx
        // -------------------------------------------------------------------
        cve(
            "CVE-2022-41741",
            7.8,
            "nginx mp4 module memory corruption allows code execution.",
            "2022-10-19",
            &[rule("nginx", None, Some("1.1.3"), Some("1.23.1"))],
        ),
        cve(
            "CVE-2021-23017",
            7.7,
            "nginx DNS resolver off-by-one heap write allows RCE.",
            "2021-06-01",
            &[rule("nginx", None, Some("0.6.18"), Some("1.21.0"))],
        ),
        cve(
            "CVE-2024-7347",
            4.7,
            "nginx mp4 module buffer overread when processing crafted mp4 files.",
            "2024-08-14",
            &[rule("nginx", None, Some("1.5.13"), Some("1.27.0"))],
        ),
        // -------------------------------------------------------------------
        // MySQL / MariaDB
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-21980",
            7.1,
            "MySQL Server Client programs unspecified vulnerability.",
            "2023-04-18",
            &[rule("mysql", None, None, Some("8.0.33"))],
        ),
        cve(
            "CVE-2023-22084",
            4.9,
            "MySQL Server InnoDB unspecified vulnerability.",
            "2023-10-17",
            &[rule("mysql", None, None, Some("8.0.35"))],
        ),
        // -------------------------------------------------------------------
        // PostgreSQL
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-5868",
            4.3,
            "PostgreSQL memory disclosure in aggregate function calls.",
            "2023-11-15",
            &[rule("postgresql", None, None, Some("16.1"))],
        ),
        cve(
            "CVE-2023-5869",
            8.8,
            "PostgreSQL buffer overrun from integer overflow in array modifications.",
            "2023-11-15",
            &[rule("postgresql", None, None, Some("16.1"))],
        ),
        // -------------------------------------------------------------------
        // Microsoft IIS
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-36899",
            7.5,
            "Microsoft IIS information disclosure vulnerability.",
            "2023-08-08",
            &[rule("iis", None, Some("10.0"), Some("10.0"))],
        ),
        // -------------------------------------------------------------------
        // Microsoft RDP (Remote Desktop)
        // -------------------------------------------------------------------
        cve(
            "CVE-2019-0708",
            9.8,
            "BlueKeep: Windows Remote Desktop Services RCE (pre-authentication).",
            "2019-05-14",
            &[rule("microsoft terminal service", None, None, None)],
        ),
        // -------------------------------------------------------------------
        // ProFTPD
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-51713",
            7.5,
            "ProFTPD heap buffer overflow in mod_sftp allows DoS.",
            "2023-12-22",
            &[rule("proftpd", None, None, Some("1.3.8"))],
        ),
        // -------------------------------------------------------------------
        // vsftpd
        // -------------------------------------------------------------------
        cve(
            "CVE-2021-3618",
            7.4,
            "ALPACA attack: TLS application protocol content confusion affects vsftpd and others.",
            "2022-03-23",
            &[rule("vsftpd", None, None, Some("3.0.4"))],
        ),
        // -------------------------------------------------------------------
        // Redis
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-41056",
            8.1,
            "Redis heap buffer overflow in networking.c allows code execution.",
            "2024-01-10",
            &[rule("redis", None, Some("7.0.0"), Some("7.0.14"))],
        ),
        // -------------------------------------------------------------------
        // Elasticsearch
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-31419",
            7.5,
            "Elasticsearch StackOverflowError via large _search API request.",
            "2023-10-26",
            &[rule("elasticsearch", None, Some("7.0.0"), Some("8.9.1"))],
        ),
        // -------------------------------------------------------------------
        // Exim (SMTP)
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-42115",
            9.8,
            "Exim SMTP AUTH out-of-bounds write allows remote code execution.",
            "2023-09-28",
            &[rule("exim", None, None, Some("4.96.1"))],
        ),
        // -------------------------------------------------------------------
        // Postfix (SMTP)
        // -------------------------------------------------------------------
        cve(
            "CVE-2023-51764",
            5.3,
            "Postfix SMTP smuggling allows bypass of email authentication.",
            "2023-12-24",
            &[rule("postfix", None, None, Some("3.8.4"))],
        ),
    ]
}

// Helper: build a CveEntry + rules tuple.
fn cve(
    id: &str,
    cvss: f64,
    desc: &str,
    published: &str,
    rules: &[CveRule],
) -> (CveEntry, Vec<CveRule>) {
    (
        CveEntry {
            cve_id: id.to_string(),
            cvss_score: Some(cvss),
            cvss_vector: None,
            description: desc.to_string(),
            published_date: Some(published.to_string()),
            last_modified: None,
            source: "bundled".to_string(),
        },
        rules.to_vec(),
    )
}

// Helper: build a CveRule.
fn rule(product: &str, exact: Option<&str>, start: Option<&str>, end: Option<&str>) -> CveRule {
    CveRule {
        cve_id: String::new(), // filled by bulk_import
        product_pattern: product.to_string(),
        version_exact: exact.map(String::from),
        version_start: start.map(String::from),
        version_end: end.map(String::from),
        version_end_exclusive: false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_entries_valid() {
        let entries = bundled_entries();
        assert!(entries.len() >= 20, "should have at least 20 bundled CVEs");
        for (entry, rules) in &entries {
            assert!(
                entry.cve_id.starts_with("CVE-"),
                "invalid CVE ID: {}",
                entry.cve_id
            );
            assert!(
                !entry.description.is_empty(),
                "empty description for {}",
                entry.cve_id
            );
            assert!(
                entry.cvss_score.is_some(),
                "missing CVSS for {}",
                entry.cve_id
            );
            assert!(!rules.is_empty(), "no rules for {}", entry.cve_id);
        }
    }

    #[test]
    fn seed_bundled_idempotent() {
        let store = ScanStore::open_in_memory().unwrap();
        seed_bundled_cves(&store).unwrap();
        let count1 = store.count_cves().unwrap();
        assert!(count1 > 0);

        // Seeding again should be a no-op
        seed_bundled_cves(&store).unwrap();
        let count2 = store.count_cves().unwrap();
        assert_eq!(count1, count2);
    }
}
