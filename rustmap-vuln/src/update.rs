// ---------------------------------------------------------------------------
// NVD API CVE database update
// ---------------------------------------------------------------------------
//
// Fetches CVE data from the NIST NVD 2.0 API and upserts into the local
// database. Feature-gated behind "update" (requires reqwest).

#[cfg(feature = "update")]
use anyhow::{Context, Result};
#[cfg(feature = "update")]
use rustmap_db::ScanStore;
#[cfg(feature = "update")]
use tracing::{info, warn};

/// Keywords to search for in the NVD API.
#[cfg(feature = "update")]
const SEARCH_KEYWORDS: &[&str] = &[
    "openssh",
    "apache http server",
    "nginx",
    "mysql",
    "postgresql",
    "microsoft iis",
    "proftpd",
    "vsftpd",
    "redis",
    "elasticsearch",
    "exim",
    "postfix",
];

/// NVD 2.0 API base URL.
#[cfg(feature = "update")]
const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Maximum results per page from NVD API.
#[cfg(feature = "update")]
const RESULTS_PER_PAGE: usize = 50;

/// Update the CVE database from the NVD API.
///
/// Returns the number of CVEs imported/updated.
#[cfg(feature = "update")]
pub async fn update_cve_database(store: &ScanStore) -> Result<usize> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("rustmap-vuln/0.1")
        .build()
        .context("failed to create HTTP client")?;

    let mut total_imported = 0;

    for keyword in SEARCH_KEYWORDS {
        info!(keyword, "fetching CVEs from NVD");

        match fetch_cves_for_keyword(&client, keyword).await {
            Ok(entries) => {
                let count = entries.len();
                if !entries.is_empty() {
                    store
                        .bulk_import_cves(&entries)
                        .map_err(|e| anyhow::anyhow!("DB import failed: {e}"))?;
                    total_imported += count;
                }
                info!(keyword, count, "imported CVEs");
            }
            Err(e) => {
                warn!(error = %e, keyword, "failed to fetch CVEs");
            }
        }

        // Rate limit: NVD allows ~5 requests per 30 seconds without an API key
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }

    // Fetch CISA KEV catalog
    info!("fetching CISA KEV catalog");
    let kev_ok = match fetch_cisa_kev(&client).await {
        Ok(kev_entries) => {
            let kev_count = kev_entries.len();
            if !kev_entries.is_empty() {
                store
                    .bulk_import_kev(&kev_entries)
                    .map_err(|e| anyhow::anyhow!("DB import failed: {e}"))?;
                total_imported += kev_count;
            }
            info!(count = kev_count, "imported CISA KEV entries");
            true
        }
        Err(e) => {
            warn!(error = %e, "failed to fetch CISA KEV (non-fatal)");
            false
        }
    };

    // Record update timestamps
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    store
        .set_cve_metadata("last_nvd_update", &ts)
        .map_err(|e| anyhow::anyhow!("failed to set update timestamp: {e}"))?;
    if kev_ok {
        store
            .set_cve_metadata("last_kev_update", &ts)
            .map_err(|e| anyhow::anyhow!("failed to set KEV update timestamp: {e}"))?;
    }

    Ok(total_imported)
}

/// Fetch CVEs for a single keyword from the NVD API, handling pagination.
#[cfg(feature = "update")]
async fn fetch_cves_for_keyword(
    client: &reqwest::Client,
    keyword: &str,
) -> Result<Vec<(rustmap_db::CveEntry, Vec<rustmap_db::CveRule>)>> {
    let mut results = Vec::new();
    let mut start_index: usize = 0;

    loop {
        let url = format!(
            "{}?keywordSearch={}&resultsPerPage={}&startIndex={}",
            NVD_API_URL,
            urlencoded(keyword),
            RESULTS_PER_PAGE,
            start_index,
        );

        // Retry up to 2 times on transient failures
        let mut body_bytes = None;
        let mut last_err = None;
        for attempt in 0..3 {
            if attempt > 0 {
                warn!(attempt, keyword, "retrying NVD request after failure");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            match client
                .get(&url)
                .header("Accept", "application/json")
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        last_err =
                            Some(anyhow::anyhow!("NVD API returned status {}", resp.status()));
                        continue;
                    }
                    match resp.bytes().await {
                        Ok(bytes) => {
                            body_bytes = Some(bytes);
                            break;
                        }
                        Err(e) => {
                            last_err =
                                Some(anyhow::anyhow!("failed to read NVD response body: {e}"));
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(anyhow::anyhow!("NVD API request failed: {e}"));
                }
            }
        }
        let body_bytes = match body_bytes {
            Some(b) => b,
            None => {
                return Err(
                    last_err.unwrap_or_else(|| anyhow::anyhow!("NVD request failed after retries"))
                );
            }
        };
        if body_bytes.len() > 50_000_000 {
            anyhow::bail!(
                "NVD response too large ({} bytes, max 50MB)",
                body_bytes.len()
            );
        }
        let body: serde_json::Value =
            serde_json::from_slice(&body_bytes).context("failed to parse NVD response")?;

        let total_results = body
            .get("totalResults")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        let vulnerabilities = body
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for vuln in &vulnerabilities {
            let cve = match vuln.get("cve") {
                Some(c) => c,
                None => continue,
            };

            let cve_id = cve.get("id").and_then(|v| v.as_str()).unwrap_or_default();

            if cve_id.is_empty() {
                continue;
            }

            let description = extract_description(cve);
            let (cvss_score, cvss_vector) = extract_cvss(cve);
            let published = cve
                .get("published")
                .and_then(|v| v.as_str())
                .map(String::from);
            let last_modified = cve
                .get("lastModified")
                .and_then(|v| v.as_str())
                .map(String::from);

            let entry = rustmap_db::CveEntry {
                cve_id: cve_id.to_string(),
                cvss_score,
                cvss_vector,
                description,
                published_date: published,
                last_modified,
                source: "nvd".to_string(),
            };

            // Extract product rules from configurations
            let rules = extract_product_rules(cve, cve_id);

            results.push((entry, rules));
        }

        // Advance to the next page
        start_index += RESULTS_PER_PAGE;
        if start_index >= total_results {
            break;
        }

        // Rate limit between pages
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }

    Ok(results)
}

/// Extract English description from NVD CVE JSON.
#[cfg(feature = "update")]
fn extract_description(cve: &serde_json::Value) -> String {
    cve.get("descriptions")
        .and_then(|d| d.as_array())
        .and_then(|arr| {
            arr.iter().find(|d| {
                d.get("lang")
                    .and_then(|l| l.as_str())
                    .is_some_and(|l| l == "en")
            })
        })
        .and_then(|d| d.get("value").and_then(|v| v.as_str()))
        .unwrap_or("No description available")
        .to_string()
}

/// Extract CVSS score and vector from NVD CVE JSON.
#[cfg(feature = "update")]
fn extract_cvss(cve: &serde_json::Value) -> (Option<f64>, Option<String>) {
    let metrics = match cve.get("metrics") {
        Some(m) => m,
        None => return (None, None),
    };

    // Try CVSS 3.1 first, then 3.0
    for key in &["cvssMetricV31", "cvssMetricV30"] {
        if let Some(arr) = metrics.get(*key).and_then(|v| v.as_array())
            && let Some(first) = arr.first()
            && let Some(data) = first.get("cvssData")
        {
            let score = data.get("baseScore").and_then(|v| v.as_f64());
            let vector = data
                .get("vectorString")
                .and_then(|v| v.as_str())
                .map(String::from);
            return (score, vector);
        }
    }

    (None, None)
}

/// Extract product matching rules from NVD CPE configurations.
#[cfg(feature = "update")]
fn extract_product_rules(cve: &serde_json::Value, cve_id: &str) -> Vec<rustmap_db::CveRule> {
    let mut rules = Vec::new();

    let configurations = cve
        .get("configurations")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();

    for config in &configurations {
        let nodes = config
            .get("nodes")
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default();

        for node in &nodes {
            let matches = node
                .get("cpeMatch")
                .and_then(|m| m.as_array())
                .cloned()
                .unwrap_or_default();

            for cpe_match in &matches {
                let vulnerable = cpe_match
                    .get("vulnerable")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if !vulnerable {
                    continue;
                }

                let criteria = cpe_match
                    .get("criteria")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                // Parse CPE 2.3 string: cpe:2.3:a:vendor:product:version:...
                let product = extract_product_from_cpe(criteria);
                if product.is_empty() {
                    continue;
                }

                let version_start = cpe_match
                    .get("versionStartIncluding")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let (version_end, version_end_exclusive) = if let Some(v) = cpe_match
                    .get("versionEndExcluding")
                    .and_then(|v| v.as_str())
                {
                    (Some(v.to_string()), true)
                } else if let Some(v) = cpe_match
                    .get("versionEndIncluding")
                    .and_then(|v| v.as_str())
                {
                    (Some(v.to_string()), false)
                } else {
                    (None, false)
                };

                rules.push(rustmap_db::CveRule {
                    cve_id: cve_id.to_string(),
                    product_pattern: product,
                    version_exact: None,
                    version_start,
                    version_end,
                    version_end_exclusive,
                });
            }
        }
    }

    rules
}

/// Extract product name from a CPE 2.3 string.
#[cfg(feature = "update")]
fn extract_product_from_cpe(cpe: &str) -> String {
    // cpe:2.3:a:vendor:product:version:update:edition:language:...
    let parts: Vec<&str> = cpe.split(':').collect();
    if parts.len() > 4 {
        parts[4].replace('_', " ")
    } else {
        String::new()
    }
}

/// Simple URL encoding for query parameters.
#[cfg(feature = "update")]
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25") // must be first to avoid double-encoding
        .replace(' ', "%20")
        .replace('/', "%2F")
        .replace('&', "%26")
        .replace('+', "%2B")
        .replace('=', "%3D")
        .replace('?', "%3F")
        .replace('#', "%23")
}

// ---------------------------------------------------------------------------
// CISA Known Exploited Vulnerabilities (KEV) feed
// ---------------------------------------------------------------------------

/// CISA KEV JSON feed URL.
#[cfg(feature = "update")]
const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Fetch CISA Known Exploited Vulnerabilities and convert to CveEntry/CveRule pairs.
#[cfg(feature = "update")]
async fn fetch_cisa_kev(
    client: &reqwest::Client,
) -> Result<Vec<(rustmap_db::CveEntry, Vec<rustmap_db::CveRule>)>> {
    let resp = client
        .get(CISA_KEV_URL)
        .header("Accept", "application/json")
        .send()
        .await
        .context("CISA KEV request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!("CISA KEV returned status {}", resp.status());
    }

    let body_bytes = resp
        .bytes()
        .await
        .context("failed to read KEV response body")?;
    if body_bytes.len() > 50_000_000 {
        anyhow::bail!(
            "CISA KEV response too large ({} bytes, max 50MB)",
            body_bytes.len()
        );
    }
    let catalog: KevCatalog =
        serde_json::from_slice(&body_bytes).context("failed to parse KEV JSON")?;

    let results: Vec<_> = catalog
        .vulnerabilities
        .into_iter()
        .map(|kev| {
            let product_pattern = normalize_kev_product(&kev.vendor_project, &kev.product);

            let entry = rustmap_db::CveEntry {
                cve_id: kev.cve_id.clone(),
                cvss_score: None, // KEV doesn't provide CVSS; NVD upsert preserves existing scores
                cvss_vector: None,
                description: kev.short_description,
                published_date: Some(kev.date_added),
                last_modified: None,
                source: "cisa_kev".to_string(),
            };

            // NOTE: KEV rules have no version bounds (version_start/version_end
            // are always None) because the CISA KEV feed does not include version
            // range data. This means KEV-sourced rules will match ANY detected
            // version of the product, which can produce false positives. These
            // matches should be treated as lower-confidence compared to NVD rules
            // that include precise version constraints. (Known limitation.)
            let rules = vec![rustmap_db::CveRule {
                cve_id: kev.cve_id,
                product_pattern,
                version_exact: None,
                version_start: None,
                version_end: None,
                version_end_exclusive: false,
            }];

            (entry, rules)
        })
        .collect();

    Ok(results)
}

/// Normalize CISA KEV product names to match our detection patterns.
///
/// Uses the same logic as query-time `normalize_product()` in matcher.rs:
/// lowercases the product and strips common suffixes ("httpd", "server", "daemon").
/// The vendor is NOT prepended, because the matcher normalizes scanned product names
/// without vendor (e.g., "Apache httpd" → "apache", not "apache_http_server").
#[cfg(feature = "update")]
fn normalize_kev_product(_vendor: &str, product: &str) -> String {
    product
        .to_lowercase()
        .replace(['-', '_'], " ")
        .trim()
        .trim_end_matches(" httpd")
        .trim_end_matches(" server")
        .trim_end_matches(" daemon")
        .trim()
        .to_string()
}

#[cfg(feature = "update")]
#[derive(serde::Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevEntry>,
}

#[cfg(feature = "update")]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    vendor_project: String,
    product: String,
    #[allow(dead_code)]
    vulnerability_name: String,
    short_description: String,
    date_added: String,
    #[allow(dead_code)]
    known_ransomware_campaign_use: String,
}

#[cfg(test)]
#[cfg(feature = "update")]
mod tests {
    use super::*;

    #[test]
    fn normalize_kev_product_basic() {
        // "HTTP Server" → strip " server" suffix → "http"
        assert_eq!(normalize_kev_product("Apache", "HTTP Server"), "http");
    }

    #[test]
    fn normalize_kev_product_dashes() {
        // "Windows-Server" → replace '-' with ' ' → "windows server" → strip " server" → "windows"
        assert_eq!(
            normalize_kev_product("Microsoft", "Windows-Server"),
            "windows"
        );
    }

    #[test]
    fn normalize_kev_product_matches_query_normalization() {
        // Verify KEV normalization aligns with matcher.rs normalize_product()
        // "OpenSSH" → "openssh" (no suffix to strip)
        assert_eq!(normalize_kev_product("OpenBSD", "OpenSSH"), "openssh");
        // "nginx" → "nginx"
        assert_eq!(normalize_kev_product("F5", "nginx"), "nginx");
        // "HTTP Server" from KEV matches "http server" → strip " server" → "http"
        // This matches CPE "http_server" → "http server" → normalize_product strips " server" → "http"
        assert_eq!(normalize_kev_product("Apache", "HTTP Server"), "http");
    }

    #[test]
    fn parse_kev_json() {
        let json = r#"{
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "vendorProject": "Apache",
                    "product": "HTTP Server",
                    "vulnerabilityName": "Apache HTTP Server RCE",
                    "shortDescription": "Remote code execution in Apache HTTP Server",
                    "dateAdded": "2024-01-15",
                    "dueDate": "2024-02-05",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": ""
                }
            ]
        }"#;

        let catalog: KevCatalog = serde_json::from_str(json).unwrap();
        assert_eq!(catalog.vulnerabilities.len(), 1);
        assert_eq!(catalog.vulnerabilities[0].cve_id, "CVE-2024-1234");
        assert_eq!(catalog.vulnerabilities[0].vendor_project, "Apache");
        assert_eq!(catalog.vulnerabilities[0].product, "HTTP Server");
        assert_eq!(
            catalog.vulnerabilities[0].short_description,
            "Remote code execution in Apache HTTP Server"
        );
    }

    #[test]
    fn extract_product_from_cpe_basic() {
        assert_eq!(
            extract_product_from_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"),
            "http server"
        );
    }

    #[test]
    fn extract_product_from_cpe_short() {
        assert_eq!(extract_product_from_cpe("cpe:2.3:a"), "");
    }
}
