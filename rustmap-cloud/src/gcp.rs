use crate::{CloudDiscoveryOptions, CloudError};
use rustmap_types::Host;
use serde::Deserialize;
use std::net::IpAddr;

/// Discover GCP Compute Engine instances and return them as scan targets.
///
/// Authentication via `GOOGLE_APPLICATION_CREDENTIALS` environment variable
/// (path to a service account JSON key file) or `GOOGLE_CLOUD_PROJECT` + metadata server.
pub async fn discover(opts: &CloudDiscoveryOptions) -> Result<Vec<Host>, CloudError> {
    let project = std::env::var("GOOGLE_CLOUD_PROJECT")
        .or_else(|_| std::env::var("GCLOUD_PROJECT"))
        .map_err(|_| {
            CloudError::AuthError("GOOGLE_CLOUD_PROJECT or GCLOUD_PROJECT not set".into())
        })?;

    let access_token = get_access_token().await?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| CloudError::ApiError(format!("failed to build HTTP client: {e}")))?;

    // Use aggregated list to get instances across all zones, with pagination
    let base_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances"
    );

    let mut hosts = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let url = match &page_token {
            Some(token) => format!("{base_url}?pageToken={token}"),
            None => base_url.clone(),
        };

        let resp = http
            .get(&url)
            .bearer_auth(&access_token)
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("list instances failed: {e}")))?;

        let body: AggregatedListResponse = resp
            .json()
            .await
            .map_err(|e| CloudError::ApiError(format!("parse instances failed: {e}")))?;

        for (_zone, scoped) in &body.items {
            let instances = match &scoped.instances {
                Some(list) => list,
                None => continue,
            };

            for instance in instances {
                // Filter by running
                if opts.running_only && instance.status.as_deref() != Some("RUNNING") {
                    continue;
                }

                // Filter by region if specified
                if !opts.regions.is_empty() {
                    if let Some(ref zone) = instance.zone {
                        // Zone format: projects/PROJECT/zones/ZONE
                        let zone_name = zone.rsplit('/').next().unwrap_or(zone);
                        // Region is zone minus the last -X suffix
                        let region = zone_name
                            .rfind('-')
                            .map(|i| &zone_name[..i])
                            .unwrap_or(zone_name);
                        if !opts
                            .regions
                            .iter()
                            .any(|r| r == region || zone_name.starts_with(r))
                        {
                            continue;
                        }
                    }
                }

                // Extract IPs from network interfaces
                if let Some(ref interfaces) = instance.network_interfaces {
                    for iface in interfaces {
                        // Prefer external (access config) IP
                        let ip_str = iface
                            .access_configs
                            .as_ref()
                            .and_then(|configs| configs.iter().find_map(|c| c.nat_ip.as_deref()))
                            .or(iface.network_ip.as_deref());

                        if let Some(ip_str) = ip_str {
                            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                hosts.push(Host {
                                    ip,
                                    hostname: Some(instance.name.clone()),
                                    geo_info: None,
                                });
                                break; // one IP per instance
                            }
                        }
                    }
                }
            }
        }

        // Follow pagination token, or break if no more pages
        match body.next_page_token {
            Some(token) if !token.is_empty() => page_token = Some(token),
            _ => break,
        }
    }

    tracing::info!(count = hosts.len(), "discovered GCP instances");
    Ok(hosts)
}

/// Obtain an access token from the metadata server or service account key.
async fn get_access_token() -> Result<String, CloudError> {
    // Try metadata server first (running on GCE)
    // Short timeout: metadata server should respond almost instantly when available
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| CloudError::AuthError(format!("failed to build HTTP client: {e}")))?;
    let metadata_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

    if let Ok(resp) = http
        .get(metadata_url)
        .header("Metadata-Flavor", "Google")
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(token) = body["access_token"].as_str() {
                    return Ok(token.to_string());
                }
            }
        }
    }

    // Fall back to `gcloud` CLI for access token (works with user and service account auth)
    let output = tokio::process::Command::new("gcloud")
        .args(["auth", "print-access-token"])
        .output()
        .await
        .map_err(|e| {
            CloudError::AuthError(format!(
                "metadata server unreachable and `gcloud` CLI not found: {e}. \
                 Install gcloud CLI or run from a GCE instance."
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CloudError::AuthError(format!(
            "gcloud auth print-access-token failed: {stderr}"
        )));
    }

    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if token.is_empty() {
        return Err(CloudError::AuthError(
            "gcloud auth print-access-token returned empty token".into(),
        ));
    }
    Ok(token)
}

// --- GCP REST API response types ---

#[derive(Deserialize)]
struct AggregatedListResponse {
    #[serde(default)]
    items: std::collections::HashMap<String, InstancesScopedList>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct InstancesScopedList {
    instances: Option<Vec<Instance>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Instance {
    name: String,
    status: Option<String>,
    zone: Option<String>,
    network_interfaces: Option<Vec<NetworkInterface>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkInterface {
    network_ip: Option<String>,
    access_configs: Option<Vec<AccessConfig>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccessConfig {
    nat_ip: Option<String>,
}
