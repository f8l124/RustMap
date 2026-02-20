use crate::{CloudDiscoveryOptions, CloudError};
use rustmap_types::Host;
use serde::Deserialize;
use std::net::IpAddr;

/// Discover Azure VM instances and return them as scan targets.
///
/// Authentication uses environment variables:
/// - `AZURE_TENANT_ID`
/// - `AZURE_CLIENT_ID`
/// - `AZURE_CLIENT_SECRET`
/// - `AZURE_SUBSCRIPTION_ID`
pub async fn discover(opts: &CloudDiscoveryOptions) -> Result<Vec<Host>, CloudError> {
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| CloudError::AuthError("AZURE_TENANT_ID not set".into()))?;
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| CloudError::AuthError("AZURE_CLIENT_ID not set".into()))?;
    // SECURITY: credential held in memory as plain String; consider wrapping
    // with the `secrecy` crate (Secret<String>) to prevent accidental logging.
    let client_secret = std::env::var("AZURE_CLIENT_SECRET")
        .map_err(|_| CloudError::AuthError("AZURE_CLIENT_SECRET not set".into()))?;
    let subscription_id = std::env::var("AZURE_SUBSCRIPTION_ID")
        .map_err(|_| CloudError::AuthError("AZURE_SUBSCRIPTION_ID not set".into()))?;

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| CloudError::ApiError(format!("failed to build HTTP client: {e}")))?;

    // Obtain OAuth2 token
    let token_url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    let token_resp = http
        .post(&token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "https://management.azure.com/.default"),
        ])
        .send()
        .await
        .map_err(|e| CloudError::AuthError(format!("token request failed: {e}")))?;

    let token_json: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| CloudError::AuthError(format!("token parse failed: {e}")))?;

    let access_token = token_json["access_token"]
        .as_str()
        .ok_or_else(|| CloudError::AuthError("no access_token in response".into()))?;

    // List VMs with instance view to get power state, with pagination
    let initial_url = format!(
        "https://management.azure.com/subscriptions/{subscription_id}\
         /providers/Microsoft.Compute/virtualMachines\
         ?api-version=2024-07-01&statusOnly=true"
    );

    let mut hosts = Vec::new();
    let mut next_url: Option<String> = Some(initial_url);

    while let Some(url) = next_url.take() {
        let vms_resp = http
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| CloudError::ApiError(format!("list VMs failed: {e}")))?;

        let vms: VmListResponse = vms_resp
            .json()
            .await
            .map_err(|e| CloudError::ApiError(format!("parse VMs failed: {e}")))?;

        for vm in &vms.value {
            // Filter by running state (check power state from instance view)
            if opts.running_only {
                let is_running = vm
                    .properties
                    .instance_view
                    .as_ref()
                    .and_then(|iv| iv.statuses.as_ref())
                    .map(|statuses| {
                        statuses
                            .iter()
                            .any(|s| s.code.as_deref() == Some("PowerState/running"))
                    })
                    .unwrap_or(false);
                if !is_running {
                    continue;
                }
            }

            // Filter by region if specified
            if !opts.regions.is_empty() {
                if let Some(ref location) = vm.location {
                    if !opts
                        .regions
                        .iter()
                        .any(|r| r.eq_ignore_ascii_case(location))
                    {
                        continue;
                    }
                }
            }

            // Filter by tags
            if !opts.tags.is_empty() {
                let matches = opts.tags.iter().all(|(key, value)| {
                    vm.tags
                        .as_ref()
                        .and_then(|t| t.get(key.as_str()))
                        .map(|v| v == value)
                        .unwrap_or(false)
                });
                if !matches {
                    continue;
                }
            }

            // Resolve NIC -> IP configuration
            if let Some(ref profile) = vm.properties.network_profile {
                for nic_ref in &profile.network_interfaces {
                    let nic_url = format!(
                        "https://management.azure.com{}?api-version=2024-01-01&$expand=ipConfigurations/publicIPAddress",
                        nic_ref.id
                    );
                    let vm_name = &vm.name;
                    match http.get(&nic_url).bearer_auth(access_token).send().await {
                        Ok(nic_resp) => {
                            match nic_resp.json::<NicResponse>().await {
                                Ok(nic) => {
                                    for ip_config in &nic.properties.ip_configurations {
                                        // Prefer public IP, fall back to private
                                        let public_ip = ip_config
                                            .properties
                                            .public_ip_address
                                            .as_ref()
                                            .and_then(|pip| pip.properties.as_ref())
                                            .and_then(|props| props.ip_address.as_deref());

                                        let ip_str = public_ip
                                            .or(ip_config.properties.private_ip_address.as_deref());

                                        if let Some(ip_str) = ip_str {
                                            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                                hosts.push(Host {
                                                    ip,
                                                    hostname: Some(vm.name.clone()),
                                                    geo_info: None,
                                                });
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(vm = %vm_name, error = %e, "failed to parse NIC response");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(vm = %vm_name, error = %e, "failed to fetch NIC details");
                        }
                    }
                }
            }
        }

        // Follow pagination link, or stop if no more pages
        next_url = vms.next_link.filter(|link| !link.is_empty());
    }

    tracing::info!(count = hosts.len(), "discovered Azure VMs");
    Ok(hosts)
}

// --- Azure REST API response types ---

#[derive(Deserialize)]
struct VmListResponse {
    #[serde(default)]
    value: Vec<VmResource>,
    #[serde(rename = "nextLink", default)]
    next_link: Option<String>,
}

#[derive(Deserialize)]
struct VmResource {
    name: String,
    location: Option<String>,
    #[serde(default)]
    tags: Option<std::collections::HashMap<String, String>>,
    properties: VmProperties,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VmProperties {
    network_profile: Option<NetworkProfile>,
    instance_view: Option<InstanceView>,
}

#[derive(Deserialize)]
struct InstanceView {
    statuses: Option<Vec<InstanceViewStatus>>,
}

#[derive(Deserialize)]
struct InstanceViewStatus {
    code: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkProfile {
    network_interfaces: Vec<NicReference>,
}

#[derive(Deserialize)]
struct NicReference {
    id: String,
}

#[derive(Deserialize)]
struct NicResponse {
    properties: NicProperties,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NicProperties {
    ip_configurations: Vec<IpConfiguration>,
}

#[derive(Deserialize)]
struct IpConfiguration {
    properties: IpConfigProperties,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpConfigProperties {
    private_ip_address: Option<String>,
    public_ip_address: Option<PublicIpRef>,
}

#[derive(Deserialize)]
struct PublicIpRef {
    properties: Option<PublicIpProperties>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicIpProperties {
    ip_address: Option<String>,
}
