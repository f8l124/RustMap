use crate::{CloudDiscoveryOptions, CloudError};
use rustmap_types::Host;
use std::net::IpAddr;

/// Discover AWS EC2 instances and return them as scan targets.
pub async fn discover(opts: &CloudDiscoveryOptions) -> Result<Vec<Host>, CloudError> {
    let regions = if opts.regions.is_empty() {
        vec!["us-east-1".to_string()]
    } else {
        opts.regions.clone()
    };

    let mut hosts = Vec::new();

    for region_name in &regions {
        let region_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region_name.clone()))
            .load()
            .await;
        let client = aws_sdk_ec2::Client::new(&region_config);

        let mut request = client.describe_instances();

        // Filter by running state if requested
        if opts.running_only {
            request = request.filters(
                aws_sdk_ec2::types::Filter::builder()
                    .name("instance-state-name")
                    .values("running")
                    .build(),
            );
        }

        // Filter by tags
        for (key, value) in &opts.tags {
            request = request.filters(
                aws_sdk_ec2::types::Filter::builder()
                    .name(format!("tag:{key}"))
                    .values(value.as_str())
                    .build(),
            );
        }

        // Paginate through all results (default page size is 1000)
        let mut next_token: Option<String> = None;
        let mut region_count = 0usize;
        loop {
            let mut page_request = request.clone();
            if let Some(ref token) = next_token {
                page_request = page_request.next_token(token);
            }

            let response = page_request
                .send()
                .await
                .map_err(|e| CloudError::ApiError(format!("EC2 DescribeInstances failed: {e}")))?;

            for reservation in response.reservations() {
                for instance in reservation.instances() {
                    // Prefer public IP, fall back to private IP
                    let ip_str = instance
                        .public_ip_address()
                        .or(instance.private_ip_address());

                    if let Some(ip_str) = ip_str {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            let hostname = instance
                                .public_dns_name()
                                .or(instance.private_dns_name())
                                .filter(|s| !s.is_empty())
                                .map(String::from);
                            hosts.push(Host {
                                ip,
                                hostname,
                                geo_info: None,
                            });
                            region_count += 1;
                        }
                    }
                }
            }

            // Check for more pages
            match response.next_token() {
                Some(token) if !token.is_empty() => {
                    next_token = Some(token.to_string());
                }
                _ => break,
            }
        }

        tracing::info!(
            region = region_name,
            count = region_count,
            "discovered EC2 instances"
        );
    }

    Ok(hosts)
}
