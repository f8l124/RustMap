use rustmap_types::Host;

mod error;
#[cfg(feature = "aws")]
pub mod aws;
#[cfg(feature = "azure")]
pub mod azure;
#[cfg(feature = "gcp")]
pub mod gcp;

pub use error::CloudError;

/// Options for cloud asset discovery.
#[derive(Debug, Clone)]
pub struct CloudDiscoveryOptions {
    /// Cloud provider name: "aws", "azure", "gcp".
    pub provider: String,
    /// Regions to enumerate (empty = all regions).
    pub regions: Vec<String>,
    /// Only include running instances.
    pub running_only: bool,
    /// Filter by tag (key=value pairs).
    pub tags: Vec<(String, String)>,
}

/// Discover cloud compute assets and return them as scan targets.
pub async fn discover_cloud_assets(
    opts: &CloudDiscoveryOptions,
) -> Result<Vec<Host>, CloudError> {
    match opts.provider.as_str() {
        #[cfg(feature = "aws")]
        "aws" => aws::discover(opts).await,
        #[cfg(feature = "azure")]
        "azure" => azure::discover(opts).await,
        #[cfg(feature = "gcp")]
        "gcp" => gcp::discover(opts).await,
        other => Err(CloudError::UnsupportedProvider(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsupported_provider_error() {
        let opts = CloudDiscoveryOptions {
            provider: "unknown".into(),
            regions: vec![],
            running_only: false,
            tags: vec![],
        };
        let err = discover_cloud_assets(&opts).await.unwrap_err();
        assert!(
            err.to_string().contains("unsupported cloud provider"),
            "expected unsupported provider error, got: {err}"
        );
    }

    #[test]
    fn cloud_options_default_construction() {
        let opts = CloudDiscoveryOptions {
            provider: "aws".into(),
            regions: vec!["us-east-1".into()],
            running_only: true,
            tags: vec![("env".into(), "prod".into())],
        };
        assert_eq!(opts.provider, "aws");
        assert!(opts.running_only);
        assert_eq!(opts.tags.len(), 1);
        assert_eq!(opts.tags[0], ("env".into(), "prod".into()));
    }
}
