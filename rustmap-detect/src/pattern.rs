use regex::Regex;
use rustmap_types::{DetectionMethod, ServiceInfo};

/// A match pattern for service detection.
///
/// Each pattern has a compiled regex and extraction rules for product,
/// version, and info fields via capture group indices.
pub struct MatchPattern {
    regex: Regex,
    service: &'static str,
    product_group: Option<usize>,
    version_group: Option<usize>,
    info_group: Option<usize>,
    /// Static product name (used when product isn't in a capture group).
    product_literal: Option<&'static str>,
}

impl MatchPattern {
    /// Create a new match pattern.
    ///
    /// - `pattern`: regex pattern string
    /// - `service`: service name to assign on match (e.g., "ssh")
    /// - `product_group`: capture group index for product name
    /// - `version_group`: capture group index for version string
    /// - `info_group`: capture group index for extra info
    /// - `product_literal`: static product name (overrides product_group)
    pub fn new(
        pattern: &str,
        service: &'static str,
        product_group: Option<usize>,
        version_group: Option<usize>,
        info_group: Option<usize>,
        product_literal: Option<&'static str>,
    ) -> Result<Self, regex::Error> {
        let regex = Regex::new(pattern)?;
        Ok(Self {
            regex,
            service,
            product_group,
            version_group,
            info_group,
            product_literal,
        })
    }

    /// Try to match this pattern against banner/response data.
    ///
    /// Returns a populated `ServiceInfo` if the pattern matches.
    pub fn try_match(&self, data: &[u8], method: DetectionMethod) -> Option<ServiceInfo> {
        let text = String::from_utf8_lossy(data);
        let captures = self.regex.captures(&text)?;

        let product = self.product_literal.map(|s| s.to_string()).or_else(|| {
            self.product_group
                .and_then(|idx| captures.get(idx))
                .map(|m| m.as_str().trim().to_string())
        });

        let version = self
            .version_group
            .and_then(|idx| captures.get(idx))
            .map(|m| m.as_str().trim().to_string());

        let info = self
            .info_group
            .and_then(|idx| captures.get(idx))
            .map(|m| m.as_str().trim().to_string());

        Some(ServiceInfo {
            name: self.service.to_string(),
            product,
            version,
            info,
            method,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_openssh_banner() {
        let pattern = MatchPattern::new(
            r"SSH-([\d.]+)-OpenSSH[_-]([\w.p]+)",
            "ssh",
            None,
            Some(2),
            Some(1),
            Some("OpenSSH"),
        )
        .unwrap();

        let banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        let result = pattern.try_match(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "ssh");
        assert_eq!(result.product.as_deref(), Some("OpenSSH"));
        assert_eq!(result.version.as_deref(), Some("8.9p1"));
        assert_eq!(result.info.as_deref(), Some("2.0"));
        assert_eq!(result.method, DetectionMethod::Banner);
    }

    #[test]
    fn match_generic_ssh_banner() {
        let pattern = MatchPattern::new(
            r"SSH-([\d.]+)-(.+?)[\r\n]",
            "ssh",
            Some(2),
            Some(1),
            None,
            None,
        )
        .unwrap();

        let banner = b"SSH-2.0-Dropbear_2022.83\r\n";
        let result = pattern.try_match(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "ssh");
        assert_eq!(result.product.as_deref(), Some("Dropbear_2022.83"));
        assert_eq!(result.version.as_deref(), Some("2.0"));
    }

    #[test]
    fn match_ftp_banner() {
        let pattern = MatchPattern::new(
            r"220[- ].*?(\w+FTP\w*)[/ ]([\d.]+)",
            "ftp",
            Some(1),
            Some(2),
            None,
            None,
        )
        .unwrap();

        let banner = b"220 ProFTPD 1.3.5 Server ready.\r\n";
        let result = pattern.try_match(banner, DetectionMethod::Banner).unwrap();

        assert_eq!(result.name, "ftp");
        assert_eq!(result.product.as_deref(), Some("ProFTPD"));
        assert_eq!(result.version.as_deref(), Some("1.3.5"));
    }

    #[test]
    fn no_match_returns_none() {
        let pattern =
            MatchPattern::new(r"SSH-([\d.]+)-", "ssh", None, Some(1), None, None).unwrap();

        let banner = b"HTTP/1.1 200 OK\r\n";
        let result = pattern.try_match(banner, DetectionMethod::Banner);

        assert!(result.is_none());
    }
}
