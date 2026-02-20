use std::path::PathBuf;

/// Supported output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Normal,
    Xml,
    Json,
    Grepable,
    Yaml,
    Csv,
    /// CEF (Common Event Format) for ArcSight/Splunk.
    Cef,
    /// LEEF (Log Event Extended Format) for IBM QRadar.
    Leef,
    /// HTML report with charts and sortable tables.
    Html,
}

/// A single output destination: format + file path.
#[derive(Debug, Clone)]
pub struct OutputSpec {
    pub format: OutputFormat,
    pub path: PathBuf,
}

/// Configuration for output destinations and display options.
#[derive(Debug, Clone, Default)]
pub struct OutputConfig {
    /// File outputs (--oN, --oX, --oG, --oJ, --oA).
    pub outputs: Vec<OutputSpec>,
    /// Only show open ports (--open).
    pub open_only: bool,
    /// Show reason for port state (--reason).
    pub show_reason: bool,
    /// Print to stdout (always true unless all output goes to files).
    pub stdout: bool,
}

impl OutputConfig {
    /// Expand an `--oA <basename>` into four output specs.
    pub fn expand_all_formats(basename: &str) -> Vec<OutputSpec> {
        vec![
            OutputSpec {
                format: OutputFormat::Normal,
                path: PathBuf::from(format!("{basename}.nmap")),
            },
            OutputSpec {
                format: OutputFormat::Xml,
                path: PathBuf::from(format!("{basename}.xml")),
            },
            OutputSpec {
                format: OutputFormat::Grepable,
                path: PathBuf::from(format!("{basename}.gnmap")),
            },
            OutputSpec {
                format: OutputFormat::Json,
                path: PathBuf::from(format!("{basename}.json")),
            },
            OutputSpec {
                format: OutputFormat::Yaml,
                path: PathBuf::from(format!("{basename}.yaml")),
            },
            OutputSpec {
                format: OutputFormat::Csv,
                path: PathBuf::from(format!("{basename}.csv")),
            },
            OutputSpec {
                format: OutputFormat::Cef,
                path: PathBuf::from(format!("{basename}.cef")),
            },
            OutputSpec {
                format: OutputFormat::Leef,
                path: PathBuf::from(format!("{basename}.leef")),
            },
            OutputSpec {
                format: OutputFormat::Html,
                path: PathBuf::from(format!("{basename}.html")),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_all_formats_creates_nine_specs() {
        let specs = OutputConfig::expand_all_formats("scan_results");
        assert_eq!(specs.len(), 9);
        assert_eq!(specs[0].format, OutputFormat::Normal);
        assert_eq!(specs[0].path, PathBuf::from("scan_results.nmap"));
        assert_eq!(specs[1].format, OutputFormat::Xml);
        assert_eq!(specs[1].path, PathBuf::from("scan_results.xml"));
        assert_eq!(specs[2].format, OutputFormat::Grepable);
        assert_eq!(specs[2].path, PathBuf::from("scan_results.gnmap"));
        assert_eq!(specs[3].format, OutputFormat::Json);
        assert_eq!(specs[3].path, PathBuf::from("scan_results.json"));
        assert_eq!(specs[4].format, OutputFormat::Yaml);
        assert_eq!(specs[4].path, PathBuf::from("scan_results.yaml"));
        assert_eq!(specs[5].format, OutputFormat::Csv);
        assert_eq!(specs[5].path, PathBuf::from("scan_results.csv"));
        assert_eq!(specs[6].format, OutputFormat::Cef);
        assert_eq!(specs[6].path, PathBuf::from("scan_results.cef"));
        assert_eq!(specs[7].format, OutputFormat::Leef);
        assert_eq!(specs[7].path, PathBuf::from("scan_results.leef"));
        assert_eq!(specs[8].format, OutputFormat::Html);
        assert_eq!(specs[8].path, PathBuf::from("scan_results.html"));
    }

    #[test]
    fn default_config_has_no_outputs() {
        let config = OutputConfig::default();
        assert!(config.outputs.is_empty());
        assert!(!config.open_only);
        assert!(!config.show_reason);
        assert!(!config.stdout);
    }
}
