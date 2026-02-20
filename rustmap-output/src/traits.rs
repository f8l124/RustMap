use rustmap_types::ScanResult;

/// Trait for formatting and emitting scan results.
pub trait OutputFormatter: Send + Sync {
    fn format(&self, result: &ScanResult) -> Result<String, OutputError>;
}

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("formatting error: {0}")]
    FormatError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
