#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("unsupported cloud provider: {0}")]
    UnsupportedProvider(String),
    #[error("cloud API error: {0}")]
    ApiError(String),
    #[error("authentication error: {0}")]
    AuthError(String),
    #[error("no instances found")]
    NoInstances,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
