use std::fmt;

/// Errors that can occur during script operations.
#[derive(Debug)]
pub enum ScriptError {
    /// Error during script discovery (finding/loading scripts).
    Discovery(String),
    /// Error from the Lua runtime.
    Lua(String),
    /// General script execution error (subprocess, Python, etc.).
    Execution(String),
    /// I/O error (reading script files, socket operations).
    Io(std::io::Error),
    /// Script execution timed out.
    Timeout,
    /// Script attempted a sandboxed operation.
    Sandbox(String),
    /// Error from the WASM runtime.
    #[cfg(feature = "wasm")]
    Wasm(String),
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(msg) => write!(f, "script discovery error: {msg}"),
            Self::Lua(msg) => write!(f, "lua error: {msg}"),
            Self::Execution(msg) => write!(f, "script execution error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Timeout => write!(f, "script execution timed out"),
            Self::Sandbox(msg) => write!(f, "sandbox violation: {msg}"),
            #[cfg(feature = "wasm")]
            Self::Wasm(msg) => write!(f, "wasm error: {msg}"),
        }
    }
}

impl std::error::Error for ScriptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ScriptError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_error_display() {
        let err = ScriptError::Discovery("not found".into());
        assert_eq!(err.to_string(), "script discovery error: not found");
    }

    #[test]
    fn lua_error_display() {
        let err = ScriptError::Lua("syntax error".into());
        assert_eq!(err.to_string(), "lua error: syntax error");
    }

    #[test]
    fn io_error_display() {
        let err = ScriptError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file missing",
        ));
        assert!(err.to_string().contains("file missing"));
    }

    #[test]
    fn timeout_error_display() {
        let err = ScriptError::Timeout;
        assert_eq!(err.to_string(), "script execution timed out");
    }

    #[test]
    fn sandbox_error_display() {
        let err = ScriptError::Sandbox("os.execute blocked".into());
        assert_eq!(err.to_string(), "sandbox violation: os.execute blocked");
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let script_err = ScriptError::from(io_err);
        assert!(matches!(script_err, ScriptError::Io(_)));
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn wasm_error_display() {
        let err = ScriptError::Wasm("module compilation failed".into());
        assert_eq!(err.to_string(), "wasm error: module compilation failed");
    }
}
