use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    /// Full raw socket access (admin on Windows, root/CAP_NET_RAW on Linux).
    Full,
    /// No raw socket access — limited to connect()-based scans.
    Unprivileged,
}

impl PrivilegeLevel {
    pub fn has_raw_socket_access(&self) -> bool {
        matches!(self, PrivilegeLevel::Full)
    }
}

impl std::fmt::Display for PrivilegeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivilegeLevel::Full => write!(f, "privileged (raw socket access)"),
            PrivilegeLevel::Unprivileged => write!(f, "unprivileged (connect scan only)"),
        }
    }
}

/// Detect current privilege level for the running process.
pub fn check_privileges() -> PrivilegeLevel {
    #[cfg(windows)]
    {
        crate::privilege_windows::check()
    }
    #[cfg(target_os = "linux")]
    {
        crate::privilege_linux::check()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        PrivilegeLevel::Unprivileged
    }
}

/// Check whether the Npcap runtime is installed (Windows only).
#[cfg(windows)]
pub fn npcap_installed() -> bool {
    crate::privilege_windows::npcap_installed()
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("insufficient privileges for raw packet operations")]
    InsufficientPrivileges,
    #[error("packet send failed: {0}")]
    SendFailed(String),
    #[error("packet receive failed: {0}")]
    ReceiveFailed(String),
    #[error("packet construction failed: {0}")]
    BuildFailed(String),
    #[error("packet parse failed: {0}")]
    ParseFailed(String),
    #[error("capture setup failed: {0}")]
    CaptureSetup(String),
    #[error("capture stopped")]
    CaptureStopped,
    #[error("no suitable network interface found")]
    NoInterface,
    #[error("pcap/npcap not available: {0}")]
    PcapNotAvailable(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_privileges_returns_valid_level() {
        let level = check_privileges();
        // Should return one of the two valid levels without panicking
        let _ = level.has_raw_socket_access();
        let display = format!("{level}");
        assert!(!display.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn npcap_detection_returns_bool() {
        // Just exercises the function — won't break on CI without Npcap runtime
        let _installed = npcap_installed();
    }
}
