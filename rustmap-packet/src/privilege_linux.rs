use crate::privilege::PrivilegeLevel;

/// Check if the current process has raw socket capabilities on Linux.
///
/// Checks: (1) running as root (uid 0), or (2) has CAP_NET_RAW in the
/// effective capability set.
pub fn check() -> PrivilegeLevel {
    // Root always has full access
    if unsafe { libc::geteuid() } == 0 {
        return PrivilegeLevel::Full;
    }

    // Check for CAP_NET_RAW capability
    match caps::has_cap(None, caps::CapSet::Effective, caps::Capability::CAP_NET_RAW) {
        Ok(true) => PrivilegeLevel::Full,
        _ => PrivilegeLevel::Unprivileged,
    }
}
