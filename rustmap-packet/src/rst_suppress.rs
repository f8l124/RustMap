use std::net::IpAddr;

use tracing::debug;
#[cfg(unix)]
use tracing::warn;

/// RAII guard that suppresses outgoing RST packets during SYN scan.
///
/// On Linux: adds an iptables rule to DROP outgoing RST packets from our source IP,
/// preventing the kernel from sending RSTs in response to SYN/ACKs (since we never
/// completed the handshake). Removed automatically on drop.
///
/// On Windows: no-op. Npcap captures at the NDIS driver level, so the kernel's
/// RST doesn't interfere with our capture.
pub struct RstSuppressGuard {
    #[cfg(unix)]
    src_ip: IpAddr,
    #[cfg(unix)]
    active: bool,
}

impl RstSuppressGuard {
    /// Create and activate RST suppression.
    pub fn activate(src_ip: IpAddr) -> Self {
        #[cfg(unix)]
        {
            let active = add_iptables_rule(src_ip);
            if active {
                debug!(src_ip = %src_ip, "RST suppression activated");
            } else {
                warn!("failed to activate RST suppression — scan may produce extra traffic");
            }
            Self { src_ip, active }
        }
        #[cfg(windows)]
        {
            let _ = src_ip;
            debug!("RST suppression not needed on Windows (Npcap driver-level capture)");
            Self {}
        }
    }

    /// Check if suppression is actually active.
    pub fn is_active(&self) -> bool {
        #[cfg(unix)]
        {
            self.active
        }
        #[cfg(windows)]
        {
            true // Always "active" (no-op) on Windows
        }
    }
}

impl Drop for RstSuppressGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if self.active {
                remove_iptables_rule(self.src_ip);
                debug!(src_ip = %self.src_ip, "RST suppression removed");
            }
        }
    }
}

#[cfg(unix)]
fn iptables_cmd(src_ip: IpAddr) -> &'static str {
    if src_ip.is_ipv6() {
        "ip6tables"
    } else {
        "iptables"
    }
}

#[cfg(unix)]
fn add_iptables_rule(src_ip: IpAddr) -> bool {
    let ip_str = src_ip.to_string();
    let cmd = iptables_cmd(src_ip);
    let result = std::process::Command::new(cmd)
        .args([
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "-s",
            &ip_str,
            "-j",
            "DROP",
        ])
        .output();

    match result {
        Ok(output) => output.status.success(),
        Err(e) => {
            warn!(error = %e, "{cmd} command failed");
            false
        }
    }
}

#[cfg(unix)]
fn remove_iptables_rule(src_ip: IpAddr) {
    let ip_str = src_ip.to_string();
    let cmd = iptables_cmd(src_ip);
    let result = std::process::Command::new(cmd)
        .args([
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "-s",
            &ip_str,
            "-j",
            "DROP",
        ])
        .output();

    match result {
        Ok(output) if !output.status.success() => {
            warn!(
                %src_ip,
                "failed to remove RST suppression iptables rule — \
                 manual cleanup may be needed: {cmd} -D OUTPUT -p tcp --tcp-flags RST RST -s {} -j DROP",
                ip_str
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                %src_ip,
                "{cmd} command not found during RST suppression cleanup"
            );
        }
        _ => {}
    }
}
