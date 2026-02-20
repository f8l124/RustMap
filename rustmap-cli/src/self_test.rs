// ---------------------------------------------------------------------------
// Built-in self-test diagnostics (--self-test)
// ---------------------------------------------------------------------------
//
// Runs 6 diagnostic checks and prints PASS/FAIL/WARN for each.
// Returns exit code 1 if any check fails.

use anyhow::Result;

enum CheckResult {
    Pass(String),
    Warn(String),
    Fail(String),
}

/// Run all self-test diagnostics and exit.
pub fn run_self_test() -> Result<()> {
    eprintln!("RustMap Self-Test Diagnostics");
    eprintln!("============================\n");

    let checks = vec![
        ("Privilege Level", check_privilege()),
        ("Npcap/libpcap", check_pcap()),
        ("Raw Socket Access", check_raw_socket()),
        ("Interface Detection", check_interfaces()),
        ("DNS Resolution", check_dns()),
        ("Loopback Connectivity", check_loopback()),
        ("Scan Database", check_database()),
        ("GeoIP Database", check_geoip()),
    ];

    let mut has_fail = false;
    for (name, result) in &checks {
        match result {
            CheckResult::Pass(detail) => {
                eprintln!("  [PASS] {name}: {detail}");
            }
            CheckResult::Warn(detail) => {
                eprintln!("  [WARN] {name}: {detail}");
            }
            CheckResult::Fail(detail) => {
                eprintln!("  [FAIL] {name}: {detail}");
                has_fail = true;
            }
        }
    }

    eprintln!();
    if has_fail {
        eprintln!("Some checks failed. See above for details.");
        anyhow::bail!("self-test failed");
    } else {
        eprintln!("All checks passed.");
    }

    Ok(())
}

fn check_privilege() -> CheckResult {
    let level = rustmap_packet::check_privileges();
    if level.has_raw_socket_access() {
        CheckResult::Pass(format!("{level} (raw socket access available)"))
    } else {
        CheckResult::Warn(format!(
            "{level} (no raw socket access — SYN scan unavailable, use -sT)"
        ))
    }
}

fn check_pcap() -> CheckResult {
    #[cfg(windows)]
    {
        if rustmap_packet::npcap_installed() {
            CheckResult::Pass("Npcap detected".into())
        } else {
            CheckResult::Fail(
                "Npcap not found. Download from https://npcap.com/#download".into(),
            )
        }
    }
    #[cfg(not(windows))]
    {
        // On Linux/macOS, try listing interfaces as a proxy for libpcap presence
        match rustmap_packet::list_interfaces() {
            Ok(ifaces) if !ifaces.is_empty() => {
                CheckResult::Pass("libpcap available".into())
            }
            Ok(_) => CheckResult::Warn("libpcap available but no interfaces found".into()),
            Err(e) => CheckResult::Fail(format!("libpcap not available: {e}")),
        }
    }
}

fn check_raw_socket() -> CheckResult {
    let level = rustmap_packet::check_privileges();
    if level.has_raw_socket_access() {
        CheckResult::Pass("raw socket access available".into())
    } else {
        CheckResult::Warn(
            "no raw socket access — SYN/FIN/UDP scans unavailable (use -sT for connect scan)"
                .into(),
        )
    }
}

fn check_interfaces() -> CheckResult {
    match rustmap_packet::list_interfaces() {
        Ok(ifaces) if !ifaces.is_empty() => {
            let display: Vec<&str> = ifaces.iter().map(|s| s.as_str()).take(5).collect();
            let suffix = if ifaces.len() > 5 {
                format!(" ... and {} more", ifaces.len() - 5)
            } else {
                String::new()
            };
            CheckResult::Pass(format!("{}{suffix}", display.join(", ")))
        }
        Ok(_) => CheckResult::Fail("no interfaces detected".into()),
        Err(e) => CheckResult::Fail(format!("failed to list interfaces: {e}")),
    }
}

fn check_database() -> CheckResult {
    match rustmap_db::ScanStore::open_default() {
        Ok(_) => CheckResult::Pass("scan database accessible".into()),
        Err(e) => CheckResult::Warn(format!("scan database unavailable: {e}")),
    }
}

fn check_geoip() -> CheckResult {
    let custom_dir: Option<&std::path::Path> = None;
    match rustmap_geoip::find_geoip_dir(custom_dir) {
        Some(dir) => CheckResult::Pass(format!("GeoIP databases found at {}", dir.display())),
        None => CheckResult::Warn(
            "GeoIP databases not found (optional — install GeoLite2 MMDB files to ~/.rustmap/geoip/)"
                .into(),
        ),
    }
}

fn check_dns() -> CheckResult {
    use std::net::ToSocketAddrs;

    match "localhost:80".to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                CheckResult::Pass(format!("localhost resolves to {}", addr.ip()))
            } else {
                CheckResult::Fail("localhost resolved but returned no addresses".into())
            }
        }
        Err(e) => CheckResult::Fail(format!("DNS resolution failed: {e}")),
    }
}

fn check_loopback() -> CheckResult {
    use std::io::ErrorKind;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
    match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
        Ok(_) => CheckResult::Pass("127.0.0.1:80 reachable (connection succeeded)".into()),
        Err(e) => {
            // Use ErrorKind for reliable cross-locale error detection
            match e.kind() {
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => {
                    CheckResult::Pass(
                        "127.0.0.1:80 reachable (connection refused — loopback works)".into(),
                    )
                }
                ErrorKind::TimedOut => {
                    CheckResult::Warn("127.0.0.1:80 timed out (firewall may be blocking)".into())
                }
                _ => CheckResult::Warn(format!("127.0.0.1:80 error: {e}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privilege_returns_valid() {
        let result = check_privilege();
        match result {
            CheckResult::Pass(_) | CheckResult::Warn(_) => {}
            CheckResult::Fail(msg) => panic!("privilege check should not fail: {msg}"),
        }
    }

    #[test]
    fn dns_resolves_localhost() {
        let result = check_dns();
        match result {
            CheckResult::Pass(_) => {}
            CheckResult::Warn(msg) | CheckResult::Fail(msg) => {
                panic!("DNS should resolve localhost: {msg}");
            }
        }
    }

    #[test]
    fn loopback_reachable() {
        let result = check_loopback();
        match result {
            CheckResult::Pass(_) | CheckResult::Warn(_) => {}
            CheckResult::Fail(msg) => panic!("loopback should be reachable: {msg}"),
        }
    }
}
