//! Npcap first-run setup for Windows.
//!
//! On Windows, RustMap requires the Npcap runtime for raw packet capture.
//! This module detects whether Npcap is installed and offers to download
//! and run the installer if it is missing.

use std::io::Write;
use std::path::Path;

/// Npcap download page (always works, user picks version).
const NPCAP_DOWNLOAD_PAGE: &str = "https://npcap.com/#download";

/// Direct installer URL (may require EULA click-through — we verify the
/// downloaded file size to detect HTML error pages).
const NPCAP_INSTALLER_URL: &str = "https://npcap.com/dist/npcap-1.80.exe";

/// Minimum expected installer size (the real installer is several MB).
const MIN_INSTALLER_BYTES: u64 = 1_000_000;

/// Ensure Npcap is available. If missing, interactively prompt the user to
/// install it. Returns `Ok(())` when Npcap is ready, or `Err` with a
/// user-facing message if the user declined or installation failed.
pub fn ensure_npcap() -> Result<(), String> {
    if rustmap_packet::npcap_installed() {
        return Ok(());
    }

    eprintln!();
    eprintln!("  Npcap is not installed.");
    eprintln!("  RustMap requires Npcap for raw packet capture on Windows.");
    eprintln!("  Npcap is free for personal use (up to 5 systems).");
    eprintln!();

    // If stdin is not a terminal (piped), skip the interactive prompt
    if !atty_stdin() {
        return Err(
            "Npcap is not installed. Install from https://npcap.com/#download\n\
             or use -sT for TCP Connect scan (no Npcap needed)."
                .into(),
        );
    }

    eprint!("  Download and install Npcap now? [Y/n] ");
    std::io::stderr().flush().ok();

    let mut response = String::new();
    if std::io::stdin().read_line(&mut response).is_err() {
        return Err("Failed to read input.".into());
    }

    let response = response.trim().to_lowercase();
    if response == "n" || response == "no" {
        return Err("Npcap is required for raw packet scans.\n\
             Download: https://npcap.com/#download\n\
             Or use -sT for TCP Connect scan (no Npcap needed)."
            .into());
    }

    // Try direct download first, fall back to opening browser
    let temp_dir = std::env::temp_dir();
    let installer_path = temp_dir.join("npcap-installer.exe");

    eprintln!("  Downloading Npcap installer...");
    match download_installer(&installer_path) {
        Ok(()) => run_installer(&installer_path),
        Err(e) => {
            eprintln!("  Download failed: {e}");
            eprintln!("  Opening Npcap download page in your browser...");
            open_browser(NPCAP_DOWNLOAD_PAGE);
            eprintln!();
            eprintln!("  Please install Npcap from the download page, then re-run RustMap.");
            Err("Npcap installation required.".into())
        }
    }
}

/// Run the downloaded Npcap installer and verify the result.
fn run_installer(installer_path: &Path) -> Result<(), String> {
    eprintln!("  Launching Npcap installer — please complete the setup wizard.");
    eprintln!();

    let status = std::process::Command::new(installer_path).status();

    // Clean up installer regardless of outcome
    let _ = std::fs::remove_file(installer_path);

    match status {
        Ok(s) if s.success() => {
            if rustmap_packet::npcap_installed() {
                eprintln!("  Npcap installed successfully!");
                eprintln!();
                Ok(())
            } else {
                Err("Npcap installer finished but wpcap.dll was not found.\n\
                     Please try reinstalling from https://npcap.com/#download"
                    .into())
            }
        }
        Ok(s) => {
            let code = s.code().map(|c| c.to_string()).unwrap_or("unknown".into());
            Err(format!(
                "Npcap installer exited with code {code}.\n\
                 You can install manually from https://npcap.com/#download"
            ))
        }
        Err(e) => Err(format!(
            "Failed to launch installer: {e}\n\
             You can install manually from https://npcap.com/#download"
        )),
    }
}

/// Download the Npcap installer via PowerShell.
fn download_installer(dest: &Path) -> Result<(), String> {
    let dest_str = dest.to_string_lossy();
    let ps_cmd = format!(
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
         Invoke-WebRequest -Uri '{NPCAP_INSTALLER_URL}' -OutFile '{dest_str}'"
    );

    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &ps_cmd,
        ])
        .status()
        .map_err(|e| format!("could not run PowerShell: {e}"))?;

    if !status.success() {
        return Err("PowerShell download command failed".into());
    }

    // Verify the file exists and is large enough to be a real installer
    // (a small file likely means we got an HTML error/redirect page)
    match std::fs::metadata(dest) {
        Ok(m) if m.len() >= MIN_INSTALLER_BYTES => Ok(()),
        Ok(m) => {
            let _ = std::fs::remove_file(dest);
            Err(format!(
                "downloaded file is only {} bytes (expected >1 MB) — \
                 the download URL may require manual EULA acceptance",
                m.len()
            ))
        }
        Err(e) => Err(format!("downloaded file not found: {e}")),
    }
}

/// Open a URL in the default browser.
fn open_browser(url: &str) {
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
}

/// Check whether stdin is connected to a terminal (console).
fn atty_stdin() -> bool {
    use std::os::windows::io::AsRawHandle;

    unsafe extern "system" {
        fn GetFileType(hFile: isize) -> u32;
    }

    let handle = std::io::stdin().as_raw_handle();
    // GetFileType returns FILE_TYPE_CHAR (0x0002) for console handles
    let file_type = unsafe { GetFileType(handle as isize) };
    file_type == 2
}
