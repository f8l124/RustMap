fn main() {
    // Embed git-derived version so the frontend can display it.
    // Format: "0.28.3" from tag "v0.28.3", or "0.28.3-dev.5" if 5 commits ahead.
    if let Ok(desc) = std::process::Command::new("git")
        .args(["describe", "--tags", "--match", "v*"])
        .output()
    {
        let raw = String::from_utf8_lossy(&desc.stdout).trim().to_string();
        if !raw.is_empty() {
            // "v0.28.3" → "0.28.3", "v0.28.3-5-gabcdef" → "0.28.3-dev.5"
            let stripped = raw.strip_prefix('v').unwrap_or(&raw);
            let version = if let Some((tag, rest)) = stripped.split_once('-') {
                // rest = "5-gabcdef"
                let commits = rest.split('-').next().unwrap_or("0");
                format!("{tag}-dev.{commits}")
            } else {
                stripped.to_string()
            };
            println!("cargo:rustc-env=RUSTMAP_VERSION={version}");
        }
    }

    tauri_build::build();
}
