use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::ArgMatches;
use clap::parser::ValueSource;
use serde::{Deserialize, Serialize};

use crate::args::Args;

/// A scan profile that can be serialized to/from TOML.
///
/// All fields are optional — `None` means "use the CLI default."
/// When applying a profile, only `Some` values are applied, and only
/// if the user did not explicitly provide that flag on the command line.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanProfile {
    /// Human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    // --- Port selection ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_ports: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast_mode: Option<bool>,

    // --- Scan type ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_type: Option<String>,

    // --- Timing ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_parallelism: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_rate: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rate: Option<f64>,

    // --- Detection ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_version: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_intensity: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_detection: Option<bool>,

    // --- Discovery ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_discovery: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_only: Option<bool>,

    // --- Scripts ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_scripts: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scripts: Option<String>,

    // --- Evasion ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub randomize_ports: Option<bool>,

    // --- Output preferences ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show_reason: Option<bool>,

    // --- Database ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_db: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predict_ports: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast_discovery: Option<bool>,

    // --- Host parallelism ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_hostgroup: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hostgroup: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_timeout_ms: Option<u64>,

    // --- Traceroute ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traceroute: Option<bool>,
}

// ---------------------------------------------------------------------------
// Built-in profiles
// ---------------------------------------------------------------------------

/// Names of built-in profiles that cannot be overwritten by users.
const BUILTIN_NAMES: &[&str] = &[
    "quick",
    "network-discovery",
    "web-audit",
    "full-audit",
    "stealth",
    "iot-scan",
    "aggressive",
];

fn builtin_profiles() -> Vec<(&'static str, ScanProfile)> {
    vec![
        (
            "quick",
            ScanProfile {
                description: Some("Fast scan of top 100 ports".into()),
                fast_mode: Some(true),
                timing: Some(4),
                ..Default::default()
            },
        ),
        (
            "network-discovery",
            ScanProfile {
                description: Some("Host discovery + top 100 ports, fast timing".into()),
                fast_mode: Some(true),
                timing: Some(4),
                service_version: Some(false),
                ..Default::default()
            },
        ),
        (
            "web-audit",
            ScanProfile {
                description: Some(
                    "Web server audit: HTTP/HTTPS ports with version detection and scripts".into(),
                ),
                ports: Some("80,443,8080,8443,8000,3000,5000".into()),
                service_version: Some(true),
                default_scripts: Some(true),
                show_reason: Some(true),
                ..Default::default()
            },
        ),
        (
            "full-audit",
            ScanProfile {
                description: Some(
                    "Comprehensive audit: all 65535 ports, service+OS detection, scripts".into(),
                ),
                ports: Some("1-65535".into()),
                service_version: Some(true),
                os_detection: Some(true),
                default_scripts: Some(true),
                timing: Some(4),
                show_reason: Some(true),
                diff: Some(true),
                ..Default::default()
            },
        ),
        (
            "stealth",
            ScanProfile {
                description: Some(
                    "Low-and-slow stealth scan: slow timing, randomized ports, evasion".into(),
                ),
                timing: Some(1),
                randomize_ports: Some(true),
                source_port: Some(53),
                fragment: Some(true),
                max_hostgroup: Some(1),
                ..Default::default()
            },
        ),
        (
            "iot-scan",
            ScanProfile {
                description: Some("IoT device scan: common IoT ports with version detection".into()),
                ports: Some("22,23,80,443,554,1883,5683,8080,8443,8883,9100,49152".into()),
                service_version: Some(true),
                version_intensity: Some(5),
                ..Default::default()
            },
        ),
        (
            "aggressive",
            ScanProfile {
                description: Some(
                    "Aggressive scan: OS + version detection + scripts + traceroute".into(),
                ),
                service_version: Some(true),
                os_detection: Some(true),
                default_scripts: Some(true),
                timing: Some(4),
                traceroute: Some(true),
                ..Default::default()
            },
        ),
    ]
}

// ---------------------------------------------------------------------------
// Profile directory
// ---------------------------------------------------------------------------

fn profiles_dir() -> PathBuf {
    if cfg!(windows) {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(appdata).join("rustmap").join("profiles")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".rustmap").join("profiles")
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that a profile name is safe (no path traversal).
fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!(
            "invalid profile name: {name:?} (only alphanumeric, hyphens, underscores, and dots allowed)"
        );
    }
    if name.contains("..") {
        bail!("invalid profile name: {name:?} (contains '..')");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load a profile by name. Checks built-in profiles first, then user TOML files.
pub fn load_profile(name: &str) -> Result<ScanProfile> {
    validate_profile_name(name)?;

    // Check built-in profiles
    for (builtin_name, profile) in builtin_profiles() {
        if builtin_name == name {
            return Ok(profile);
        }
    }

    // Check user profiles
    let path = profiles_dir().join(format!("{name}.toml"));
    if path.exists() {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read profile '{}'", path.display()))?;
        let profile: ScanProfile = toml::from_str(&content)
            .with_context(|| format!("failed to parse profile '{}'", path.display()))?;
        return Ok(profile);
    }

    bail!(
        "unknown profile '{name}'. Use --list-profiles to see available profiles."
    );
}

/// Save the current CLI arguments as a named user profile.
pub fn save_profile(name: &str, profile: &ScanProfile) -> Result<()> {
    validate_profile_name(name)?;

    if BUILTIN_NAMES.contains(&name) {
        bail!("cannot overwrite built-in profile '{name}'");
    }

    let dir = profiles_dir();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create profiles directory: {}", dir.display()))?;

    let path = dir.join(format!("{name}.toml"));
    let content = toml::to_string_pretty(profile)
        .context("failed to serialize profile to TOML")?;
    std::fs::write(&path, content)
        .with_context(|| format!("failed to write profile to {}", path.display()))?;

    Ok(())
}

/// List all available profiles: built-in + user-defined.
/// Returns (name, profile, is_builtin) tuples.
pub fn list_all_profiles() -> Result<Vec<(String, ScanProfile, bool)>> {
    let mut profiles = Vec::new();

    // Built-in profiles
    for (name, profile) in builtin_profiles() {
        profiles.push((name.to_string(), profile, true));
    }

    // User profiles
    let dir = profiles_dir();
    if dir.exists()
        && let Ok(entries) = std::fs::read_dir(&dir)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "toml") {
                let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                // Skip if it shadows a built-in
                if BUILTIN_NAMES.contains(&name.as_str()) {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&path)
                    && let Ok(profile) = toml::from_str::<ScanProfile>(&content)
                {
                    profiles.push((name, profile, false));
                }
            }
        }
    }

    Ok(profiles)
}

/// Print formatted profile list to stdout.
pub fn show_profiles() -> Result<()> {
    let profiles = list_all_profiles()?;

    println!("Available scan profiles:\n");
    for (name, profile, is_builtin) in &profiles {
        let tag = if *is_builtin { "[built-in]" } else { "[user]" };
        let desc = profile
            .description
            .as_deref()
            .unwrap_or("(no description)");
        println!("  {name:<20} {tag:<12} {desc}");
    }

    println!(
        "\nUsage: rustmap --profile <NAME> <TARGET>\n\
         Save:  rustmap --save-profile <NAME> [options] <TARGET>"
    );

    Ok(())
}

/// Apply a profile's settings to an `Args` struct.
///
/// Only applies fields where the profile has a `Some` value AND the user
/// did not explicitly provide that flag on the command line.
pub fn apply_profile_with_matches(
    profile: &ScanProfile,
    args: &mut Args,
    matches: &ArgMatches,
) {
    // Helper: returns true if the user did NOT explicitly set this flag.
    let not_set = |id: &str| -> bool {
        matches
            .value_source(id)
            .is_none_or(|s| s != ValueSource::CommandLine)
    };

    // Port selection
    if let Some(ref v) = profile.ports
        && not_set("ports")
    {
        args.ports = Some(v.clone());
    }
    if let Some(v) = profile.top_ports
        && not_set("top_ports")
    {
        args.top_ports = Some(v);
    }
    if let Some(v) = profile.fast_mode
        && not_set("fast_mode")
    {
        args.fast_mode = v;
    }

    // Scan type
    if let Some(ref v) = profile.scan_type
        && not_set("scan_type")
    {
        args.scan_type = Some(v.clone());
    }

    // Timing
    if let Some(v) = profile.timing
        && not_set("timing")
    {
        args.timing = Some(v);
    }
    if let Some(v) = profile.timeout_ms
        && not_set("timeout_ms")
    {
        args.timeout_ms = Some(v);
    }
    if let Some(v) = profile.max_parallelism
        && not_set("concurrency")
    {
        args.concurrency = Some(v);
    }
    if let Some(v) = profile.min_rate
        && not_set("min_rate")
    {
        args.min_rate = Some(v);
    }
    if let Some(v) = profile.max_rate
        && not_set("max_rate")
    {
        args.max_rate = Some(v);
    }

    // Detection
    if let Some(v) = profile.service_version
        && not_set("service_version")
    {
        args.service_version = v;
    }
    if let Some(v) = profile.version_intensity
        && not_set("version_intensity")
    {
        args.version_intensity = v;
    }
    if let Some(v) = profile.os_detection
        && not_set("os_detection")
    {
        args.os_detection = v;
    }

    // Discovery
    if let Some(v) = profile.skip_discovery
        && not_set("skip_discovery")
    {
        args.skip_discovery = v;
    }
    if let Some(v) = profile.ping_only
        && not_set("ping_only")
    {
        args.ping_only = v;
    }

    // Scripts
    if let Some(v) = profile.default_scripts
        && not_set("default_scripts")
    {
        args.default_scripts = v;
    }
    if let Some(ref v) = profile.scripts
        && not_set("script")
    {
        args.script = Some(v.clone());
    }

    // Evasion
    if let Some(v) = profile.source_port
        && not_set("source_port")
    {
        args.source_port = Some(v);
    }
    if let Some(v) = profile.fragment
        && not_set("fragment")
    {
        args.fragment = v;
    }
    if let Some(v) = profile.randomize_ports
        && not_set("randomize_ports")
    {
        args.randomize_ports = v;
    }

    // Output preferences
    if let Some(v) = profile.open_only
        && not_set("open_only")
    {
        args.open_only = v;
    }
    if let Some(v) = profile.show_reason
        && not_set("show_reason")
    {
        args.show_reason = v;
    }

    // Database
    if let Some(v) = profile.no_db
        && not_set("no_db")
    {
        args.no_db = v;
    }
    if let Some(v) = profile.diff
        && not_set("diff")
    {
        args.diff = v;
    }
    if let Some(v) = profile.predict_ports
        && not_set("predict_ports")
    {
        args.predict_ports = v;
    }
    if let Some(v) = profile.fast_discovery
        && not_set("fast_discovery")
    {
        args.fast_discovery = v;
    }

    // Host parallelism
    if let Some(v) = profile.min_hostgroup
        && not_set("min_hostgroup")
    {
        args.min_hostgroup = v;
    }
    if let Some(v) = profile.max_hostgroup
        && not_set("max_hostgroup")
    {
        args.max_hostgroup = v;
    }
    if let Some(v) = profile.host_timeout_ms
        && not_set("host_timeout_ms")
    {
        args.host_timeout_ms = v;
    }

    // Traceroute
    if let Some(v) = profile.traceroute
        && not_set("traceroute")
    {
        args.traceroute = v;
    }
}

/// Convert current CLI args to a `ScanProfile` (for `--save-profile`).
pub fn args_to_profile(args: &Args) -> ScanProfile {
    ScanProfile {
        description: None,
        ports: args.ports.clone(),
        top_ports: args.top_ports,
        fast_mode: Some(args.fast_mode),
        scan_type: args.scan_type.clone(),
        timing: args.timing,
        timeout_ms: args.timeout_ms,
        max_parallelism: args.concurrency,
        min_rate: args.min_rate,
        max_rate: args.max_rate,
        service_version: Some(args.service_version),
        version_intensity: if args.version_intensity != 7 {
            Some(args.version_intensity)
        } else {
            None
        },
        os_detection: Some(args.os_detection),
        skip_discovery: Some(args.skip_discovery),
        ping_only: Some(args.ping_only),
        default_scripts: Some(args.default_scripts),
        scripts: args.script.clone(),
        source_port: args.source_port,
        fragment: Some(args.fragment),
        randomize_ports: Some(args.randomize_ports),
        open_only: Some(args.open_only),
        show_reason: Some(args.show_reason),
        no_db: Some(args.no_db),
        diff: Some(args.diff),
        predict_ports: Some(args.predict_ports),
        fast_discovery: Some(args.fast_discovery),
        min_hostgroup: if args.min_hostgroup != 1 {
            Some(args.min_hostgroup)
        } else {
            None
        },
        max_hostgroup: if args.max_hostgroup != crate::args::DEFAULT_MAX_HOSTGROUP {
            Some(args.max_hostgroup)
        } else {
            None
        },
        host_timeout_ms: if args.host_timeout_ms != 0 {
            Some(args.host_timeout_ms)
        } else {
            None
        },
        traceroute: Some(args.traceroute),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    #[test]
    fn builtin_profiles_all_valid() {
        let profiles = builtin_profiles();
        assert_eq!(profiles.len(), BUILTIN_NAMES.len());
        for (name, profile) in &profiles {
            assert!(
                BUILTIN_NAMES.contains(name),
                "profile '{name}' not in BUILTIN_NAMES"
            );
            assert!(
                profile.description.is_some(),
                "profile '{name}' missing description"
            );
        }
    }

    #[test]
    fn load_builtin_by_name() {
        let profile = load_profile("web-audit").unwrap();
        assert_eq!(
            profile.ports.as_deref(),
            Some("80,443,8080,8443,8000,3000,5000")
        );
        assert_eq!(profile.service_version, Some(true));
        assert_eq!(profile.default_scripts, Some(true));
    }

    #[test]
    fn load_unknown_returns_error() {
        let result = load_profile("nonexistent-profile-xyz");
        assert!(result.is_err());
    }

    #[test]
    fn cannot_overwrite_builtin() {
        let profile = ScanProfile::default();
        let result = save_profile("quick", &profile);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("cannot overwrite built-in")
        );
    }

    #[test]
    fn save_and_load_user_profile() {
        let dir = std::env::temp_dir().join("rustmap_test_profiles");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("test-profile.toml");
        let profile = ScanProfile {
            description: Some("Test profile".into()),
            ports: Some("22,80,443".into()),
            timing: Some(3),
            service_version: Some(true),
            ..Default::default()
        };

        let content = toml::to_string_pretty(&profile).unwrap();
        std::fs::write(&path, &content).unwrap();

        let loaded: ScanProfile =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.ports.as_deref(), Some("22,80,443"));
        assert_eq!(loaded.timing, Some(3));
        assert_eq!(loaded.service_version, Some(true));
        assert!(loaded.os_detection.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_includes_builtins() {
        let profiles = list_all_profiles().unwrap();
        let names: Vec<&str> = profiles.iter().map(|(n, _, _)| n.as_str()).collect();
        for builtin in BUILTIN_NAMES {
            assert!(names.contains(builtin), "missing built-in: {builtin}");
        }
    }

    #[test]
    fn profile_toml_roundtrip() {
        let profile = ScanProfile {
            description: Some("Roundtrip test".into()),
            ports: Some("1-1000".into()),
            timing: Some(2),
            source_port: Some(53),
            fragment: Some(true),
            max_hostgroup: Some(4),
            ..Default::default()
        };

        let toml_str = toml::to_string_pretty(&profile).unwrap();
        let loaded: ScanProfile = toml::from_str(&toml_str).unwrap();

        assert_eq!(loaded.description.as_deref(), Some("Roundtrip test"));
        assert_eq!(loaded.ports.as_deref(), Some("1-1000"));
        assert_eq!(loaded.timing, Some(2));
        assert_eq!(loaded.source_port, Some(53));
        assert_eq!(loaded.fragment, Some(true));
        assert_eq!(loaded.max_hostgroup, Some(4));
        // Unset fields stay None
        assert!(loaded.scan_type.is_none());
        assert!(loaded.os_detection.is_none());
    }

    #[test]
    fn web_audit_has_expected_ports() {
        let profile = load_profile("web-audit").unwrap();
        let ports = profile.ports.unwrap();
        assert!(ports.contains("80"));
        assert!(ports.contains("443"));
        assert!(ports.contains("8080"));
        assert!(ports.contains("8443"));
    }

    #[test]
    fn apply_sets_unset_values() {
        let profile = ScanProfile {
            timing: Some(4),
            service_version: Some(true),
            show_reason: Some(true),
            ..Default::default()
        };

        // Build args with no explicit overrides (simulate default parse)
        let matches = Args::command().get_matches_from(["rustmap", "10.0.0.1"]);
        let mut args = Args::from_arg_matches(&matches).unwrap();

        apply_profile_with_matches(&profile, &mut args, &matches);

        assert_eq!(args.timing, Some(4));
        assert!(args.service_version);
        assert!(args.show_reason);
    }

    #[test]
    fn apply_does_not_override_explicit() {
        let profile = ScanProfile {
            timing: Some(4),
            ports: Some("80,443".into()),
            ..Default::default()
        };

        // User explicitly sets -T2 and -p 22
        let matches =
            Args::command().get_matches_from(["rustmap", "-T", "2", "-p", "22", "10.0.0.1"]);
        let mut args = Args::from_arg_matches(&matches).unwrap();

        apply_profile_with_matches(&profile, &mut args, &matches);

        // Explicit values should NOT be overridden
        assert_eq!(args.timing, Some(2));
        assert_eq!(args.ports.as_deref(), Some("22"));
    }

    #[test]
    fn args_to_profile_captures_settings() {
        let matches = Args::command().get_matches_from([
            "rustmap",
            "-p",
            "22,80",
            "-T",
            "4",
            "--sV",
            "--traceroute",
            "10.0.0.1",
        ]);
        let args = Args::from_arg_matches(&matches).unwrap();
        let profile = args_to_profile(&args);

        assert_eq!(profile.ports.as_deref(), Some("22,80"));
        assert_eq!(profile.timing, Some(4));
        assert_eq!(profile.service_version, Some(true));
        assert_eq!(profile.traceroute, Some(true));
        // Disabled booleans should be Some(false)
        assert_eq!(profile.os_detection, Some(false));
        assert_eq!(profile.fast_mode, Some(false));
    }
}
