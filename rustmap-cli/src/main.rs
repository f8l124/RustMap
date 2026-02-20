mod args;
mod profiles;
mod self_test;
#[cfg(feature = "tui")]
mod tui;
mod watch;

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, FromArgMatches};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use args::Args;
use rustmap_core::{ScanEngine, parse_targets_with_dns};
use rustmap_output::{OutputConfig, OutputFormat, OutputManager, OutputSpec, filter_open_ports};
use rustmap_packet::check_privileges;
use rustmap_script::{ScriptDiscovery, ScriptRunner};
use rustmap_types::{
    DEFAULT_TOP_PORTS, DiscoveryConfig, DiscoveryMethod, DiscoveryMode, DnsConfig,
    FAST_MODE_TOP_PORTS, PortRange, ScanConfig, ScanType, ScriptConfig, TimingTemplate,
    top_tcp_ports,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse args using get_matches() so we can access ArgMatches for profile merging
    let matches = Args::command().get_matches();
    let mut args = Args::from_arg_matches(&matches).map_err(|e| anyhow::anyhow!(e))?;

    // Handle --list-profiles: show available profiles and exit (before tracing init)
    if args.list_profiles {
        return profiles::show_profiles();
    }

    // Handle --save-profile: save current args as a profile and exit
    if let Some(ref name) = args.save_profile {
        let profile = profiles::args_to_profile(&args);
        profiles::save_profile(name, &profile)?;
        println!("Profile '{}' saved.", name);
        return Ok(());
    }

    // Apply scan profile if specified (before -A expansion so profile + -A works)
    if let Some(ref profile_name) = args.profile.clone() {
        let profile = profiles::load_profile(profile_name)
            .with_context(|| format!("failed to load profile '{profile_name}'"))?;
        profiles::apply_profile_with_matches(&profile, &mut args, &matches);
    }

    // -A: aggressive mode enables OS detection, version detection, and default scripts
    if args.aggressive {
        args.os_detection = true;
        args.service_version = true;
        if !args.default_scripts && args.script.is_none() {
            args.default_scripts = true;
        }
    }

    // Initialize tracing based on verbosity
    let filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();

    if args.profile.is_some() {
        info!(
            profile = args.profile.as_deref().unwrap(),
            "applied scan profile"
        );
    }

    // Handle --history: list scan history and exit
    if args.history {
        return show_history();
    }

    // Handle --vuln-update: update CVE database and exit
    if args.vuln_update {
        return update_vuln_db().await;
    }

    // Handle --self-test: run diagnostics and exit
    if args.self_test {
        return self_test::run_self_test();
    }

    // Handle --api: start REST API server and block
    #[cfg(feature = "api")]
    if args.api {
        let addr: std::net::SocketAddr = args
            .listen
            .parse()
            .with_context(|| format!("invalid --listen address: {}", args.listen))?;
        let config = rustmap_api::ApiConfig {
            listen_addr: addr,
            api_key: args.api_key.clone(),
        };
        eprintln!("RustMap API server listening on http://{addr}");
        if config.api_key.is_some() {
            eprintln!("  Authentication: enabled (Bearer token required)");
        } else {
            eprintln!("  Authentication: disabled (use --api-key to enable)");
        }
        return rustmap_api::start_server(config)
            .await
            .map_err(|e| anyhow::anyhow!(e));
    }

    // Handle --resume: resume an interrupted scan
    if let Some(ref scan_id) = args.resume {
        return resume_scan(scan_id).await;
    }

    // Handle --diff-scans: compare two scans and exit
    if let Some(ref spec) = args.diff_scans {
        return show_diff_scans(spec);
    }

    // Build DNS config from CLI flags
    let dns_config = DnsConfig {
        servers: args
            .dns_servers
            .as_deref()
            .map(|s| s.split(',').map(|ip| ip.trim().to_string()).collect())
            .unwrap_or_default(),
        timeout_ms: args.resolve_timeout,
    };

    // Validate DNS server entries eagerly
    for server in &dns_config.servers {
        server.parse::<std::net::IpAddr>().with_context(|| {
            format!(
                "invalid --dns-servers value: '{}' is not a valid IP address",
                server
            )
        })?;
    }

    // Handle --show-profile: display learned network profile and exit
    if args.show_profile {
        // We need to parse targets first for subnet computation
        let targets = parse_targets_with_dns(&args.targets, &dns_config)
            .await
            .with_context(|| format!("failed to parse target(s): {:?}", args.targets))?;
        if targets.is_empty() {
            anyhow::bail!("no valid targets specified");
        }
        return show_network_profile(&targets);
    }

    // Detect privileges
    let privilege_level = check_privileges();
    info!("privilege level: {}", privilege_level);

    // Check Npcap availability on Windows
    #[cfg(windows)]
    if privilege_level.has_raw_socket_access() && !rustmap_packet::npcap_installed() {
        bail!(
            "Npcap is not installed. Raw packet scans require Npcap.\n\
             Download: https://npcap.com/#download\n\
             Hint: Use -sT for TCP Connect scan (no Npcap needed)."
        );
    }

    // Build discovery config
    let discovery = build_discovery_config(&args)?;

    // Determine scan type(s) — supports combined like "SU" for SYN+UDP
    let (scan_type, additional_scan_types) =
        parse_scan_types(args.scan_type.as_deref(), &privilege_level)?;

    // Parse targets (supports IPs, CIDR, ranges, hostnames)
    #[allow(unused_mut)]
    let mut targets = parse_targets_with_dns(&args.targets, &dns_config)
        .await
        .with_context(|| format!("failed to parse target(s): {:?}", args.targets))?;

    // Cloud asset discovery: append discovered instances to targets
    #[cfg(not(any(feature = "cloud-aws", feature = "cloud-azure", feature = "cloud-gcp")))]
    if args.cloud_provider.is_some() {
        eprintln!(
            "Warning: --cloud requires cloud features (cloud-aws, cloud-azure, cloud-gcp). \
             Rebuild with: cargo build --features cloud"
        );
    }
    #[cfg(any(feature = "cloud-aws", feature = "cloud-azure", feature = "cloud-gcp"))]
    if let Some(ref provider) = args.cloud_provider {
        let cloud_opts = rustmap_cloud::CloudDiscoveryOptions {
            provider: provider.clone(),
            regions: args
                .cloud_regions
                .as_deref()
                .map(|s| s.split(',').map(|r| r.trim().to_string()).collect())
                .unwrap_or_default(),
            running_only: args.cloud_running_only,
            tags: args
                .cloud_tags
                .iter()
                .filter_map(|t| {
                    t.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect(),
        };

        eprintln!("Discovering {} cloud assets...", provider);
        match rustmap_cloud::discover_cloud_assets(&cloud_opts).await {
            Ok(cloud_hosts) => {
                let count = cloud_hosts.len();
                targets.extend(cloud_hosts);
                eprintln!("Discovered {count} cloud instances");
            }
            Err(e) => {
                eprintln!("Warning: cloud discovery failed: {e}");
            }
        }
    }

    if targets.is_empty() {
        bail!("no valid targets specified");
    }

    info!(
        targets = targets.len(),
        first_target = %targets[0].ip,
        "resolved target(s)"
    );

    // Parse timing template — with adaptive suggestion from scan database
    let timing_template = match args.timing {
        Some(t) => TimingTemplate::try_from(t)
            .map_err(|e| anyhow::anyhow!(e))
            .context("invalid timing template")?,
        None => {
            // Check if we have learned timing data for this network
            let suggested = suggest_timing_from_db(&targets[0].ip);
            if let Some(tmpl) = suggested {
                info!(
                    recommended = %tmpl,
                    "using learned timing for this network"
                );
                tmpl
            } else {
                TimingTemplate::default()
            }
        }
    };

    // Parse ports: -p overrides everything; otherwise use -F, --top-ports, or default top 1000
    let ports = if let Some(ref port_spec) = args.ports {
        PortRange::parse(port_spec)
            .with_context(|| format!("failed to parse port spec '{port_spec}'"))?
            .expand()
    } else if args.ping_only {
        vec![]
    } else if args.fast_mode {
        top_tcp_ports(FAST_MODE_TOP_PORTS)
    } else if let Some(n) = args.top_ports {
        if n == 0 {
            bail!("--top-ports requires a positive number");
        }
        top_tcp_ports(n)
    } else {
        // Default: top 1000 TCP ports (matches nmap)
        top_tcp_ports(DEFAULT_TOP_PORTS)
    };

    // Reorder ports using historical prediction data
    let ports = if args.predict_ports && !args.no_db && !args.randomize_ports {
        reorder_ports_with_predictions(&ports, &targets)
    } else {
        ports
    };

    let num_services = ports.len();

    info!(
        targets = targets.len(),
        ports = ports.len(),
        scan_type = ?scan_type,
        timing = %timing_template,
        discovery = ?discovery.mode,
        "starting scan"
    );

    // Build service detection config
    let service_detection = rustmap_types::ServiceDetectionConfig {
        enabled: args.service_version,
        intensity: args.version_intensity,
        probe_timeout: std::time::Duration::from_secs(5),
        quic_probing: !args.no_quic,
        ..rustmap_types::ServiceDetectionConfig::default()
    };

    // Build OS detection config
    let os_detection = rustmap_types::OsDetectionConfig {
        enabled: args.os_detection,
    };

    // Record the command line for output headers (properly quoted for shlex round-trip)
    let command_args = {
        let raw_args: Vec<String> = std::env::args()
            .map(|a| shlex::try_quote(&a).map_or_else(|_| a.clone(), |q| q.into_owned()))
            .collect();
        redact_sensitive_args(&raw_args).join(" ")
    };
    let start_time = SystemTime::now();

    // Validate rate limiting arguments
    if let Some(min) = args.min_rate
        && min <= 0.0
    {
        bail!("--min-rate must be positive");
    }
    if let Some(max) = args.max_rate
        && max <= 0.0
    {
        bail!("--max-rate must be positive");
    }
    if let (Some(min), Some(max)) = (args.min_rate, args.max_rate)
        && min > max
    {
        bail!("--min-rate cannot exceed --max-rate");
    }

    // Validate scan-delay arguments
    if let (Some(sd), Some(msd)) = (args.scan_delay_ms, args.max_scan_delay_ms)
        && msd < sd
    {
        bail!("--max-scan-delay cannot be less than --scan-delay");
    }

    // Parse custom payload (mutually exclusive flags)
    let custom_payload = parse_custom_payload(&args)?;

    // Validate hostgroup arguments
    if args.min_hostgroup == 0 {
        bail!("--min-hostgroup must be >= 1");
    }
    if args.max_hostgroup < args.min_hostgroup {
        bail!("--max-hostgroup must be >= --min-hostgroup");
    }

    // Resolve timing-aware defaults for concurrency, timeout, and host_timeout
    let timing_params = rustmap_timing::TimingParams::from_template(timing_template);

    let concurrency = args
        .concurrency
        .unwrap_or(timing_params.connect_concurrency);
    let timeout_ms = match args.timeout_ms {
        Some(0) | None => timing_params.connect_timeout.as_millis() as u64,
        Some(ms) => ms,
    };

    let host_timeout = if args.host_timeout_ms > 0 {
        std::time::Duration::from_millis(args.host_timeout_ms)
    } else {
        timing_params.host_timeout
    };

    // Apply stealth mode hostgroup defaults when user didn't override
    let max_hostgroup = if args.max_hostgroup == args::DEFAULT_MAX_HOSTGROUP {
        // User didn't override — apply timing template defaults
        match timing_template {
            TimingTemplate::Paranoid | TimingTemplate::Sneaky => 1,
            TimingTemplate::Polite => 4,
            _ => args.max_hostgroup,
        }
    } else {
        args.max_hostgroup
    };

    // Parse decoys
    let decoys = if let Some(ref decoy_str) = args.decoys {
        parse_decoys(decoy_str, scan_type)?
    } else {
        vec![]
    };

    // Query learned timing parameters from historical data
    let (learned_rto, learned_cwnd, learned_ss, learned_retries) =
        if !args.no_db && !args.no_adaptive && !targets.is_empty() {
            match rustmap_db::ScanStore::open_default() {
                Ok(store) => {
                    let subnet = compute_subnet(targets[0].ip);
                    match store.learned_timing_params(&subnet) {
                        Ok(Some(learned)) if learned.confidence >= 0.3 => {
                            info!(
                                confidence = learned.confidence,
                                rto_us = ?learned.suggested_initial_rto_us,
                                cwnd = ?learned.suggested_initial_cwnd,
                                "applying learned timing parameters"
                            );
                            (
                                learned.suggested_initial_rto_us,
                                learned.suggested_initial_cwnd,
                                learned.suggested_ssthresh,
                                learned.suggested_max_retries,
                            )
                        }
                        _ => (None, None, None, None),
                    }
                }
                Err(_) => (None, None, None, None),
            }
        } else {
            (None, None, None, None)
        };

    // Query hosts known to always be up for fast discovery
    let pre_resolved_up = if args.fast_discovery && !args.no_db && !targets.is_empty() {
        match rustmap_db::ScanStore::open_default() {
            Ok(store) => {
                let subnet = compute_subnet(targets[0].ip);
                store
                    .hosts_always_up(&subnet, 5)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|ip| ip.parse().ok())
                    .collect()
            }
            Err(_) => vec![],
        }
    } else {
        vec![]
    };

    // Parse proxy configuration
    let proxy = if let Some(ref proxy_url) = args.proxy {
        Some(
            rustmap_types::ProxyConfig::parse(proxy_url)
                .map_err(|e| anyhow::anyhow!("invalid --proxy URL: {e}"))?,
        )
    } else {
        None
    };

    // Build scan configuration
    let mut config = ScanConfig {
        targets,
        ports,
        scan_type,
        timeout: std::time::Duration::from_millis(timeout_ms),
        concurrency,
        timing_template,
        verbose: args.verbose > 0,
        discovery,
        service_detection,
        os_detection,
        min_hostgroup: args.min_hostgroup,
        max_hostgroup,
        host_timeout,
        min_rate: args.min_rate,
        max_rate: args.max_rate,
        randomize_ports: args.randomize_ports,
        source_port: args.source_port,
        decoys,
        fragment_packets: args.fragment,
        custom_payload,
        traceroute: args.traceroute,
        scan_delay: args.scan_delay_ms.map(Duration::from_millis),
        max_scan_delay: args.max_scan_delay_ms.map(Duration::from_millis),
        learned_initial_rto_us: learned_rto,
        learned_initial_cwnd: learned_cwnd,
        learned_ssthresh: learned_ss,
        learned_max_retries: learned_retries,
        pre_resolved_up,
        proxy,
        mtu_discovery: args.mtu_discovery,
    };

    // MTU discovery requires raw sockets for ICMP
    if config.mtu_discovery && !privilege_level.has_raw_socket_access() {
        eprintln!(
            "Warning: --mtu-discovery requires elevated privileges for raw ICMP sockets. Disabling."
        );
        config.mtu_discovery = false;
    }

    // Proxy scan type fallback: only TCP connect works through SOCKS5
    if config.proxy.is_some() && config.scan_type != ScanType::TcpConnect {
        eprintln!(
            "Warning: --proxy only supports TCP connect scan (-sT). Falling back from {} scan.",
            config.scan_type
        );
        config.scan_type = ScanType::TcpConnect;
    }

    // TUI mode: interactive terminal UI
    #[cfg(feature = "tui")]
    if args.tui {
        let output_config = build_output_config(&args);
        return tui::run_tui(config, output_config).await;
    }

    // Watch mode: continuous rescanning with change detection
    if args.watch {
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            eprintln!("\nWatch mode stopping...");
            cancel_clone.cancel();
        });

        let script_config = build_script_config(&args);
        let output_config = build_output_config(&args);
        let watch_config = watch::WatchConfig {
            interval: Duration::from_secs(args.watch_interval),
            webhook_url: args.webhook_url.clone(),
            on_change_cmd: args.on_change_cmd.clone(),
            no_db: args.no_db,
            timing: args.timing,
        };

        return watch::run_watch_loop(
            config,
            output_config,
            watch_config,
            script_config,
            cancel,
            additional_scan_types,
        )
        .await;
    }

    // Create checkpoint for resume support (skip for trivial scans)
    let scan_id = format!("scan-{}", uuid::Uuid::new_v4());
    let checkpoint_store = if !args.no_db && config.targets.len() > 10 {
        match rustmap_db::ScanStore::open_default() {
            Ok(store) => {
                let cp = rustmap_db::ScanCheckpoint {
                    scan_id: scan_id.clone(),
                    created_at: start_time
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    updated_at: start_time
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    command_args: command_args.clone(),
                    targets: args.targets.clone(),
                    status: "in_progress".into(),
                    completed_hosts: vec![],
                    partial_results: vec![],
                    total_hosts: config.targets.len(),
                    timing_template: args.timing,
                };
                if let Err(e) = store.create_checkpoint(&cp) {
                    warn!(error = %e, "failed to create scan checkpoint");
                }
                Some(store)
            }
            Err(e) => {
                warn!(error = %e, "failed to open DB for checkpoint");
                None
            }
        }
    } else {
        None
    };

    // Run the primary scan with streaming for checkpoint support
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_for_engine = cancel.clone();
    let cancel_for_signal = cancel.clone();
    let scan_id_for_signal = scan_id.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!(
            "\nScan interrupted. Resume with: rustmap --resume {}",
            scan_id_for_signal
        );
        cancel_for_signal.cancel();
    });

    let config_for_engine = config.clone();
    tokio::spawn(async move {
        if let Err(e) = ScanEngine::run_streaming(&config_for_engine, tx, cancel_for_engine).await {
            warn!(error = %e, "scan engine error");
        }
    });

    let mut result = rustmap_types::ScanResult {
        hosts: vec![],
        scan_type: config.scan_type,
        total_duration: Duration::ZERO,
        start_time: Some(start_time),
        command_args: Some(command_args.clone()),
        num_services,
        pre_script_results: vec![],
        post_script_results: vec![],
    };

    while let Some(event) = rx.recv().await {
        match event {
            rustmap_core::ScanEvent::DiscoveryComplete { hosts_total } => {
                info!(hosts_total, "discovery complete");
            }
            rustmap_core::ScanEvent::HostResult {
                result: host_result,
                ..
            } => {
                let host_ip = host_result.host.ip.to_string();
                if let Some(ref store) = checkpoint_store
                    && let Err(e) = store.update_checkpoint(&scan_id, &host_ip, &host_result)
                {
                    warn!(error = %e, "failed to update checkpoint");
                }
                result.hosts.push(*host_result);
            }
            rustmap_core::ScanEvent::Complete(scan_result) => {
                result = *scan_result;
                break;
            }
            rustmap_core::ScanEvent::Error(msg) => {
                warn!("scan error: {msg}");
                // Don't break -- continue collecting results from other hosts
            }
        }
    }

    if cancel.is_cancelled() {
        // Checkpoint is already saved — just exit
        return Ok(());
    }

    // Delete checkpoint on successful completion
    if let Some(ref store) = checkpoint_store
        && let Err(e) = store.delete_checkpoint(&scan_id)
    {
        warn!(error = %e, "failed to delete checkpoint");
    }

    // Run additional scan types (e.g., UDP in -sSU)
    for &extra_type in &additional_scan_types {
        let mut extra_config = config.clone();
        extra_config.scan_type = extra_type;
        info!(scan_type = ?extra_type, "running additional scan");
        let extra_result = ScanEngine::run(&extra_config)
            .await
            .with_context(|| format!("additional {:?} scan failed", extra_type))?;
        merge_results(&mut result, &extra_result);
    }

    // Attach metadata for output formatters
    result.start_time = Some(start_time);
    result.command_args = Some(command_args);
    result.num_services = num_services;

    // Run scripts if enabled
    let script_config = build_script_config(&args);
    if script_config.enabled {
        let script_dirs = find_script_dirs();
        let mut script_discovery = ScriptDiscovery::new(script_dirs);
        match script_discovery.discover() {
            Err(e) => eprintln!("Warning: script discovery failed: {e}"),
            Ok(_) => {
                let scripts = script_discovery.resolve_scripts(&script_config.scripts);
                if scripts.is_empty() {
                    eprintln!("Warning: no scripts matched the specified pattern(s)");
                } else {
                    info!(scripts = scripts.len(), "running NSE scripts");
                    let runner =
                        ScriptRunner::new(script_config, scripts).with_proxy(config.proxy.clone());
                    if let Err(e) = runner.run_all(&mut result) {
                        eprintln!("Warning: script execution error: {e}");
                    }
                }
            }
        }
    }

    // GeoIP enrichment
    if args.geoip {
        let custom_dir = args.geoip_db.as_ref().map(std::path::Path::new);
        match rustmap_geoip::find_geoip_dir(custom_dir) {
            Some(dir) => match rustmap_geoip::GeoIpReader::open(&dir) {
                Ok(reader) => {
                    info!(dir = %dir.display(), "GeoIP databases loaded");
                    rustmap_geoip::enrich_scan_result(&mut result, &reader);
                }
                Err(e) => eprintln!("Warning: failed to open GeoIP databases: {e}"),
            },
            None => {
                eprintln!(
                    "Warning: --geoip enabled but no GeoLite2 MMDB files found.\n\
                     Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data\n\
                     Place in: ~/.rustmap/geoip/ or use --geoip-db <DIR>"
                );
            }
        }
    }

    // Vulnerability correlation (before output so risk scores are included)
    if args.vuln_check {
        let vuln_results = run_vuln_check(&result, args.vuln_min_cvss);
        for vuln_host in &vuln_results {
            if let Some(risk) = vuln_host.risk_score
                && let Some(host) = result
                    .hosts
                    .iter_mut()
                    .find(|h| h.host.ip.to_string() == vuln_host.ip)
            {
                host.risk_score = Some(risk);
            }
        }
        if !vuln_results.is_empty() {
            print_vuln_results(&vuln_results);
        }
    }

    // Build output configuration
    let output_config = build_output_config(&args);

    // Filter open-only if requested
    let result = if output_config.open_only {
        filter_open_ports(&result)
    } else {
        result
    };

    // Output results
    let manager = OutputManager::new(output_config);
    manager
        .run(&result)
        .map_err(|e| anyhow::anyhow!("output error: {}", e))?;

    // Save scan to database unless --no-db
    let scan_id = if !args.no_db {
        save_scan_to_db(&result, start_time, args.timing)
    } else {
        None
    };

    // Show diff against previous scan if --diff
    if args.diff
        && let Some(ref current_id) = scan_id
    {
        show_diff_against_previous(&result, current_id);
    }

    // Topology graph output
    if let Some(ref fmt) = args.topology {
        use rustmap_output::{TopologyGraph, format_dot, format_graphml, format_json_graph};

        let graph = TopologyGraph::from_scan_result(&result);
        let output = match fmt.as_str() {
            "dot" => format_dot(&graph),
            "graphml" => format_graphml(&graph),
            "json" => format_json_graph(&graph),
            other => bail!("unknown topology format: {other}; supported: dot, graphml, json"),
        };
        if let Some(ref path) = args.topology_output {
            std::fs::write(path, &output)
                .with_context(|| format!("failed to write topology to {path}"))?;
            eprintln!("Topology graph written to {path}");
        } else {
            println!("{output}");
        }
    }

    Ok(())
}

/// Parse scan type string into primary + additional scan types.
/// Supports combined scan types like "SU" (SYN + UDP).
fn parse_scan_types(
    spec: Option<&str>,
    privilege_level: &rustmap_packet::PrivilegeLevel,
) -> Result<(ScanType, Vec<ScanType>)> {
    let spec = match spec {
        None => {
            // Auto-detect: use SYN if privileged, connect otherwise
            if privilege_level.has_raw_socket_access() {
                info!("privileged — defaulting to SYN scan");
                return Ok((ScanType::TcpSyn, vec![]));
            } else {
                info!("unprivileged — defaulting to TCP connect scan");
                return Ok((ScanType::TcpConnect, vec![]));
            }
        }
        Some(s) => s,
    };

    let mut types = Vec::new();
    for ch in spec.chars() {
        let scan_type = match ch.to_ascii_uppercase() {
            'S' => {
                if !privilege_level.has_raw_socket_access() {
                    warn!("SYN scan requires privileges; falling back to TCP connect scan");
                    eprintln!(
                        "Warning: SYN scan requires elevated privileges. \
                         Falling back to TCP connect scan."
                    );
                    ScanType::TcpConnect
                } else {
                    ScanType::TcpSyn
                }
            }
            'T' => ScanType::TcpConnect,
            'U' => {
                if !privilege_level.has_raw_socket_access() {
                    bail!("UDP scan requires elevated privileges");
                }
                ScanType::Udp
            }
            'F' => {
                if !privilege_level.has_raw_socket_access() {
                    bail!("FIN scan requires elevated privileges");
                }
                ScanType::TcpFin
            }
            'N' => {
                if !privilege_level.has_raw_socket_access() {
                    bail!("NULL scan requires elevated privileges");
                }
                ScanType::TcpNull
            }
            'X' => {
                if !privilege_level.has_raw_socket_access() {
                    bail!("Xmas scan requires elevated privileges");
                }
                ScanType::TcpXmas
            }
            'A' => {
                if !privilege_level.has_raw_socket_access() {
                    bail!("ACK scan requires elevated privileges");
                }
                ScanType::TcpAck
            }
            'W' => {
                if !privilege_level.has_raw_socket_access() {
                    bail!("Window scan requires elevated privileges");
                }
                ScanType::TcpWindow
            }
            'M' => {
                if !privilege_level.has_raw_socket_access() {
                    bail!("Maimon scan requires elevated privileges");
                }
                ScanType::TcpMaimon
            }
            'Z' => {
                if !privilege_level.has_raw_socket_access() {
                    bail!("SCTP INIT scan requires elevated privileges");
                }
                ScanType::SctpInit
            }
            other => bail!(
                "unknown scan type '{}' (use S=SYN, T=connect, U=UDP, F=FIN, N=NULL, X=Xmas, A=ACK, W=Window, M=Maimon, Z=SCTP)",
                other
            ),
        };
        if !types.contains(&scan_type) {
            types.push(scan_type);
        }
    }

    if types.is_empty() {
        bail!("empty scan type specification");
    }

    let primary = types.remove(0);
    Ok((primary, types))
}

/// Merge results from an additional scan into the primary result.
/// Matches hosts by IP address and appends ports, sorted by (port number, protocol).
pub(crate) fn merge_results(
    primary: &mut rustmap_types::ScanResult,
    additional: &rustmap_types::ScanResult,
) {
    // Build a lookup from IP to index in primary results for O(1) matching
    let primary_index: std::collections::HashMap<std::net::IpAddr, usize> = primary
        .hosts
        .iter()
        .enumerate()
        .map(|(i, h)| (h.host.ip, i))
        .collect();

    for host_result in &additional.hosts {
        if let Some(&idx) = primary_index.get(&host_result.host.ip) {
            primary.hosts[idx]
                .ports
                .extend(host_result.ports.iter().cloned());
            primary.hosts[idx].ports.sort_by_key(|p| {
                let proto_ord = match p.protocol {
                    rustmap_types::Protocol::Tcp => 0u8,
                    rustmap_types::Protocol::Udp => 1,
                    rustmap_types::Protocol::Sctp => 2,
                };
                (p.number, proto_ord)
            });
        }
    }
    // Accumulate total duration
    primary.total_duration += additional.total_duration;
}

/// Build output configuration from CLI flags.
pub(crate) fn build_output_config(args: &Args) -> OutputConfig {
    let mut outputs = Vec::new();

    if let Some(ref path) = args.output_normal {
        outputs.push(OutputSpec {
            format: OutputFormat::Normal,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref path) = args.output_xml {
        outputs.push(OutputSpec {
            format: OutputFormat::Xml,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref path) = args.output_grepable {
        outputs.push(OutputSpec {
            format: OutputFormat::Grepable,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref path) = args.output_json {
        outputs.push(OutputSpec {
            format: OutputFormat::Json,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref path) = args.output_yaml {
        outputs.push(OutputSpec {
            format: OutputFormat::Yaml,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref path) = args.output_csv {
        outputs.push(OutputSpec {
            format: OutputFormat::Csv,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref path) = args.output_cef {
        outputs.push(OutputSpec {
            format: OutputFormat::Cef,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref path) = args.output_leef {
        outputs.push(OutputSpec {
            format: OutputFormat::Leef,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref path) = args.output_html {
        outputs.push(OutputSpec {
            format: OutputFormat::Html,
            path: PathBuf::from(path),
        });
    }
    if let Some(ref basename) = args.output_all {
        outputs.extend(OutputConfig::expand_all_formats(basename));
    }

    OutputConfig {
        outputs,
        open_only: args.open_only,
        show_reason: args.show_reason,
        stdout: true,
    }
}

/// Build discovery configuration from CLI flags.
fn build_discovery_config(args: &Args) -> Result<DiscoveryConfig> {
    // --Pn: skip discovery
    if args.skip_discovery {
        return Ok(DiscoveryConfig {
            mode: DiscoveryMode::Skip,
            ..DiscoveryConfig::default()
        });
    }

    // Check if any custom discovery methods were specified
    let has_custom = args.icmp_echo
        || args.tcp_syn_ping.is_some()
        || args.tcp_ack_ping.is_some()
        || args.icmp_timestamp
        || args.udp_ping.is_some()
        || args.arp_ping
        || args.http_ping.is_some()
        || args.https_ping.is_some();

    let mut config = DiscoveryConfig::default();

    if has_custom {
        let mut methods = Vec::new();
        if args.icmp_echo {
            methods.push(DiscoveryMethod::IcmpEcho);
        }
        if args.tcp_syn_ping.is_some() {
            methods.push(DiscoveryMethod::TcpSyn);
        }
        if args.tcp_ack_ping.is_some() {
            methods.push(DiscoveryMethod::TcpAck);
        }
        if args.icmp_timestamp {
            methods.push(DiscoveryMethod::IcmpTimestamp);
        }
        if args.udp_ping.is_some() {
            methods.push(DiscoveryMethod::UdpPing);
        }
        if args.arp_ping {
            methods.push(DiscoveryMethod::ArpPing);
        }
        if args.http_ping.is_some() {
            methods.push(DiscoveryMethod::HttpPing);
        }
        if args.https_ping.is_some() {
            methods.push(DiscoveryMethod::HttpsPing);
        }
        config.mode = DiscoveryMode::Custom(methods);
    }

    // --sn: ping-only (only set PingOnly when no custom methods specified;
    // with custom methods, the engine handles not doing a port scan)
    if args.ping_only && !has_custom {
        config.mode = DiscoveryMode::PingOnly;
    }

    // Parse custom ports for discovery probes
    if let Some(ref ports_str) = args.tcp_syn_ping
        && !ports_str.is_empty()
    {
        config.tcp_syn_ports =
            parse_port_list(ports_str).context("invalid --PS port specification")?;
    }
    if let Some(ref ports_str) = args.tcp_ack_ping
        && !ports_str.is_empty()
    {
        config.tcp_ack_ports =
            parse_port_list(ports_str).context("invalid --PA port specification")?;
    }
    if let Some(ref ports_str) = args.udp_ping
        && !ports_str.is_empty()
    {
        config.udp_ports = parse_port_list(ports_str).context("invalid --PU port specification")?;
    }
    if let Some(ref ports_str) = args.http_ping
        && !ports_str.is_empty()
    {
        config.http_ports =
            parse_port_list(ports_str).context("invalid --PH port specification")?;
    }
    if let Some(ref ports_str) = args.https_ping
        && !ports_str.is_empty()
    {
        config.https_ports =
            parse_port_list(ports_str).context("invalid --PHT port specification")?;
    }

    Ok(config)
}

/// Parse a comma-separated list of port numbers.
fn parse_port_list(s: &str) -> Result<Vec<u16>> {
    s.split(',')
        .map(|p| {
            p.trim()
                .parse::<u16>()
                .with_context(|| format!("invalid port number '{p}'"))
        })
        .collect()
}

/// Build script configuration from CLI flags.
pub(crate) fn build_script_config(args: &Args) -> ScriptConfig {
    let mut config = ScriptConfig::default();

    if args.default_scripts {
        config.enabled = true;
        config.scripts.push("default".into());
    }

    if let Some(ref script_spec) = args.script {
        config.enabled = true;
        for s in script_spec.split(',') {
            let s = s.trim();
            if !s.is_empty() {
                config.scripts.push(s.to_string());
            }
        }
    }

    if let Some(ref args_str) = args.script_args {
        for pair in args_str.split(',') {
            if let Some((key, value)) = pair.split_once('=') {
                config
                    .script_args
                    .push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }

    config
}

/// Parse decoy specification string (e.g., "10.0.0.1,ME,10.0.0.2").
///
/// "ME" is a placeholder for the scanner's real IP (kept as-is in the list;
/// the scan engine inserts the real IP at send time).
fn parse_decoys(spec: &str, scan_type: ScanType) -> Result<Vec<std::net::IpAddr>> {
    if scan_type == ScanType::TcpConnect {
        bail!("decoy scanning (-D) is not compatible with TCP connect scan (-sT)");
    }

    let mut decoys = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.eq_ignore_ascii_case("ME") {
            // ME marker — the engine will use the real source IP
            continue;
        }
        let ip: std::net::IpAddr = part
            .parse()
            .with_context(|| format!("invalid decoy IP: '{part}'"))?;
        decoys.push(ip);
    }
    Ok(decoys)
}

/// Save the scan result to the database. Returns the scan ID if successful.
pub(crate) fn save_scan_to_db(
    result: &rustmap_types::ScanResult,
    start_time: SystemTime,
    timing: Option<u8>,
) -> Option<String> {
    let store = match rustmap_db::ScanStore::open_default() {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to open scan database");
            return None;
        }
    };

    let started_at = start_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let finished_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    // Include PID to avoid collisions when multiple scans start within the same millisecond
    let pid = std::process::id();
    let scan_id = format!("scan-{started_at}-{pid}");

    if let Err(e) = store.save_scan(&scan_id, result, started_at, finished_at, timing) {
        warn!(error = %e, "failed to save scan to database");
        return None;
    }

    // Compute aggregate metrics once (used for network profile, timing, and time patterns)
    if !result.hosts.is_empty() {
        let first_ip = result.hosts[0].host.ip;
        let subnet = compute_subnet(first_ip);

        let rtt_values: Vec<f64> = result
            .hosts
            .iter()
            .filter_map(|h| h.discovery_latency.map(|d| d.as_secs_f64() * 1000.0))
            .collect();
        let avg_rtt = if rtt_values.is_empty() {
            0.0
        } else {
            rtt_values.iter().sum::<f64>() / rtt_values.len() as f64
        };

        // Aggregate timing telemetry from per-host snapshots
        let (
            total_sent,
            total_responded,
            total_timed_out,
            srtt_sum,
            srtt_count,
            rto_sum,
            cwnd_sum,
            host_count,
        ) = result
            .hosts
            .iter()
            .filter_map(|h| h.timing_snapshot.as_ref())
            .fold(
                (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0f64, 0u64),
                |(s, r, t, ss, sc, rs, cs, hc), ts| {
                    (
                        s + ts.probes_sent,
                        r + ts.probes_responded,
                        t + ts.probes_timed_out,
                        ss + ts.srtt_us.unwrap_or(0),
                        sc + u64::from(ts.srtt_us.is_some()),
                        rs + ts.rto_us,
                        cs + ts.cwnd as f64,
                        hc + 1,
                    )
                },
            );

        let loss_rate = if total_sent > 0 {
            1.0 - (total_responded as f64 / total_sent as f64)
        } else {
            0.0
        };

        // Update network profile
        if let Err(e) = store.update_network_profile(&subnet, avg_rtt, loss_rate) {
            warn!(error = %e, "failed to update network profile");
        }

        // Save detailed timing telemetry
        if host_count > 0 {
            let avg_srtt_us = if srtt_count > 0 {
                Some((srtt_sum / srtt_count) as i64)
            } else {
                None
            };
            let avg_rto_us = (rto_sum / host_count) as i64;
            let avg_cwnd = cwnd_sum / host_count as f64;

            if let Err(e) = store.save_scan_timing(
                &scan_id,
                avg_srtt_us,
                avg_rto_us,
                avg_cwnd,
                total_sent as i64,
                total_responded as i64,
                total_timed_out as i64,
                loss_rate,
                finished_at,
            ) {
                warn!(error = %e, "failed to save scan timing");
            }
        }

        // Update time-of-day pattern
        let hour = {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ((secs % 86400) / 3600) as u8
        };
        if let Err(e) = store.update_time_pattern(&subnet, hour, avg_rtt, loss_rate) {
            warn!(error = %e, "failed to update time pattern");
        }

        // Compute average jitter from RTTVAR snapshots and update stability
        let jitter_vals: Vec<f64> = result
            .hosts
            .iter()
            .filter_map(|h| h.timing_snapshot.as_ref())
            .filter_map(|ts| ts.rttvar_us.map(|v| v as f64))
            .collect();
        if !jitter_vals.is_empty() {
            let avg_jitter = jitter_vals.iter().sum::<f64>() / jitter_vals.len() as f64;
            if let Err(e) = store.update_network_stability(&subnet, avg_jitter) {
                warn!(error = %e, "failed to update network stability");
            }
        }
    }

    // Update port history, service cache, and host profiles per-host
    for host in &result.hosts {
        let ip = host.host.ip.to_string();
        let subnet = compute_subnet(host.host.ip);
        for port in &host.ports {
            let proto = format!("{}", port.protocol);
            if let Err(e) = store.update_port_history(
                &ip,
                &subnet,
                port.number,
                &proto,
                port.state == rustmap_types::PortState::Open,
                finished_at,
            ) {
                warn!(error = %e, ip, port = port.number, "failed to update port history");
            }

            // Update service cache for open ports with detected services
            if port.state == rustmap_types::PortState::Open
                && let Some(ref svc) = port.service
            {
                let (product, version) = port
                    .service_info
                    .as_ref()
                    .map(|i| (i.product.as_deref(), i.version.as_deref()))
                    .unwrap_or((None, None));
                if let Err(e) = store.update_service_cache(
                    &ip,
                    port.number,
                    &proto,
                    svc,
                    product,
                    version,
                    finished_at,
                ) {
                    warn!(error = %e, ip, port = port.number, "failed to update service cache");
                }
            }
        }

        // Detect and report service changes
        if let Ok(changes) = store.detect_service_changes(&ip, &host.ports) {
            for change in &changes {
                eprintln!(
                    "  SERVICE CHANGE {}:{} -- {} -> {}",
                    change.ip,
                    change.port,
                    change.old_service.as_deref().unwrap_or("(none)"),
                    change.new_service.as_deref().unwrap_or("(none)")
                );
            }
        }

        // Update host behavior profile
        // Treat Unknown as Up — it means discovery was skipped (-Pn) and the host was scanned
        let was_up = host.host_status == rustmap_types::HostStatus::Up
            || host.host_status == rustmap_types::HostStatus::Unknown;
        let disc_ms = host.discovery_latency.map(|d| d.as_secs_f64() * 1000.0);
        if let Err(e) = store.update_host_profile(&ip, &subnet, was_up, disc_ms, finished_at) {
            warn!(error = %e, ip, "failed to update host profile");
        }
    }

    info!(scan_id, "scan saved to database");
    Some(scan_id)
}

/// Show diff against the previous scan for the same target(s).
fn show_diff_against_previous(result: &rustmap_types::ScanResult, current_scan_id: &str) {
    let store = match rustmap_db::ScanStore::open_default() {
        Ok(s) => s,
        Err(_) => return,
    };

    // Find the most recent previous scan for the first host (excluding current)
    if let Some(host) = result.hosts.first() {
        let ip = host.host.ip.to_string();

        if let Ok(Some(prev_id)) = store.previous_scan_id_for_host(&ip, current_scan_id) {
            match store.diff_scans(&prev_id, current_scan_id) {
                Ok(diff) => print_scan_diff(&diff),
                Err(e) => warn!(error = %e, "failed to compute scan diff"),
            }
        }
    }
}

/// Print a scan diff to stderr.
fn print_scan_diff(diff: &rustmap_db::ScanDiff) {
    if diff.new_hosts.is_empty() && diff.removed_hosts.is_empty() && diff.port_changes.is_empty() {
        eprintln!("\nNo changes detected since last scan.");
        return;
    }

    eprintln!(
        "\n--- Scan Diff ({} vs {}) ---",
        diff.old_scan_id, diff.new_scan_id
    );

    for host in &diff.new_hosts {
        eprintln!("  + New host: {host}");
    }
    for host in &diff.removed_hosts {
        eprintln!("  - Removed host: {host}");
    }
    for change in &diff.port_changes {
        let old = change.old_state.as_deref().unwrap_or("(none)");
        let new = change.new_state.as_deref().unwrap_or("(removed)");
        eprintln!(
            "  ~ {ip}:{port}/{proto}: {old} -> {new}",
            ip = change.ip,
            port = change.port,
            proto = change.protocol,
        );
    }
}

/// Show scan history from the database.
fn show_history() -> Result<()> {
    let store = rustmap_db::ScanStore::open_default()
        .map_err(|e| anyhow::anyhow!("failed to open scan database: {e}"))?;
    let scans = store
        .list_scans()
        .map_err(|e| anyhow::anyhow!("failed to list scans: {e}"))?;

    if scans.is_empty() {
        println!("No scan history found.");
    } else {
        println!(
            "{:<24} {:<12} {:<8} {:<8} DURATION",
            "SCAN ID", "TYPE", "HOSTS", "PORTS"
        );
        for s in &scans {
            println!(
                "{:<24} {:<12} {:<8} {:<8} {}ms",
                s.scan_id, s.scan_type, s.num_hosts, s.num_services, s.total_duration_ms
            );
        }
    }
    Ok(())
}

/// Show a diff between two named scans.
fn show_diff_scans(spec: &str) -> Result<()> {
    let (old_id, new_id) = spec
        .split_once(',')
        .ok_or_else(|| anyhow::anyhow!("--diff-scans expects OLD_ID,NEW_ID"))?;

    let store = rustmap_db::ScanStore::open_default()
        .map_err(|e| anyhow::anyhow!("failed to open scan database: {e}"))?;

    let diff = store
        .diff_scans(old_id.trim(), new_id.trim())
        .map_err(|e| anyhow::anyhow!("failed to diff scans: {e}"))?;

    print_scan_diff(&diff);
    Ok(())
}

/// Resume an interrupted scan from its checkpoint.
async fn resume_scan(scan_id: &str) -> Result<()> {
    use rustmap_core::ScanEvent;
    use tokio::sync::mpsc;

    let store = rustmap_db::ScanStore::open_default()
        .map_err(|e| anyhow::anyhow!("failed to open scan database: {e}"))?;

    let cp = store
        .load_checkpoint(scan_id)
        .map_err(|e| anyhow::anyhow!("failed to load checkpoint: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("no checkpoint found for scan: {scan_id}"))?;

    // Re-parse the original command args first so we can build DNS config
    let shell_args: Vec<String> = match shlex::split(&cp.command_args) {
        Some(args) => args,
        None => bail!("failed to parse stored command args: {}", cp.command_args),
    };

    let resume_matches = args::Args::command()
        .try_get_matches_from(&shell_args)
        .map_err(|e| anyhow::anyhow!("failed to re-parse command args: {e}"))?;
    let mut resume_args = args::Args::from_arg_matches(&resume_matches)
        .map_err(|e| anyhow::anyhow!("failed to extract args: {e}"))?;

    // Build DNS config from the stored args so hostname resolution matches the original scan
    let resume_dns_config = DnsConfig {
        servers: resume_args
            .dns_servers
            .as_deref()
            .map(|s| s.split(',').map(|ip| ip.trim().to_string()).collect())
            .unwrap_or_default(),
        timeout_ms: resume_args.resolve_timeout,
    };

    // Expand all original targets to individual IPs, then filter out completed ones
    let all_targets = parse_targets_with_dns(&cp.targets, &resume_dns_config)
        .await
        .context("failed to parse checkpoint targets")?;

    let completed_set: std::collections::HashSet<IpAddr> = cp
        .completed_hosts
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();

    let remaining_ips: Vec<IpAddr> = all_targets
        .iter()
        .filter(|h| !completed_set.contains(&h.ip))
        .map(|h| h.ip)
        .collect();

    if remaining_ips.is_empty() {
        eprintln!("All hosts already completed in checkpoint. Nothing to resume.");
        store
            .delete_checkpoint(scan_id)
            .map_err(|e| anyhow::anyhow!("failed to delete checkpoint: {e}"))?;
        return Ok(());
    }

    eprintln!(
        "Resuming scan {scan_id}: {}/{} hosts remaining",
        remaining_ips.len(),
        cp.total_hosts
    );

    // Apply -A aggressive mode expansion (same as main flow)
    if resume_args.aggressive {
        resume_args.os_detection = true;
        resume_args.service_version = true;
        if !resume_args.default_scripts && resume_args.script.is_none() {
            resume_args.default_scripts = true;
        }
    }

    // Build targets from remaining IPs (already expanded and filtered above)
    let targets: Vec<rustmap_types::Host> = remaining_ips
        .into_iter()
        .map(|ip| rustmap_types::Host {
            ip,
            hostname: None,
            geo_info: None,
        })
        .collect();

    let privilege_level = check_privileges();
    let (scan_type, _) = parse_scan_types(resume_args.scan_type.as_deref(), &privilege_level)?;

    let ports = if let Some(ref port_spec) = resume_args.ports {
        PortRange::parse(port_spec)
            .context("invalid port specification")?
            .expand()
    } else if resume_args.fast_mode {
        top_tcp_ports(FAST_MODE_TOP_PORTS)
    } else if let Some(n) = resume_args.top_ports {
        top_tcp_ports(n)
    } else {
        top_tcp_ports(DEFAULT_TOP_PORTS)
    };

    let timing_template = match resume_args.timing.unwrap_or(3) {
        0 => TimingTemplate::Paranoid,
        1 => TimingTemplate::Sneaky,
        2 => TimingTemplate::Polite,
        3 => TimingTemplate::Normal,
        4 => TimingTemplate::Aggressive,
        5 => TimingTemplate::Insane,
        n => bail!("invalid timing template: {n}"),
    };

    let timing_params = rustmap_timing::TimingParams::from_template(timing_template);
    let timeout = match resume_args.timeout_ms {
        Some(ms) if ms > 0 => Duration::from_millis(ms),
        _ => timing_params.connect_timeout,
    };

    let concurrency = resume_args
        .concurrency
        .unwrap_or(timing_params.connect_concurrency);

    let discovery = build_discovery_config(&resume_args)?;

    let config = ScanConfig {
        targets,
        ports,
        scan_type,
        timeout,
        concurrency,
        verbose: resume_args.verbose > 0,
        timing_template,
        discovery,
        service_detection: rustmap_types::ServiceDetectionConfig {
            enabled: resume_args.service_version,
            intensity: resume_args.version_intensity,
            probe_timeout: std::time::Duration::from_secs(5),
            quic_probing: !resume_args.no_quic,
            ..rustmap_types::ServiceDetectionConfig::default()
        },
        os_detection: rustmap_types::OsDetectionConfig {
            enabled: resume_args.os_detection,
        },
        min_hostgroup: resume_args.min_hostgroup,
        max_hostgroup: resume_args.max_hostgroup,
        host_timeout: Duration::from_millis(resume_args.host_timeout_ms),
        min_rate: resume_args.min_rate,
        max_rate: resume_args.max_rate,
        randomize_ports: resume_args.randomize_ports,
        source_port: resume_args.source_port,
        decoys: if let Some(ref decoy_str) = resume_args.decoys {
            parse_decoys(decoy_str, scan_type)?
        } else {
            vec![]
        },
        fragment_packets: resume_args.fragment,
        custom_payload: None,
        traceroute: resume_args.traceroute,
        scan_delay: resume_args.scan_delay_ms.map(Duration::from_millis),
        max_scan_delay: resume_args.max_scan_delay_ms.map(Duration::from_millis),
        learned_initial_rto_us: None,
        learned_initial_cwnd: None,
        learned_ssthresh: None,
        learned_max_retries: None,
        pre_resolved_up: vec![],
        proxy: None,
        mtu_discovery: resume_args.mtu_discovery,
    };

    // Run streaming scan for remaining targets
    let (tx, mut rx) = mpsc::channel(64);
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_for_engine = cancel.clone();
    let cancel_for_signal = cancel.clone();

    let scan_id_for_signal = scan_id.to_string();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!(
            "\nScan interrupted. Checkpoint saved — resume with: rustmap --resume {scan_id_for_signal}"
        );
        cancel_for_signal.cancel();
    });

    let scan_id_owned = scan_id.to_string();
    let engine_handle = tokio::spawn(async move {
        if let Err(e) = ScanEngine::run_streaming(&config, tx, cancel_for_engine).await {
            warn!(error = %e, "scan engine error");
        }
    });

    // Collect new results from the streaming scan
    let mut new_results: Vec<rustmap_types::HostScanResult> = Vec::new();
    while let Some(event) = rx.recv().await {
        match event {
            ScanEvent::DiscoveryComplete { hosts_total } => {
                eprintln!("  Discovery: {hosts_total} hosts to scan");
            }
            ScanEvent::HostResult {
                result,
                hosts_completed,
                hosts_total,
                ..
            } => {
                let host_ip = result.host.ip.to_string();
                eprintln!("  [{hosts_completed}/{hosts_total}] {host_ip} completed",);
                // Update checkpoint in DB
                if let Err(e) = store.update_checkpoint(&scan_id_owned, &host_ip, &result) {
                    warn!(error = %e, "failed to update checkpoint");
                }
                new_results.push(*result);
            }
            ScanEvent::Complete(result) => {
                eprintln!("  Remaining scan completed");
                // Take hosts from the complete result instead
                new_results = result.hosts;
                break;
            }
            ScanEvent::Error(msg) => {
                warn!("scan error: {msg}");
            }
        }
    }

    engine_handle.await.ok();

    // If the scan was cancelled (Ctrl+C), preserve the checkpoint and exit early.
    // The per-host checkpoint updates already saved progress to DB.
    if cancel.is_cancelled() {
        eprintln!("Checkpoint preserved. Resume with: rustmap --resume {scan_id_owned}");
        return Ok(());
    }

    // Merge: checkpoint partial results + new results, deduplicated by IP
    let mut seen_ips: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();
    let mut all_hosts: Vec<rustmap_types::HostScanResult> = Vec::new();

    // New results take priority (more recent)
    for host in new_results {
        if seen_ips.insert(host.host.ip) {
            all_hosts.push(host);
        }
    }

    // Then add any checkpoint results not already covered
    for host in cp.partial_results {
        if seen_ips.insert(host.host.ip) {
            all_hosts.push(host);
        }
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let total_duration = Duration::from_millis(now_ms.saturating_sub(cp.created_at));

    let num_services = all_hosts
        .iter()
        .flat_map(|h| h.ports.iter())
        .filter(|p| p.service.is_some() || p.service_info.is_some())
        .count();

    let result = rustmap_types::ScanResult {
        hosts: all_hosts,
        scan_type,
        total_duration,
        start_time: Some(UNIX_EPOCH + Duration::from_millis(cp.created_at)),
        command_args: Some(cp.command_args.clone()),
        num_services,
        pre_script_results: vec![],
        post_script_results: vec![],
    };

    // Delete checkpoint since we're done
    store
        .delete_checkpoint(&scan_id_owned)
        .map_err(|e| anyhow::anyhow!("failed to delete checkpoint: {e}"))?;

    // Save the merged result
    let started_at = cp.created_at;
    let finished_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if let Err(e) = store.save_scan(
        &scan_id_owned,
        &result,
        started_at,
        finished_at,
        cp.timing_template,
    ) {
        warn!(error = %e, "failed to save merged scan result");
    }

    // Output results
    let output_config = build_output_config(&resume_args);
    let output_result = if output_config.open_only {
        filter_open_ports(&result)
    } else {
        result
    };

    let manager = OutputManager::new(output_config);
    manager
        .run(&output_result)
        .map_err(|e| anyhow::anyhow!("output error: {}", e))?;

    eprintln!(
        "\nResumed scan complete. Total hosts: {}",
        output_result.hosts.len()
    );

    Ok(())
}

/// Look up learned timing from the scan database.
/// Returns a suggested timing template if we have enough data (3+ scans).
fn suggest_timing_from_db(ip: &IpAddr) -> Option<TimingTemplate> {
    let store = rustmap_db::ScanStore::open_default().ok()?;
    let subnet = compute_subnet(*ip);
    let profile = store.network_profile(&subnet).ok()??;
    if profile.scan_count >= 3 {
        TimingTemplate::try_from(profile.recommended_timing).ok()
    } else {
        None
    }
}

/// Display the learned network profile for the given targets and exit.
fn show_network_profile(targets: &[rustmap_types::Host]) -> Result<()> {
    let store =
        rustmap_db::ScanStore::open_default().with_context(|| "failed to open scan database")?;
    let subnet = compute_subnet(targets[0].ip);
    match store.network_profile(&subnet)? {
        Some(profile) => {
            println!("Network Profile: {}", subnet);
            println!("  Avg RTT:        {:.1}ms", profile.avg_rtt_ms);
            println!("  Loss Rate:      {:.1}%", profile.avg_loss_rate * 100.0);
            println!("  Timing:         T{}", profile.recommended_timing);
            println!("  Scan Count:     {}", profile.scan_count);
            if let Some(jitter) = profile.avg_jitter_us {
                println!("  Avg Jitter:     {:.0}us", jitter);
            }
            if let Some(stability) = profile.stability_score {
                println!("  Stability:      {:.2}", stability);
            }
            if let Ok(patterns) = store.get_time_patterns(&subnet)
                && !patterns.is_empty()
            {
                println!("  Time-of-Day Patterns:");
                for p in &patterns {
                    println!(
                        "    {:02}:00  RTT={:.1}ms  Loss={:.1}%  (n={})",
                        p.hour,
                        p.avg_rtt_ms,
                        p.avg_loss * 100.0,
                        p.sample_count
                    );
                }
            }
        }
        None => println!("No network profile found for {}", subnet),
    }
    Ok(())
}

/// Compute the /24 (IPv4) or /64 (IPv6) subnet for an IP.
fn compute_subnet(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
    }
}

/// Reorder ports so historically-open ports come first.
fn reorder_ports_with_predictions(ports: &[u16], targets: &[rustmap_types::Host]) -> Vec<u16> {
    use std::collections::HashSet;

    let store = match rustmap_db::ScanStore::open_default() {
        Ok(s) => s,
        Err(_) => return ports.to_vec(),
    };

    let mut high_priority = Vec::new(); // probability > 0.8 (per-host)
    let mut medium_priority = Vec::new(); // probability > 0.5 (subnet)
    let mut low_priority = HashSet::new(); // probability < 0.1

    // Query per-host predictions for first target
    if let Some(target) = targets.first() {
        let ip = target.ip.to_string();
        if let Ok(predictions) = store.predict_ports_for_host(&ip, 200) {
            for pred in &predictions {
                if pred.open_probability > 0.8 {
                    high_priority.push(pred.port);
                } else if pred.open_probability < 0.1 {
                    low_priority.insert(pred.port);
                }
            }
        }

        // Query subnet predictions
        let subnet = compute_subnet(target.ip);
        if let Ok(predictions) = store.predict_ports_for_subnet(&subnet, 200) {
            for pred in &predictions {
                if pred.open_probability > 0.5 {
                    medium_priority.push(pred.port);
                } else if pred.open_probability < 0.1 {
                    low_priority.insert(pred.port);
                }
            }
        }
    }

    if high_priority.is_empty() && medium_priority.is_empty() {
        return ports.to_vec();
    }

    let mut seen = HashSet::new();
    let mut result = Vec::with_capacity(ports.len());
    let ports_set: HashSet<u16> = ports.iter().copied().collect();

    // Tier 1: high priority (known open on this host)
    for &p in &high_priority {
        if ports_set.contains(&p) && seen.insert(p) {
            result.push(p);
        }
    }
    // Tier 2: medium priority (open on subnet)
    for &p in &medium_priority {
        if ports_set.contains(&p) && seen.insert(p) {
            result.push(p);
        }
    }
    // Tier 3: remaining ports (original order, excluding low priority)
    for &p in ports {
        if !low_priority.contains(&p) && seen.insert(p) {
            result.push(p);
        }
    }
    // Tier 4: low priority (historically closed)
    for &p in ports {
        if seen.insert(p) {
            result.push(p);
        }
    }

    info!(
        high = high_priority.len(),
        medium = medium_priority.len(),
        low = low_priority.len(),
        "port prediction reordering applied"
    );

    result
}

/// Find directories containing Lua scripts.
pub(crate) fn find_script_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Next to the executable
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let scripts_dir = dir.join("scripts");
        if scripts_dir.is_dir() {
            dirs.push(scripts_dir);
        }
    }

    // Relative to CWD (development)
    let cwd_scripts = PathBuf::from("scripts");
    if cwd_scripts.is_dir() {
        dirs.push(cwd_scripts);
    }
    let dev_scripts = PathBuf::from("rustmap-script/scripts");
    if dev_scripts.is_dir() {
        dirs.push(dev_scripts);
    }

    dirs
}

/// Update the CVE vulnerability database.
async fn update_vuln_db() -> Result<()> {
    let store = rustmap_db::ScanStore::open_default()
        .map_err(|e| anyhow::anyhow!("failed to open scan database: {e}"))?;

    // Always seed bundled CVEs first
    eprintln!("Seeding bundled CVE data...");
    rustmap_vuln::seed_bundled_cves(&store)
        .map_err(|e| anyhow::anyhow!("failed to seed bundled CVEs: {e}"))?;

    let bundled_count = store
        .count_cves()
        .map_err(|e| anyhow::anyhow!("failed to count CVEs: {e}"))?;
    eprintln!("Bundled CVE entries: {bundled_count}");

    // Fetch from NVD API
    #[cfg(feature = "watch")]
    {
        eprintln!("Fetching CVEs from NVD API (this may take a minute)...");
        match rustmap_vuln::update_cve_database(&store).await {
            Ok(count) => eprintln!("Updated {count} CVE(s) from NVD."),
            Err(e) => eprintln!("Warning: NVD update failed: {e}"),
        }
    }

    let total = store
        .count_cves()
        .map_err(|e| anyhow::anyhow!("failed to count CVEs: {e}"))?;
    eprintln!("Total CVE entries: {total}");

    Ok(())
}

/// Run vulnerability checks against scan results.
fn run_vuln_check(
    result: &rustmap_types::ScanResult,
    min_cvss: f64,
) -> Vec<rustmap_vuln::HostVulnResult> {
    let store = match rustmap_db::ScanStore::open_default() {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "failed to open scan database for vuln check");
            return vec![];
        }
    };

    // Ensure bundled CVEs are seeded
    if let Err(e) = rustmap_vuln::seed_bundled_cves(&store) {
        warn!(error = %e, "failed to seed bundled CVEs");
    }

    let min_filter = if min_cvss > 0.0 { Some(min_cvss) } else { None };

    let mut results = Vec::new();
    for host in &result.hosts {
        let host_result = rustmap_vuln::check_host_vulns(
            &store,
            &host.host.ip.to_string(),
            &host.ports,
            min_filter,
        );
        if !host_result.port_vulns.is_empty() {
            results.push(host_result);
        }
    }
    results
}

/// Print vulnerability results to stderr.
fn print_vuln_results(results: &[rustmap_vuln::HostVulnResult]) {
    eprintln!("\n--- Vulnerability Report ---");
    for host in results {
        if let Some(risk) = host.risk_score {
            let sev = if risk >= 9.0 {
                "CRITICAL"
            } else if risk >= 7.0 {
                "HIGH"
            } else if risk >= 4.0 {
                "MEDIUM"
            } else {
                "LOW"
            };
            eprintln!("  Host {}: Risk Score {risk:.1}/10.0 ({sev})", host.ip);
        }
        for port_vuln in &host.port_vulns {
            let svc = port_vuln.product.as_deref().unwrap_or("unknown");
            let ver = port_vuln.version.as_deref().unwrap_or("?");

            for vuln in &port_vuln.vulns {
                let severity = match vuln.cvss_score {
                    Some(s) if s >= 9.0 => "CRITICAL",
                    Some(s) if s >= 7.0 => "HIGH",
                    Some(s) if s >= 4.0 => "MEDIUM",
                    Some(_) => "LOW",
                    None => "UNKNOWN",
                };
                eprintln!(
                    "  [{severity}] {}:{}/{} ({svc} {ver}) - {}: {}",
                    host.ip,
                    port_vuln.port,
                    port_vuln.protocol,
                    vuln.cve_id,
                    truncate_description(&vuln.description, 80),
                );
                if let Some(score) = vuln.cvss_score {
                    eprintln!("    CVSS: {score:.1}");
                }
            }
        }
    }
}

/// Truncate a description string for display.
fn truncate_description(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        let end = s.floor_char_boundary(max_len.saturating_sub(3));
        &s[..end]
    }
}

/// Redact sensitive arguments from a command-line argument list.
///
/// Replaces the value following `--api-key` with `[REDACTED]`, and replaces
/// `--proxy` values that contain embedded credentials (user:pass@host) with
/// a redacted form.
fn redact_sensitive_args(args: &[String]) -> Vec<String> {
    let mut result = Vec::with_capacity(args.len());
    let mut skip_next = false;
    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            result.push("[REDACTED]".to_string());
            skip_next = false;
            continue;
        }
        if arg == "--api-key" {
            result.push(arg.clone());
            skip_next = true;
            continue;
        }
        if arg.starts_with("--api-key=") {
            result.push("--api-key=[REDACTED]".to_string());
            continue;
        }
        // Redact --proxy if it contains credentials (user:pass@host pattern)
        if arg == "--proxy" {
            result.push(arg.clone());
            // Check if the next arg contains credentials
            if let Some(next) = args.get(i + 1)
                && next.contains('@')
            {
                skip_next = true;
            }
            continue;
        }
        if let Some(value) = arg.strip_prefix("--proxy=") {
            if value.contains('@') {
                result.push("--proxy=[REDACTED]".to_string());
            } else {
                result.push(arg.clone());
            }
            continue;
        }
        result.push(arg.clone());
    }
    result
}

/// Parse --data-hex, --data-string, or --data-length into a custom payload.
/// Only one of the three flags may be specified.
fn parse_custom_payload(args: &Args) -> Result<Option<Vec<u8>>> {
    let count = args.data_hex.is_some() as u8
        + args.data_string.is_some() as u8
        + args.data_length.is_some() as u8;
    if count > 1 {
        bail!("only one of --data-hex, --data-string, --data-length may be specified");
    }
    if let Some(ref hex) = args.data_hex {
        let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
        if hex.len() % 2 != 0 {
            bail!("--data-hex must have even length");
        }
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("invalid --data-hex: {e}"))?;
        return Ok(Some(bytes));
    }
    if let Some(ref s) = args.data_string {
        return Ok(Some(s.as_bytes().to_vec()));
    }
    if let Some(n) = args.data_length {
        if n > 65400 {
            bail!("--data-length must be <= 65400 (max IP payload)");
        }
        let mut buf = vec![0u8; n];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        return Ok(Some(buf));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_args() -> Args {
        Args {
            targets: vec![],
            ports: None,
            aggressive: false,
            fast_mode: false,
            top_ports: None,
            scan_type: None,
            timing: None,
            verbose: 0,
            timeout_ms: None,
            concurrency: None,
            min_rate: None,
            max_rate: None,
            scan_delay_ms: None,
            max_scan_delay_ms: None,
            min_hostgroup: 1,
            max_hostgroup: 256,
            host_timeout_ms: 0,
            service_version: false,
            version_intensity: 7,
            no_quic: false,
            os_detection: false,
            ping_only: false,
            skip_discovery: false,
            icmp_echo: false,
            tcp_syn_ping: None,
            tcp_ack_ping: None,
            icmp_timestamp: false,
            udp_ping: None,
            arp_ping: false,
            http_ping: None,
            https_ping: None,
            script: None,
            script_args: None,
            default_scripts: false,
            output_normal: None,
            output_xml: None,
            output_grepable: None,
            output_json: None,
            output_yaml: None,
            output_csv: None,
            output_cef: None,
            output_leef: None,
            output_html: None,
            output_all: None,
            open_only: false,
            show_reason: false,
            randomize_ports: false,
            source_port: None,
            decoys: None,
            fragment: false,
            data_hex: None,
            data_string: None,
            data_length: None,
            traceroute: false,
            mtu_discovery: false,
            proxy: None,
            dns_servers: None,
            resolve_timeout: 5000,
            topology: None,
            topology_output: None,
            no_db: false,
            diff: false,
            history: false,
            diff_scans: None,
            resume: None,
            predict_ports: false,
            no_adaptive: false,
            fast_discovery: false,
            show_profile: false,
            profile: None,
            save_profile: None,
            list_profiles: false,
            watch: false,
            watch_interval: 300,
            webhook_url: None,
            on_change_cmd: None,
            vuln_check: false,
            vuln_update: false,
            vuln_min_cvss: 0.0,
            geoip: false,
            geoip_db: None,
            cloud_provider: None,
            cloud_regions: None,
            cloud_running_only: false,
            cloud_tags: vec![],
            tui: false,
            api: false,
            listen: "127.0.0.1:8080".into(),
            api_key: None,
            self_test: false,
        }
    }

    #[test]
    fn parse_payload_hex_valid() {
        let mut args = make_args();
        args.data_hex = Some("deadbeef".into());
        let payload = parse_custom_payload(&args).unwrap().unwrap();
        assert_eq!(payload, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn parse_payload_hex_with_prefix() {
        let mut args = make_args();
        args.data_hex = Some("0xCAFE".into());
        let payload = parse_custom_payload(&args).unwrap().unwrap();
        assert_eq!(payload, vec![0xca, 0xfe]);
    }

    #[test]
    fn parse_payload_hex_odd_length_fails() {
        let mut args = make_args();
        args.data_hex = Some("abc".into());
        assert!(parse_custom_payload(&args).is_err());
    }

    #[test]
    fn parse_payload_string() {
        let mut args = make_args();
        args.data_string = Some("hello".into());
        let payload = parse_custom_payload(&args).unwrap().unwrap();
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn parse_payload_length() {
        let mut args = make_args();
        args.data_length = Some(16);
        let payload = parse_custom_payload(&args).unwrap().unwrap();
        assert_eq!(payload.len(), 16);
    }

    #[test]
    fn parse_payload_none() {
        let args = make_args();
        assert!(parse_custom_payload(&args).unwrap().is_none());
    }

    #[test]
    fn parse_payload_mutual_exclusion() {
        let mut args = make_args();
        args.data_hex = Some("ff".into());
        args.data_string = Some("x".into());
        assert!(parse_custom_payload(&args).is_err());
    }
}
