use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use rustmap_types::{HostScanResult, Port, ScriptResult};

use crate::error::ScriptError;

/// Run a Python script via subprocess.
///
/// Passes host/port data as JSON on stdin, reads result as JSON from stdout.
/// The Python script must read JSON from stdin and write a JSON result to stdout.
///
/// If the script returns `null` or produces no output, returns `Ok(None)`.
pub fn run_python_subprocess(
    script_path: &Path,
    script_id: &str,
    host: &HostScanResult,
    port: Option<&Port>,
    phase: &str,
    args: &[(String, String)],
    timeout: Duration,
) -> Result<Option<ScriptResult>, ScriptError> {
    let input = build_input_json(host, port, phase, args);

    // Try python3 first, fall back to python
    let python = find_python();

    let mut child = Command::new(&python)
        .arg(script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            ScriptError::Execution(format!(
                "failed to spawn {} for {}: {e}",
                python,
                script_path.display()
            ))
        })?;

    // Write JSON to stdin
    if let Some(mut stdin) = child.stdin.take() {
        let input_bytes = input.to_string().into_bytes();
        stdin
            .write_all(&input_bytes)
            .map_err(|e| ScriptError::Execution(format!("failed to write to stdin: {e}")))?;
        // Drop stdin to close it so the child can finish reading
    }

    // Wait for the process with a timeout
    let output = wait_with_timeout(&mut child, timeout)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            return Err(ScriptError::Execution(format!(
                "Python script {} failed: {stderr}",
                script_id
            )));
        }
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();

    if stdout.is_empty() || stdout == "null" {
        return Ok(None);
    }

    // Parse JSON result
    let value: serde_json::Value = serde_json::from_str(stdout).map_err(|e| {
        ScriptError::Execution(format!(
            "failed to parse Python script output as JSON: {e}"
        ))
    })?;

    extract_result(script_id, &value)
}

/// Build the JSON input to send to the Python script.
fn build_input_json(
    host: &HostScanResult,
    port: Option<&Port>,
    phase: &str,
    args: &[(String, String)],
) -> serde_json::Value {
    let args_map: HashMap<&str, &str> = args
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    serde_json::json!({
        "phase": phase,
        "host": {
            "ip": host.host.ip.to_string(),
            "hostname": host.host.hostname,
        },
        "port": port.map(|p| serde_json::json!({
            "number": p.number,
            "protocol": format!("{}", p.protocol),
            "state": format!("{}", p.state),
            "service": p.service,
        })),
        "args": args_map,
    })
}

/// Extract a ScriptResult from parsed JSON.
fn extract_result(
    script_id: &str,
    value: &serde_json::Value,
) -> Result<Option<ScriptResult>, ScriptError> {
    if value.is_null() {
        return Ok(None);
    }

    // If it's a string, use it directly
    if let Some(s) = value.as_str() {
        return Ok(Some(ScriptResult {
            id: script_id.to_string(),
            output: s.to_string(),
            elements: None,
        }));
    }

    // If it's an object with an "output" field
    if let Some(obj) = value.as_object() {
        let output = obj
            .get("output")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        return Ok(Some(ScriptResult {
            id: script_id.to_string(),
            output,
            elements: None,
        }));
    }

    // Otherwise stringify it
    Ok(Some(ScriptResult {
        id: script_id.to_string(),
        output: value.to_string(),
        elements: None,
    }))
}

/// Find the Python executable (python3 or python).
fn find_python() -> String {
    // On Windows, python3 may not exist; try python first
    if cfg!(windows) {
        "python".to_string()
    } else {
        "python3".to_string()
    }
}

/// Wait for a child process with a timeout.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, ScriptError> {
    // Simple approach: use try_wait in a loop with sleep
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process finished — read remaining output
                let stdout = child
                    .stdout
                    .take()
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut s, &mut buf).ok();
                        buf
                    })
                    .unwrap_or_default();
                let stderr = child
                    .stderr
                    .take()
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut s, &mut buf).ok();
                        buf
                    })
                    .unwrap_or_default();

                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                // Still running
                if start.elapsed() > timeout {
                    // Kill the process
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ScriptError::Execution(
                        "Python script timed out".to_string(),
                    ));
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                return Err(ScriptError::Execution(format!(
                    "failed to wait for Python process: {e}"
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_input_json_with_port() {
        use rustmap_types::{Host, HostStatus, Port, PortState, Protocol};
        use std::net::IpAddr;

        let host = HostScanResult {
            host: Host {
                ip: IpAddr::from([10, 0, 0, 1]),
                hostname: Some("test.local".into()),
                geo_info: None,
            },
            ports: vec![],
            scan_duration: Duration::from_millis(100),
            host_status: HostStatus::Up,
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: None,
            timing_snapshot: None,
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        };

        let port = Port {
            number: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        };

        let json = build_input_json(&host, Some(&port), "portrule", &[("key".into(), "val".into())]);
        assert_eq!(json["phase"], "portrule");
        assert_eq!(json["host"]["ip"], "10.0.0.1");
        assert_eq!(json["host"]["hostname"], "test.local");
        assert_eq!(json["port"]["number"], 80);
        assert_eq!(json["port"]["protocol"], "tcp");
        assert_eq!(json["args"]["key"], "val");
    }

    #[test]
    fn build_input_json_without_port() {
        use rustmap_types::{Host, HostStatus};
        use std::net::IpAddr;

        let host = HostScanResult {
            host: Host {
                ip: IpAddr::from([10, 0, 0, 1]),
                hostname: None,
                geo_info: None,
            },
            ports: vec![],
            scan_duration: Duration::from_millis(100),
            host_status: HostStatus::Up,
            discovery_latency: None,
            os_fingerprint: None,
            traceroute: None,
            timing_snapshot: None,
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        };

        let json = build_input_json(&host, None, "hostrule", &[]);
        assert_eq!(json["phase"], "hostrule");
        assert!(json["port"].is_null());
    }

    #[test]
    fn extract_result_string() {
        let value = serde_json::json!("hello world");
        let result = extract_result("test", &value).unwrap().unwrap();
        assert_eq!(result.id, "test");
        assert_eq!(result.output, "hello world");
    }

    #[test]
    fn extract_result_object() {
        let value = serde_json::json!({"output": "some output"});
        let result = extract_result("test", &value).unwrap().unwrap();
        assert_eq!(result.output, "some output");
    }

    #[test]
    fn extract_result_null() {
        let value = serde_json::json!(null);
        assert!(extract_result("test", &value).unwrap().is_none());
    }
}
