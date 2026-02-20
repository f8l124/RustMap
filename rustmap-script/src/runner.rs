use rustmap_types::{ScriptConfig, ScriptPhase, ScriptResult, ScanResult};

use crate::discovery::{ScriptLanguage, ScriptMeta};
use crate::error::ScriptError;
use crate::lua_api;
use crate::sandbox::{LuaSandbox, lua_value_to_script_value};
use crate::subprocess_runner;

/// Check if a rule function's return value indicates the script should run.
fn check_rule(rule_result: Result<mlua::Value, ScriptError>) -> Result<bool, ScriptError> {
    match rule_result {
        Ok(mlua::Value::Boolean(b)) => Ok(b),
        Ok(mlua::Value::Nil) => Ok(false),
        Ok(_) => Ok(true),
        Err(e) => {
            if e.to_string().contains("not found") {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

/// Extract a ScriptResult from a Lua action return value.
fn extract_script_result(
    sandbox: &LuaSandbox,
    script_id: &str,
    action_result: &mlua::Value,
) -> Option<ScriptResult> {
    match action_result {
        mlua::Value::Nil => None,
        mlua::Value::String(s) => Some(ScriptResult {
            id: script_id.to_string(),
            output: s.to_string_lossy().to_string(),
            elements: None,
        }),
        mlua::Value::Table(_) => {
            let output = if let Ok(tostring) =
                sandbox.lua().globals().get::<mlua::Function>("tostring")
            {
                tostring
                    .call::<String>(action_result.clone())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let elements = lua_value_to_script_value(action_result);
            Some(ScriptResult {
                id: script_id.to_string(),
                output,
                elements,
            })
        }
        _ => None,
    }
}

/// Executes scripts against scan results.
pub struct ScriptRunner {
    config: ScriptConfig,
    scripts: Vec<ScriptMeta>,
    proxy: Option<rustmap_types::ProxyConfig>,
}

impl ScriptRunner {
    /// Create a new script runner with the given configuration and scripts.
    pub fn new(config: ScriptConfig, scripts: Vec<ScriptMeta>) -> Self {
        Self {
            config,
            scripts,
            proxy: None,
        }
    }

    /// Set the SOCKS5 proxy configuration for script TCP sockets.
    pub fn with_proxy(mut self, proxy: Option<rustmap_types::ProxyConfig>) -> Self {
        self.proxy = proxy;
        self
    }

    /// Run portrule scripts against all hosts and ports.
    pub fn run_portrule_scripts(&self, result: &mut ScanResult) -> Result<(), ScriptError> {
        let portrule_scripts: Vec<&ScriptMeta> = self
            .scripts
            .iter()
            .filter(|s| s.phases.contains(&ScriptPhase::Portrule))
            .collect();

        if portrule_scripts.is_empty() {
            return Ok(());
        }

        for host in &mut result.hosts {
            for port_idx in 0..host.ports.len() {
                for script in &portrule_scripts {
                    // Borrow port immutably for script execution
                    let port_ref = &host.ports[port_idx];
                    match self.execute_portrule_script(script, host, port_ref) {
                        Ok(Some(script_result)) => {
                            host.ports[port_idx].script_results.push(script_result);
                        }
                        Ok(None) => {
                            // Script rule returned false or produced no output
                        }
                        Err(e) => {
                            eprintln!(
                                "NSE: script {} failed on {}:{}: {}",
                                script.id, host.host.ip, host.ports[port_idx].number, e
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Execute a single portrule script against a host/port.
    fn execute_portrule_script(
        &self,
        script: &ScriptMeta,
        host: &rustmap_types::HostScanResult,
        port: &rustmap_types::Port,
    ) -> Result<Option<ScriptResult>, ScriptError> {
        match script.language {
            ScriptLanguage::Lua => self.execute_lua_portrule(script, host, port),
            ScriptLanguage::Python => subprocess_runner::run_python_subprocess(
                &script.path,
                &script.id,
                host,
                Some(port),
                "portrule",
                &self.config.script_args,
                std::time::Duration::from_secs(30),
            ),
            #[cfg(feature = "wasm")]
            ScriptLanguage::Wasm => {
                let wasm_bytes = std::fs::read(&script.path)?;
                let mut sandbox = crate::wasm_sandbox::WasmSandbox::new(&wasm_bytes)?;
                let args_map: std::collections::HashMap<&str, &str> = self.config.script_args
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                let input = serde_json::json!({
                    "host": host.host.ip.to_string(),
                    "port": port.number,
                    "protocol": format!("{}", port.protocol),
                    "service": port.service,
                    "phase": "portrule",
                    "args": args_map,
                });
                let input_bytes = serde_json::to_vec(&input)
                    .map_err(|e| ScriptError::Execution(format!("JSON serialization: {e}")))?;
                let output_bytes = sandbox.execute(&input_bytes)?;
                crate::wasm_sandbox::parse_wasm_output(&script.id, &output_bytes)
            }
        }
    }

    /// Execute a Lua portrule script.
    fn execute_lua_portrule(
        &self,
        script: &ScriptMeta,
        host: &rustmap_types::HostScanResult,
        port: &rustmap_types::Port,
    ) -> Result<Option<ScriptResult>, ScriptError> {
        let sandbox = LuaSandbox::new()?;
        lua_api::register_all_with_proxy(sandbox.lua(), self.proxy.clone())?;
        self.register_script_args(&sandbox)?;
        sandbox.execute_file(&script.path)?;

        let host_table = lua_api::build_host_table(sandbox.lua(), host)
            .map_err(|e| ScriptError::Lua(format!("failed to build host table: {e}")))?;
        let port_table = lua_api::build_port_table(sandbox.lua(), port)
            .map_err(|e| ScriptError::Lua(format!("failed to build port table: {e}")))?;

        if !check_rule(sandbox.call_function("portrule", (host_table.clone(), port_table.clone())))? {
            return Ok(None);
        }

        let action_result = sandbox.call_function("action", (host_table, port_table))?;
        Ok(extract_script_result(&sandbox, &script.id, &action_result))
    }

    /// Register script arguments in the nmap table.
    fn register_script_args(&self, sandbox: &LuaSandbox) -> Result<(), ScriptError> {
        if self.config.script_args.is_empty() {
            return Ok(());
        }

        let lua = sandbox.lua();
        let nmap: mlua::Table = lua
            .globals()
            .get("nmap")
            .map_err(|e| ScriptError::Lua(format!("nmap table not found: {e}")))?;

        let args_table = lua
            .create_table()
            .map_err(|e| ScriptError::Lua(format!("failed to create args table: {e}")))?;

        for (key, value) in &self.config.script_args {
            args_table
                .set(key.as_str(), value.as_str())
                .map_err(|e| ScriptError::Lua(format!("failed to set arg {key}: {e}")))?;
        }

        nmap.set("args", args_table)
            .map_err(|e| ScriptError::Lua(format!("failed to set nmap.args: {e}")))?;

        Ok(())
    }

    /// Run hostrule scripts against all hosts.
    pub fn run_hostrule_scripts(&self, result: &mut ScanResult) -> Result<(), ScriptError> {
        let hostrule_scripts: Vec<&ScriptMeta> = self
            .scripts
            .iter()
            .filter(|s| s.phases.contains(&ScriptPhase::Hostrule))
            .collect();

        if hostrule_scripts.is_empty() {
            return Ok(());
        }

        for host in &mut result.hosts {
            for script in &hostrule_scripts {
                match self.execute_hostrule_script(script, host) {
                    Ok(Some(script_result)) => {
                        host.host_script_results.push(script_result);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("NSE: script {} failed on {}: {}", script.id, host.host.ip, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Run prerule scripts (execute once before host/port scanning).
    pub fn run_prerule_scripts(&self, result: &mut ScanResult) -> Result<(), ScriptError> {
        let prerule_scripts: Vec<&ScriptMeta> = self
            .scripts
            .iter()
            .filter(|s| s.phases.contains(&ScriptPhase::Prerule))
            .collect();

        for script in &prerule_scripts {
            match self.execute_phase_script(script, "prerule") {
                Ok(Some(script_result)) => {
                    result.pre_script_results.push(script_result);
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("NSE: prerule script {} failed: {}", script.id, e);
                }
            }
        }

        Ok(())
    }

    /// Run postrule scripts (execute once after all host/port scripts).
    pub fn run_postrule_scripts(&self, result: &mut ScanResult) -> Result<(), ScriptError> {
        let postrule_scripts: Vec<&ScriptMeta> = self
            .scripts
            .iter()
            .filter(|s| s.phases.contains(&ScriptPhase::Postrule))
            .collect();

        for script in &postrule_scripts {
            match self.execute_phase_script(script, "postrule") {
                Ok(Some(script_result)) => {
                    result.post_script_results.push(script_result);
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("NSE: postrule script {} failed: {}", script.id, e);
                }
            }
        }

        Ok(())
    }

    /// Run all script phases in the correct order: pre → host → port → post.
    pub fn run_all(&self, result: &mut ScanResult) -> Result<(), ScriptError> {
        self.run_prerule_scripts(result)?;
        self.run_hostrule_scripts(result)?;
        self.run_portrule_scripts(result)?;
        self.run_postrule_scripts(result)?;
        Ok(())
    }

    /// Execute a single hostrule script against a host.
    fn execute_hostrule_script(
        &self,
        script: &ScriptMeta,
        host: &rustmap_types::HostScanResult,
    ) -> Result<Option<ScriptResult>, ScriptError> {
        match script.language {
            ScriptLanguage::Lua => {
                let sandbox = LuaSandbox::new()?;
                lua_api::register_all_with_proxy(sandbox.lua(), self.proxy.clone())?;
                self.register_script_args(&sandbox)?;
                sandbox.execute_file(&script.path)?;

                let host_table = lua_api::build_host_table(sandbox.lua(), host)
                    .map_err(|e| ScriptError::Lua(format!("failed to build host table: {e}")))?;

                if !check_rule(sandbox.call_function("hostrule", host_table.clone()))? {
                    return Ok(None);
                }

                let action_result = sandbox.call_function("action", host_table)?;
                Ok(extract_script_result(&sandbox, &script.id, &action_result))
            }
            ScriptLanguage::Python => subprocess_runner::run_python_subprocess(
                &script.path,
                &script.id,
                host,
                None,
                "hostrule",
                &self.config.script_args,
                std::time::Duration::from_secs(30),
            ),
            #[cfg(feature = "wasm")]
            ScriptLanguage::Wasm => {
                let wasm_bytes = std::fs::read(&script.path)?;
                let mut sandbox = crate::wasm_sandbox::WasmSandbox::new(&wasm_bytes)?;
                let args_map: std::collections::HashMap<&str, &str> = self.config.script_args
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                let input = serde_json::json!({
                    "host": host.host.ip.to_string(),
                    "phase": "hostrule",
                    "args": args_map,
                });
                let input_bytes = serde_json::to_vec(&input)
                    .map_err(|e| ScriptError::Execution(format!("JSON serialization: {e}")))?;
                let output_bytes = sandbox.execute(&input_bytes)?;
                crate::wasm_sandbox::parse_wasm_output(&script.id, &output_bytes)
            }
        }
    }

    /// Execute a single prerule or postrule script (no host/port arguments).
    fn execute_phase_script(
        &self,
        script: &ScriptMeta,
        rule_name: &str,
    ) -> Result<Option<ScriptResult>, ScriptError> {
        match script.language {
            ScriptLanguage::Lua => {
                let sandbox = LuaSandbox::new()?;
                lua_api::register_all_with_proxy(sandbox.lua(), self.proxy.clone())?;
                self.register_script_args(&sandbox)?;
                sandbox.execute_file(&script.path)?;

                if !check_rule(sandbox.call_function(rule_name, ()))? {
                    return Ok(None);
                }

                let action_result = sandbox.call_function("action", ())?;
                Ok(extract_script_result(&sandbox, &script.id, &action_result))
            }
            ScriptLanguage::Python => {
                // For prerule/postrule, create a minimal empty host
                let empty_host = rustmap_types::HostScanResult {
                    host: rustmap_types::Host::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    ports: vec![],
                    scan_duration: std::time::Duration::ZERO,
                    host_status: rustmap_types::HostStatus::Unknown,
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
                subprocess_runner::run_python_subprocess(
                    &script.path,
                    &script.id,
                    &empty_host,
                    None,
                    rule_name,
                    &self.config.script_args,
                    std::time::Duration::from_secs(30),
                )
            }
            #[cfg(feature = "wasm")]
            ScriptLanguage::Wasm => {
                let wasm_bytes = std::fs::read(&script.path)?;
                let mut sandbox = crate::wasm_sandbox::WasmSandbox::new(&wasm_bytes)?;
                let args_map: std::collections::HashMap<&str, &str> = self.config.script_args
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                let input = serde_json::json!({
                    "phase": rule_name,
                    "args": args_map,
                });
                let input_bytes = serde_json::to_vec(&input)
                    .map_err(|e| ScriptError::Execution(format!("JSON serialization: {e}")))?;
                let output_bytes = sandbox.execute(&input_bytes)?;
                crate::wasm_sandbox::parse_wasm_output(&script.id, &output_bytes)
            }
        }
    }

    /// Get the scripts this runner will execute.
    pub fn scripts(&self) -> &[ScriptMeta] {
        &self.scripts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::{
        Host, HostScanResult, HostStatus, Port, PortState, Protocol, ScanType, ScriptPhase,
    };
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_scan_result(ports: Vec<Port>) -> ScanResult {
        ScanResult {
            hosts: vec![HostScanResult {
                host: Host::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                ports,
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
            }],
            total_duration: Duration::from_millis(200),
            scan_type: ScanType::TcpConnect,
            start_time: None,
            command_args: None,
            num_services: 1,
            pre_script_results: vec![],
            post_script_results: vec![],
        }
    }

    fn make_port(number: u16) -> Port {
        Port {
            number,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("http".into()),
            service_info: None,
            reason: None,
            script_results: vec![],
            tls_info: None,
        }
    }

    fn write_test_script(dir: &std::path::Path, name: &str, content: &str) -> ScriptMeta {
        let path = dir.join(format!("{name}.lua"));
        fs::write(&path, content).unwrap();
        ScriptMeta {
            id: name.into(),
            path,
            description: String::new(),
            categories: vec![],
            phases: vec![ScriptPhase::Portrule],
            dependencies: vec![],
            language: ScriptLanguage::Lua,
        }
    }

    #[test]
    fn portrule_true_runs_action() {
        let tmp = std::env::temp_dir().join("rustmap_test_portrule_true");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-true",
            r#"
            summary = "test"
            categories = {"safe"}
            phases = {"portrule"}

            function portrule(host, port)
                return true
            end

            function action(host, port)
                return "Port " .. port.number .. " is open"
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec!["test-true".into()],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        assert_eq!(result.hosts[0].ports[0].script_results.len(), 1);
        let sr = &result.hosts[0].ports[0].script_results[0];
        assert_eq!(sr.id, "test-true");
        assert_eq!(sr.output, "Port 80 is open");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn portrule_false_skips_action() {
        let tmp = std::env::temp_dir().join("rustmap_test_portrule_false");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-false",
            r#"
            function portrule(host, port)
                return false
            end

            function action(host, port)
                return "should not run"
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec!["test-false".into()],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        assert!(result.hosts[0].ports[0].script_results.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn portrule_nil_output_not_stored() {
        let tmp = std::env::temp_dir().join("rustmap_test_portrule_nil");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-nil",
            r#"
            function portrule(host, port)
                return true
            end

            function action(host, port)
                return nil
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec!["test-nil".into()],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        assert!(result.hosts[0].ports[0].script_results.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn script_error_doesnt_crash_runner() {
        let tmp = std::env::temp_dir().join("rustmap_test_script_error");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let bad_script = write_test_script(
            &tmp,
            "test-error",
            r#"
            function portrule(host, port)
                return true
            end

            function action(host, port)
                error("intentional error")
            end
            "#,
        );

        let good_script = write_test_script(
            &tmp,
            "test-good",
            r#"
            function portrule(host, port)
                return true
            end

            function action(host, port)
                return "success"
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec!["test-error".into(), "test-good".into()],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![bad_script, good_script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        // Good script should still produce output despite bad script failing
        assert_eq!(result.hosts[0].ports[0].script_results.len(), 1);
        assert_eq!(result.hosts[0].ports[0].script_results[0].id, "test-good");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn script_accesses_host_and_port_info() {
        let tmp = std::env::temp_dir().join("rustmap_test_host_port_access");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-access",
            r#"
            function portrule(host, port)
                return true
            end

            function action(host, port)
                return host.ip .. ":" .. port.number .. "/" .. port.protocol
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec!["test-access".into()],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(443)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        assert_eq!(result.hosts[0].ports[0].script_results.len(), 1);
        assert_eq!(
            result.hosts[0].ports[0].script_results[0].output,
            "192.168.1.1:443/tcp"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn script_uses_nmap_api() {
        let tmp = std::env::temp_dir().join("rustmap_test_nmap_api");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-api",
            r#"
            function portrule(host, port)
                return true
            end

            function action(host, port)
                nmap.registry["seen"] = (nmap.registry["seen"] or 0) + 1
                return "verbosity=" .. nmap.verbosity()
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec!["test-api".into()],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        assert_eq!(
            result.hosts[0].ports[0].script_results[0].output,
            "verbosity=0"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn script_with_table_output() {
        let tmp = std::env::temp_dir().join("rustmap_test_table_output");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-table",
            r#"
            function portrule(host, port)
                return true
            end

            function action(host, port)
                return {title = "Example Page", server = "Apache"}
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec!["test-table".into()],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        assert_eq!(result.hosts[0].ports[0].script_results.len(), 1);
        let sr = &result.hosts[0].ports[0].script_results[0];
        assert_eq!(sr.id, "test-table");
        assert!(sr.elements.is_some());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn script_args_available() {
        let tmp = std::env::temp_dir().join("rustmap_test_script_args");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-args",
            r#"
            function portrule(host, port)
                return true
            end

            function action(host, port)
                if nmap.args and nmap.args["key1"] then
                    return "arg: " .. nmap.args["key1"]
                end
                return "no args"
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec!["test-args".into()],
            script_args: vec![("key1".into(), "value1".into())],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        assert_eq!(
            result.hosts[0].ports[0].script_results[0].output,
            "arg: value1"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn multiple_scripts_on_same_port() {
        let tmp = std::env::temp_dir().join("rustmap_test_multi_scripts");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script1 = write_test_script(
            &tmp,
            "test-a",
            r#"
            function portrule(host, port) return true end
            function action(host, port) return "output-a" end
            "#,
        );

        let script2 = write_test_script(
            &tmp,
            "test-b",
            r#"
            function portrule(host, port) return true end
            function action(host, port) return "output-b" end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script1, script2]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        assert_eq!(result.hosts[0].ports[0].script_results.len(), 2);
        let ids: Vec<&str> = result.hosts[0].ports[0]
            .script_results
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert!(ids.contains(&"test-a"));
        assert!(ids.contains(&"test-b"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn empty_scripts_no_error() {
        let config = ScriptConfig::default();
        let runner = ScriptRunner::new(config, vec![]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();
        assert!(result.hosts[0].ports[0].script_results.is_empty());
    }

    #[test]
    fn non_portrule_scripts_skipped() {
        let tmp = std::env::temp_dir().join("rustmap_test_non_portrule");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join("test-hostrule.lua");
        fs::write(
            &path,
            r#"
            function hostrule(host) return true end
            function action(host) return "host output" end
            "#,
        )
        .unwrap();

        let script = ScriptMeta {
            id: "test-hostrule".into(),
            path,
            description: String::new(),
            categories: vec![],
            phases: vec![ScriptPhase::Hostrule], // Not Portrule!
            dependencies: vec![],
            language: ScriptLanguage::Lua,
        };

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_portrule_scripts(&mut result).unwrap();

        // Should be empty because the script is hostrule, not portrule
        assert!(result.hosts[0].ports[0].script_results.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn shortport_integration_in_script() {
        let tmp = std::env::temp_dir().join("rustmap_test_shortport_integration");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-shortport",
            r#"
            portrule = shortport.port_or_service({80, 443}, {"http", "https"}, nil, nil)

            function action(host, port)
                return "HTTP service on port " .. port.number
            end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80), make_port(22)]);
        // Port 22 has service "http" from make_port, so let's fix it
        result.hosts[0].ports[1].service = Some("ssh".into());

        runner.run_portrule_scripts(&mut result).unwrap();

        // Port 80 matches (by port number)
        assert_eq!(result.hosts[0].ports[0].script_results.len(), 1);
        assert_eq!(
            result.hosts[0].ports[0].script_results[0].output,
            "HTTP service on port 80"
        );

        // Port 22 should not match (wrong port and wrong service)
        assert!(result.hosts[0].ports[1].script_results.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }

    fn write_test_script_phase(
        dir: &std::path::Path,
        name: &str,
        content: &str,
        phase: ScriptPhase,
    ) -> ScriptMeta {
        let path = dir.join(format!("{name}.lua"));
        fs::write(&path, content).unwrap();
        ScriptMeta {
            id: name.into(),
            path,
            description: String::new(),
            categories: vec![],
            phases: vec![phase],
            dependencies: vec![],
            language: ScriptLanguage::Lua,
        }
    }

    #[test]
    fn hostrule_true_runs_action() {
        let tmp = std::env::temp_dir().join("rustmap_test_hostrule_true");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script_phase(
            &tmp,
            "test-hostrule",
            r#"
            function hostrule(host)
                return true
            end

            function action(host)
                return "Host " .. host.ip .. " is up"
            end
            "#,
            ScriptPhase::Hostrule,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_hostrule_scripts(&mut result).unwrap();

        assert_eq!(result.hosts[0].host_script_results.len(), 1);
        let sr = &result.hosts[0].host_script_results[0];
        assert_eq!(sr.id, "test-hostrule");
        assert_eq!(sr.output, "Host 192.168.1.1 is up");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn hostrule_false_skips_action() {
        let tmp = std::env::temp_dir().join("rustmap_test_hostrule_false");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script_phase(
            &tmp,
            "test-hostrule-false",
            r#"
            function hostrule(host) return false end
            function action(host) return "should not run" end
            "#,
            ScriptPhase::Hostrule,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_hostrule_scripts(&mut result).unwrap();

        assert!(result.hosts[0].host_script_results.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn prerule_runs_and_stores() {
        let tmp = std::env::temp_dir().join("rustmap_test_prerule");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script_phase(
            &tmp,
            "test-prerule",
            r#"
            function prerule()
                return true
            end

            function action()
                return "prerule output"
            end
            "#,
            ScriptPhase::Prerule,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_prerule_scripts(&mut result).unwrap();

        assert_eq!(result.pre_script_results.len(), 1);
        assert_eq!(result.pre_script_results[0].id, "test-prerule");
        assert_eq!(result.pre_script_results[0].output, "prerule output");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn postrule_runs_and_stores() {
        let tmp = std::env::temp_dir().join("rustmap_test_postrule");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script_phase(
            &tmp,
            "test-postrule",
            r#"
            function postrule()
                return true
            end

            function action()
                return "postrule output"
            end
            "#,
            ScriptPhase::Postrule,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_postrule_scripts(&mut result).unwrap();

        assert_eq!(result.post_script_results.len(), 1);
        assert_eq!(result.post_script_results[0].id, "test-postrule");
        assert_eq!(result.post_script_results[0].output, "postrule output");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn run_all_executes_all_phases() {
        let tmp = std::env::temp_dir().join("rustmap_test_run_all");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let prerule = write_test_script_phase(
            &tmp,
            "test-pre",
            r#"
            function prerule() return true end
            function action() return "pre" end
            "#,
            ScriptPhase::Prerule,
        );

        let hostrule = write_test_script_phase(
            &tmp,
            "test-host",
            r#"
            function hostrule(host) return true end
            function action(host) return "host" end
            "#,
            ScriptPhase::Hostrule,
        );

        let portrule = write_test_script(
            &tmp,
            "test-port",
            r#"
            function portrule(host, port) return true end
            function action(host, port) return "port" end
            "#,
        );

        let postrule = write_test_script_phase(
            &tmp,
            "test-post",
            r#"
            function postrule() return true end
            function action() return "post" end
            "#,
            ScriptPhase::Postrule,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![prerule, hostrule, portrule, postrule]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_all(&mut result).unwrap();

        assert_eq!(result.pre_script_results.len(), 1);
        assert_eq!(result.pre_script_results[0].output, "pre");

        assert_eq!(result.hosts[0].host_script_results.len(), 1);
        assert_eq!(result.hosts[0].host_script_results[0].output, "host");

        assert_eq!(result.hosts[0].ports[0].script_results.len(), 1);
        assert_eq!(result.hosts[0].ports[0].script_results[0].output, "port");

        assert_eq!(result.post_script_results.len(), 1);
        assert_eq!(result.post_script_results[0].output, "post");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn hostrule_error_doesnt_crash() {
        let tmp = std::env::temp_dir().join("rustmap_test_hostrule_error");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let bad_script = write_test_script_phase(
            &tmp,
            "test-bad-host",
            r#"
            function hostrule(host) return true end
            function action(host) error("intentional error") end
            "#,
            ScriptPhase::Hostrule,
        );

        let good_script = write_test_script_phase(
            &tmp,
            "test-good-host",
            r#"
            function hostrule(host) return true end
            function action(host) return "success" end
            "#,
            ScriptPhase::Hostrule,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![bad_script, good_script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_hostrule_scripts(&mut result).unwrap();

        assert_eq!(result.hosts[0].host_script_results.len(), 1);
        assert_eq!(result.hosts[0].host_script_results[0].id, "test-good-host");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn non_hostrule_skipped_by_hostrule_runner() {
        let tmp = std::env::temp_dir().join("rustmap_test_non_hostrule_skip");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let script = write_test_script(
            &tmp,
            "test-portrule-only",
            r#"
            function portrule(host, port) return true end
            function action(host, port) return "port output" end
            "#,
        );

        let config = ScriptConfig {
            enabled: true,
            scripts: vec![],
            script_args: vec![],
        };

        let runner = ScriptRunner::new(config, vec![script]);
        let mut result = make_scan_result(vec![make_port(80)]);
        runner.run_hostrule_scripts(&mut result).unwrap();

        assert!(result.hosts[0].host_script_results.is_empty());

        let _ = fs::remove_dir_all(&tmp);
    }
}
