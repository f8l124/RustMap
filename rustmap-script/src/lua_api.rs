use mlua::{Lua, Result as LuaResult, Table, Value};
use rustmap_types::{HostScanResult, Port, ProxyConfig};

use crate::error::ScriptError;
use crate::socket::{LuaSocket, LuaUdpSocket};

/// Wrapper to store an optional ProxyConfig in Lua's app data.
#[derive(Clone)]
pub(crate) struct ProxyAppData(pub Option<ProxyConfig>);

/// Register the `nmap` global table in the Lua environment.
pub fn register_nmap_api(lua: &Lua, proxy: Option<ProxyConfig>) -> Result<(), ScriptError> {
    // Store proxy config in Lua app data so sockets can access it.
    lua.set_app_data(ProxyAppData(proxy));

    let nmap = lua
        .create_table()
        .map_err(|e| ScriptError::Lua(format!("failed to create nmap table: {e}")))?;

    // nmap.registry = {} (shared state between scripts)
    let registry = lua
        .create_table()
        .map_err(|e| ScriptError::Lua(format!("failed to create registry: {e}")))?;
    nmap.set("registry", registry)
        .map_err(|e| ScriptError::Lua(format!("failed to set registry: {e}")))?;

    // nmap.verbosity() -> number
    let verbosity_fn = lua
        .create_function(|_, ()| Ok(0i32))
        .map_err(|e| ScriptError::Lua(format!("failed to create verbosity fn: {e}")))?;
    nmap.set("verbosity", verbosity_fn)
        .map_err(|e| ScriptError::Lua(format!("failed to set verbosity: {e}")))?;

    // nmap.debugging() -> number
    let debugging_fn = lua
        .create_function(|_, ()| Ok(0i32))
        .map_err(|e| ScriptError::Lua(format!("failed to create debugging fn: {e}")))?;
    nmap.set("debugging", debugging_fn)
        .map_err(|e| ScriptError::Lua(format!("failed to set debugging: {e}")))?;

    // nmap.log_write(level, msg) -> nil
    let log_write_fn = lua
        .create_function(|_, (level, msg): (String, String)| {
            eprintln!("[NSE {level}] {msg}");
            Ok(())
        })
        .map_err(|e| ScriptError::Lua(format!("failed to create log_write fn: {e}")))?;
    nmap.set("log_write", log_write_fn)
        .map_err(|e| ScriptError::Lua(format!("failed to set log_write: {e}")))?;

    // nmap.new_socket() -> LuaSocket userdata (TCP)
    let new_socket_fn = lua
        .create_function(|lua, ()| {
            let proxy = lua
                .app_data_ref::<ProxyAppData>()
                .and_then(|p| p.0.clone());
            lua.create_userdata(LuaSocket::new(proxy))
        })
        .map_err(|e| ScriptError::Lua(format!("failed to create new_socket fn: {e}")))?;
    nmap.set("new_socket", new_socket_fn)
        .map_err(|e| ScriptError::Lua(format!("failed to set new_socket: {e}")))?;

    // nmap.new_udp_socket() -> LuaUdpSocket userdata (UDP)
    let new_udp_socket_fn = lua
        .create_function(|lua, ()| lua.create_userdata(LuaUdpSocket::new()))
        .map_err(|e| ScriptError::Lua(format!("failed to create new_udp_socket fn: {e}")))?;
    nmap.set("new_udp_socket", new_udp_socket_fn)
        .map_err(|e| ScriptError::Lua(format!("failed to set new_udp_socket: {e}")))?;

    // nmap.md5(data) -> hex_string
    let md5_fn = lua
        .create_function(|_, data: mlua::String| {
            let digest = md5::compute(data.as_bytes());
            Ok(format!("{digest:x}"))
        })
        .map_err(|e| ScriptError::Lua(format!("failed to create md5 fn: {e}")))?;
    nmap.set("md5", md5_fn)
        .map_err(|e| ScriptError::Lua(format!("failed to set md5: {e}")))?;

    lua.globals()
        .set("nmap", nmap)
        .map_err(|e| ScriptError::Lua(format!("failed to set nmap global: {e}")))?;

    Ok(())
}

/// Register the `shortport` global table in the Lua environment.
pub fn register_shortport_api(lua: &Lua) -> Result<(), ScriptError> {
    let shortport = lua
        .create_table()
        .map_err(|e| ScriptError::Lua(format!("failed to create shortport table: {e}")))?;

    // shortport.port_or_service(ports, services, protos, states)
    // Returns a function that matches against port/service
    let port_or_service_fn = lua
        .create_function(
            |lua, (ports, services, _protos, _states): (Value, Value, Value, Value)| {
                // Extract port numbers
                let port_list = extract_number_list(&ports);
                let service_list = extract_string_list(lua, &services);

                // Return a portrule function
                lua.create_function(move |_, (_, port_table): (Value, Table)| {
                    // Check port number
                    let port_num: u16 = port_table.get("number").unwrap_or(0);
                    if port_list.contains(&port_num) {
                        return Ok(true);
                    }

                    // Check service name
                    if let Ok(service_table) = port_table.get::<Table>("service")
                        && let Ok(name) = service_table.get::<String>("name")
                        && service_list.contains(&name)
                    {
                        return Ok(true);
                    }

                    Ok(false)
                })
            },
        )
        .map_err(|e| ScriptError::Lua(format!("failed to create port_or_service: {e}")))?;

    shortport
        .set("port_or_service", port_or_service_fn)
        .map_err(|e| ScriptError::Lua(format!("failed to set port_or_service: {e}")))?;

    lua.globals()
        .set("shortport", shortport)
        .map_err(|e| ScriptError::Lua(format!("failed to set shortport global: {e}")))?;

    Ok(())
}

/// Build a Lua host table from a HostScanResult.
pub fn build_host_table(lua: &Lua, host: &HostScanResult) -> LuaResult<Table> {
    let table = lua.create_table()?;

    table.set("ip", host.host.ip.to_string())?;

    if let Some(ref hostname) = host.host.hostname {
        table.set("name", hostname.as_str())?;
    }

    // OS information
    if let Some(ref os) = host.os_fingerprint {
        let os_table = lua.create_table()?;
        if let Some(ref family) = os.os_family {
            os_table.set("family", family.as_str())?;
        }
        if let Some(ref generation) = os.os_generation {
            os_table.set("generation", generation.as_str())?;
        }
        if let Some(accuracy) = os.accuracy {
            os_table.set("accuracy", accuracy)?;
        }
        table.set("os", os_table)?;
    }

    Ok(table)
}

/// Build a Lua port table from a Port.
pub fn build_port_table(lua: &Lua, port: &Port) -> LuaResult<Table> {
    let table = lua.create_table()?;

    table.set("number", port.number)?;
    table.set("protocol", port.protocol.to_string())?;
    table.set("state", port.state.to_string())?;

    // Service information
    if let Some(ref service_name) = port.service {
        let service_table = lua.create_table()?;
        service_table.set("name", service_name.as_str())?;

        if let Some(ref info) = port.service_info {
            if let Some(ref product) = info.product {
                service_table.set("product", product.as_str())?;
            }
            if let Some(ref version) = info.version {
                service_table.set("version", version.as_str())?;
            }
            if let Some(ref extra) = info.info {
                service_table.set("info", extra.as_str())?;
            }
        }

        table.set("service", service_table)?;
    }

    Ok(table)
}

/// Register all API functions in the Lua environment.
pub fn register_all(lua: &Lua) -> Result<(), ScriptError> {
    register_nmap_api(lua, None)?;
    register_shortport_api(lua)?;
    Ok(())
}

/// Register all API functions with optional proxy config for socket connections.
pub fn register_all_with_proxy(
    lua: &Lua,
    proxy: Option<ProxyConfig>,
) -> Result<(), ScriptError> {
    register_nmap_api(lua, proxy)?;
    register_shortport_api(lua)?;
    Ok(())
}

/// Extract a list of numbers from a Lua value (table or single number).
fn extract_number_list(value: &Value) -> Vec<u16> {
    match value {
        Value::Integer(n) => vec![*n as u16],
        Value::Number(n) => vec![*n as u16],
        Value::Table(t) => {
            let mut result = Vec::new();
            let len = t.raw_len();
            for i in 1..=len {
                if let Ok(n) = t.raw_get::<i64>(i) {
                    result.push(n as u16);
                }
            }
            result
        }
        _ => Vec::new(),
    }
}

/// Extract a list of strings from a Lua value (table or single string).
fn extract_string_list(lua: &Lua, value: &Value) -> Vec<String> {
    let _ = lua;
    match value {
        Value::String(s) => vec![s.to_string_lossy().to_string()],
        Value::Table(t) => {
            let mut result = Vec::new();
            let len = t.raw_len();
            for i in 1..=len {
                if let Ok(s) = t.raw_get::<String>(i) {
                    result.push(s);
                }
            }
            result
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::LuaSandbox;
    use rustmap_types::{Host, HostStatus, OsFingerprint, OsProbeResults, PortState, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_sandbox_with_api() -> LuaSandbox {
        let sandbox = LuaSandbox::new().unwrap();
        register_all(sandbox.lua()).unwrap();
        sandbox
    }

    #[test]
    fn nmap_registry_exists() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox.execute("return type(nmap.registry)").unwrap();
        assert_eq!(result.as_str().unwrap(), "table");
    }

    #[test]
    fn nmap_registry_persists() {
        let sandbox = make_sandbox_with_api();
        sandbox
            .execute(r#"nmap.registry["test"] = "hello""#)
            .unwrap();
        let result = sandbox
            .execute(r#"return nmap.registry["test"]"#)
            .unwrap();
        assert_eq!(result.as_str().unwrap(), "hello");
    }

    #[test]
    fn nmap_verbosity_returns_number() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox.execute("return nmap.verbosity()").unwrap();
        assert_eq!(result.as_integer(), Some(0));
    }

    #[test]
    fn nmap_debugging_returns_number() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox.execute("return nmap.debugging()").unwrap();
        assert_eq!(result.as_integer(), Some(0));
    }

    #[test]
    fn shortport_port_or_service_matches_port() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox
            .execute(
                r#"
            local rule = shortport.port_or_service({80, 443}, {"http"}, nil, nil)
            local host = {ip = "127.0.0.1"}
            local port = {number = 80, protocol = "tcp", state = "open"}
            return rule(host, port)
        "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(true));
    }

    #[test]
    fn shortport_port_or_service_matches_service() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox
            .execute(
                r#"
            local rule = shortport.port_or_service({80}, {"http", "https"}, nil, nil)
            local host = {ip = "127.0.0.1"}
            local port = {number = 8080, protocol = "tcp", state = "open", service = {name = "http"}}
            return rule(host, port)
        "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(true));
    }

    #[test]
    fn shortport_port_or_service_no_match() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox
            .execute(
                r#"
            local rule = shortport.port_or_service({80}, {"http"}, nil, nil)
            local host = {ip = "127.0.0.1"}
            local port = {number = 22, protocol = "tcp", state = "open", service = {name = "ssh"}}
            return rule(host, port)
        "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(false));
    }

    #[test]
    fn build_host_table_basic() {
        let sandbox = make_sandbox_with_api();
        let host_result = HostScanResult {
            host: Host {
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                hostname: Some("example.com".into()),
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

        let table = build_host_table(sandbox.lua(), &host_result).unwrap();
        let ip: String = table.get("ip").unwrap();
        assert_eq!(ip, "192.168.1.1");
        let name: String = table.get("name").unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn build_host_table_with_os() {
        let sandbox = make_sandbox_with_api();
        let host_result = HostScanResult {
            host: Host::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            ports: vec![],
            scan_duration: Duration::from_millis(100),
            host_status: HostStatus::Up,
            discovery_latency: None,
            os_fingerprint: Some(OsFingerprint {
                os_family: Some("Linux".into()),
                os_generation: Some("5.x".into()),
                accuracy: Some(92),
                probe_results: OsProbeResults::default(),
            }),
            traceroute: None,
            timing_snapshot: None,
            host_script_results: vec![],
            scan_error: None,
            uptime_estimate: None,
            risk_score: None,
            mtu: None,
        };

        let table = build_host_table(sandbox.lua(), &host_result).unwrap();
        let os_table: Table = table.get("os").unwrap();
        let family: String = os_table.get("family").unwrap();
        assert_eq!(family, "Linux");
        let generation: String = os_table.get("generation").unwrap();
        assert_eq!(generation, "5.x");
        let accuracy: u8 = os_table.get("accuracy").unwrap();
        assert_eq!(accuracy, 92);
    }

    #[test]
    fn build_port_table_basic() {
        let sandbox = make_sandbox_with_api();
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

        let table = build_port_table(sandbox.lua(), &port).unwrap();
        let num: u16 = table.get("number").unwrap();
        assert_eq!(num, 80);
        let proto: String = table.get("protocol").unwrap();
        assert_eq!(proto, "tcp");
        let state: String = table.get("state").unwrap();
        assert_eq!(state, "open");

        let service: Table = table.get("service").unwrap();
        let name: String = service.get("name").unwrap();
        assert_eq!(name, "http");
    }

    #[test]
    fn nmap_new_socket_creates_userdata() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox
            .execute("return type(nmap.new_socket())")
            .unwrap();
        assert_eq!(result.as_str().unwrap(), "userdata");
    }

    #[test]
    fn nmap_new_socket_has_methods() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_socket()
                s:set_timeout(1000)
                s:close()
                return true
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(true));
    }

    #[test]
    fn nmap_new_udp_socket_creates_userdata() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox
            .execute("return type(nmap.new_udp_socket())")
            .unwrap();
        assert_eq!(result.as_str().unwrap(), "userdata");
    }

    #[test]
    fn nmap_new_udp_socket_has_methods() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_udp_socket()
                s:set_timeout(1000)
                s:close()
                return true
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(true));
    }

    #[test]
    fn nmap_md5_correct_hash() {
        let sandbox = make_sandbox_with_api();
        // MD5("test") = 098f6bcd4621d373cade4e832627b4f6
        let result = sandbox.execute(r#"return nmap.md5("test")"#).unwrap();
        assert_eq!(
            result.as_str().unwrap(),
            "098f6bcd4621d373cade4e832627b4f6"
        );
    }

    #[test]
    fn nmap_md5_empty_string() {
        let sandbox = make_sandbox_with_api();
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let result = sandbox.execute(r#"return nmap.md5("")"#).unwrap();
        assert_eq!(
            result.as_str().unwrap(),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn nmap_md5_binary_data() {
        let sandbox = make_sandbox_with_api();
        let result = sandbox
            .execute(r#"return nmap.md5("\x00\x01\x02\x03")"#)
            .unwrap();
        // Just verify it returns a 32-char hex string
        let hash = result.as_str().unwrap();
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn build_port_table_with_service_info() {
        let sandbox = make_sandbox_with_api();
        let port = Port {
            number: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some("ssh".into()),
            service_info: Some(rustmap_types::ServiceInfo {
                name: "ssh".into(),
                product: Some("OpenSSH".into()),
                version: Some("8.9p1".into()),
                info: None,
                method: rustmap_types::DetectionMethod::Probe,
            }),
            reason: None,
            script_results: vec![],
            tls_info: None,
        };

        let table = build_port_table(sandbox.lua(), &port).unwrap();
        let service: Table = table.get("service").unwrap();
        let product: String = service.get("product").unwrap();
        assert_eq!(product, "OpenSSH");
        let version: String = service.get("version").unwrap();
        assert_eq!(version, "8.9p1");
    }
}
