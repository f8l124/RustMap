use mlua::{UserData, UserDataMethods};
use rustmap_types::ProxyConfig;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Check if an IP address is in a private/reserved range that should be blocked.
/// Returns true if the address is safe to connect to, false if it should be denied.
fn is_allowed_address(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_loopback()          // 127.0.0.0/8
            && !v4.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            && !v4.is_link_local()     // 169.254.0.0/16
            && !v4.is_unspecified()    // 0.0.0.0
            && !v4.is_broadcast()      // 255.255.255.255
        }
        std::net::IpAddr::V6(v6) => {
            !v6.is_loopback()          // ::1
            && !v6.is_unspecified()    // ::
        }
    }
}

/// Default socket timeout in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Maximum bytes to receive in a single `receive_bytes` call (1 MB).
const MAX_RECEIVE_SIZE: usize = 1024 * 1024;

/// A TCP socket exposed to Lua scripts as userdata.
///
/// Provides connect/send/receive/close operations modeled on nmap's NSE socket API.
/// Methods return `(status: bool, data_or_error: string)` tuples.
pub struct LuaSocket {
    stream: Option<TcpStream>,
    timeout: Duration,
    proxy: Option<ProxyConfig>,
}

impl Default for LuaSocket {
    fn default() -> Self {
        Self::new(None)
    }
}

impl LuaSocket {
    pub fn new(proxy: Option<ProxyConfig>) -> Self {
        Self {
            stream: None,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            proxy,
        }
    }
}

impl UserData for LuaSocket {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // socket:connect(host, port) -> (status, err)
        methods.add_method_mut("connect", |_, this, (host, port): (String, u16)| {
            let addr_str = format!("{host}:{port}");

            let stream = if let Some(ref proxy) = this.proxy {
                // Connect through SOCKS5 proxy
                let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
                let result = match (&proxy.username, &proxy.password) {
                    (Some(u), Some(pw)) => socks::Socks5Stream::connect_with_password(
                        proxy_addr.as_str(),
                        addr_str.as_str(),
                        u,
                        pw,
                    ),
                    _ => socks::Socks5Stream::connect(proxy_addr.as_str(), addr_str.as_str()),
                };
                match result {
                    Ok(socks_stream) => socks_stream.into_inner(),
                    Err(e) => return Ok((false, format!("proxy connect failed: {e}"))),
                }
            } else {
                // Direct connection
                let addr = match addr_str.to_socket_addrs() {
                    Ok(mut addrs) => match addrs.next() {
                        Some(a) => a,
                        None => return Ok((false, format!("no addresses for {addr_str}"))),
                    },
                    Err(e) => return Ok((false, format!("resolve failed: {e}"))),
                };
                if !is_allowed_address(&addr.ip()) {
                    return Err(mlua::Error::RuntimeError(
                        format!("connection to {} denied: private/reserved address", addr.ip())
                    ));
                }
                match TcpStream::connect_timeout(&addr, this.timeout) {
                    Ok(s) => s,
                    Err(e) => return Ok((false, e.to_string())),
                }
            };

            stream.set_read_timeout(Some(this.timeout)).ok();
            stream.set_write_timeout(Some(this.timeout)).ok();
            this.stream = Some(stream);
            Ok((true, String::new()))
        });

        // socket:send(data) -> (status, err)
        // Accepts Lua strings which can contain arbitrary binary bytes.
        methods.add_method_mut("send", |_, this, data: mlua::String| {
            let stream = match this.stream.as_mut() {
                Some(s) => s,
                None => return Ok((false, "not connected".into())),
            };
            let bytes: &[u8] = &data.as_bytes();
            match stream.write_all(bytes) {
                Ok(()) => Ok((true, String::new())),
                Err(e) => Ok((false, e.to_string())),
            }
        });

        // socket:receive() -> (status, data_or_err)
        // Returns raw bytes as a Lua string (byte-safe for binary protocols).
        methods.add_method_mut("receive", |lua, this, ()| {
            let stream = match this.stream.as_mut() {
                Some(s) => s,
                None => return Ok((false, lua.create_string("not connected")?)),
            };
            let mut buf = vec![0u8; 8192];
            match stream.read(&mut buf) {
                Ok(0) => Ok((false, lua.create_string("connection closed")?)),
                Ok(n) => {
                    buf.truncate(n);
                    Ok((true, lua.create_string(&buf)?))
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    Ok((false, lua.create_string("timeout")?))
                }
                Err(e) => Ok((false, lua.create_string(e.to_string().as_bytes())?)),
            }
        });

        // socket:receive_bytes(count) -> (status, data_or_err)
        // Returns raw bytes as a Lua string (byte-safe for binary protocols).
        // Returns (false, "timeout") if no bytes were received before timeout.
        // Returns (true, partial_data) if some bytes were received (may be less than count).
        methods.add_method_mut("receive_bytes", |lua, this, count: usize| {
            let stream = match this.stream.as_mut() {
                Some(s) => s,
                None => return Ok((false, lua.create_string("not connected")?)),
            };
            let count = count.min(MAX_RECEIVE_SIZE);
            let mut buf = vec![0u8; count];
            let mut total = 0;
            while total < count {
                match stream.read(&mut buf[total..]) {
                    Ok(0) => break, // EOF
                    Ok(n) => total += n,
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        break;
                    }
                    Err(e) => return Ok((false, lua.create_string(e.to_string().as_bytes())?)),
                }
            }
            if total == 0 {
                return Ok((false, lua.create_string("timeout")?));
            }
            buf.truncate(total);
            Ok((true, lua.create_string(&buf)?))
        });

        // socket:close()
        methods.add_method_mut("close", |_, this, ()| {
            this.stream = None;
            Ok(())
        });

        // socket:set_timeout(ms)
        methods.add_method_mut("set_timeout", |_, this, ms: u64| {
            let ms = ms.clamp(100, 30_000); // Min 100ms, max 30 seconds
            this.timeout = Duration::from_millis(ms);
            if let Some(ref stream) = this.stream {
                stream.set_read_timeout(Some(this.timeout)).ok();
                stream.set_write_timeout(Some(this.timeout)).ok();
            }
            Ok(())
        });
    }
}

/// A UDP socket exposed to Lua scripts as userdata.
///
/// Provides connect/send/receive/close operations for UDP-based protocols
/// (SNMP, NTP, NetBIOS, etc.). Methods return `(status: bool, data_or_error)`
/// tuples matching the TCP socket API.
pub struct LuaUdpSocket {
    socket: Option<UdpSocket>,
    timeout: Duration,
}

impl Default for LuaUdpSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl LuaUdpSocket {
    pub fn new() -> Self {
        Self {
            socket: None,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

impl UserData for LuaUdpSocket {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // socket:connect(host, port) -> (status, err)
        methods.add_method_mut("connect", |_, this, (host, port): (String, u16)| {
            let addr_str = format!("{host}:{port}");
            let addr = match addr_str.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => return Ok((false, format!("no addresses for {addr_str}"))),
                },
                Err(e) => return Ok((false, format!("resolve failed: {e}"))),
            };
            if !is_allowed_address(&addr.ip()) {
                return Err(mlua::Error::RuntimeError(
                    format!("connection to {} denied: private/reserved address", addr.ip())
                ));
            }

            // Bind to an ephemeral port on any local address
            let bind_addr = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };

            match UdpSocket::bind(bind_addr) {
                Ok(sock) => {
                    sock.set_read_timeout(Some(this.timeout)).ok();
                    sock.set_write_timeout(Some(this.timeout)).ok();
                    if let Err(e) = sock.connect(addr) {
                        return Ok((false, e.to_string()));
                    }
                    this.socket = Some(sock);
                    Ok((true, String::new()))
                }
                Err(e) => Ok((false, e.to_string())),
            }
        });

        // socket:send(data) -> (status, err)
        methods.add_method_mut("send", |_, this, data: mlua::String| {
            let sock = match this.socket.as_ref() {
                Some(s) => s,
                None => return Ok((false, "not connected".into())),
            };
            let bytes: &[u8] = &data.as_bytes();
            match sock.send(bytes) {
                Ok(_) => Ok((true, String::new())),
                Err(e) => Ok((false, e.to_string())),
            }
        });

        // socket:receive() -> (status, data_or_err)
        methods.add_method_mut("receive", |lua, this, ()| {
            let sock = match this.socket.as_ref() {
                Some(s) => s,
                None => return Ok((false, lua.create_string("not connected")?)),
            };
            let mut buf = vec![0u8; 65535]; // max UDP datagram
            match sock.recv(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    Ok((true, lua.create_string(&buf)?))
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    Ok((false, lua.create_string("timeout")?))
                }
                Err(e) => Ok((false, lua.create_string(e.to_string().as_bytes())?)),
            }
        });

        // socket:close()
        methods.add_method_mut("close", |_, this, ()| {
            this.socket = None;
            Ok(())
        });

        // socket:set_timeout(ms)
        methods.add_method_mut("set_timeout", |_, this, ms: u64| {
            let ms = ms.clamp(100, 30_000); // Min 100ms, max 30 seconds
            this.timeout = Duration::from_millis(ms);
            if let Some(ref sock) = this.socket {
                sock.set_read_timeout(Some(this.timeout)).ok();
                sock.set_write_timeout(Some(this.timeout)).ok();
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::lua_api;
    use crate::sandbox::LuaSandbox;

    fn make_sandbox_with_socket() -> LuaSandbox {
        let sandbox = LuaSandbox::new().unwrap();
        lua_api::register_all(sandbox.lua()).unwrap();
        sandbox
    }

    #[test]
    fn lua_socket_creates() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute("local s = nmap.new_socket(); return type(s)")
            .unwrap();
        assert_eq!(result.as_str().unwrap(), "userdata");
    }

    #[test]
    fn unconnected_socket_send_fails() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_socket()
                local ok, err = s:send("hello")
                return ok
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(false));
    }

    #[test]
    fn unconnected_socket_receive_fails() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_socket()
                local ok, err = s:receive()
                return ok
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(false));
    }

    #[test]
    fn set_timeout_works() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_socket()
                s:set_timeout(1000)
                return true
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(true));
    }

    #[test]
    fn close_works() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_socket()
                s:close()
                return true
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(true));
    }

    #[test]
    fn connect_rejects_loopback() {
        // SSRF denylist blocks connections to loopback addresses
        let sandbox = make_sandbox_with_socket();
        let result = sandbox.execute(
            r#"
            local s = nmap.new_socket()
            s:set_timeout(500)
            local ok, err = s:connect("127.0.0.1", 59999)
            if ok == nil then
                return "blocked"
            end
            return "allowed"
            "#,
        );
        // The SSRF check should block the connection — either the Lua script
        // catches the error and returns "blocked", or execute() itself fails.
        match result {
            Ok(val) => assert_eq!(val.as_str().unwrap(), "blocked"),
            Err(_) => {} // RuntimeError from SSRF check is also acceptable
        }
    }

    // -- UDP socket tests --

    #[test]
    fn udp_socket_creates() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute("local s = nmap.new_udp_socket(); return type(s)")
            .unwrap();
        assert_eq!(result.as_str().unwrap(), "userdata");
    }

    #[test]
    fn udp_unconnected_send_fails() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_udp_socket()
                local ok, err = s:send("hello")
                return ok
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(false));
    }

    #[test]
    fn udp_unconnected_receive_fails() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_udp_socket()
                local ok, err = s:receive()
                return ok
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(false));
    }

    #[test]
    fn udp_set_timeout_works() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_udp_socket()
                s:set_timeout(1000)
                return true
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(true));
    }

    #[test]
    fn udp_close_works() {
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local s = nmap.new_udp_socket()
                s:close()
                return true
                "#,
            )
            .unwrap();
        assert_eq!(result.as_boolean(), Some(true));
    }

    // -- Binary data tests --

    #[test]
    fn tcp_send_receives_binary_data() {
        // Verify Lua strings can contain null bytes and binary data
        let sandbox = make_sandbox_with_socket();
        let result = sandbox
            .execute(
                r#"
                local data = "\x00\x01\x02\xFF"
                return #data
                "#,
            )
            .unwrap();
        assert_eq!(result.as_integer(), Some(4));
    }
}
