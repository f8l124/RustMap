//! Windows networking helpers for MAC address and gateway resolution.
//!
//! Uses the IP Helper API (`iphlpapi.dll`) to retrieve adapter information,
//! resolve MAC addresses, and determine correct Ethernet frame addressing
//! for Npcap packet injection.

use std::net::Ipv4Addr;

use tracing::{debug, warn};
use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_GATEWAY_ADDRESS_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, SendARP,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR, SOCKADDR_IN};

/// Flag for `GetAdaptersAddresses` to include gateway addresses in results.
/// Without this flag (on Vista+), `FirstGatewayAddress` is NULL.
const GAA_FLAG_INCLUDE_GATEWAYS: u32 = 0x0010;

/// Information about a network adapter relevant for raw packet operations.
#[derive(Debug)]
pub struct AdapterInfo {
    /// MAC (physical) address of the adapter.
    pub mac: [u8; 6],
    /// Default gateway IPv4 address, if configured.
    pub gateway: Option<Ipv4Addr>,
    /// Subnet prefix length (e.g., 24 for a /24 network).
    pub prefix_len: u8,
}

/// Retrieve adapter information for the adapter that owns `src_ip`.
///
/// Calls `GetAdaptersAddresses` to enumerate all network adapters and finds
/// the one whose unicast address matches `src_ip`. Returns its MAC address,
/// default gateway, and subnet prefix length.
///
/// Returns `None` if no matching adapter is found or if the API call fails.
pub fn get_adapter_info(src_ip: Ipv4Addr) -> Option<AdapterInfo> {
    // SAFETY: All pointer operations are bounded by the buffer allocated from
    // GetAdaptersAddresses. The linked-list traversal terminates at NULL.
    unsafe {
        // First call: determine required buffer size
        let mut buf_len: u32 = 0;
        let ret = GetAdaptersAddresses(
            AF_INET as u32,
            GAA_FLAG_INCLUDE_GATEWAYS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut buf_len,
        );
        if ret != ERROR_BUFFER_OVERFLOW {
            warn!(error_code = ret, "GetAdaptersAddresses sizing call failed");
            return None;
        }

        // Allocate buffer and call again
        let mut buf = vec![0u8; buf_len as usize];
        let adapters_ptr = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

        let ret = GetAdaptersAddresses(
            AF_INET as u32,
            GAA_FLAG_INCLUDE_GATEWAYS,
            std::ptr::null_mut(),
            adapters_ptr,
            &mut buf_len,
        );
        if ret != 0 {
            warn!(error_code = ret, "GetAdaptersAddresses failed");
            return None;
        }

        // Walk the linked list of adapters
        let mut adapter = adapters_ptr;
        while !adapter.is_null() {
            let a = &*adapter;

            if let Some(info) = try_match_adapter(a, src_ip) {
                return Some(info);
            }

            adapter = a.Next;
        }

        warn!(%src_ip, "no adapter found matching source IP");
        None
    }
}

/// Try to match a single adapter against the target source IP.
///
/// # Safety
/// Caller must ensure `adapter` points to a valid `IP_ADAPTER_ADDRESSES_LH`.
unsafe fn try_match_adapter(
    adapter: &IP_ADAPTER_ADDRESSES_LH,
    src_ip: Ipv4Addr,
) -> Option<AdapterInfo> {
    let mut unicast = adapter.FirstUnicastAddress;

    while !unicast.is_null() {
        let ua = unsafe { &*unicast };

        if let Some(info) = unsafe { try_match_unicast_address(adapter, ua, src_ip) } {
            return Some(info);
        }

        unicast = ua.Next;
    }

    None
}

/// Try to match a single unicast address against the target source IP.
///
/// # Safety
/// Caller must ensure both pointers are valid.
unsafe fn try_match_unicast_address(
    adapter: &IP_ADAPTER_ADDRESSES_LH,
    ua: &IP_ADAPTER_UNICAST_ADDRESS_LH,
    src_ip: Ipv4Addr,
) -> Option<AdapterInfo> {
    let sockaddr = ua.Address.lpSockaddr;
    if sockaddr.is_null() {
        return None;
    }

    let sa = unsafe { &*(sockaddr as *const SOCKADDR) };
    if sa.sa_family != AF_INET {
        return None;
    }

    let sin = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
    let ip_bytes = unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes();
    let addr = Ipv4Addr::from(ip_bytes);

    if addr != src_ip {
        return None;
    }

    // Found the matching adapter — extract MAC
    let mac_len = adapter.PhysicalAddressLength as usize;
    if mac_len < 6 {
        // Virtual adapter (loopback, tunnel) — no physical MAC
        return None;
    }

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&adapter.PhysicalAddress[..6]);

    let prefix_len = ua.OnLinkPrefixLength;
    let gateway = unsafe { read_first_ipv4_gateway(adapter.FirstGatewayAddress) };

    debug!(
        mac = ?mac,
        ?gateway,
        prefix_len,
        "adapter info resolved for {src_ip}"
    );

    Some(AdapterInfo {
        mac,
        gateway,
        prefix_len,
    })
}

/// Walk the gateway address linked list and return the first IPv4 gateway.
///
/// # Safety
/// Caller must ensure the pointer chain is valid (comes from GetAdaptersAddresses).
unsafe fn read_first_ipv4_gateway(
    first_gw: *mut IP_ADAPTER_GATEWAY_ADDRESS_LH,
) -> Option<Ipv4Addr> {
    let mut gw = first_gw;

    while !gw.is_null() {
        let g = unsafe { &*gw };
        let sockaddr = g.Address.lpSockaddr;

        if !sockaddr.is_null() {
            let sa = unsafe { &*(sockaddr as *const SOCKADDR) };
            if sa.sa_family == AF_INET {
                let sin = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
                let ip_bytes = unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes();
                return Some(Ipv4Addr::from(ip_bytes));
            }
        }

        gw = g.Next;
    }

    None
}

/// Resolve an IPv4 address to a MAC address via ARP.
///
/// Uses the Windows `SendARP` API which checks the system ARP cache first
/// and sends a broadcast ARP request if no cached entry exists.
///
/// This is a blocking call that may take a few seconds on cache miss.
/// Returns `None` if ARP resolution fails (host unreachable, timeout).
pub fn arp_resolve(target_ip: Ipv4Addr, src_ip: Ipv4Addr) -> Option<[u8; 6]> {
    // SendARP expects IP addresses as u32 in network byte order.
    // On little-endian Windows, `to_ne_bytes` on the octets gives us exactly that.
    let dst = u32::from_ne_bytes(target_ip.octets());
    let src = u32::from_ne_bytes(src_ip.octets());

    // Buffer for the returned MAC address (must be at least 6 bytes)
    let mut mac_buf = [0u32; 2]; // ULONG[2] = 8 bytes, properly aligned
    let mut mac_len: u32 = 6;

    // SAFETY: mac_buf is properly sized and aligned. SendARP writes at most
    // mac_len bytes into the buffer.
    let ret = unsafe {
        SendARP(
            dst,
            src,
            mac_buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut mac_len,
        )
    };

    if ret == 0 && mac_len >= 6 {
        let raw = mac_buf.as_ptr() as *const u8;
        let mut mac = [0u8; 6];
        // SAFETY: mac_buf is 8 bytes; reading 6 bytes is in bounds.
        unsafe { std::ptr::copy_nonoverlapping(raw, mac.as_mut_ptr(), 6) };
        debug!(target = %target_ip, mac = ?mac, "ARP resolved");
        Some(mac)
    } else {
        debug!(target = %target_ip, error_code = ret, "ARP resolution failed");
        None
    }
}

/// Check if two IPv4 addresses are on the same subnet given a CIDR prefix length.
pub fn is_same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 32 {
        return a == b;
    }
    let mask = !0u32 << (32 - prefix_len);
    let a_masked = u32::from_be_bytes(a.octets()) & mask;
    let b_masked = u32::from_be_bytes(b.octets()) & mask;
    a_masked == b_masked
}

/// Determine the correct destination MAC for reaching `target_ip` from `src_ip`.
///
/// - **Same subnet**: uses broadcast MAC (`FF:FF:FF:FF:FF:FF`). The Ethernet switch
///   delivers broadcast frames to all ports, so the target will receive the packet
///   and respond using our real source MAC.
/// - **Different subnet**: ARP-resolves the gateway's MAC address so the frame is
///   delivered to the router for forwarding.
/// - **Fallback**: broadcast if gateway is unknown or ARP resolution fails.
pub fn resolve_dst_mac(src_ip: Ipv4Addr, target_ip: Ipv4Addr, adapter: &AdapterInfo) -> [u8; 6] {
    const BROADCAST: [u8; 6] = [0xFF; 6];

    if is_same_subnet(src_ip, target_ip, adapter.prefix_len) {
        debug!(%target_ip, "same subnet — using broadcast dst MAC");
        return BROADCAST;
    }

    // Cross-subnet: resolve gateway MAC via ARP
    match adapter.gateway {
        Some(gw) => {
            debug!(gateway = %gw, "resolving gateway MAC via ARP");
            arp_resolve(gw, src_ip).unwrap_or_else(|| {
                warn!(gateway = %gw, "gateway ARP failed — falling back to broadcast");
                BROADCAST
            })
        }
        None => {
            warn!("no gateway configured — using broadcast dst MAC");
            BROADCAST
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_same_subnet ---

    #[test]
    fn same_subnet_24() {
        assert!(is_same_subnet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 254),
            24,
        ));
    }

    #[test]
    fn different_subnet_24() {
        assert!(!is_same_subnet(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 2, 1),
            24,
        ));
    }

    #[test]
    fn same_subnet_16() {
        assert!(is_same_subnet(
            Ipv4Addr::new(10, 0, 1, 1),
            Ipv4Addr::new(10, 0, 254, 254),
            16,
        ));
    }

    #[test]
    fn different_subnet_16() {
        assert!(!is_same_subnet(
            Ipv4Addr::new(10, 0, 1, 1),
            Ipv4Addr::new(10, 1, 1, 1),
            16,
        ));
    }

    #[test]
    fn prefix_0_always_same() {
        assert!(is_same_subnet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(200, 100, 50, 25),
            0,
        ));
    }

    #[test]
    fn prefix_32_requires_exact_match() {
        assert!(is_same_subnet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            32,
        ));
        assert!(!is_same_subnet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            32,
        ));
    }

    #[test]
    fn boundary_at_prefix_24() {
        // .0 and .255 are in the same /24
        assert!(is_same_subnet(
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 255),
            24,
        ));
        // .0 of next /24 is different
        assert!(!is_same_subnet(
            Ipv4Addr::new(10, 0, 0, 255),
            Ipv4Addr::new(10, 0, 1, 0),
            24,
        ));
    }

    // --- resolve_dst_mac (unit tests with mock AdapterInfo) ---

    #[test]
    fn resolve_dst_mac_same_subnet_returns_broadcast() {
        let adapter = AdapterInfo {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            prefix_len: 24,
        };
        let dst = resolve_dst_mac(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
            &adapter,
        );
        assert_eq!(dst, [0xFF; 6]);
    }

    #[test]
    fn resolve_dst_mac_no_gateway_returns_broadcast() {
        let adapter = AdapterInfo {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            gateway: None,
            prefix_len: 24,
        };
        let dst = resolve_dst_mac(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(10, 0, 0, 1),
            &adapter,
        );
        // No gateway → must fall back to broadcast
        assert_eq!(dst, [0xFF; 6]);
    }

    // --- get_adapter_info (integration test — requires real adapter) ---

    #[test]
    fn get_adapter_info_loopback_returns_none() {
        // Loopback (127.0.0.1) should not match any physical adapter
        let result = get_adapter_info(Ipv4Addr::new(127, 0, 0, 1));
        assert!(result.is_none());
    }
}
