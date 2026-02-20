//! Service-specific UDP probe payloads for common ports.
//!
//! Many UDP services will only respond to well-formed requests.
//! Sending empty UDP datagrams usually produces no response (→ open|filtered).
//! Service-specific payloads increase the chance of getting a response from open ports.

/// DNS version.bind query (TXT CH class).
const DNS_QUERY: &[u8] = &[
    0x00, 0x00, // Transaction ID
    0x00, 0x00, // Flags: standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    // Query: version.bind TXT CH
    0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n',
    0x04, b'b', b'i', b'n', b'd', 0x00,
    0x00, 0x10, // Type: TXT
    0x00, 0x03, // Class: CH (Chaos)
];

/// NTP v4 client mode request.
const NTP_REQUEST: &[u8] = &[
    0x23, // LI=0, VN=4, Mode=3 (client)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// SNMPv1 GetRequest for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0).
const SNMP_GETREQUEST: &[u8] = &[
    0x30, 0x26, // SEQUENCE, length 38
    0x02, 0x01, 0x00, // INTEGER: version (0 = v1)
    0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // OCTET STRING: community "public"
    0xa0, 0x19, // GetRequest-PDU, length 25
    0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // request-id: 1
    0x02, 0x01, 0x00, // error-status: 0
    0x02, 0x01, 0x00, // error-index: 0
    0x30, 0x0b, // varbind list, length 11
    0x30, 0x09, // varbind, length 9
    0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID: 1.3.6.1.2.1 (iso.org.dod.internet.mgmt.mib-2)
    0x05, 0x00, // NULL value
];

/// NetBIOS Name Service node status request.
const NBSTAT_REQUEST: &[u8] = &[
    0x80, 0x94, // Transaction ID
    0x00, 0x00, // Flags
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    // Name: *\x00... (wildcard NBSTAT query)
    0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x00,
    0x00, 0x21, // Type: NBSTAT
    0x00, 0x01, // Class: IN
];

/// SSDP/UPnP M-SEARCH discovery request.
const SSDP_MSEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
Host:239.255.255.250:1900\r\n\
Man:\"ssdp:discover\"\r\n\
ST:ssdp:all\r\n\
MX:1\r\n\r\n";

/// mDNS query for _services._dns-sd._udp.local.
const MDNS_QUERY: &[u8] = &[
    0x00, 0x00, // Transaction ID
    0x00, 0x00, // Flags: standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    // _services._dns-sd._udp.local
    0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's',
    0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
    0x04, b'_', b'u', b'd', b'p',
    0x05, b'l', b'o', b'c', b'a', b'l',
    0x00,
    0x00, 0x0c, // Type: PTR
    0x00, 0x01, // Class: IN
];

/// Get the service-specific UDP payload for a given port.
///
/// Returns a non-empty payload for known services, or an empty slice
/// for unknown ports (which sends an empty UDP datagram).
pub fn udp_payload_for_port(port: u16) -> &'static [u8] {
    match port {
        53 => DNS_QUERY,
        123 => NTP_REQUEST,
        161 => SNMP_GETREQUEST,
        137 => NBSTAT_REQUEST,
        1900 => SSDP_MSEARCH,
        5353 => MDNS_QUERY,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports_have_payloads() {
        assert!(!udp_payload_for_port(53).is_empty());
        assert!(!udp_payload_for_port(123).is_empty());
        assert!(!udp_payload_for_port(161).is_empty());
        assert!(!udp_payload_for_port(137).is_empty());
        assert!(!udp_payload_for_port(1900).is_empty());
        assert!(!udp_payload_for_port(5353).is_empty());
    }

    #[test]
    fn unknown_ports_return_empty() {
        assert!(udp_payload_for_port(80).is_empty());
        assert!(udp_payload_for_port(443).is_empty());
        assert!(udp_payload_for_port(9999).is_empty());
    }

    #[test]
    fn dns_query_starts_with_transaction_id() {
        let payload = udp_payload_for_port(53);
        // First 2 bytes are transaction ID, next 2 are flags
        assert!(payload.len() > 4);
    }

    #[test]
    fn ntp_request_is_48_bytes() {
        let payload = udp_payload_for_port(123);
        assert_eq!(payload.len(), 48);
        // First byte: LI=0, VN=4, Mode=3 → 0x23
        assert_eq!(payload[0], 0x23);
    }
}
