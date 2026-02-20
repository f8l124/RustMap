use crate::privilege::PacketError;

/// Fragment an IPv4 packet into 8-byte payload fragments for IDS evasion.
///
/// Returns a Vec of complete IP packets, each with proper MF (More Fragments)
/// flag and fragment offset. The IP header is duplicated for each fragment.
///
/// Only works with IPv4 packets (IPv6 uses extension headers for fragmentation,
/// which is handled differently and rarely used for evasion).
///
/// # Fragment structure
/// Each fragment has:
/// - Same IP header as original (with updated total_length, MF flag, frag_offset)
/// - 8 bytes of the original transport payload (last fragment may be smaller)
/// - Recalculated IP header checksum
pub fn fragment_ipv4_packet(packet: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
    // Minimum IPv4 header is 20 bytes
    if packet.len() < 20 {
        return Err(PacketError::BuildFailed(
            "packet too short to fragment".into(),
        ));
    }

    // Check IP version
    let version = packet[0] >> 4;
    if version != 4 {
        return Err(PacketError::BuildFailed(
            "fragmentation only supported for IPv4".into(),
        ));
    }

    // IP header length (IHL field, in 32-bit words)
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if ihl < 20 || ihl > packet.len() {
        return Err(PacketError::BuildFailed(
            "invalid IP header length".into(),
        ));
    }

    let payload = &packet[ihl..];
    if payload.is_empty() {
        // Nothing to fragment
        return Ok(vec![packet.to_vec()]);
    }

    // Fragment size must be a multiple of 8 bytes
    const FRAG_SIZE: usize = 8;

    let mut fragments = Vec::new();
    let total_chunks = payload.len().div_ceil(FRAG_SIZE);

    for (i, chunk) in payload.chunks(FRAG_SIZE).enumerate() {
        let is_last = i == total_chunks - 1;
        let frag_offset = (i * FRAG_SIZE / 8) as u16; // In 8-byte units

        let mut frag = Vec::with_capacity(ihl + chunk.len());

        // Copy original IP header
        frag.extend_from_slice(&packet[..ihl]);

        // Update total length (IP header + fragment payload)
        let total_len = (ihl + chunk.len()) as u16;
        frag[2] = (total_len >> 8) as u8;
        frag[3] = (total_len & 0xFF) as u8;

        // Update flags + fragment offset (bytes 6-7)
        // Flags: bit 15 = reserved, bit 14 = DF, bit 13 = MF
        // Fragment offset: 13 bits, in 8-byte units
        // Preserve the reserved bit from the original flags byte (top bit of byte 6 = bit 15)
        let original_reserved: u16 = ((packet[6] & 0x80) as u16) << 8;
        let mf_flag: u16 = if is_last { 0 } else { 0x2000 }; // MF = bit 13
        let flags_and_offset = original_reserved | mf_flag | frag_offset;
        frag[6] = (flags_and_offset >> 8) as u8;
        frag[7] = (flags_and_offset & 0xFF) as u8;

        // Append fragment payload
        frag.extend_from_slice(chunk);

        // Recalculate IP header checksum
        // Zero out old checksum first
        frag[10] = 0;
        frag[11] = 0;
        let checksum = ip_checksum(&frag[..ihl]);
        frag[10] = (checksum >> 8) as u8;
        frag[11] = (checksum & 0xFF) as u8;

        fragments.push(frag);
    }

    Ok(fragments)
}

/// Calculate the IP header checksum (RFC 1071).
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += ((header[i] as u32) << 8) | (header[i + 1] as u32);
        i += 2;
    }
    // Handle odd byte
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4 TCP SYN packet for testing.
    fn make_test_packet(payload_size: usize) -> Vec<u8> {
        let total_len = 20 + payload_size; // 20-byte IP header + payload
        let mut pkt = vec![0u8; total_len];

        // IP header
        pkt[0] = 0x45; // Version=4, IHL=5 (20 bytes)
        pkt[2] = (total_len >> 8) as u8;
        pkt[3] = (total_len & 0xFF) as u8;
        pkt[8] = 64; // TTL
        pkt[9] = 6; // Protocol: TCP

        // Source IP: 10.0.0.1
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        // Destination IP: 10.0.0.2
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);

        // Fill payload with recognizable pattern
        for (i, byte) in pkt[20..].iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }

        // Calculate checksum
        pkt[10] = 0;
        pkt[11] = 0;
        let cksum = ip_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xFF) as u8;

        pkt
    }

    #[test]
    fn fragment_40_byte_tcp_syn() {
        // 20-byte IP header + 20-byte TCP header = 40 bytes total
        let pkt = make_test_packet(20);
        let fragments = fragment_ipv4_packet(&pkt).unwrap();

        // 20 bytes payload / 8 = 2.5 → 3 fragments
        assert_eq!(fragments.len(), 3);

        // Fragment 1: 20 IP + 8 payload = 28 bytes
        assert_eq!(fragments[0].len(), 28);
        // Fragment 2: 20 IP + 8 payload = 28 bytes
        assert_eq!(fragments[1].len(), 28);
        // Fragment 3: 20 IP + 4 payload = 24 bytes (last chunk)
        assert_eq!(fragments[2].len(), 24);
    }

    #[test]
    fn fragment_sets_mf_flag_on_non_last() {
        let pkt = make_test_packet(16); // 2 fragments of 8 bytes each
        let fragments = fragment_ipv4_packet(&pkt).unwrap();

        assert_eq!(fragments.len(), 2);

        // First fragment: MF bit should be set (bit 13 = 0x2000)
        let flags1 = ((fragments[0][6] as u16) << 8) | (fragments[0][7] as u16);
        assert!(flags1 & 0x2000 != 0, "MF flag should be set on first fragment");

        // Last fragment: MF bit should be clear
        let flags2 = ((fragments[1][6] as u16) << 8) | (fragments[1][7] as u16);
        assert!(flags2 & 0x2000 == 0, "MF flag should not be set on last fragment");
    }

    #[test]
    fn fragment_offsets_are_correct() {
        let pkt = make_test_packet(24); // 3 fragments
        let fragments = fragment_ipv4_packet(&pkt).unwrap();

        assert_eq!(fragments.len(), 3);

        // Fragment 0: offset = 0
        let off0 = ((fragments[0][6] as u16 & 0x1F) << 8) | (fragments[0][7] as u16);
        assert_eq!(off0, 0);

        // Fragment 1: offset = 1 (8 bytes / 8 = 1)
        let off1 = ((fragments[1][6] as u16 & 0x1F) << 8) | (fragments[1][7] as u16);
        assert_eq!(off1, 1);

        // Fragment 2: offset = 2 (16 bytes / 8 = 2)
        let off2 = ((fragments[2][6] as u16 & 0x1F) << 8) | (fragments[2][7] as u16);
        assert_eq!(off2, 2);
    }

    #[test]
    fn fragment_preserves_ip_header_fields() {
        let pkt = make_test_packet(16);
        let fragments = fragment_ipv4_packet(&pkt).unwrap();

        for frag in &fragments {
            // Version and IHL
            assert_eq!(frag[0], 0x45);
            // TTL
            assert_eq!(frag[8], 64);
            // Protocol: TCP
            assert_eq!(frag[9], 6);
            // Source IP
            assert_eq!(&frag[12..16], &[10, 0, 0, 1]);
            // Destination IP
            assert_eq!(&frag[16..20], &[10, 0, 0, 2]);
        }
    }

    #[test]
    fn fragment_updates_total_length() {
        let pkt = make_test_packet(20); // 3 frags: 8, 8, 4
        let fragments = fragment_ipv4_packet(&pkt).unwrap();

        // Fragment 1: IP(20) + 8 = 28
        let len1 = ((fragments[0][2] as u16) << 8) | (fragments[0][3] as u16);
        assert_eq!(len1, 28);

        // Fragment 3: IP(20) + 4 = 24
        let len3 = ((fragments[2][2] as u16) << 8) | (fragments[2][3] as u16);
        assert_eq!(len3, 24);
    }

    #[test]
    fn fragment_checksum_is_valid() {
        let pkt = make_test_packet(16);
        let fragments = fragment_ipv4_packet(&pkt).unwrap();

        for frag in &fragments {
            // Verify checksum: sum of all 16-bit words in IP header should be 0xFFFF
            let cksum = ip_checksum(&frag[..20]);
            assert_eq!(cksum, 0, "IP checksum should validate to 0 (one's complement)");
        }
    }

    #[test]
    fn empty_payload_returns_original() {
        let pkt = make_test_packet(0);
        let fragments = fragment_ipv4_packet(&pkt).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], pkt);
    }

    #[test]
    fn rejects_ipv6() {
        let mut pkt = make_test_packet(16);
        pkt[0] = 0x60; // IPv6 version
        assert!(fragment_ipv4_packet(&pkt).is_err());
    }

    #[test]
    fn rejects_too_short() {
        let pkt = vec![0u8; 10];
        assert!(fragment_ipv4_packet(&pkt).is_err());
    }
}
