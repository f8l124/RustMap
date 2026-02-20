use std::net::IpAddr;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::DetectionError;
use crate::proxy::connect_tcp;
use rustmap_types::{CertificateInfo, ProxyConfig, TlsServerFingerprint};

/// Timeout for TLS probe connection and handshake.
const TLS_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Ports commonly associated with TLS services.
pub const TLS_PORTS: &[u16] = &[443, 8443, 993, 995, 465, 636, 989, 990, 992, 994, 5061, 8883];

/// Cipher suites offered in our ClientHello (broad selection to elicit server preference).
const CIPHER_SUITES: &[[u8; 2]] = &[
    // TLS 1.3
    [0x13, 0x01], // TLS_AES_128_GCM_SHA256
    [0x13, 0x02], // TLS_AES_256_GCM_SHA384
    [0x13, 0x03], // TLS_CHACHA20_POLY1305_SHA256
    // TLS 1.2 ECDHE
    [0xC0, 0x2F], // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    [0xC0, 0x30], // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    [0xC0, 0x2B], // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    [0xC0, 0x2C], // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    [0xC0, 0x27], // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    [0xC0, 0x28], // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    // TLS 1.2 RSA
    [0x00, 0x9C], // TLS_RSA_WITH_AES_128_GCM_SHA256
    [0x00, 0x9D], // TLS_RSA_WITH_AES_256_GCM_SHA384
    [0x00, 0x2F], // TLS_RSA_WITH_AES_128_CBC_SHA
    [0x00, 0x35], // TLS_RSA_WITH_AES_256_CBC_SHA
];

/// Probe a TLS server and extract a fingerprint from its ServerHello.
///
/// Connects to the target, sends a crafted ClientHello with a broad cipher suite
/// offering, and parses the ServerHello response to extract distinguishing features.
pub async fn probe_tls_server(
    target_ip: IpAddr,
    port: u16,
    hostname: Option<&str>,
    proxy: Option<&ProxyConfig>,
) -> Result<Option<TlsServerFingerprint>, DetectionError> {
    let addr = std::net::SocketAddr::new(target_ip, port);

    let stream = match connect_tcp(addr, proxy, TLS_PROBE_TIMEOUT).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            debug!(port, "TLS probe: connection timed out");
            return Ok(None);
        }
        Err(e) => {
            debug!(port, error = %e, "TLS probe: connection failed");
            return Ok(None);
        }
    };

    let client_hello = build_client_hello(hostname);
    let (mut reader, mut writer) = stream.into_split();

    match tokio::time::timeout(TLS_PROBE_TIMEOUT, writer.write_all(&client_hello)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            debug!(port, error = %e, "TLS probe: write failed");
            return Ok(None);
        }
        Err(_) => {
            debug!(port, "TLS probe: write timed out");
            return Ok(None);
        }
    }

    // Multi-read: accumulate approximately 16KB, stopping on ServerHelloDone (0x0E)
    let mut buf = Vec::with_capacity(16384);
    let mut tmp = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + TLS_PROBE_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() || buf.len() >= 16384 {
            break;
        }
        match tokio::time::timeout(remaining, reader.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => {
                buf.extend_from_slice(&tmp[..n]);
                if has_server_hello_done(&buf) {
                    break;
                }
            }
            _ => break,
        }
    }

    if buf.is_empty() {
        debug!(port, "TLS probe: empty response");
        return Ok(None);
    }

    let (mut fp, certs) = parse_tls_handshake_flight(&buf);
    if let Some(ref mut fingerprint) = fp {
        fingerprint.sni = hostname.map(|s| s.to_string());
        fingerprint.ja4s = Some(compute_ja4s(fingerprint));
        if fingerprint.tls_version <= 0x0303 {
            // TLS 1.2 and below: certs are sent in plaintext
            fingerprint.certificate_chain = certs;
        }
    }
    Ok(fp)
}

/// Check if a port is commonly associated with TLS.
pub fn is_tls_port(port: u16) -> bool {
    TLS_PORTS.contains(&port)
}

/// Build a TLS ClientHello message with a broad cipher suite offering.
fn build_client_hello(hostname: Option<&str>) -> Vec<u8> {
    let mut hello_body = Vec::new();

    // Client version: TLS 1.2 (0x0303)
    hello_body.extend_from_slice(&[0x03, 0x03]);

    // Random (32 bytes): timestamp + pseudorandom fill
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    hello_body.extend_from_slice(&ts.to_be_bytes());
    for i in 0u8..28 {
        hello_body.push(i.wrapping_mul(7).wrapping_add(0x42));
    }

    // Session ID length: 0 (no session resumption)
    hello_body.push(0);

    // Cipher suites
    let suites_len = (CIPHER_SUITES.len() * 2) as u16;
    hello_body.extend_from_slice(&suites_len.to_be_bytes());
    for suite in CIPHER_SUITES {
        hello_body.extend_from_slice(suite);
    }

    // Compression methods: 1 method, null (0x00)
    hello_body.push(1);
    hello_body.push(0);

    // Extensions
    let extensions = build_extensions(hostname);
    let ext_len = extensions.len() as u16;
    hello_body.extend_from_slice(&ext_len.to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    // Wrap in Handshake message (type=ClientHello)
    let mut handshake = Vec::new();
    handshake.push(0x01); // HandshakeType: ClientHello
    let body_len = hello_body.len() as u32;
    handshake.push((body_len >> 16) as u8);
    handshake.push((body_len >> 8) as u8);
    handshake.push(body_len as u8);
    handshake.extend_from_slice(&hello_body);

    // Wrap in TLS Record
    let mut record = Vec::new();
    record.push(0x16); // ContentType: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // Record version: TLS 1.0 (for compat)
    let record_len = handshake.len() as u16;
    record.extend_from_slice(&record_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Build ClientHello extensions.
fn build_extensions(hostname: Option<&str>) -> Vec<u8> {
    let mut exts = Vec::new();

    // server_name (SNI) (0x0000) — only when hostname is provided
    if let Some(host) = hostname {
        let host_bytes = host.as_bytes();
        let mut data = Vec::new();
        // ServerNameList: length(2) + HostName entry
        let list_len = (host_bytes.len() + 3) as u16;
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0x00); // HostNameType: host_name
        data.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(host_bytes);
        append_extension(&mut exts, 0x0000, &data);
    }

    // supported_groups (0x000A)
    {
        // x25519, secp256r1, secp384r1, secp521r1
        let groups: &[u16] = &[0x001D, 0x0017, 0x0018, 0x0019];
        let mut data = Vec::new();
        let list_len = (groups.len() * 2) as u16;
        data.extend_from_slice(&list_len.to_be_bytes());
        for g in groups {
            data.extend_from_slice(&g.to_be_bytes());
        }
        append_extension(&mut exts, 0x000A, &data);
    }

    // ec_point_formats (0x000B)
    {
        let data = [0x01, 0x00]; // 1 format: uncompressed
        append_extension(&mut exts, 0x000B, &data);
    }

    // signature_algorithms (0x000D)
    {
        let algos: &[u16] = &[
            0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha256/384/512
            0x0403, 0x0503, // ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384
            0x0804, 0x0805, // rsa_pss_rsae_sha256/384
        ];
        let mut data = Vec::new();
        let list_len = (algos.len() * 2) as u16;
        data.extend_from_slice(&list_len.to_be_bytes());
        for a in algos {
            data.extend_from_slice(&a.to_be_bytes());
        }
        append_extension(&mut exts, 0x000D, &data);
    }

    // application_layer_protocol_negotiation (ALPN) (0x0010)
    {
        let protocols: &[&[u8]] = &[b"h2", b"http/1.1"];
        let mut list = Vec::new();
        for proto in protocols {
            list.push(proto.len() as u8);
            list.extend_from_slice(proto);
        }
        let mut data = Vec::new();
        data.extend_from_slice(&(list.len() as u16).to_be_bytes());
        data.extend_from_slice(&list);
        append_extension(&mut exts, 0x0010, &data);
    }

    // encrypt_then_mac (0x0016) — empty
    append_extension(&mut exts, 0x0016, &[]);

    // extended_master_secret (0x0017) — empty
    append_extension(&mut exts, 0x0017, &[]);

    // supported_versions (0x002B) — for TLS 1.3 negotiation
    {
        let versions: &[u16] = &[0x0304, 0x0303]; // TLS 1.3, TLS 1.2
        let mut data = Vec::new();
        data.push((versions.len() * 2) as u8); // list length (1 byte for client)
        for v in versions {
            data.extend_from_slice(&v.to_be_bytes());
        }
        append_extension(&mut exts, 0x002B, &data);
    }

    exts
}

/// Append a single TLS extension to the buffer.
fn append_extension(buf: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    buf.extend_from_slice(&ext_type.to_be_bytes());
    let len = data.len() as u16;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// Compute a JA4S (server) fingerprint.
///
/// Format: `t{ver}{ext_count}_{cipher_hex}_{ext_hash}`
/// - `t` = TCP TLS
/// - `ver` = "13" for TLS 1.3, "12" for 1.2, etc.
/// - `ext_count` = zero-padded count of server extensions
/// - `cipher_hex` = 4-hex-char cipher suite
/// - `ext_hash` = first 12 hex chars of SHA-256 of sorted extension types
fn compute_ja4s(fp: &TlsServerFingerprint) -> String {
    let ver = match fp.tls_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let ext_count = format!("{:02}", fp.extensions.len().min(99));
    let cipher_hex = format!("{:04x}", fp.cipher_suite);

    let mut sorted_exts = fp.extensions.clone();
    sorted_exts.sort();
    let ext_str: String = sorted_exts
        .iter()
        .map(|e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");
    let ext_hash = if ext_str.is_empty() {
        "000000000000".to_string()
    } else {
        let hash = Sha256::digest(ext_str.as_bytes());
        let full = format!("{:x}", hash);
        full[..12].to_string()
    };

    format!("t{ver}{ext_count}_{cipher_hex}_{ext_hash}")
}

/// Parse a TLS ServerHello from raw bytes.
pub fn parse_server_hello(data: &[u8]) -> Option<TlsServerFingerprint> {
    // Minimum TLS record header: 5 bytes
    if data.len() < 5 {
        return None;
    }

    // Check content type: must be Handshake (0x16)
    if data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let available = data.len().saturating_sub(5);
    let fragment = &data[5..5 + record_len.min(available)];

    // Handshake header: type(1) + length(3)
    if fragment.len() < 4 {
        return None;
    }

    let handshake_type = fragment[0];
    if handshake_type != 0x02 {
        // Not ServerHello
        return None;
    }

    let body_len =
        ((fragment[1] as usize) << 16) | ((fragment[2] as usize) << 8) | (fragment[3] as usize);
    let available_body = fragment.len().saturating_sub(4);
    let body = &fragment[4..4 + body_len.min(available_body)];

    parse_server_hello_body(body)
}

/// Parse the ServerHello body (after handshake header).
fn parse_server_hello_body(body: &[u8]) -> Option<TlsServerFingerprint> {
    // ServerVersion(2) + Random(32) + SessionIDLen(1) = 35 minimum
    if body.len() < 35 {
        return None;
    }

    let mut tls_version = u16::from_be_bytes([body[0], body[1]]);

    // Skip Random (32 bytes), then read SessionID length
    let session_id_len = body[34] as usize;
    let pos = 35 + session_id_len;

    // CipherSuite(2) + CompressionMethod(1)
    if body.len() < pos + 3 {
        return None;
    }

    let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    let compression_method = body[pos + 2];
    let mut ext_pos = pos + 3;

    // Parse extensions if present
    let mut extensions = Vec::new();
    let mut alpn_protocol: Option<String> = None;
    if body.len() > ext_pos + 2 {
        let ext_total_len = u16::from_be_bytes([body[ext_pos], body[ext_pos + 1]]) as usize;
        ext_pos += 2;
        let ext_end = ext_pos + ext_total_len.min(body.len().saturating_sub(ext_pos));

        while ext_pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([body[ext_pos], body[ext_pos + 1]]);
            let ext_len = u16::from_be_bytes([body[ext_pos + 2], body[ext_pos + 3]]) as usize;

            // Check for supported_versions extension (TLS 1.3 negotiation)
            if ext_type == 0x002B && ext_len == 2 && ext_pos + 6 <= ext_end {
                tls_version = u16::from_be_bytes([body[ext_pos + 4], body[ext_pos + 5]]);
            }

            // Check for ALPN extension (0x0010)
            if ext_type == 0x0010 && ext_len >= 4 {
                let this_ext_end = (ext_pos + 4 + ext_len).min(ext_end);
                let alpn_data_start = ext_pos + 4;
                // ALPN: list_len(2) + proto_len(1) + proto_bytes
                if alpn_data_start + 2 <= this_ext_end {
                    let proto_len_pos = alpn_data_start + 2;
                    if proto_len_pos < this_ext_end {
                        let proto_len = body[proto_len_pos] as usize;
                        let proto_start = proto_len_pos + 1;
                        if proto_start + proto_len <= this_ext_end {
                            alpn_protocol = Some(
                                String::from_utf8_lossy(
                                    &body[proto_start..proto_start + proto_len],
                                )
                                .to_string(),
                            );
                        }
                    }
                }
            }

            extensions.push(ext_type);
            ext_pos += 4 + ext_len;
        }
    }

    Some(TlsServerFingerprint {
        tls_version,
        cipher_suite,
        extensions,
        compression_method,
        alpn: alpn_protocol,
        ja4s: None,
        sni: None,
        certificate_chain: None,
    })
}

/// Concatenate all TLS Handshake (0x16) record payloads into a contiguous buffer.
///
/// TLS allows a single handshake message to span multiple records, so we must
/// reassemble them before parsing individual handshake messages.
fn collect_handshake_payloads(data: &[u8]) -> Vec<u8> {
    let mut handshake_buf = Vec::new();
    let mut pos = 0;
    while pos + 5 <= data.len() {
        let content_type = data[pos];
        let rec_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        let rec_end = (pos + 5 + rec_len).min(data.len());
        if content_type == 0x16 {
            handshake_buf.extend_from_slice(&data[pos + 5..rec_end]);
        }
        pos = rec_end;
    }
    handshake_buf
}

/// Check if the buffer contains a ServerHelloDone handshake message (type 0x0E).
fn has_server_hello_done(data: &[u8]) -> bool {
    let handshake_buf = collect_handshake_payloads(data);

    // Scan for ServerHelloDone (type 0x0E) in the contiguous handshake buffer
    let mut hs_pos = 0;
    while hs_pos + 4 <= handshake_buf.len() {
        let hs_type = handshake_buf[hs_pos];
        if hs_type == 0x0E {
            return true;
        }
        let hs_len = ((handshake_buf[hs_pos + 1] as usize) << 16)
            | ((handshake_buf[hs_pos + 2] as usize) << 8)
            | (handshake_buf[hs_pos + 3] as usize);
        hs_pos += 4 + hs_len;
    }
    false
}

/// Parse a TLS handshake flight containing ServerHello + optional Certificate.
///
/// Returns (fingerprint, certificate_chain).
fn parse_tls_handshake_flight(
    data: &[u8],
) -> (Option<TlsServerFingerprint>, Option<Vec<CertificateInfo>>) {
    let handshake_buf = collect_handshake_payloads(data);

    // Parse handshake messages from the contiguous buffer.
    let mut fingerprint = None;
    let mut certs = None;
    let mut hs_pos = 0;

    while hs_pos + 4 <= handshake_buf.len() {
        let hs_type = handshake_buf[hs_pos];
        let hs_len = ((handshake_buf[hs_pos + 1] as usize) << 16)
            | ((handshake_buf[hs_pos + 2] as usize) << 8)
            | (handshake_buf[hs_pos + 3] as usize);
        if hs_pos + 4 + hs_len > handshake_buf.len() {
            break; // truncated message — stop parsing
        }
        let hs_body = &handshake_buf[hs_pos + 4..hs_pos + 4 + hs_len];

        match hs_type {
            0x02 => fingerprint = parse_server_hello_body(hs_body),
            0x0B => certs = parse_certificate_message(hs_body),
            0x0E => return (fingerprint, certs),
            _ => {}
        }

        hs_pos += 4 + hs_len;
    }

    (fingerprint, certs)
}

/// Parse a Certificate handshake message body.
///
/// Format: `CertificateListLength(3) | [CertLength(3) | CertDER(CertLength)]*`
fn parse_certificate_message(data: &[u8]) -> Option<Vec<CertificateInfo>> {
    if data.len() < 3 {
        return None;
    }

    let total_len =
        ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);
    let end = (3 + total_len).min(data.len());
    let mut pos = 3;
    let mut certs = Vec::new();
    let mut chain_pos = 0u8;

    while pos + 3 <= end {
        let cert_len =
            ((data[pos] as usize) << 16) | ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
        pos += 3;
        let cert_end = (pos + cert_len).min(end);
        if cert_end > pos {
            let der = &data[pos..cert_end];
            if let Some(info) = parse_x509_certificate(der, chain_pos) {
                certs.push(info);
            }
            chain_pos = chain_pos.saturating_add(1);
        }
        pos = cert_end;
    }

    if certs.is_empty() { None } else { Some(certs) }
}

/// Parse a single DER-encoded X.509 certificate into CertificateInfo.
fn parse_x509_certificate(der: &[u8], chain_position: u8) -> Option<CertificateInfo> {
    use x509_parser::prelude::*;
    use x509_parser::public_key::PublicKey;

    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let subject_dn = Some(cert.subject().to_string());

    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let issuer_dn = Some(cert.issuer().to_string());

    let serial = Some(
        cert.raw_serial()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    );

    let not_before = Some(cert.validity().not_before.to_string());
    let not_after = Some(cert.validity().not_after.to_string());

    // Subject Alternative Names (DNS entries only)
    let san_dns = cert
        .extensions()
        .iter()
        .filter_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
        .flat_map(|san| san.general_names.iter())
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect();

    let signature_algorithm = Some(signature_algorithm_name(
        &cert.signature_algorithm.algorithm.to_id_string(),
    ));

    let public_key_info = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => Some(format!("RSA {}", rsa.key_size())),
        Ok(PublicKey::EC(_)) => {
            let curve = cert
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| match oid.to_id_string().as_str() {
                    "1.2.840.10045.3.1.7" => "P-256",
                    "1.3.132.0.34" => "P-384",
                    "1.3.132.0.35" => "P-521",
                    _ => "unknown",
                })
                .unwrap_or("unknown");
            Some(format!("EC {curve}"))
        }
        _ => None,
    };

    let sha256_fingerprint = Some(format!("{:x}", Sha256::digest(der)));

    let self_signed = cert.subject() == cert.issuer();

    Some(CertificateInfo {
        subject_cn,
        subject_dn,
        issuer_cn,
        issuer_dn,
        serial,
        not_before,
        not_after,
        san_dns,
        signature_algorithm,
        public_key_info,
        sha256_fingerprint,
        self_signed,
        chain_position,
    })
}

/// Map common signature algorithm OIDs to human-readable names.
fn signature_algorithm_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".into(),
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".into(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        "1.2.840.113549.1.1.10" => "RSASSA-PSS".into(),
        "1.3.101.112" => "Ed25519".into(),
        "1.3.101.113" => "Ed448".into(),
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_client_hello_valid_tls_record() {
        let hello = build_client_hello(None);
        // Must start with TLS Handshake content type
        assert_eq!(hello[0], 0x16);
        // Record version: TLS 1.0
        assert_eq!(&hello[1..3], &[0x03, 0x01]);
        // Record length
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + record_len);
        // Handshake type: ClientHello
        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn build_client_hello_contains_cipher_suites() {
        let hello = build_client_hello(None);
        // After record(5) + handshake_header(4) + version(2) + random(32) + session_id_len(1)
        let pos = 5 + 4 + 2 + 32 + 1;
        let suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
        assert_eq!(suites_len, CIPHER_SUITES.len() * 2);
    }

    #[test]
    fn build_client_hello_contains_extensions() {
        let hello = build_client_hello(None);
        // Find extensions area: after cipher suites and compression
        let suites_start = 5 + 4 + 2 + 32 + 1;
        let suites_len = u16::from_be_bytes([hello[suites_start], hello[suites_start + 1]]) as usize;
        let comp_start = suites_start + 2 + suites_len;
        let comp_len = hello[comp_start] as usize;
        let ext_len_pos = comp_start + 1 + comp_len;
        let ext_len = u16::from_be_bytes([hello[ext_len_pos], hello[ext_len_pos + 1]]) as usize;
        assert!(ext_len > 0, "should have extensions");
    }

    /// Helper to build a raw ServerHello TLS record from parts.
    fn build_test_server_hello(
        version: [u8; 2],
        session_id: &[u8],
        cipher_suite: [u8; 2],
        compression: u8,
        extensions: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version);
        body.extend_from_slice(&[0x00; 32]); // Random
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&cipher_suite);
        body.push(compression);
        if !extensions.is_empty() {
            let ext_len = extensions.len() as u16;
            body.extend_from_slice(&ext_len.to_be_bytes());
            body.extend_from_slice(extensions);
        }

        // Wrap in handshake
        let mut handshake = vec![0x02]; // ServerHello
        let len = body.len() as u32;
        handshake.push((len >> 16) as u8);
        handshake.push((len >> 8) as u8);
        handshake.push(len as u8);
        handshake.extend_from_slice(&body);

        // Wrap in record
        let mut record = vec![0x16, 0x03, 0x03];
        let rec_len = handshake.len() as u16;
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// Helper to build raw extension bytes.
    fn build_test_extensions(exts: &[(u16, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        for (ext_type, data) in exts {
            buf.extend_from_slice(&ext_type.to_be_bytes());
            let len = data.len() as u16;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(data);
        }
        buf
    }

    #[test]
    fn parse_server_hello_tls12() {
        let exts = build_test_extensions(&[
            (0xFF01, &[0x00]),            // renegotiation_info
            (0x0017, &[]),                // extended_master_secret
        ]);
        let record = build_test_server_hello(
            [0x03, 0x03],
            &[],
            [0xC0, 0x2F], // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0,
            &exts,
        );

        let fp = parse_server_hello(&record).unwrap();
        assert_eq!(fp.tls_version, 0x0303);
        assert_eq!(fp.cipher_suite, 0xC02F);
        assert_eq!(fp.compression_method, 0);
        assert_eq!(fp.extensions, vec![0xFF01, 0x0017]);
    }

    #[test]
    fn parse_server_hello_tls13_via_extension() {
        let exts = build_test_extensions(&[
            (0x002B, &[0x03, 0x04]), // supported_versions: TLS 1.3
        ]);
        let record = build_test_server_hello(
            [0x03, 0x03], // Version field is TLS 1.2 per TLS 1.3 spec
            &[],
            [0x13, 0x01], // TLS_AES_128_GCM_SHA256
            0,
            &exts,
        );

        let fp = parse_server_hello(&record).unwrap();
        assert_eq!(fp.tls_version, 0x0304); // Should detect TLS 1.3
        assert_eq!(fp.cipher_suite, 0x1301);
        assert_eq!(fp.extensions, vec![0x002B]);
    }

    #[test]
    fn parse_server_hello_with_session_id() {
        let session_id = [0xAA; 32];
        let exts = build_test_extensions(&[(0xFF01, &[0x00])]);
        let record = build_test_server_hello(
            [0x03, 0x03],
            &session_id,
            [0x00, 0x9C],
            0,
            &exts,
        );

        let fp = parse_server_hello(&record).unwrap();
        assert_eq!(fp.tls_version, 0x0303);
        assert_eq!(fp.cipher_suite, 0x009C);
    }

    #[test]
    fn parse_server_hello_no_extensions() {
        let record = build_test_server_hello(
            [0x03, 0x03],
            &[],
            [0x00, 0x2F],
            0,
            &[],
        );

        let fp = parse_server_hello(&record).unwrap();
        assert_eq!(fp.tls_version, 0x0303);
        assert_eq!(fp.cipher_suite, 0x002F);
        assert!(fp.extensions.is_empty());
    }

    #[test]
    fn parse_non_tls_returns_none() {
        let data = b"HTTP/1.1 200 OK\r\n";
        assert!(parse_server_hello(data).is_none());
    }

    #[test]
    fn parse_too_short_returns_none() {
        assert!(parse_server_hello(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn parse_alert_returns_none() {
        // TLS Alert record (content type 0x15)
        let data = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert!(parse_server_hello(&data).is_none());
    }

    #[test]
    fn parse_non_server_hello_handshake_returns_none() {
        // Certificate handshake type (0x0B) instead of ServerHello (0x02)
        let mut record = vec![0x16, 0x03, 0x03, 0x00, 0x04];
        record.extend_from_slice(&[0x0B, 0x00, 0x00, 0x00]); // Certificate, len=0
        assert!(parse_server_hello(&record).is_none());
    }

    #[test]
    fn is_tls_port_common_ports() {
        assert!(is_tls_port(443));
        assert!(is_tls_port(8443));
        assert!(is_tls_port(993));
        assert!(is_tls_port(995));
        assert!(is_tls_port(465));
        assert!(!is_tls_port(80));
        assert!(!is_tls_port(22));
        assert!(!is_tls_port(8080));
    }

    #[test]
    fn client_hello_contains_sni() {
        let hello = build_client_hello(Some("example.com"));
        // SNI extension type is 0x0000 — search for the hostname bytes in the payload
        let hostname_bytes = b"example.com";
        let found = hello
            .windows(hostname_bytes.len())
            .any(|w| w == hostname_bytes);
        assert!(found, "ClientHello should contain SNI hostname bytes");
    }

    #[test]
    fn client_hello_no_sni_without_hostname() {
        let hello = build_client_hello(None);
        // The hostname "example.com" should NOT appear
        let hostname_bytes = b"example.com";
        let found = hello
            .windows(hostname_bytes.len())
            .any(|w| w == hostname_bytes);
        assert!(!found, "ClientHello without hostname should not contain SNI");
    }

    #[test]
    fn client_hello_contains_alpn() {
        let hello = build_client_hello(None);
        // ALPN offers "h2" and "http/1.1" — check for "h2" bytes
        let h2_bytes = b"h2";
        let found = hello.windows(h2_bytes.len()).any(|w| w == h2_bytes);
        assert!(found, "ClientHello should contain ALPN 'h2' offer");
    }

    #[test]
    fn parse_server_hello_alpn() {
        // Build ALPN extension: list_len(2) + proto_len(1) + "h2"(2)
        let mut alpn_data = Vec::new();
        let proto = b"h2";
        let list_len = (1 + proto.len()) as u16;
        alpn_data.extend_from_slice(&list_len.to_be_bytes());
        alpn_data.push(proto.len() as u8);
        alpn_data.extend_from_slice(proto);

        let exts = build_test_extensions(&[
            (0xFF01, &[0x00]),     // renegotiation_info
            (0x0010, &alpn_data),  // ALPN
        ]);
        let record = build_test_server_hello(
            [0x03, 0x03],
            &[],
            [0xC0, 0x2F],
            0,
            &exts,
        );

        let fp = parse_server_hello(&record).unwrap();
        assert_eq!(fp.alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn parse_server_hello_no_alpn() {
        let exts = build_test_extensions(&[(0xFF01, &[0x00])]);
        let record = build_test_server_hello(
            [0x03, 0x03],
            &[],
            [0xC0, 0x2F],
            0,
            &exts,
        );

        let fp = parse_server_hello(&record).unwrap();
        assert!(fp.alpn.is_none());
    }

    #[test]
    fn compute_ja4s_tls13() {
        let fp = TlsServerFingerprint {
            tls_version: 0x0304,
            cipher_suite: 0x1301,
            extensions: vec![0x002B, 0xFF01],
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };
        let ja4s = compute_ja4s(&fp);
        assert!(ja4s.starts_with("t1302_1301_"), "JA4S should start with t1302_1301_, got: {ja4s}");
        // ext_hash should be 12 hex chars
        let parts: Vec<&str> = ja4s.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn compute_ja4s_tls12() {
        let fp = TlsServerFingerprint {
            tls_version: 0x0303,
            cipher_suite: 0xC02F,
            extensions: vec![0xFF01, 0x0017],
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };
        let ja4s = compute_ja4s(&fp);
        assert!(ja4s.starts_with("t1202_c02f_"), "JA4S should start with t1202_c02f_, got: {ja4s}");
    }

    #[test]
    fn compute_ja4s_no_extensions() {
        let fp = TlsServerFingerprint {
            tls_version: 0x0303,
            cipher_suite: 0x002F,
            extensions: vec![],
            compression_method: 0,
            alpn: None,
            ja4s: None,
            sni: None,
            certificate_chain: None,
        };
        let ja4s = compute_ja4s(&fp);
        assert!(ja4s.ends_with("_000000000000"), "No extensions should use fallback hash, got: {ja4s}");
    }

    // Self-signed EC P-256 test certificate (CN=test.example.com, O=RustMap Test)
    // SANs: test.example.com, *.example.com
    const TEST_CERT_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xe4, 0x30, 0x82, 0x01, 0x8b, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x33,
        0x85, 0xcb, 0xf8, 0xb9, 0x64, 0x00, 0x2f, 0x4a, 0x5a, 0x3d, 0x26, 0xb4, 0x5e, 0x59, 0x0b, 0x84,
        0xa6, 0x07, 0xc5, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x32, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x10, 0x74, 0x65, 0x73, 0x74,
        0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x15, 0x30, 0x13,
        0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x52, 0x75, 0x73, 0x74, 0x4d, 0x61, 0x70, 0x20, 0x54,
        0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x32, 0x31, 0x39, 0x32, 0x30, 0x32,
        0x30, 0x30, 0x39, 0x5a, 0x17, 0x0d, 0x32, 0x37, 0x30, 0x32, 0x31, 0x39, 0x32, 0x30, 0x32, 0x30,
        0x30, 0x39, 0x5a, 0x30, 0x32, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x10,
        0x74, 0x65, 0x73, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0c, 0x52, 0x75, 0x73, 0x74, 0x4d,
        0x61, 0x70, 0x20, 0x54, 0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
        0x00, 0x04, 0x3f, 0x60, 0x67, 0x0d, 0x32, 0xe9, 0x61, 0x56, 0xdb, 0x78, 0x72, 0x91, 0xed, 0xe2,
        0xf4, 0x86, 0xfe, 0x9f, 0xeb, 0x15, 0xe9, 0x64, 0x98, 0x52, 0xc2, 0x64, 0x16, 0xcc, 0x6e, 0x9d,
        0x47, 0xd3, 0x15, 0x4a, 0xe3, 0x6f, 0xba, 0xcb, 0x82, 0xf9, 0x82, 0xf2, 0x8a, 0x8f, 0x76, 0x7c,
        0xab, 0xff, 0xf0, 0x9a, 0xb7, 0xf1, 0xbf, 0x3d, 0x2e, 0xe7, 0xe0, 0x8e, 0x20, 0xc2, 0xd8, 0x60,
        0xf0, 0x5e, 0xa3, 0x7f, 0x30, 0x7d, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
        0x14, 0x6f, 0x75, 0xc4, 0xd8, 0xa9, 0x76, 0x1c, 0x01, 0xa1, 0x32, 0x7f, 0x33, 0x71, 0xc1, 0x23,
        0x07, 0xf9, 0xa2, 0x14, 0x45, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
        0x80, 0x14, 0x6f, 0x75, 0xc4, 0xd8, 0xa9, 0x76, 0x1c, 0x01, 0xa1, 0x32, 0x7f, 0x33, 0x71, 0xc1,
        0x23, 0x07, 0xf9, 0xa2, 0x14, 0x45, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
        0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x2a, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x23,
        0x30, 0x21, 0x82, 0x10, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0d, 0x2a, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03,
        0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x4f, 0x7f, 0x20, 0x1b, 0xfe, 0x4d, 0x80, 0x57, 0xbf, 0xe9,
        0xd6, 0xda, 0x83, 0xb2, 0x32, 0xb1, 0xd0, 0xeb, 0xd3, 0xe3, 0xd1, 0x7f, 0x57, 0x5a, 0xf9, 0x56,
        0x8e, 0xe8, 0xf9, 0xb1, 0x0b, 0x00, 0x02, 0x20, 0x30, 0x64, 0xa2, 0x63, 0xbc, 0x93, 0x88, 0xce,
        0x67, 0x32, 0xdd, 0xc0, 0xf7, 0xf8, 0xaa, 0xda, 0xdd, 0x5a, 0xc8, 0x65, 0xbe, 0xd4, 0xc3, 0x04,
        0x50, 0x26, 0x6e, 0x40, 0xd9, 0x6b, 0xe6, 0xd3,
    ];

    /// Build a Certificate handshake message wrapping one DER cert.
    fn build_test_certificate_message(cert_der: &[u8]) -> Vec<u8> {
        let cert_len = cert_der.len();
        let list_len = cert_len + 3; // cert_length(3) + cert_der
        let mut body = Vec::new();
        // Certificate list length (3 bytes)
        body.push((list_len >> 16) as u8);
        body.push((list_len >> 8) as u8);
        body.push(list_len as u8);
        // First cert: length(3) + DER
        body.push((cert_len >> 16) as u8);
        body.push((cert_len >> 8) as u8);
        body.push(cert_len as u8);
        body.extend_from_slice(cert_der);
        body
    }

    /// Build a complete TLS handshake flight record (ServerHello + Certificate + ServerHelloDone).
    fn build_test_handshake_flight(
        server_hello_body: &[u8],
        cert_message_body: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut handshakes = Vec::new();

        // ServerHello (type 0x02)
        handshakes.push(0x02);
        let len = server_hello_body.len() as u32;
        handshakes.push((len >> 16) as u8);
        handshakes.push((len >> 8) as u8);
        handshakes.push(len as u8);
        handshakes.extend_from_slice(server_hello_body);

        // Certificate (type 0x0B) — optional
        if let Some(cert_body) = cert_message_body {
            handshakes.push(0x0B);
            let len = cert_body.len() as u32;
            handshakes.push((len >> 16) as u8);
            handshakes.push((len >> 8) as u8);
            handshakes.push(len as u8);
            handshakes.extend_from_slice(cert_body);
        }

        // ServerHelloDone (type 0x0E, length 0)
        handshakes.extend_from_slice(&[0x0E, 0x00, 0x00, 0x00]);

        // Wrap in a single TLS record
        let mut record = vec![0x16, 0x03, 0x03];
        let rec_len = handshakes.len() as u16;
        record.extend_from_slice(&rec_len.to_be_bytes());
        record.extend_from_slice(&handshakes);
        record
    }

    /// Build raw ServerHello body bytes (no handshake header, no TLS record).
    fn build_server_hello_body(
        version: [u8; 2],
        cipher_suite: [u8; 2],
        extensions: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&version);
        body.extend_from_slice(&[0x00; 32]); // Random
        body.push(0); // Session ID length
        body.extend_from_slice(&cipher_suite);
        body.push(0); // Compression method
        if !extensions.is_empty() {
            let ext_len = extensions.len() as u16;
            body.extend_from_slice(&ext_len.to_be_bytes());
            body.extend_from_slice(extensions);
        }
        body
    }

    #[test]
    fn has_server_hello_done_detection() {
        // A record with ServerHelloDone
        let record = vec![
            0x16, 0x03, 0x03, 0x00, 0x04, // TLS record header (4 bytes payload)
            0x0E, 0x00, 0x00, 0x00,         // ServerHelloDone (type=0x0E, len=0)
        ];
        assert!(has_server_hello_done(&record));

        // A record without ServerHelloDone (just a ServerHello stub)
        let record2 = vec![
            0x16, 0x03, 0x03, 0x00, 0x04,
            0x02, 0x00, 0x00, 0x00, // ServerHello (type=0x02, len=0)
        ];
        assert!(!has_server_hello_done(&record2));

        // Empty data
        assert!(!has_server_hello_done(&[]));
    }

    #[test]
    fn parse_x509_self_signed_detection() {
        let info = parse_x509_certificate(TEST_CERT_DER, 0).unwrap();
        assert!(info.self_signed, "test cert should be self-signed");
        assert_eq!(info.subject_cn.as_deref(), Some("test.example.com"));
        assert_eq!(info.issuer_cn.as_deref(), Some("test.example.com"));
        assert_eq!(info.chain_position, 0);
        assert!(info.public_key_info.as_ref().unwrap().starts_with("EC"));
        assert!(info.sha256_fingerprint.is_some());
        assert_eq!(
            info.signature_algorithm.as_deref(),
            Some("ecdsa-with-SHA256")
        );
    }

    #[test]
    fn parse_x509_san_extraction() {
        let info = parse_x509_certificate(TEST_CERT_DER, 0).unwrap();
        assert!(info.san_dns.contains(&"test.example.com".to_string()));
        assert!(info.san_dns.contains(&"*.example.com".to_string()));
        assert_eq!(info.san_dns.len(), 2);
    }

    #[test]
    fn parse_certificate_message_single_cert() {
        let cert_msg = build_test_certificate_message(TEST_CERT_DER);
        let certs = parse_certificate_message(&cert_msg).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject_cn.as_deref(), Some("test.example.com"));
        assert_eq!(certs[0].chain_position, 0);
    }

    #[test]
    fn parse_handshake_flight_tls12_with_certs() {
        let exts = build_test_extensions(&[(0xFF01, &[0x00])]);
        let sh_body = build_server_hello_body([0x03, 0x03], [0xC0, 0x2F], &exts);
        let cert_msg = build_test_certificate_message(TEST_CERT_DER);
        let flight = build_test_handshake_flight(&sh_body, Some(&cert_msg));

        let (fp, certs) = parse_tls_handshake_flight(&flight);
        let fp = fp.unwrap();
        assert_eq!(fp.tls_version, 0x0303);
        assert_eq!(fp.cipher_suite, 0xC02F);

        let certs = certs.unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].subject_cn.as_deref(), Some("test.example.com"));
    }

    #[test]
    fn parse_handshake_flight_tls13_no_certs() {
        // TLS 1.3: ServerHello with supported_versions extension, no Certificate message
        let sv_ext = build_test_extensions(&[(0x002B, &[0x03, 0x04])]);
        let sh_body = build_server_hello_body([0x03, 0x03], [0x13, 0x01], &sv_ext);
        // No certificate message, just ServerHello + ServerHelloDone
        let flight = build_test_handshake_flight(&sh_body, None);

        let (fp, certs) = parse_tls_handshake_flight(&flight);
        let fp = fp.unwrap();
        assert_eq!(fp.tls_version, 0x0304);
        assert!(certs.is_none(), "TLS 1.3 flight should have no certs");
    }

    #[test]
    fn parse_certificate_message_empty() {
        // Certificate message with 0-length cert list
        let data = [0x00, 0x00, 0x00]; // total_len = 0
        assert!(parse_certificate_message(&data).is_none());
    }

    #[test]
    fn parse_certificate_message_invalid_der() {
        // Certificate message wrapping garbage DER
        let garbage = [0xFF; 32];
        let cert_msg = build_test_certificate_message(&garbage);
        // Should return None because x509 parsing fails
        assert!(parse_certificate_message(&cert_msg).is_none());
    }
}
